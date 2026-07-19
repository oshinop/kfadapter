// Package selector derives and validates opaque per-node SOCKS credentials.
package selector

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/kfadapter/kfadapter/internal/state"
	"golang.org/x/net/idna"
)

const (
	selectorPrefix = "n_"
	passwordPrefix = "p_"
	selectorBytes  = 12
	passwordBytes  = 18

	// DefaultTombstoneGrace keeps removed selectors as explicit failures long
	// enough for consumers to reload an updated subscription.
	DefaultTombstoneGrace = 24 * time.Hour
	// MaxLiveSelectorsPerGeneration bounds active selector references.
	MaxLiveSelectorsPerGeneration = 4096
	// MaxTombstonesPerGeneration bounds removed selector references.
	MaxTombstonesPerGeneration = 8192
	maxPreviousSelectors       = 2 * (MaxLiveSelectorsPerGeneration + MaxTombstonesPerGeneration)
)

var (
	ErrInvalidIdentity   = errors.New("invalid node identity")
	ErrInvalidKey        = errors.New("invalid selector key")
	ErrUnknownGeneration = errors.New("unknown selector generation")
	ErrDuplicateNodeID   = errors.New("duplicate node id")
	ErrTooManyNodes      = errors.New("too many live selector nodes")
	ErrTooManySelectors  = errors.New("too many prior selector references")
)

var lookupIDNA = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(true),
	idna.ValidateForRegistration(),
	idna.VerifyDNSLength(true),
)

// NodeIdentity is the upstream identity that determines a selector. Display
// metadata deliberately does not participate in credential derivation.
type NodeIdentity struct {
	Provider string
	Host     string
	Port     int
}

// CanonicalIdentity is a validated normal form suitable for fingerprints.
type CanonicalIdentity struct {
	Provider string
	Host     string
	Port     uint16
}

// Canonicalize implements the exact provider, host, and port normalization.
func Canonicalize(identity NodeIdentity) (CanonicalIdentity, error) {
	provider, err := canonicalProvider(identity.Provider)
	if err != nil {
		return CanonicalIdentity{}, err
	}
	host, err := canonicalHost(identity.Host)
	if err != nil {
		return CanonicalIdentity{}, err
	}
	if identity.Port < 1 || identity.Port > 65535 {
		return CanonicalIdentity{}, fmt.Errorf("%w: port out of range", ErrInvalidIdentity)
	}
	return CanonicalIdentity{Provider: provider, Host: host, Port: uint16(identity.Port)}, nil
}

func canonicalProvider(provider string) (string, error) {
	if provider == "" {
		return "", fmt.Errorf("%w: empty provider", ErrInvalidIdentity)
	}
	var builder strings.Builder
	builder.Grow(len(provider))
	for _, value := range []byte(provider) {
		if value > 0x7f || value == 0 || value <= ' ' || value == 0x7f {
			return "", fmt.Errorf("%w: provider is not printable ASCII", ErrInvalidIdentity)
		}
		if value >= 'a' && value <= 'z' {
			value -= 'a' - 'A'
		}
		builder.WriteByte(value)
	}
	return builder.String(), nil
}

func canonicalHost(host string) (string, error) {
	if host == "" || strings.IndexByte(host, 0) >= 0 {
		return "", fmt.Errorf("%w: empty host", ErrInvalidIdentity)
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String(), nil
	}
	ascii, err := lookupIDNA.ToASCII(strings.ToLower(host))
	if err != nil {
		return "", fmt.Errorf("%w: IDNA host: %v", ErrInvalidIdentity, err)
	}
	ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if ascii == "" || strings.ContainsAny(ascii, "\x00/\\@") {
		return "", fmt.Errorf("%w: invalid DNS host", ErrInvalidIdentity)
	}
	return ascii, nil
}

// Fingerprint serializes the normative credential input.
func (i CanonicalIdentity) Fingerprint() []byte {
	return []byte("v1\x00" + i.Provider + "\x00" + i.Host + "\x00" + fmt.Sprintf("%d", i.Port))
}

// Credentials are the opaque username/password placed in a logical SOCKS URL.
type Credentials struct {
	Selector string
	Password string
}

// Derive creates HMAC-derived selector and password credentials.
func Derive(identity NodeIdentity, selectorKey, proxyAuthKey []byte) (Credentials, error) {
	canonical, err := Canonicalize(identity)
	if err != nil {
		return Credentials{}, err
	}
	return DeriveCanonical(canonical, selectorKey, proxyAuthKey)
}

// DeriveCanonical is Derive for a previously canonical identity.
func DeriveCanonical(identity CanonicalIdentity, selectorKey, proxyAuthKey []byte) (Credentials, error) {
	if len(selectorKey) != sha256.Size || len(proxyAuthKey) != sha256.Size {
		return Credentials{}, ErrInvalidKey
	}
	selectorMAC := mac(selectorKey, identity.Fingerprint())
	selector := selectorPrefix + base64.RawURLEncoding.EncodeToString(selectorMAC[:selectorBytes])
	passwordMAC := mac(proxyAuthKey, []byte("v1\x00password\x00"+selector))
	password := passwordPrefix + base64.RawURLEncoding.EncodeToString(passwordMAC[:passwordBytes])
	return Credentials{Selector: selector, Password: password}, nil
}

func mac(key, message []byte) []byte {
	result := hmac.New(sha256.New, key)
	_, _ = result.Write(message)
	return result.Sum(nil)
}

// Registry derives and authenticates exactly one immutable credential
// generation. Account cutover constructs a replacement registry and the
// runtime swaps that pointer atomically with its SOCKS authority.
type Registry struct {
	generation generation
}

type generation struct {
	generation   uint64
	selectorKey  [sha256.Size]byte
	proxyAuthKey [sha256.Size]byte
}

// NewRegistry constructs a registry for one persisted subscription generation.
// There is deliberately no pending or expiring credential authority.
func NewRegistry(source state.SubscriptionGeneration) (*Registry, error) {
	current, err := makeGeneration(source)
	if err != nil {
		return nil, err
	}
	return &Registry{generation: *current}, nil
}

func makeGeneration(source state.SubscriptionGeneration) (*generation, error) {
	if source.Generation == 0 || len(source.SelectorKey) != sha256.Size || len(source.ProxyAuthKey) != sha256.Size {
		return nil, ErrInvalidKey
	}
	result := &generation{generation: source.Generation}
	copy(result.selectorKey[:], source.SelectorKey)
	copy(result.proxyAuthKey[:], source.ProxyAuthKey)
	return result, nil
}

// Generations returns the sole active generation in authentication priority.
func (r *Registry) Generations() []uint64 {
	if r == nil {
		return nil
	}
	return []uint64{r.generation.generation}
}

// Credentials derives credentials only for the current generation.
func (r *Registry) Credentials(want uint64, identity NodeIdentity) (Credentials, bool) {
	keys := r.load(want)
	if keys == nil {
		return Credentials{}, false
	}
	credential, err := Derive(identity, keys.selectorKey[:], keys.proxyAuthKey[:])
	return credential, err == nil
}

// Authenticate verifies fixed-format credentials in constant time. A
// successful response always names the sole generation that created it.
func (r *Registry) Authenticate(selector, password string) (uint64, bool) {
	return r.AuthenticateAt(selector, password, time.Now())
}

// AuthenticateAt is retained for clock-controlled callers; one-current
// authority has no expiry branch.
func (r *Registry) AuthenticateAt(selector, password string, _ time.Time) (uint64, bool) {
	keys := r.load(0)
	if keys == nil || !validSelector(selector) || !validPassword(password) {
		return 0, false
	}
	expectedMAC := mac(keys.proxyAuthKey[:], []byte("v1\x00password\x00"+selector))
	expected := passwordPrefix + base64.RawURLEncoding.EncodeToString(expectedMAC[:passwordBytes])
	if subtle.ConstantTimeCompare([]byte(password), []byte(expected)) != 1 {
		return 0, false
	}
	return keys.generation, true
}

// Resolve authenticates then resolves against a caller-pinned runtime
// snapshot. A credential from any superseded generation cannot resolve.
func (r *Registry) Resolve(snapshot *state.RuntimeSnapshot, selector, password string, now time.Time) (state.Node, state.NodeRef, error) {
	generation, authenticated := r.AuthenticateAt(selector, password, now)
	if !authenticated {
		return state.Node{}, state.NodeRef{}, state.ErrSelectorUnknown
	}
	node, ref, err := snapshot.ResolveSelector(selector, now)
	if err != nil || ref.Generation != generation {
		return state.Node{}, ref, state.ErrSelectorUnknown
	}
	return node, ref, nil
}

// BuildResult is a complete immutable selector view for the current generation.
type BuildResult struct {
	Nodes     []state.Node
	Selectors map[string]state.NodeRef
}

// BuildWithTombstones creates deterministic selectors and carries only this
// generation's prior selector state forward. An active tombstone always wins
// over a reappearing selector, and a selector never remaps to another node ID.
func (r *Registry) BuildWithTombstones(want uint64, nodes []state.Node, previous map[string]state.NodeRef, now time.Time) (BuildResult, error) {
	keys := r.load(want)
	if keys == nil {
		return BuildResult{}, ErrUnknownGeneration
	}
	if len(nodes) > MaxLiveSelectorsPerGeneration {
		return BuildResult{}, ErrTooManyNodes
	}
	if len(previous) > maxPreviousSelectors {
		return BuildResult{}, ErrTooManySelectors
	}
	selected := make([]state.Node, 0, len(nodes))
	ids := make(map[string]struct{}, len(nodes))
	activeIndex := make(map[string]int, len(nodes))
	for _, source := range nodes {
		if source.ID == "" {
			return BuildResult{}, ErrDuplicateNodeID
		}
		if _, duplicate := ids[source.ID]; duplicate {
			return BuildResult{}, ErrDuplicateNodeID
		}
		ids[source.ID] = struct{}{}
		identity, err := Canonicalize(NodeIdentity{Provider: source.Provider, Host: source.Host, Port: int(source.Port)})
		if err != nil {
			return BuildResult{}, err
		}
		credential, err := DeriveCanonical(identity, keys.selectorKey[:], keys.proxyAuthKey[:])
		if err != nil {
			return BuildResult{}, err
		}
		if _, collision := activeIndex[credential.Selector]; collision {
			return BuildResult{}, ErrDuplicateNodeID
		}
		source.Provider = identity.Provider
		source.Host = identity.Host
		source.Port = identity.Port
		source.Selector = credential.Selector
		activeIndex[source.Selector] = len(selected)
		selected = append(selected, source)
	}
	active := make([]bool, len(selected))
	for index := range active {
		active[index] = true
	}
	tombstones := make([]tombstone, 0, MaxTombstonesPerGeneration)
	for name, ref := range previous {
		if ref.Generation != want {
			continue
		}
		index, reappeared := activeIndex[name]
		if ref.Tombstoned {
			if !ref.IsTombstoned(now) {
				continue
			}
			if reappeared {
				active[index] = false
			}
			ref.NodeID = ""
			tombstones = append(tombstones, tombstone{selector: name, ref: ref})
			continue
		}
		if reappeared && ref.NodeID == selected[index].ID {
			continue
		}
		if reappeared {
			active[index] = false
		}
		tombstones = append(tombstones, tombstone{selector: name, ref: state.NodeRef{Generation: want, Tombstoned: true, TombstoneUntil: now.UTC().Add(DefaultTombstoneGrace)}})
	}
	sort.Slice(tombstones, func(i, j int) bool {
		if !tombstones[i].ref.TombstoneUntil.Equal(tombstones[j].ref.TombstoneUntil) {
			return tombstones[i].ref.TombstoneUntil.Before(tombstones[j].ref.TombstoneUntil)
		}
		return tombstones[i].selector < tombstones[j].selector
	})
	if len(tombstones) > MaxTombstonesPerGeneration {
		tombstones = tombstones[len(tombstones)-MaxTombstonesPerGeneration:]
	}
	result := BuildResult{Nodes: make([]state.Node, 0, len(selected)), Selectors: make(map[string]state.NodeRef, len(selected)+len(tombstones))}
	for index, source := range selected {
		if !active[index] {
			continue
		}
		result.Nodes = append(result.Nodes, source)
		result.Selectors[source.Selector] = state.NodeRef{NodeID: source.ID, Generation: want}
	}
	for _, entry := range tombstones {
		result.Selectors[entry.selector] = entry.ref
	}
	return result, nil
}

type tombstone struct {
	selector string
	ref      state.NodeRef
}

// Build implements state.SelectorBuilder for callers that do not need prior
// selector tombstones.
func (r *Registry) Build(generation uint64, nodes []state.Node) (map[string]state.NodeRef, error) {
	result, err := r.BuildWithTombstones(generation, nodes, nil, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return result.Selectors, nil
}

func (r *Registry) load(want uint64) *generation {
	if r == nil || (want != 0 && r.generation.generation != want) {
		return nil
	}
	return &r.generation
}

func validSelector(selector string) bool {
	if len(selector) != len(selectorPrefix)+base64.RawURLEncoding.EncodedLen(selectorBytes) || !strings.HasPrefix(selector, selectorPrefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(selector[len(selectorPrefix):])
	return err == nil && len(decoded) == selectorBytes
}

func validPassword(password string) bool {
	if len(password) != len(passwordPrefix)+base64.RawURLEncoding.EncodedLen(passwordBytes) || !strings.HasPrefix(password, passwordPrefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(password[len(passwordPrefix):])
	return err == nil && len(decoded) == passwordBytes
}

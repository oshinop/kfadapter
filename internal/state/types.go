// Package state owns the adapter's durable state and immutable runtime view.
package state

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/kfadapter/kfadapter/internal/wifiin"
)

const (
	maxPersistedNodes            = 4096
	maxRuntimeNodes              = 4096
	maxRuntimeSelectorRefs       = 4096 + 8192
	maxRenderedSubscriptionBytes = 10 << 20
	maxSessionLifetime           = 24 * time.Hour
	maxSessionFieldBytes         = 4096
	maxProviderExtensionBytes    = 3*maxSessionFieldBytes + 128
)

var (
	ErrAccountChanged                = errors.New("account changed")
	ErrAccessTokenAlreadyInitialized = errors.New("access token is already initialized")
	ErrInvalidAccessToken            = errors.New("invalid access token")
	ErrBindingKeyAlreadyConfigured   = errors.New("account binding key is already configured")
	ErrStateNotFound                 = errors.New("persistent state not found")
	ErrCorruptState                  = errors.New("persistent state is corrupt")
	ErrInsecureStatePath             = errors.New("state path has insecure ownership or mode")
	ErrInvalidSnapshot               = errors.New("invalid runtime snapshot")
	ErrInvalidTransition             = errors.New("invalid service state transition")
	ErrOperationInProgress           = errors.New("service operation already in progress")
	ErrNoOperation                   = errors.New("no service operation in progress")
	ErrSelectorUnknown               = errors.New("unknown selector")
	ErrSelectorTombstoned            = errors.New("selector is tombstoned")
)

// ServiceState is the externally visible lifecycle state. State transitions are
// serialized by Manager.
type ServiceState string

const (
	StateSignedOut      ServiceState = "signed_out"
	StateAuthenticating ServiceState = "authenticating"
	StateSyncing        ServiceState = "syncing"
	StateReady          ServiceState = "ready"
	StateDegraded       ServiceState = "degraded"
	StateExpired        ServiceState = "expired"
	StateError          ServiceState = "error"
)

// Operation identifies an exclusive control-plane operation.
type Operation string

const (
	OperationLogin   Operation = "login"
	OperationRefresh Operation = "refresh"
)

// Outcome tells a Manager operation lease how it ended.
type Outcome string

const (
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeCancelled Outcome = "cancelled"
)

// NodeHealth is intentionally distinct from eligibility. Continuous selection
// health is external to the adapter; this is only its latest explicit observation.
type NodeHealth string

const (
	NodeHealthUnknown     NodeHealth = "unknown"
	NodeHealthHealthy     NodeHealth = "healthy"
	NodeHealthUnhealthy   NodeHealth = "unhealthy"
	NodeHealthUnsupported NodeHealth = "unsupported"
)

// UDPHealth reports the deliberately feature-gated UDP state.
type UDPHealth string

const (
	UDPHealthUnavailable UDPHealth = "unavailable"
	UDPHealthUnknown     UDPHealth = "unknown"
)

// Node is a validated upstream metadata record. It contains no tunnel
// password, token, authority material, or provider extension.
type Node struct {
	ID       string `json:"id"`
	Selector string `json:"selector"`
	Provider string `json:"provider"`
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	Name     string `json:"name"`
	Group    string `json:"group"`
	Model    string `json:"model,omitempty"`
	Weight   int    `json:"weight,omitempty"`
	Auto     bool   `json:"auto,omitempty"`

	Eligible  bool          `json:"eligible"`
	Excluded  bool          `json:"excluded"`
	Health    NodeHealth    `json:"health"`
	UDPHealth UDPHealth     `json:"udpHealth"`
	TCPRTT    time.Duration `json:"tcpRtt,omitempty"`
	ProbedAt  time.Time     `json:"probedAt,omitempty"`
}

// TunnelEligible reports whether a node can be selected by the baseline data
// plane. Excluded records are presentation history only and never affect local
// tunnel selection.
func (n Node) TunnelEligible() bool {
	return n.Eligible && n.Port != 0 && n.Host != "" && strings.EqualFold(n.Provider, "WIFIIN")
}

// SelectorBuilder derives opaque selector references without making state
// depend on the selector implementation. selector.Registry implements it.
type SelectorBuilder interface {
	Build(generation uint64, nodes []Node) (map[string]NodeRef, error)
}

// NodeRef is a generation-bound selector resolution record. Tombstones never
// include a replacement node, preventing accidental remapping.
type NodeRef struct {
	NodeID         string    `json:"nodeId,omitempty"`
	Generation     uint64    `json:"generation"`
	Tombstoned     bool      `json:"tombstoned,omitempty"`
	TombstoneUntil time.Time `json:"tombstoneUntil,omitempty"`
}

// IsTombstoned reports whether a selector is an active tombstone at now.
func (r NodeRef) IsTombstoned(now time.Time) bool {
	return r.Tombstoned && (r.TombstoneUntil.IsZero() || now.Before(r.TombstoneUntil))
}

// SessionSecrets contain provider authority material. They are persisted only
// in the permission-protected SQLite state database by explicit product choice.
type SessionSecrets struct {
	UserID            string `json:"-"`
	LoginToken        string `json:"-"`
	ProviderToken     string `json:"-"`
	TunnelPassword    string `json:"-"`
	TunnelMethod      string `json:"-"`
	ProviderExtension string `json:"-"`
}

// Valid reports whether the session fields are non-empty, bounded provider
// authority material suitable for an in-memory runtime snapshot.
func (s SessionSecrets) Valid() bool {
	return validSessionField(s.UserID, maxSessionFieldBytes) &&
		validSessionField(s.LoginToken, maxSessionFieldBytes) &&
		validSessionField(s.ProviderToken, maxSessionFieldBytes) &&
		validSessionField(s.TunnelPassword, maxSessionFieldBytes) &&
		validSessionField(s.TunnelMethod, maxSessionFieldBytes) &&
		validSessionField(s.ProviderExtension, maxProviderExtensionBytes)
}

func validSessionField(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.IndexByte(value, 0) < 0
}

func validPersistedSession(session SessionSecrets) bool {
	if !session.Valid() || session.TunnelMethod != "aes-256-cfb" || !wifiin.ValidProviderExtension(session.ProviderExtension) {
		return false
	}
	parts := strings.Split(session.ProviderExtension, "|")
	return parts[1] == session.ProviderToken && parts[4] == session.UserID
}

// Clone returns an independent SessionSecrets value. String contents are
// immutable in Go, so copying does not create a mutable alias.
func (s SessionSecrets) Clone() SessionSecrets { return s }

// Wipe clears references held by this value. Callers should invoke it once a
// transient session is no longer required; Go cannot guarantee immediate heap
// erasure of immutable strings.
func (s *SessionSecrets) Wipe() {
	if s == nil {
		return
	}
	*s = SessionSecrets{}
}

// AccountSummary deliberately has no raw account identifier. Display must be
// produced with RedactAccount before publication.
type AccountSummary struct {
	Display   string    `json:"display"`
	IsVIP     bool      `json:"isVip"`
	VIPEndsAt time.Time `json:"vipEndsAt,omitempty"`
}

// NewAccountSummary is the safe construction path for browser-visible account
// metadata. It never retains the supplied raw account identifier.
func NewAccountSummary(account string, isVIP bool, vipEndsAt time.Time) AccountSummary {
	return AccountSummary{Display: RedactAccount(account), IsVIP: isVIP, VIPEndsAt: vipEndsAt}
}

// RedactAccount returns a safe display form. It never returns the original
// local part and declines to expose malformed account strings.
func RedactAccount(account string) string {
	account = strings.TrimSpace(account)
	at := strings.LastIndexByte(account, '@')
	if at <= 0 || at == len(account)-1 || strings.Count(account, "@") != 1 {
		return "•••"
	}
	local := []rune(account[:at])
	if len(local) == 0 {
		return "•••"
	}
	return string(local[0]) + "•••@" + account[at+1:]
}

// RuntimeSnapshot is a generation-pinned runtime view. RuntimeStore deep
// copies it on publication and retrieval so no caller can mutate stored state.
type RuntimeSnapshot struct {
	Generation uint64             `json:"generation"`
	CreatedAt  time.Time          `json:"createdAt"`
	ExpiresAt  time.Time          `json:"expiresAt"`
	Account    AccountSummary     `json:"account"`
	Session    SessionSecrets     `json:"-"`
	Nodes      []Node             `json:"nodes"`
	Selectors  map[string]NodeRef `json:"selectors"`
}

// Clone deep-copies all mutable runtime fields.
func (s *RuntimeSnapshot) Clone() *RuntimeSnapshot {
	if s == nil {
		return nil
	}
	clone := *s
	clone.Session = s.Session.Clone()
	clone.Nodes = append([]Node(nil), s.Nodes...)
	clone.Selectors = make(map[string]NodeRef, len(s.Selectors))
	for selector, ref := range s.Selectors {
		clone.Selectors[selector] = ref
	}
	return &clone
}

// NodeByID returns a copy of the node identified by its opaque ID.
func (s *RuntimeSnapshot) NodeByID(id string) (Node, bool) {
	if s == nil {
		return Node{}, false
	}
	for _, node := range s.Nodes {
		if node.ID == id {
			return node, true
		}
	}
	return Node{}, false
}

// ResolveSelector resolves a selector in this pinned snapshot and explicitly
// distinguishes a tombstone from an unknown selector.
func (s *RuntimeSnapshot) ResolveSelector(selector string, now time.Time) (Node, NodeRef, error) {
	if s == nil {
		return Node{}, NodeRef{}, ErrSelectorUnknown
	}
	ref, ok := s.Selectors[selector]
	if !ok {
		return Node{}, NodeRef{}, ErrSelectorUnknown
	}
	if ref.IsTombstoned(now) {
		return Node{}, ref, ErrSelectorTombstoned
	}
	if ref.Tombstoned {
		return Node{}, NodeRef{}, ErrSelectorUnknown
	}
	node, ok := s.NodeByID(ref.NodeID)
	if !ok {
		return Node{}, NodeRef{}, ErrSelectorUnknown
	}
	return node, ref, nil
}

// ValidateRuntimeSnapshot checks the invariants state can enforce without
// importing the selector package.
func ValidateRuntimeSnapshot(snapshot *RuntimeSnapshot) error {
	if snapshot == nil || snapshot.Generation == 0 || snapshot.CreatedAt.IsZero() || snapshot.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: missing generation, creation time, or expiry", ErrInvalidSnapshot)
	}
	if !snapshot.ExpiresAt.After(snapshot.CreatedAt) || snapshot.ExpiresAt.Sub(snapshot.CreatedAt) > maxSessionLifetime {
		return fmt.Errorf("%w: invalid session lifetime", ErrInvalidSnapshot)
	}
	if len(snapshot.Nodes) > maxRuntimeNodes || len(snapshot.Selectors) > maxRuntimeSelectorRefs {
		return fmt.Errorf("%w: runtime snapshot exceeds selector bounds", ErrInvalidSnapshot)
	}
	if time.Now().Before(snapshot.ExpiresAt) && !snapshot.Session.Valid() {
		return fmt.Errorf("%w: incomplete usable session", ErrInvalidSnapshot)
	}
	ids := make(map[string]struct{}, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		if err := ValidateNode(node); err != nil {
			return fmt.Errorf("%w: incomplete node", ErrInvalidSnapshot)
		}
		if _, exists := ids[node.ID]; exists {
			return fmt.Errorf("%w: duplicate node id", ErrInvalidSnapshot)
		}
		ids[node.ID] = struct{}{}
	}
	for selector, ref := range snapshot.Selectors {
		if selector == "" {
			return fmt.Errorf("%w: empty selector", ErrInvalidSnapshot)
		}
		if ref.Generation == 0 {
			return fmt.Errorf("%w: selector has no credential generation", ErrInvalidSnapshot)
		}
		if ref.Tombstoned {
			if ref.NodeID != "" || ref.TombstoneUntil.IsZero() {
				return fmt.Errorf("%w: malformed selector tombstone", ErrInvalidSnapshot)
			}
			continue
		}
		if ref.NodeID == "" {
			return fmt.Errorf("%w: selector has no node", ErrInvalidSnapshot)
		}
		if _, exists := ids[ref.NodeID]; !exists {
			return fmt.Errorf("%w: selector references absent node", ErrInvalidSnapshot)
		}
	}
	return nil
}

// Preferences are durable, non-secret user choices. ExcludedNodeIDs does not
// affect runtime tunnel selection.
type Preferences struct {
	ExcludedNodeIDs map[string]bool
	RevealEndpoints bool
	RefreshPolicy   string
}

func (p Preferences) clone() Preferences {
	clone := p
	clone.ExcludedNodeIDs = make(map[string]bool, len(p.ExcludedNodeIDs))
	for nodeID, excluded := range p.ExcludedNodeIDs {
		clone.ExcludedNodeIDs[nodeID] = excluded
	}
	return clone
}

// PersistedNode is the last-good non-secret metadata record. Tunnel credentials
// and account/session material are intentionally absent.
type PersistedNode struct {
	ID       string
	Selector string
	Provider string
	Host     string
	Port     uint16
	Name     string
	Group    string
	Eligible bool
	Excluded bool
}

// LastGoodState lets the subscription service retain a structurally valid
// rendered body during a control-plane outage. FetchedAt and FetchedBodyHash
// describe the exact successfully fetched active subscription response body.
type LastGoodState struct {
	Generation           uint64
	CreatedAt            time.Time
	Nodes                []PersistedNode
	RenderedSubscription string
	FetchedGeneration    uint64
	FetchedAt            time.Time
	FetchedBodyHash      []byte
}

func (l LastGoodState) clone() LastGoodState {
	l.Nodes = append([]PersistedNode(nil), l.Nodes...)
	l.FetchedBodyHash = append([]byte(nil), l.FetchedBodyHash...)
	return l
}

// SubscriptionGeneration contains account-bound selector and proxy credential
// keys. AccountBinding is the stable, non-reversible subscription path token.
type SubscriptionGeneration struct {
	Generation     uint64
	SelectorKey    []byte
	ProxyAuthKey   []byte
	AccountBinding []byte
	ActivatedAt    time.Time
}

const accountBindingDomain = "kfadapter/subscription-account/v2\x00"

func (g SubscriptionGeneration) clone() SubscriptionGeneration {
	g.SelectorKey = append([]byte(nil), g.SelectorKey...)
	g.ProxyAuthKey = append([]byte(nil), g.ProxyAuthKey...)
	g.AccountBinding = append([]byte(nil), g.AccountBinding...)
	return g
}

// AccountBindingString returns the raw Base64url stable subscription token.
// It is empty until the installation has an access token and logged-in account.
func (g SubscriptionGeneration) AccountBindingString() string {
	if len(g.AccountBinding) != sha256.Size {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(g.AccountBinding)
}

type Argon2idParameters struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

// AccessTokenVerifier contains only a salted Argon2id verifier. Hash is also
// the secret HMAC key used to derive the durable account binding; the token is
// never persisted.
type AccessTokenVerifier struct {
	Parameters Argon2idParameters
	Salt       []byte
	Hash       []byte
}

const (
	accessTokenMinBytes  = 16
	accessTokenMaxBytes  = 128
	accessTokenSaltBytes = 16
	accessTokenHashBytes = sha256.Size
)

var productionArgon2idParameters = Argon2idParameters{
	MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 1,
}

func (v *AccessTokenVerifier) clone() *AccessTokenVerifier {
	if v == nil {
		return nil
	}
	clone := *v
	clone.Salt = append([]byte(nil), v.Salt...)
	clone.Hash = append([]byte(nil), v.Hash...)
	return &clone
}

// BindingKey returns a private copy of the 32-byte derived verifier hash for
// configuring in-memory account-binding authority.
func (v *AccessTokenVerifier) BindingKey() []byte {
	if validateAccessTokenVerifier(v) != nil {
		return nil
	}
	return append([]byte(nil), v.Hash...)
}

func validAccessToken(token string) bool {
	token = strings.TrimSpace(token)
	return utf8.ValidString(token) && len(token) >= accessTokenMinBytes && len(token) <= accessTokenMaxBytes
}

func sameArgon2idParameters(left, right Argon2idParameters) bool {
	return left.MemoryKiB == right.MemoryKiB && left.Iterations == right.Iterations && left.Parallelism == right.Parallelism
}

func validateAccessTokenVerifier(verifier *AccessTokenVerifier) error {
	if verifier == nil || !sameArgon2idParameters(verifier.Parameters, productionArgon2idParameters) || len(verifier.Salt) != accessTokenSaltBytes || len(verifier.Hash) != accessTokenHashBytes {
		return ErrInvalidAccessToken
	}
	return nil
}

// NewAccessTokenVerifier derives the production Argon2id verifier for token.
func NewAccessTokenVerifier(token string) (*AccessTokenVerifier, error) {
	token = strings.TrimSpace(token)
	if !validAccessToken(token) {
		return nil, ErrInvalidAccessToken
	}
	salt, err := randomBytes(accessTokenSaltBytes)
	if err != nil {
		return nil, err
	}
	parameters := productionArgon2idParameters
	hash := argon2.IDKey([]byte(token), salt, parameters.Iterations, parameters.MemoryKiB, parameters.Parallelism, accessTokenHashBytes)
	return &AccessTokenVerifier{Parameters: parameters, Salt: salt, Hash: hash}, nil
}

// VerifyAccessToken performs one Argon2id derivation and a constant-time
// comparison. Invalid and mismatched tokens both return false.
func (v *AccessTokenVerifier) VerifyAccessToken(token string) bool {
	if validateAccessTokenVerifier(v) != nil {
		return false
	}
	token = strings.TrimSpace(token)
	if !validAccessToken(token) {
		return false
	}
	actual := argon2.IDKey([]byte(token), v.Salt, v.Parameters.Iterations, v.Parameters.MemoryKiB, v.Parameters.Parallelism, accessTokenHashBytes)
	defer wipeBytes(actual)
	return subtle.ConstantTimeCompare(actual, v.Hash) == 1
}

func canonicalProviderUserID(userID string) (string, error) {
	canonical := strings.TrimSpace(userID)
	if canonical == "" || len(canonical) > 1024 || !utf8.ValidString(canonical) || strings.IndexByte(canonical, 0) >= 0 {
		return "", ErrAccountChanged
	}
	return canonical, nil
}

func accountBindingFor(bindingKey []byte, userID string) ([]byte, error) {
	canonical, err := canonicalProviderUserID(userID)
	if err != nil || len(bindingKey) != sha256.Size {
		return nil, ErrAccountChanged
	}
	mac := hmac.New(sha256.New, bindingKey)
	_, _ = mac.Write([]byte(accountBindingDomain))
	_, _ = mac.Write([]byte(canonical))
	return mac.Sum(nil), nil
}

func matchesAccountBinding(binding, bindingKey []byte, userID string) bool {
	expected, err := accountBindingFor(bindingKey, userID)
	if err != nil || len(binding) != sha256.Size {
		return false
	}
	defer wipeBytes(expected)
	return subtle.ConstantTimeCompare(binding, expected) == 1
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// PersistentState is deliberately closed. It stores an Argon2id verifier but
// never the raw local access token or provider account password. ActiveSession
// is persisted only by SQLiteStore.
type PersistentState struct {
	InstallationID      string
	AccessTokenVerifier *AccessTokenVerifier
	Subscription        SubscriptionGeneration
	Preferences         Preferences
	LastGood            LastGoodState
	ActiveSession       *RuntimeSnapshot `json:"-"`
}

func (p PersistentState) Clone() PersistentState {
	p.AccessTokenVerifier = p.AccessTokenVerifier.clone()
	p.Subscription = p.Subscription.clone()
	p.Preferences = p.Preferences.clone()
	p.LastGood = p.LastGood.clone()
	p.ActiveSession = p.ActiveSession.Clone()
	return p
}

// AccessTokenInitialized reports whether setup has permanently claimed this
// installation. There is intentionally no reset operation.
func (p PersistentState) AccessTokenInitialized() bool {
	return validateAccessTokenVerifier(p.AccessTokenVerifier) == nil
}

// SetAccessToken initializes the verifier exactly once.
func (p *PersistentState) SetAccessToken(token string) error {
	if p == nil {
		return ErrInvalidAccessToken
	}
	if p.AccessTokenVerifier != nil {
		return ErrAccessTokenAlreadyInitialized
	}
	verifier, err := NewAccessTokenVerifier(token)
	if err != nil {
		return err
	}
	p.AccessTokenVerifier = verifier
	return nil
}

// VerifyAccessToken authenticates a transient access token without retaining it.
func (p PersistentState) VerifyAccessToken(token string) bool {
	return p.AccessTokenVerifier.VerifyAccessToken(token)
}

// DeriveAccountBinding computes the durable subscription path token for userID.
func (p PersistentState) DeriveAccountBinding(userID string) ([]byte, error) {
	if !p.AccessTokenInitialized() {
		return nil, ErrAccountChanged
	}
	return accountBindingFor(p.AccessTokenVerifier.Hash, userID)
}

// MatchesAccount verifies the active durable account binding in constant time.
func (p PersistentState) MatchesAccount(userID string) bool {
	if !p.AccessTokenInitialized() {
		return false
	}
	return matchesAccountBinding(p.Subscription.AccountBinding, p.AccessTokenVerifier.Hash, userID)
}

// NewPersistentState creates an uninitialized installation with fresh local
// selector and proxy keys. Setup and account login bind it later.
func NewPersistentState() (PersistentState, error) {
	installation, err := randomInstallationID()
	if err != nil {
		return PersistentState{}, err
	}
	generation, err := newSubscriptionGeneration(1, time.Now().UTC())
	if err != nil {
		return PersistentState{}, err
	}
	return PersistentState{
		InstallationID: installation,
		Subscription:   generation,
		Preferences:    Preferences{ExcludedNodeIDs: make(map[string]bool)},
	}, nil
}

func newSubscriptionGeneration(number uint64, activatedAt time.Time) (SubscriptionGeneration, error) {
	selectorKey, err := randomBytes(32)
	if err != nil {
		return SubscriptionGeneration{}, err
	}
	proxyKey, err := randomBytes(32)
	if err != nil {
		wipeBytes(selectorKey)
		return SubscriptionGeneration{}, err
	}
	return SubscriptionGeneration{Generation: number, SelectorKey: selectorKey, ProxyAuthKey: proxyKey, ActivatedAt: activatedAt.UTC()}, nil
}

// EnsureSubscriptionAccountBinding keeps credentials stable for the same
// account. A changed account receives fresh selector/proxy keys, a new binding,
// and no credential-bearing cached subscription state.
func EnsureSubscriptionAccountBinding(p *PersistentState, userID string, now time.Time) (bool, error) {
	if p == nil || !p.AccessTokenInitialized() || validateSubscriptionGeneration(p.Subscription) != nil {
		return false, ErrAccountChanged
	}
	binding, err := p.DeriveAccountBinding(userID)
	if err != nil {
		return false, err
	}
	defer wipeBytes(binding)
	if len(p.Subscription.AccountBinding) == 0 {
		p.Subscription.AccountBinding = append([]byte(nil), binding...)
		return false, nil
	}
	if subtle.ConstantTimeCompare(p.Subscription.AccountBinding, binding) == 1 {
		return false, nil
	}
	next, err := newSubscriptionGeneration(p.Subscription.Generation+1, now)
	if err != nil {
		return false, err
	}
	next.AccountBinding = append([]byte(nil), binding...)
	wipeBytes(p.Subscription.SelectorKey)
	wipeBytes(p.Subscription.ProxyAuthKey)
	p.Subscription = next
	p.LastGood = LastGoodState{}
	p.ActiveSession = nil
	return true, nil
}

func validatePreferences(preferences Preferences) error {
	for nodeID, excluded := range preferences.ExcludedNodeIDs {
		if nodeID == "" || !excluded {
			return fmt.Errorf("invalid excluded node preference")
		}
	}
	if preferences.RefreshPolicy != "" {
		interval, err := time.ParseDuration(preferences.RefreshPolicy)
		if err != nil || interval < 15*time.Minute || interval > 24*time.Hour {
			return fmt.Errorf("invalid refresh policy")
		}
	}
	return nil
}

// ValidatePersistentState verifies the aggregate reconstructed from SQLite.
func ValidatePersistentState(p PersistentState) error {
	if !validInstallationID(p.InstallationID) {
		return fmt.Errorf("invalid persistent state")
	}
	if p.AccessTokenVerifier != nil && validateAccessTokenVerifier(p.AccessTokenVerifier) != nil {
		return fmt.Errorf("invalid access token verifier")
	}
	if err := validateSubscriptionGeneration(p.Subscription); err != nil {
		return err
	}
	if len(p.Subscription.AccountBinding) != 0 && p.AccessTokenVerifier == nil {
		return fmt.Errorf("bound subscription has no access token verifier")
	}
	if len(p.Subscription.AccountBinding) == 0 {
		if !lastGoodStateEmpty(p.LastGood) {
			return fmt.Errorf("unbound subscription retains last-good state")
		}
		if p.ActiveSession != nil {
			return fmt.Errorf("unbound subscription retains active session")
		}
	} else if err := validateLastGoodState(p.LastGood, p.Subscription.Generation); err != nil {
		return err
	}
	if p.ActiveSession != nil {
		if err := ValidateRuntimeSnapshot(p.ActiveSession); err != nil {
			return fmt.Errorf("invalid active session: %w", err)
		}
		if !validPersistedSession(p.ActiveSession.Session) || !p.MatchesAccount(p.ActiveSession.Session.UserID) {
			return fmt.Errorf("active session does not match durable account binding")
		}
		for _, reference := range p.ActiveSession.Selectors {
			if reference.Generation != p.Subscription.Generation {
				return fmt.Errorf("active session selector has stale subscription generation")
			}
		}
	}
	return validatePreferences(p.Preferences)
}

func validateSubscriptionGeneration(g SubscriptionGeneration) error {
	if g.Generation == 0 || g.ActivatedAt.IsZero() || len(g.SelectorKey) != sha256.Size || len(g.ProxyAuthKey) != sha256.Size || (len(g.AccountBinding) != 0 && len(g.AccountBinding) != sha256.Size) {
		return fmt.Errorf("invalid subscription generation")
	}
	return nil
}

func lastGoodStateEmpty(lastGood LastGoodState) bool {
	return lastGood.Generation == 0 && lastGood.CreatedAt.IsZero() && len(lastGood.Nodes) == 0 && lastGood.RenderedSubscription == "" && lastGood.FetchedGeneration == 0 && lastGood.FetchedAt.IsZero() && len(lastGood.FetchedBodyHash) == 0
}

func validateLastGoodState(lastGood LastGoodState, activeGeneration uint64) error {
	if lastGoodStateEmpty(lastGood) {
		return nil
	}
	if lastGood.Generation != activeGeneration || lastGood.CreatedAt.IsZero() || len(lastGood.Nodes) == 0 || lastGood.RenderedSubscription == "" {
		return fmt.Errorf("incomplete last-good state")
	}
	if len(lastGood.FetchedBodyHash) != 0 && len(lastGood.FetchedBodyHash) != sha256.Size {
		return fmt.Errorf("invalid last-good fetch hash")
	}
	hasFetch := !lastGood.FetchedAt.IsZero()
	if hasFetch != (len(lastGood.FetchedBodyHash) == sha256.Size) || hasFetch != (lastGood.FetchedGeneration != 0) || (hasFetch && (lastGood.FetchedGeneration > lastGood.Generation || lastGood.FetchedAt.Before(lastGood.CreatedAt))) {
		return fmt.Errorf("incomplete last-good fetch metadata")
	}
	if err := validatePersistedNodes(lastGood.Nodes); err != nil {
		return err
	}
	return validateRenderedSubscription(lastGood.RenderedSubscription, lastGood.Nodes)
}

func validatePersistedNodes(nodes []PersistedNode) error {
	if len(nodes) == 0 || len(nodes) > maxPersistedNodes {
		return fmt.Errorf("invalid persisted node count")
	}
	ids := make(map[string]struct{}, len(nodes))
	for _, persisted := range nodes {
		if persisted.Selector == "" {
			return fmt.Errorf("invalid persisted node selector")
		}
		node := Node{ID: persisted.ID, Provider: persisted.Provider, Host: persisted.Host, Port: persisted.Port, Eligible: persisted.Eligible}
		if err := ValidateNode(node); err != nil {
			return err
		}
		if _, exists := ids[persisted.ID]; exists {
			return fmt.Errorf("duplicate persisted node id")
		}
		ids[persisted.ID] = struct{}{}
	}
	return nil
}

// ValidateNode checks the non-secret structural fields shared by runtime and
// persisted nodes. Provider compatibility remains an eligibility decision.
func ValidateNode(node Node) error {
	if node.ID == "" || node.Provider == "" || node.Host == "" || node.Port == 0 || strings.IndexByte(node.Provider, 0) >= 0 || strings.IndexByte(node.Host, 0) >= 0 {
		return fmt.Errorf("invalid node")
	}
	return nil
}

func validateRenderedSubscription(body string, nodes []PersistedNode) error {
	if len(body) == 0 || len(body) > maxRenderedSubscriptionBytes {
		return fmt.Errorf("invalid rendered subscription size")
	}
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != body || !utf8.Valid(decoded) || len(decoded) == 0 || decoded[len(decoded)-1] != '\n' {
		return fmt.Errorf("invalid rendered subscription")
	}
	eligible, unexcludedEligible := 0, 0
	for _, node := range nodes {
		if node.Eligible && strings.EqualFold(node.Provider, "WIFIIN") {
			eligible++
			if !node.Excluded {
				unexcludedEligible++
			}
		}
	}
	if eligible == 0 {
		return fmt.Errorf("rendered subscription has no eligible nodes")
	}
	lines := strings.Split(string(decoded[:len(decoded)-1]), "\n")
	if len(lines) != eligible && len(lines) != unexcludedEligible {
		return fmt.Errorf("rendered subscription node count mismatch")
	}
	for _, line := range lines {
		if line == "" || strings.IndexByte(line, '\r') >= 0 {
			return fmt.Errorf("invalid rendered subscription link")
		}
		link, err := url.Parse(line)
		if err != nil || link.String() != line || link.Scheme != "socks5" || link.Opaque != "" || link.Host == "" || link.Path != "" || link.RawQuery != "" || link.User == nil || link.User.Username() == "" {
			return fmt.Errorf("invalid rendered subscription link")
		}
		if password, ok := link.User.Password(); !ok || password == "" {
			return fmt.Errorf("invalid rendered subscription link")
		}
	}
	return nil
}

func randomBytes(n int) ([]byte, error) {
	value := make([]byte, n)
	if _, err := rand.Read(value); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return value, nil
}

func randomInstallationID() (string, error) {
	value, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func validInstallationID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for index := range len(value) {
		if (value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f') {
			return false
		}
	}
	return true
}

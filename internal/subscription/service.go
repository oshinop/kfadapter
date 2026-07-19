package subscription

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
)

var errRenderedSubscriptionMismatch = errors.New("rendered subscription does not match durable node authority")

const (
	subscriptionResponseConcurrency = 8
	subscriptionResponseChunkBytes  = 32 << 10
)

// SnapshotSource is satisfied by state.Manager. It lets callers render a
// pinned state view without coupling the service to control-plane code.
type SnapshotSource interface {
	Current() *state.RuntimeSnapshot
}

// ServiceConfig wires the single, account-bound subscription authority. The
// mutation locker is shared with the runtime coordinator; when present its
// lock is always acquired before Service.mu by fetch-proof persistence.
type ServiceConfig struct {
	Store          *state.SQLiteStore
	Snapshots      SnapshotSource
	SocksAddress   string
	Now            func() time.Time
	MutationLocker sync.Locker
}

// Service stores and serves exactly one current subscription generation. Its
// URL token is the verifier-derived account binding.
type Service struct {
	store          *state.SQLiteStore
	snapshots      SnapshotSource
	socksAddress   string
	now            func() time.Time
	mutationLocker sync.Locker

	mu            sync.Mutex
	cache         cachedSubscription
	responseSlots chan struct{}
	hooks         serviceHooks
}

// RuntimeCommitPlan is a non-durable candidate subscription generation. It
// lets runtime install matching selector authority before the final aggregate
// transaction writes the binding, rendered subscription, and active session.
type RuntimeCommitPlan struct {
	Generation state.SubscriptionGeneration
	userID     string
	previous   state.SubscriptionGeneration
}

type serviceHooks struct {
	onLoad   func()
	onRender func()
}

// cachedSubscription is the only state consulted for unauthenticated path
// admission after syntax validation. Invalid probes therefore never load disk
// state or derive SOCKS credentials.
type cachedSubscription struct {
	binding           [sha256.Size]byte
	body              string
	bodyHash          [sha256.Size]byte
	generation        uint64
	nodeCount         int
	fetchedAt         time.Time
	fetchedGeneration uint64
	fetchedBodyHash   [sha256.Size]byte
	fetching          bool
}

func subscriptionBodyHash(body string) [sha256.Size]byte { return sha256.Sum256([]byte(body)) }

func (s *Service) noteStateLoad() {
	if s.hooks.onLoad != nil {
		s.hooks.onLoad()
	}
}

func (s *Service) loadPersisted() (state.PersistentState, error) {
	s.noteStateLoad()
	return s.store.Load()
}

// NewService validates and primes serving material before it accepts requests.
// A valid body rendered for a prior configured listener is migrated by exact
// re-rendering; tampered bodies remain fail-closed.
func NewService(config ServiceConfig) (*Service, error) {
	if config.Store == nil {
		return nil, errors.New("subscription state store is required")
	}
	if err := validateAddress(config.SocksAddress); err != nil {
		return nil, err
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	service := &Service{
		store: config.Store, snapshots: config.Snapshots,
		socksAddress: config.SocksAddress, now: config.Now, mutationLocker: config.MutationLocker,
		responseSlots: make(chan struct{}, subscriptionResponseConcurrency),
	}
	if err := service.reconcileAndPrime(); err != nil {
		return nil, err
	}
	return service, nil
}

// SetSocksAddress re-renders the active subscription when a wildcard listener
// is reached through a concrete host address.
func (s *Service) SetSocksAddress(address string) error {
	if s == nil {
		return ErrSubscriptionUnavailable
	}
	if err := validateAddress(address); err != nil {
		return err
	}
	if s.mutationLocker != nil {
		s.mutationLocker.Lock()
		defer s.mutationLocker.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.socksAddress == address {
		return nil
	}
	previous := s.socksAddress
	s.socksAddress = address
	persistent, err := s.loadPersisted()
	if err != nil {
		s.socksAddress = previous
		return err
	}
	updated, changed, err := s.reconcileListenerAddress(persistent)
	if err != nil {
		s.socksAddress = previous
		return err
	}
	if changed {
		updated, err = s.store.Update(func(candidate *state.PersistentState) error {
			repaired, changed, err := s.reconcileListenerAddress(*candidate)
			if err != nil || !changed {
				return err
			}
			*candidate = repaired
			return nil
		})
		if err != nil {
			s.socksAddress = previous
			return err
		}
	}
	if err := s.validateRenderedState(updated); err != nil {
		return err
	}
	s.primeCacheLocked(updated)
	return nil
}

func (s *Service) reconcileAndPrime() error {
	if s.mutationLocker != nil {
		s.mutationLocker.Lock()
		defer s.mutationLocker.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	persistent, err := s.loadPersisted()
	if err != nil {
		return err
	}
	if address, ok := concreteRenderedAddress(s.socksAddress, persistent.LastGood.RenderedSubscription); ok {
		s.socksAddress = address
	}
	updated, changed, err := s.reconcileListenerAddress(persistent)
	if err != nil {
		return err
	}
	if changed {
		updated, err = s.store.Update(func(candidate *state.PersistentState) error {
			repaired, changed, err := s.reconcileListenerAddress(*candidate)
			if err != nil || !changed {
				return err
			}
			*candidate = repaired
			return nil
		})
		if err != nil {
			return err
		}
	}
	if err := s.validateRenderedState(updated); err != nil {
		return err
	}
	s.primeCacheLocked(updated)
	return nil
}

func concreteRenderedAddress(listenAddress, body string) (string, bool) {
	listenHost, listenPort, err := parseAddress(listenAddress)
	if err != nil {
		return "", false
	}
	listenIP, _ := netip.ParseAddr(listenHost)
	if !listenIP.IsUnspecified() {
		return "", false
	}
	address, ok := renderedAddress(body)
	if !ok {
		return "", false
	}
	host, port, err := parseAddress(address)
	if err != nil || port != listenPort {
		return "", false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return address, true
	}
	return address, !ip.IsUnspecified() && ip.Is4() == listenIP.Is4()
}

func (s *Service) reconcileListenerAddress(persistent state.PersistentState) (state.PersistentState, bool, error) {
	candidate := persistent.Clone()
	lastGood := candidate.LastGood
	if lastGood.RenderedSubscription == "" {
		if !emptyLastGood(lastGood) {
			return state.PersistentState{}, false, errRenderedSubscriptionMismatch
		}
		return candidate, false, nil
	}
	if len(candidate.Subscription.AccountBinding) != sha256.Size || lastGood.Generation != candidate.Subscription.Generation {
		return state.PersistentState{}, false, errRenderedSubscriptionMismatch
	}
	rendered, _, _, err := s.renderPersistedNodes(lastGood.Nodes, candidate.Subscription)
	if err != nil {
		return state.PersistentState{}, false, errRenderedSubscriptionMismatch
	}
	if rendered == lastGood.RenderedSubscription {
		return candidate, false, nil
	}
	if !s.matchesRenderedAtAddress(lastGood.RenderedSubscription, lastGood.Nodes, candidate.Subscription) {
		return state.PersistentState{}, false, errRenderedSubscriptionMismatch
	}
	candidate.LastGood.RenderedSubscription = rendered
	candidate.LastGood.FetchedAt = time.Time{}
	candidate.LastGood.FetchedGeneration = 0
	candidate.LastGood.FetchedBodyHash = nil
	return candidate, true, nil
}

// matchesRenderedAtAddress accepts the current renderer and a pre-cutover body
// filtered by persisted legacy exclusions, so startup can safely rewrite the
// latter with every currently eligible node.
func (s *Service) matchesRenderedAtAddress(body string, nodes []state.PersistedNode, generation state.SubscriptionGeneration) bool {
	address, ok := renderedAddress(body)
	if !ok {
		return false
	}
	rendered, _, _, err := s.renderPersistedNodesAt(nodes, generation, address)
	if err == nil && rendered == body {
		return true
	}
	legacy, _, _, err := s.renderPersistedNodesAtWithLegacyExclusions(nodes, generation, address, true)
	return err == nil && legacy == body
}

func renderedAddress(body string) (string, bool) {
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(decoded) == 0 {
		return "", false
	}
	lines := strings.Split(strings.TrimSuffix(string(decoded), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "", false
	}
	address := ""
	for _, line := range lines {
		link, err := url.Parse(line)
		if err != nil || link.Scheme != "socks5" || link.Host == "" || link.User == nil || link.RawQuery != "" {
			return "", false
		}
		if address == "" {
			if validateAddress(link.Host) != nil {
				return "", false
			}
			address = link.Host
		} else if link.Host != address {
			return "", false
		}
	}
	return address, true
}

func emptyLastGood(lastGood state.LastGoodState) bool {
	return lastGood.Generation == 0 && lastGood.CreatedAt.IsZero() && len(lastGood.Nodes) == 0 &&
		lastGood.RenderedSubscription == "" && lastGood.FetchedGeneration == 0 &&
		lastGood.FetchedAt.IsZero() && len(lastGood.FetchedBodyHash) == 0
}

func (s *Service) primeCacheLocked(persistent state.PersistentState) {
	cache := cachedSubscription{}
	if len(persistent.Subscription.AccountBinding) == sha256.Size && persistent.LastGood.RenderedSubscription != "" {
		copy(cache.binding[:], persistent.Subscription.AccountBinding)
		cache.body = persistent.LastGood.RenderedSubscription
		cache.bodyHash = subscriptionBodyHash(cache.body)
		cache.generation = persistent.Subscription.Generation
		cache.nodeCount = eligiblePersistedCount(persistent.LastGood.Nodes)
		if !persistent.LastGood.FetchedAt.IsZero() && len(persistent.LastGood.FetchedBodyHash) == sha256.Size {
			cache.fetchedAt = persistent.LastGood.FetchedAt
			cache.fetchedGeneration = persistent.LastGood.FetchedGeneration
			copy(cache.fetchedBodyHash[:], persistent.LastGood.FetchedBodyHash)
		}
	}
	if previous := s.cache; previous.fetching && previous.binding == cache.binding && previous.generation == cache.generation && previous.bodyHash == cache.bodyHash {
		cache.fetching = true
	}
	s.cache = cache
}

// PublishAccount binds a successfully authenticated canonical account to the
// durable generation. Same-account calls preserve binding and SOCKS keys;
// account change clears the old body so its path immediately becomes a uniform
// empty 404. The caller must invoke the returned rollback after a later
// selector, manager, or snapshot publication failure.
func (s *Service) PublishAccount(ctx context.Context, userID string) (state.SubscriptionGeneration, func(), error) {
	if err := ctx.Err(); err != nil {
		return state.SubscriptionGeneration{}, nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return state.SubscriptionGeneration{}, nil, state.ErrAccountChanged
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var before state.PersistentState
	after, err := s.store.Update(func(candidate *state.PersistentState) error {
		before = candidate.Clone()
		_, err := state.EnsureSubscriptionAccountBinding(candidate, userID, s.now().UTC())
		return err
	})
	if err != nil {
		return state.SubscriptionGeneration{}, nil, err
	}
	if err := s.validateRenderedState(after); err != nil {
		if rollbackErr := s.store.Save(before); rollbackErr != nil {
			return state.SubscriptionGeneration{}, nil, fmt.Errorf("subscription binding validation failed and rollback failed: %w", err)
		}
		return state.SubscriptionGeneration{}, nil, err
	}
	s.primeCacheLocked(after)
	var once sync.Once
	rollback := func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if err := s.store.Save(before); err == nil {
				s.primeCacheLocked(before)
			}
		})
	}
	return cloneSubscriptionGeneration(after.Subscription), rollback, nil
}

func cloneSubscriptionGeneration(generation state.SubscriptionGeneration) state.SubscriptionGeneration {
	generation.SelectorKey = append([]byte(nil), generation.SelectorKey...)
	generation.ProxyAuthKey = append([]byte(nil), generation.ProxyAuthKey...)
	generation.AccountBinding = append([]byte(nil), generation.AccountBinding...)
	return generation
}

// PrepareRuntimeCommit derives, but does not persist, the account-bound
// generation needed to install matching selector authority. CommitRuntimeSnapshot
// verifies the plan against current durable state before writing it.
func (s *Service) PrepareRuntimeCommit(ctx context.Context, userID string) (RuntimeCommitPlan, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeCommitPlan{}, err
	}
	if s == nil || strings.TrimSpace(userID) == "" {
		return RuntimeCommitPlan{}, state.ErrAccountChanged
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	persistent, err := s.loadPersisted()
	if err != nil {
		return RuntimeCommitPlan{}, err
	}
	candidate := persistent.Clone()
	if _, err := state.EnsureSubscriptionAccountBinding(&candidate, userID, s.now().UTC()); err != nil {
		return RuntimeCommitPlan{}, err
	}
	return RuntimeCommitPlan{
		Generation: cloneSubscriptionGeneration(candidate.Subscription),
		userID:     userID,
		previous:   cloneSubscriptionGeneration(persistent.Subscription),
	}, nil
}

// CommitRuntimeSnapshot atomically persists one coherent provider authority
// aggregate: the planned account binding, rendered LastGood subscription, and
// complete ActiveSession. The returned rollback restores the exact prior
// aggregate if the in-memory manager later rejects publication.
func (s *Service) CommitRuntimeSnapshot(ctx context.Context, plan RuntimeCommitPlan, snapshot *state.RuntimeSnapshot) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || snapshot == nil || !snapshot.Session.Valid() || snapshot.Session.UserID != plan.userID {
		return nil, state.ErrAccountChanged
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var before state.PersistentState
	after, err := s.store.Update(func(candidate *state.PersistentState) error {
		before = candidate.Clone()
		if !sameSubscriptionGeneration(candidate.Subscription, plan.previous) {
			return state.ErrAccountChanged
		}
		expectedBinding, err := candidate.DeriveAccountBinding(plan.userID)
		if err != nil {
			return err
		}
		matchesBinding := subtle.ConstantTimeCompare(plan.Generation.AccountBinding, expectedBinding) == 1
		for index := range expectedBinding {
			expectedBinding[index] = 0
		}
		if !matchesBinding {
			return state.ErrAccountChanged
		}
		changedAccount := !sameSubscriptionGeneration(candidate.Subscription, plan.Generation)
		candidate.Subscription = cloneSubscriptionGeneration(plan.Generation)
		if changedAccount {
			candidate.LastGood = state.LastGoodState{}
			candidate.ActiveSession = nil
		}
		if err := s.updateLastGood(candidate, snapshot); err != nil {
			return err
		}
		candidate.ActiveSession = snapshot.Clone()
		return s.validateRenderedState(*candidate)
	})
	if err != nil {
		return nil, err
	}
	s.primeCacheLocked(after)
	var once sync.Once
	var rollbackErr error
	rollback := func() error {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			rollbackErr = s.store.Save(before)
			if rollbackErr == nil {
				s.primeCacheLocked(before)
			}
		})
		return rollbackErr
	}
	return rollback, nil
}

func sameSubscriptionGeneration(left, right state.SubscriptionGeneration) bool {
	return left.Generation == right.Generation &&
		subtle.ConstantTimeCompare(left.SelectorKey, right.SelectorKey) == 1 &&
		subtle.ConstantTimeCompare(left.ProxyAuthKey, right.ProxyAuthKey) == 1 &&
		subtle.ConstantTimeCompare(left.AccountBinding, right.AccountBinding) == 1
}

func (s *Service) updateLastGood(candidate *state.PersistentState, snapshot *state.RuntimeSnapshot) error {
	if candidate == nil || len(candidate.Subscription.AccountBinding) != sha256.Size {
		return ErrSubscriptionUnavailable
	}
	body, _, nodes, err := s.renderNodes(snapshot.Nodes, candidate.Subscription)
	if err != nil {
		return err
	}
	oldBody := candidate.LastGood.RenderedSubscription
	oldGeneration := candidate.LastGood.Generation
	bodyChanged := oldGeneration != candidate.Subscription.Generation || oldBody != body
	candidate.LastGood.Generation = candidate.Subscription.Generation
	candidate.LastGood.Nodes = nodes
	candidate.LastGood.RenderedSubscription = body
	if bodyChanged {
		candidate.LastGood.CreatedAt = s.now().UTC()
		candidate.LastGood.FetchedAt = time.Time{}
		candidate.LastGood.FetchedGeneration = 0
		candidate.LastGood.FetchedBodyHash = nil
	}
	return nil
}

// PublishSnapshot renders and persists the current account-bound subscription.
func (s *Service) PublishSnapshot(snapshot *state.RuntimeSnapshot) error {
	if snapshot == nil {
		return ErrNoEligibleLinks
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	after, err := s.store.Update(func(candidate *state.PersistentState) error {
		if err := s.updateLastGood(candidate, snapshot); err != nil {
			return err
		}
		return s.validateRenderedState(*candidate)
	})
	if err != nil {
		return err
	}
	s.primeCacheLocked(after)
	return nil
}

// PublishCurrent renders the current snapshot source when configured.
func (s *Service) PublishCurrent() error {
	if s.snapshots == nil {
		return ErrNoEligibleLinks
	}
	return s.PublishSnapshot(s.snapshots.Current())
}

// Metadata returns redacted state and never exposes the subscription URL,
// account binding, SOCKS credentials, or provider material.
func (s *Service) Metadata() (Metadata, error) {
	if s == nil {
		return Metadata{}, ErrSubscriptionUnavailable
	}
	s.mu.Lock()
	current := s.cache
	s.mu.Unlock()
	active := current.body != ""
	fetchedExactBody := !current.fetchedAt.IsZero() && current.fetchedGeneration == current.generation && current.fetchedBodyHash == current.bodyHash
	return Metadata{
		Active: active, Generation: current.generation, NodeCount: current.nodeCount,
		LastFetchedAt: current.fetchedAt, LastFetchedGeneration: current.fetchedGeneration,
		ReloadRecommended: active && !fetchedExactBody,
	}, nil
}

// SubscriptionURL returns the reusable path token for the one active account
// binding. Web authentication is intentionally enforced by the caller.
func (s *Service) SubscriptionURL(baseURL string) (string, uint64, error) {
	if s == nil {
		return "", 0, ErrSubscriptionUnavailable
	}
	s.mu.Lock()
	current := s.cache
	s.mu.Unlock()
	if current.body == "" || current.generation == 0 {
		return "", 0, ErrSubscriptionUnavailable
	}
	return subscriptionURL(baseURL, base64.RawURLEncoding.EncodeToString(current.binding[:])), current.generation, nil
}

// ServeHTTP handles the full canonical subscription path. It is useful for
// direct tests; production routing extracts the token and calls ServeSubscription.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.acquireResponseSlot(w) {
		return
	}
	defer s.releaseResponseSlot()
	binding, ok := subscriptionRequestPath(r.URL.Path)
	if !ok {
		writeNotFound(w)
		return
	}
	s.serveSubscription(w, r, binding, "")
}

// ServeSubscription serves one router-extracted account-binding path segment.
// Every malformed, stale, unknown, or method-invalid request gets the same
// empty no-store 404 response.
func (s *Service) ServeSubscription(w http.ResponseWriter, r *http.Request, binding string) {
	if !s.acquireResponseSlot(w) {
		return
	}
	defer s.releaseResponseSlot()
	s.serveSubscription(w, r, binding, "")
}

// ServeSubscriptionAt serves a valid binding after adapting a wildcard SOCKS
// listener to the concrete host used for this request.
func (s *Service) ServeSubscriptionAt(w http.ResponseWriter, r *http.Request, binding, socksAddress string) {
	if !s.acquireResponseSlot(w) {
		return
	}
	defer s.releaseResponseSlot()
	s.serveSubscription(w, r, binding, socksAddress)
}

func (s *Service) acquireResponseSlot(w http.ResponseWriter) bool {
	select {
	case s.responseSlots <- struct{}{}:
		return true
	default:
		writeResponseBusy(w)
		return false
	}
}

func (s *Service) releaseResponseSlot() { <-s.responseSlots }

func writeResponseBusy(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusServiceUnavailable)
}

func writeResponseUnavailable(w http.ResponseWriter, retry bool) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Cache-Control", "no-store")
	if retry {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(http.StatusServiceUnavailable)
}

func (s *Service) serveSubscription(w http.ResponseWriter, r *http.Request, binding, socksAddress string) {
	if r.Method != http.MethodGet || !validBinding(binding) {
		writeNotFound(w)
		return
	}
	var token [sha256.Size]byte
	_, _ = base64.RawURLEncoding.Decode(token[:], []byte(binding))
	s.mu.Lock()
	current := s.cache
	matched := current.body != "" && subtle.ConstantTimeCompare(token[:], current.binding[:]) == 1
	s.mu.Unlock()
	if !matched {
		writeNotFound(w)
		return
	}
	if socksAddress != "" {
		if err := s.SetSocksAddress(socksAddress); err != nil {
			writeResponseUnavailable(w, true)
			return
		}
		s.mu.Lock()
		current = s.cache
		matched = current.body != "" && subtle.ConstantTimeCompare(token[:], current.binding[:]) == 1
		s.mu.Unlock()
		if !matched {
			writeNotFound(w)
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(current.body)))
	w.WriteHeader(http.StatusOK)
	written, err := writeSubscriptionBody(w, current.body)
	if err != nil || written != len(current.body) {
		return
	}
	s.recordActiveFetch(current.generation, current.bodyHash, s.now().UTC())
}

func validBinding(binding string) bool {
	if len(binding) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(binding)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == binding
}

func writeSubscriptionBody(w io.Writer, body string) (int, error) {
	written := 0
	for len(body) != 0 {
		limit := subscriptionResponseChunkBytes
		if len(body) < limit {
			limit = len(body)
		}
		n, err := io.WriteString(w, body[:limit])
		written += n
		if err != nil {
			return written, err
		}
		if n != limit {
			return written, io.ErrShortWrite
		}
		body = body[n:]
	}
	return written, nil
}

// recordActiveFetch persists proof only after every response byte was accepted,
// and only if the exact body/generation remains current at persistence time.
func (s *Service) recordActiveFetch(generation uint64, bodyHash [sha256.Size]byte, now time.Time) {
	s.mu.Lock()
	current := &s.cache
	if current.body == "" || current.generation != generation || current.bodyHash != bodyHash ||
		(!current.fetchedAt.IsZero() && current.fetchedGeneration == generation && current.fetchedBodyHash == bodyHash) || current.fetching {
		s.mu.Unlock()
		return
	}
	current.fetching = true
	s.mu.Unlock()

	if s.mutationLocker != nil {
		s.mutationLocker.Lock()
		defer s.mutationLocker.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current = &s.cache
	if current.body == "" || current.generation != generation || current.bodyHash != bodyHash || !current.fetching {
		return
	}
	if !current.fetchedAt.IsZero() && current.fetchedGeneration == generation && current.fetchedBodyHash == bodyHash {
		current.fetching = false
		return
	}
	s.noteStateLoad()
	after, err := s.store.Update(func(candidate *state.PersistentState) error {
		if candidate.Subscription.Generation != generation || candidate.LastGood.Generation != generation || subscriptionBodyHash(candidate.LastGood.RenderedSubscription) != bodyHash {
			return errors.New("active fetch no longer matches rendered subscription")
		}
		candidate.LastGood.FetchedGeneration = generation
		candidate.LastGood.FetchedAt = now.UTC()
		candidate.LastGood.FetchedBodyHash = append(candidate.LastGood.FetchedBodyHash[:0], bodyHash[:]...)
		return s.validateRenderedState(*candidate)
	})
	if err != nil {
		if current.generation == generation && current.bodyHash == bodyHash {
			current.fetching = false
		}
		return
	}
	s.primeCacheLocked(after)
}

// ValidatePersistentState re-derives all durable local authority from the
// subscription generation. It is pure so offline state validation can reject
// a database that would later be rejected by NewService.
func ValidatePersistentState(persistent state.PersistentState) error {
	if err := state.ValidatePersistentState(persistent); err != nil {
		return err
	}
	lastGood := persistent.LastGood
	if lastGood.RenderedSubscription == "" {
		if !emptyLastGood(lastGood) {
			return errRenderedSubscriptionMismatch
		}
	} else {
		if len(persistent.Subscription.AccountBinding) != sha256.Size || lastGood.Generation != persistent.Subscription.Generation {
			return errRenderedSubscriptionMismatch
		}
		address, err := renderedSubscriptionAddress(lastGood.RenderedSubscription)
		if err != nil {
			return errRenderedSubscriptionMismatch
		}
		links := make([]Link, 0, len(lastGood.Nodes))
		for _, node := range lastGood.Nodes {
			credential, err := selector.Derive(selector.NodeIdentity{Provider: node.Provider, Host: node.Host, Port: int(node.Port)}, persistent.Subscription.SelectorKey, persistent.Subscription.ProxyAuthKey)
			if err != nil || credential.Selector != node.Selector {
				return errRenderedSubscriptionMismatch
			}
			links = append(links, Link{
				Selector: credential.Selector, Password: credential.Password, Name: node.Name, Group: node.Group,
				Eligible: node.Eligible && strings.EqualFold(node.Provider, "WIFIIN") && node.Host != "" && node.Port != 0,
			})
		}
		rendered, _, err := Render(links, address)
		if err != nil || rendered != lastGood.RenderedSubscription {
			legacyLinks := make([]Link, 0, len(lastGood.Nodes))
			for _, node := range lastGood.Nodes {
				credential, deriveErr := selector.Derive(selector.NodeIdentity{Provider: node.Provider, Host: node.Host, Port: int(node.Port)}, persistent.Subscription.SelectorKey, persistent.Subscription.ProxyAuthKey)
				if deriveErr != nil {
					return errRenderedSubscriptionMismatch
				}
				legacyLinks = append(legacyLinks, Link{
					Selector: credential.Selector, Password: credential.Password, Name: node.Name, Group: node.Group,
					Eligible: node.Eligible && !node.Excluded && strings.EqualFold(node.Provider, "WIFIIN") && node.Host != "" && node.Port != 0,
				})
			}
			legacy, _, legacyErr := Render(legacyLinks, address)
			if legacyErr != nil || legacy != lastGood.RenderedSubscription {
				return errRenderedSubscriptionMismatch
			}
		}
	}
	if active := persistent.ActiveSession; active != nil {
		if lastGood.RenderedSubscription == "" || lastGood.Generation != persistent.Subscription.Generation || len(active.Nodes) != len(lastGood.Nodes) {
			return errRenderedSubscriptionMismatch
		}
		persistedNodes := make(map[string]state.PersistedNode, len(lastGood.Nodes))
		for _, node := range lastGood.Nodes {
			persistedNodes[node.ID] = node
		}
		liveSelectors := make(map[string]struct{}, len(active.Nodes))
		for _, node := range active.Nodes {
			persistedNode, found := persistedNodes[node.ID]
			if !found || node.Selector != persistedNode.Selector || node.Provider != persistedNode.Provider || node.Host != persistedNode.Host || node.Port != persistedNode.Port || node.Name != persistedNode.Name || node.Group != persistedNode.Group || node.Eligible != persistedNode.Eligible || node.Excluded != persistedNode.Excluded {
				return errRenderedSubscriptionMismatch
			}
			credential, err := selector.Derive(selector.NodeIdentity{Provider: node.Provider, Host: node.Host, Port: int(node.Port)}, persistent.Subscription.SelectorKey, persistent.Subscription.ProxyAuthKey)
			if err != nil || node.Selector != credential.Selector {
				return errRenderedSubscriptionMismatch
			}
			reference, found := active.Selectors[credential.Selector]
			if !found || reference.Tombstoned || reference.NodeID != node.ID || reference.Generation != persistent.Subscription.Generation {
				return errRenderedSubscriptionMismatch
			}
			liveSelectors[credential.Selector] = struct{}{}
		}
		for name, reference := range active.Selectors {
			if !reference.Tombstoned {
				if _, found := liveSelectors[name]; !found {
					return errRenderedSubscriptionMismatch
				}
			}
		}
	}
	return nil
}

func renderedSubscriptionAddress(rendered string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(rendered)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != rendered {
		return "", errRenderedSubscriptionMismatch
	}
	text := string(decoded)
	if text == "" || !strings.HasSuffix(text, "\n") {
		return "", errRenderedSubscriptionMismatch
	}
	first := strings.Split(strings.TrimSuffix(text, "\n"), "\n")[0]
	parsed, err := url.Parse(first)
	if err != nil || parsed.Scheme != "socks5" || parsed.User == nil || parsed.Host == "" || parsed.RawQuery != "" {
		return "", errRenderedSubscriptionMismatch
	}
	if err := validateAddress(parsed.Host); err != nil {
		return "", errRenderedSubscriptionMismatch
	}
	return parsed.Host, nil
}

func (s *Service) validateRenderedState(persistent state.PersistentState) error {
	if err := ValidatePersistentState(persistent); err != nil {
		return err
	}
	lastGood := persistent.LastGood
	if lastGood.RenderedSubscription == "" {
		return nil
	}
	rendered, _, _, err := s.renderPersistedNodes(lastGood.Nodes, persistent.Subscription)
	if err != nil || rendered != lastGood.RenderedSubscription {
		return errRenderedSubscriptionMismatch
	}
	return nil
}

func (s *Service) renderNodes(nodes []state.Node, generation state.SubscriptionGeneration) (string, int, []state.PersistedNode, error) {
	if s.hooks.onRender != nil {
		s.hooks.onRender()
	}
	links := make([]Link, 0, len(nodes))
	persisted := make([]state.PersistedNode, 0, len(nodes))
	for _, node := range nodes {
		credential, err := selector.Derive(selector.NodeIdentity{Provider: node.Provider, Host: node.Host, Port: int(node.Port)}, generation.SelectorKey, generation.ProxyAuthKey)
		if err != nil {
			return "", 0, nil, err
		}
		links = append(links, Link{Selector: credential.Selector, Password: credential.Password, Name: node.Name, Group: node.Group, Eligible: node.TunnelEligible()})
		persisted = append(persisted, state.PersistedNode{ID: node.ID, Selector: credential.Selector, Provider: node.Provider, Host: node.Host, Port: node.Port, Name: node.Name, Group: node.Group, Eligible: node.Eligible, Excluded: node.Excluded})
	}
	body, count, err := Render(links, s.socksAddress)
	if err != nil {
		return "", 0, nil, err
	}
	return body, count, persisted, nil
}

func (s *Service) renderPersistedNodes(nodes []state.PersistedNode, generation state.SubscriptionGeneration) (string, int, []state.PersistedNode, error) {
	return s.renderPersistedNodesAt(nodes, generation, s.socksAddress)
}

func (s *Service) renderPersistedNodesAt(nodes []state.PersistedNode, generation state.SubscriptionGeneration, socksAddress string) (string, int, []state.PersistedNode, error) {
	return s.renderPersistedNodesAtWithLegacyExclusions(nodes, generation, socksAddress, false)
}

func (s *Service) renderPersistedNodesAtWithLegacyExclusions(nodes []state.PersistedNode, generation state.SubscriptionGeneration, socksAddress string, legacyExclusions bool) (string, int, []state.PersistedNode, error) {
	if s.hooks.onRender != nil {
		s.hooks.onRender()
	}
	links := make([]Link, 0, len(nodes))
	for _, node := range nodes {
		credential, err := selector.Derive(selector.NodeIdentity{Provider: node.Provider, Host: node.Host, Port: int(node.Port)}, generation.SelectorKey, generation.ProxyAuthKey)
		if err != nil {
			return "", 0, nil, err
		}
		eligible := node.Eligible && strings.EqualFold(node.Provider, "WIFIIN") && node.Host != "" && node.Port != 0
		if legacyExclusions {
			eligible = eligible && !node.Excluded
		}
		links = append(links, Link{Selector: credential.Selector, Password: credential.Password, Name: node.Name, Group: node.Group, Eligible: eligible})
	}
	body, count, err := Render(links, socksAddress)
	return body, count, append([]state.PersistedNode(nil), nodes...), err
}

func eligiblePersistedCount(nodes []state.PersistedNode) int {
	count := 0
	for _, node := range nodes {
		if node.Eligible && strings.EqualFold(node.Provider, "WIFIIN") && node.Host != "" && node.Port != 0 {
			count++
		}
	}
	return count
}

func subscriptionRequestPath(requestPath string) (string, bool) {
	parts := strings.Split(requestPath, "/")
	if len(parts) != 3 || parts[0] != "" || parts[1] != "sub" || parts[2] == "" {
		return "", false
	}
	return parts[2], true
}

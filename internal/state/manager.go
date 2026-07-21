package state

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// RuntimeStore publishes immutable snapshots through an atomic pointer. It
// deep-copies both input and output, so callers cannot mutate a published view.
type RuntimeStore struct {
	snapshot atomic.Pointer[RuntimeSnapshot]
}

// NewRuntimeStore makes an empty store or publishes an initial complete view.
func NewRuntimeStore(initial *RuntimeSnapshot) (*RuntimeStore, error) {
	store := &RuntimeStore{}
	if initial != nil {
		if err := ValidateRuntimeSnapshot(initial); err != nil {
			return nil, err
		}
		store.snapshot.Store(initial.Clone())
	}
	return store, nil
}

// Current returns a private, generation-pinned copy of the current view.
func (s *RuntimeStore) Current() *RuntimeSnapshot {
	if s == nil {
		return nil
	}
	return s.snapshot.Load().Clone()
}

// Publish atomically replaces the view with a deep copy. Generations must be
// strictly monotonic; refresh callers cannot publish partial in-place changes.
func (s *RuntimeStore) Publish(next *RuntimeSnapshot) error {
	if s == nil {
		return fmt.Errorf("nil runtime store")
	}
	if err := ValidateRuntimeSnapshot(next); err != nil {
		return err
	}
	clone := next.Clone()
	for {
		current := s.snapshot.Load()
		if current != nil && clone.Generation <= current.Generation {
			return fmt.Errorf("%w: non-monotonic generation", ErrInvalidSnapshot)
		}
		if s.snapshot.CompareAndSwap(current, clone) {
			return nil
		}
	}
}

// replace is reserved for explicit lifecycle invalidation. It intentionally
// does not relax Publish's generation rules for normal refreshes.
func (s *RuntimeStore) replace(next *RuntimeSnapshot) {
	s.snapshot.Store(next.Clone())
}

// Status is a redacted lifecycle view for API and event consumers.
type Status struct {
	State      ServiceState   `json:"state"`
	Generation uint64         `json:"generation,omitempty"`
	CreatedAt  time.Time      `json:"createdAt,omitempty"`
	ExpiresAt  time.Time      `json:"expiresAt,omitempty"`
	Account    AccountSummary `json:"account"`
	NodeTotal  int            `json:"nodeTotal"`
	Eligible   int            `json:"eligible"`
}

// AccountBindingStatus reports whether a raw account ID is authorized by the
// durable selector-key binding without exposing that identifier.
type AccountBindingStatus string

const (
	AccountBindingUnbound  AccountBindingStatus = "unbound"
	AccountBindingMatch    AccountBindingStatus = "match"
	AccountBindingMismatch AccountBindingStatus = "mismatch"
)

// Manager serializes service-state transitions and wraps a RuntimeStore.
type Manager struct {
	runtime *RuntimeStore

	mu                   sync.Mutex
	state                ServiceState
	active               Operation
	lease                uint64
	subscription         SubscriptionGeneration
	accountBindingKey    []byte
	bindingKeyConfigured bool
}

// NewManager constructs a manager with no durable account-binding authority.
func NewManager(initial *RuntimeSnapshot) (*Manager, error) {
	return NewManagerWithSubscription(initial, SubscriptionGeneration{}, nil)
}

// NewManagerWithSubscription restores persisted subscription authority. An
// uninitialized v2 installation has an unbound generation and nil binding key.
func NewManagerWithSubscription(initial *RuntimeSnapshot, subscription SubscriptionGeneration, bindingKey []byte) (*Manager, error) {
	if len(bindingKey) != 0 && len(bindingKey) != sha256.Size {
		return nil, ErrAccountChanged
	}
	if subscription.Generation != 0 && validateSubscriptionGeneration(subscription) != nil {
		return nil, ErrAccountChanged
	}
	if len(subscription.AccountBinding) != 0 && len(bindingKey) != sha256.Size {
		return nil, ErrAccountChanged
	}
	prepared := initial
	now := time.Now()
	if initial != nil && now.Before(initial.CreatedAt) {
		prepared = nil
	} else if initial != nil && !SessionUsable(initial, now) {
		prepared = initial.Clone()
		prepared.Sessions.Wipe()
		if now.Before(prepared.ExpiresAt) {
			prepared.ExpiresAt = now.UTC()
		}
	}
	store, err := NewRuntimeStore(prepared)
	if err != nil {
		return nil, err
	}
	manager := &Manager{
		runtime: store, state: StateSignedOut, subscription: subscription.clone(),
		accountBindingKey: append([]byte(nil), bindingKey...), bindingKeyConfigured: len(bindingKey) == sha256.Size,
	}
	if initial != nil {
		if SessionUsable(initial, now) {
			if !manager.bindingKeyConfigured || subscription.Generation == 0 || len(subscription.AccountBinding) != sha256.Size || !matchesAccountBinding(subscription.AccountBinding, bindingKey, initial.Sessions.UserID()) {
				return nil, ErrAccountChanged
			}
			manager.state = StateReady
		} else if prepared != nil && len(prepared.Nodes) != 0 {
			manager.state = StateExpired
		}
	}
	return manager, nil
}

// ConfigureBindingKey installs the verifier-derived account-binding key once.
// It must be called after first-token setup and never accepts raw tokens.
func (m *Manager) ConfigureBindingKey(bindingKey []byte) error {
	if m == nil || len(bindingKey) != sha256.Size {
		return ErrAccountChanged
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bindingKeyConfigured {
		return ErrBindingKeyAlreadyConfigured
	}
	m.accountBindingKey = append([]byte(nil), bindingKey...)
	m.bindingKeyConfigured = true
	return nil
}

// Current returns an immutable copy of the current generation.
func (m *Manager) Current() *RuntimeSnapshot {
	if m == nil {
		return nil
	}
	return m.runtime.Current()
}

// TunnelPin is the compact authority and route record retained by one SOCKS
// flow. It deliberately contains no RuntimeSnapshot or selector map.
type TunnelPin struct {
	Session   SessionSecrets
	ExpiresAt time.Time
	Node      Node
	Ref       NodeRef
}

// CompactPin atomically resolves one authenticated selector from the internal
// immutable snapshot. Callers authenticate selector/password in selector.Registry
// first, then provide the resulting credentialGeneration.
func (m *Manager) CompactPin(selector string, credentialGeneration uint64, now time.Time) (TunnelPin, error) {
	if m == nil || selector == "" || credentialGeneration == 0 {
		return TunnelPin{}, ErrSelectorUnknown
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateReady && m.state != StateDegraded && m.state != StateSyncing {
		return TunnelPin{}, ErrSelectorUnknown
	}
	current := m.runtime.snapshot.Load()
	if !SessionUsable(current, now) {
		return TunnelPin{}, ErrSelectorUnknown
	}
	node, ref, err := current.ResolveSelector(selector, now)
	if err != nil {
		return TunnelPin{}, err
	}
	if ref.Generation != credentialGeneration {
		return TunnelPin{}, ErrSelectorUnknown
	}
	session, available := current.Sessions.For(node.EffectiveClientProfile())
	if !available {
		return TunnelPin{}, ErrSelectorUnknown
	}
	return TunnelPin{Session: session, ExpiresAt: current.ExpiresAt, Node: node, Ref: ref}, nil
}

// SessionCurrentPin is the compact final admission check for a SOCKS flow
// after upstream acknowledgement. It is linearizable with state mutation and
// does not require retaining a full runtime snapshot.
func (m *Manager) SessionCurrentPin(pin TunnelPin, now time.Time) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.runtime.snapshot.Load()
	return (m.state == StateReady || m.state == StateDegraded || m.state == StateSyncing) &&
		current != nil &&
		current.ExpiresAt.Equal(pin.ExpiresAt) &&
		SessionUsable(current, now) &&
		currentSessionMatchesPin(current, pin)
}

// InstallSubscriptionGeneration installs a durable candidate only while an
// authentication operation is active. It supports first binding and an account
// change, and returns an idempotent rollback for a later failed publish.
func (m *Manager) InstallSubscriptionGeneration(candidate SubscriptionGeneration, userID string) (func(), error) {
	if m == nil || validateSubscriptionGeneration(candidate) != nil {
		return nil, ErrAccountChanged
	}
	m.mu.Lock()
	if (m.state != StateAuthenticating && m.state != StateSyncing) || !m.bindingKeyConfigured || len(m.accountBindingKey) != sha256.Size || len(candidate.AccountBinding) != sha256.Size || !matchesAccountBinding(candidate.AccountBinding, m.accountBindingKey, userID) {
		m.mu.Unlock()
		return nil, ErrAccountChanged
	}
	current := m.subscription
	switch {
	case current.Generation == 0:
		// A manager created without an on-disk generation may adopt a validated candidate.
	case len(current.AccountBinding) == 0:
		if candidate.Generation != current.Generation || !sameSubscriptionCredentials(current, candidate) {
			m.mu.Unlock()
			return nil, ErrAccountChanged
		}
	case subtle.ConstantTimeCompare(current.AccountBinding, candidate.AccountBinding) == 1:
		if candidate.Generation != current.Generation || !sameSubscriptionCredentials(current, candidate) {
			m.mu.Unlock()
			return nil, ErrAccountChanged
		}
	default:
		if candidate.Generation != current.Generation+1 || !rotatedSubscriptionMaterial(current, candidate) {
			m.mu.Unlock()
			return nil, ErrAccountChanged
		}
	}
	previous := current.clone()
	m.subscription = candidate.clone()
	m.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if sameSubscriptionGeneration(m.subscription, candidate) {
				m.subscription = previous
			}
		})
	}, nil
}

func sameSubscriptionCredentials(left, right SubscriptionGeneration) bool {
	return subtle.ConstantTimeCompare(left.SelectorKey, right.SelectorKey) == 1 &&
		subtle.ConstantTimeCompare(left.ProxyAuthKey, right.ProxyAuthKey) == 1
}

func sameSubscriptionGeneration(left, right SubscriptionGeneration) bool {
	return left.Generation == right.Generation &&
		sameSubscriptionCredentials(left, right) &&
		subtle.ConstantTimeCompare(left.AccountBinding, right.AccountBinding) == 1
}

// AccountBindingStatus checks the supplied account against durable authority
// without retaining the raw identifier.
func (m *Manager) AccountBindingStatus(userID string) AccountBindingStatus {
	if m == nil {
		return AccountBindingMismatch
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.bindingKeyConfigured || m.subscription.Generation == 0 || len(m.subscription.AccountBinding) == 0 {
		return AccountBindingUnbound
	}
	if matchesAccountBinding(m.subscription.AccountBinding, m.accountBindingKey, userID) {
		return AccountBindingMatch
	}
	return AccountBindingMismatch
}

// SessionCurrent atomically admits a pinned snapshot for a new tunnel after an
// upstream handshake. It permits metadata-only probe publications, but rejects
// logout, expiry, and authority renewal. Established relays retain their own
// pinned snapshot.
func (m *Manager) SessionCurrent(pinned *RuntimeSnapshot, now time.Time) bool {
	if m == nil || pinned == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.runtime.snapshot.Load()
	return (m.state == StateReady || m.state == StateDegraded || m.state == StateSyncing) &&
		current != nil &&
		current.ExpiresAt.Equal(pinned.ExpiresAt) &&
		SessionUsable(current, now) &&
		sameClientSessions(current.Sessions, pinned.Sessions)
}

func sameClientSessions(left, right ClientSessions) bool {
	return sameSessionAuthority(left.IOS, right.IOS) && sameSessionAuthority(left.Windows, right.Windows)
}

func currentSessionMatchesPin(current *RuntimeSnapshot, pin TunnelPin) bool {
	if current == nil {
		return false
	}
	session, available := current.Sessions.For(pin.Node.EffectiveClientProfile())
	return available && sameSessionAuthority(session, pin.Session)
}

// sameSessionAuthority compares all source authority material without making
// a secret-bearing session comparable through ordinary string equality.
func sameSessionAuthority(a, b SessionSecrets) bool {
	match := subtle.ConstantTimeCompare([]byte(a.UserID), []byte(b.UserID))
	match &= subtle.ConstantTimeCompare([]byte(a.LoginToken), []byte(b.LoginToken))
	match &= subtle.ConstantTimeCompare([]byte(a.ProviderToken), []byte(b.ProviderToken))
	match &= subtle.ConstantTimeCompare([]byte(a.TunnelPassword), []byte(b.TunnelPassword))
	match &= subtle.ConstantTimeCompare([]byte(a.TunnelMethod), []byte(b.TunnelMethod))
	match &= subtle.ConstantTimeCompare([]byte(a.ProviderExtension), []byte(b.ProviderExtension))
	return match == 1
}

// State returns the current lifecycle state.
func (m *Manager) State() ServiceState {
	if m == nil {
		return StateError
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Status returns only non-secret, redacted state.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{State: StateError}
	}
	m.mu.Lock()
	currentState := m.state
	m.mu.Unlock()
	snapshot := m.Current()
	if snapshot == nil {
		return Status{State: currentState}
	}
	status := Status{
		State:      currentState,
		Generation: snapshot.Generation,
		CreatedAt:  snapshot.CreatedAt,
		ExpiresAt:  snapshot.ExpiresAt,
		Account:    snapshot.Account,
		NodeTotal:  len(snapshot.Nodes),
	}
	for _, node := range snapshot.Nodes {
		if node.TunnelEligible() {
			status.Eligible++
		}
	}
	return status
}

// Begin acquires the exclusive login or refresh lease. The returned function
// must be called exactly once to release the lease.
func (m *Manager) Begin(operation Operation) (func(Outcome), error) {
	if m == nil {
		return nil, ErrNoOperation
	}
	m.mu.Lock()
	if m.active != "" {
		m.mu.Unlock()
		return nil, ErrOperationInProgress
	}
	var target ServiceState
	switch operation {
	case OperationLogin:
		switch m.state {
		case StateSignedOut, StateExpired, StateError:
			target = StateAuthenticating
		default:
			m.mu.Unlock()
			return nil, ErrInvalidTransition
		}
	case OperationRefresh:
		switch m.state {
		case StateReady, StateDegraded:
			target = StateSyncing
		default:
			m.mu.Unlock()
			return nil, ErrInvalidTransition
		}
	default:
		m.mu.Unlock()
		return nil, ErrInvalidTransition
	}
	m.state = target
	m.active = operation
	m.lease++
	lease := m.lease
	m.mu.Unlock()

	var once sync.Once
	return func(outcome Outcome) {
		once.Do(func() { m.finish(lease, operation, outcome) })
	}, nil
}

func (m *Manager) finish(lease uint64, operation Operation, outcome Outcome) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lease != lease || m.active != operation {
		return
	}
	m.active = ""
	if outcome == OutcomeSucceeded {
		if operation == OperationLogin && m.state == StateAuthenticating {
			m.state = StateSyncing
		}
		return
	}
	if operation == OperationLogin {
		m.signOutLocked()
		return
	}
	current := m.runtime.Current()
	if current != nil && current.Sessions.Valid() {
		if !current.ExpiresAt.IsZero() && !time.Now().Before(current.ExpiresAt) {
			m.expireLocked(time.Now())
		} else {
			m.state = StateDegraded
		}
	} else {
		m.state = StateError
	}
}

// Transition moves between explicit lifecycle states while retaining operation
// serialization. It is useful to expose the authenticating -> syncing phase.
func (m *Manager) Transition(next ServiceState) error {
	if m == nil {
		return ErrInvalidTransition
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !validTransition(m.state, next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, m.state, next)
	}
	m.state = next
	return nil
}

func validTransition(from, to ServiceState) bool {
	switch from {
	case StateSignedOut:
		return to == StateAuthenticating
	case StateAuthenticating:
		return to == StateSyncing || to == StateReady || to == StateSignedOut || to == StateError
	case StateSyncing:
		return to == StateReady || to == StateDegraded || to == StateExpired || to == StateError || to == StateSignedOut
	case StateReady:
		return to == StateSyncing || to == StateDegraded || to == StateExpired || to == StateSignedOut
	case StateDegraded:
		return to == StateSyncing || to == StateReady || to == StateExpired || to == StateSignedOut || to == StateError
	case StateExpired:
		return to == StateAuthenticating || to == StateSignedOut
	case StateError:
		return to == StateAuthenticating || to == StateSignedOut
	default:
		return false
	}
}

// Commit publishes a complete newly refreshed snapshot only for the account
// already installed in durable subscription state.
func (m *Manager) Commit(snapshot *RuntimeSnapshot) error {
	if m == nil || snapshot == nil {
		return ErrInvalidSnapshot
	}
	if err := ValidateRuntimeSnapshot(snapshot); err != nil {
		return err
	}
	if !snapshot.Sessions.Valid() {
		return fmt.Errorf("%w: incomplete client sessions", ErrInvalidSnapshot)
	}
	hasEligible := false
	for _, node := range snapshot.Nodes {
		if node.TunnelEligible() {
			hasEligible = true
			break
		}
	}
	if !hasEligible {
		return fmt.Errorf("%w: no eligible nodes", ErrInvalidSnapshot)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateAuthenticating && m.state != StateSyncing && m.state != StateReady && m.state != StateDegraded {
		return fmt.Errorf("%w: %s cannot publish", ErrInvalidTransition, m.state)
	}
	if m.runtime.snapshot.Load() != nil && snapshot.Generation <= m.runtime.snapshot.Load().Generation {
		return fmt.Errorf("%w: non-monotonic generation", ErrInvalidSnapshot)
	}
	if !m.bindingKeyConfigured || m.subscription.Generation == 0 || len(m.subscription.AccountBinding) != sha256.Size || !matchesAccountBinding(m.subscription.AccountBinding, m.accountBindingKey, snapshot.Sessions.UserID()) {
		return ErrAccountChanged
	}
	m.runtime.replace(snapshot)
	if m.state == StateAuthenticating || m.state == StateSyncing {
		m.state = StateReady
	}
	return nil
}

func rotatedSubscriptionMaterial(current, candidate SubscriptionGeneration) bool {
	return subtle.ConstantTimeCompare(current.SelectorKey, candidate.SelectorKey) != 1 &&
		subtle.ConstantTimeCompare(current.ProxyAuthKey, candidate.ProxyAuthKey) != 1
}

// SignOut removes session material from the current generation while preserving
// the last non-secret node metadata. Previously returned snapshots remain pinned
// for established flows; new flows receive a session-less snapshot and fail.
func (m *Manager) SignOut() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = ""
	m.lease++
	m.signOutLocked()
}

// signOutLocked publishes a sessionless, account-redacted snapshot. It must be
// called while m.mu is held.
func (m *Manager) signOutLocked() {
	current := m.runtime.Current()
	if current != nil {
		current.Sessions.Wipe()
		current.Account = AccountSummary{}
		m.runtime.replace(current)
	}
	m.state = StateSignedOut
}

// MarkDegraded preserves the current complete generation after a refresh error.
func (m *Manager) MarkDegraded() error { return m.Transition(StateDegraded) }

// MarkExpired makes all newly fetched snapshots fail the expiry check while
// leaving earlier pinned snapshots available for bounded existing-flow drain.
func (m *Manager) MarkExpired(now time.Time) error {
	if m == nil {
		return ErrInvalidTransition
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == StateExpired {
		m.expireLocked(now)
		return nil
	}
	if m.state != StateReady && m.state != StateDegraded && m.state != StateSyncing && m.state != StateError {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, m.state, StateExpired)
	}
	m.expireLocked(now)
	return nil
}

// expireLocked publishes a secret-free expired view. It must be called while
// m.mu is held; snapshots already held by established relays remain unchanged.
func (m *Manager) expireLocked(now time.Time) {
	current := m.runtime.Current()
	if current != nil {
		current.ExpiresAt = now.UTC()
		current.Sessions.Wipe()
		m.runtime.replace(current)
	}
	m.state = StateExpired
}

// SessionUsable reports whether the supplied pinned snapshot may establish a
// new tunnel at now. Existing relays deliberately do not re-check this value.
func SessionUsable(snapshot *RuntimeSnapshot, now time.Time) bool {
	return snapshot != nil && snapshot.Sessions.Valid() && !snapshot.CreatedAt.IsZero() && !snapshot.ExpiresAt.IsZero() && !now.Before(snapshot.CreatedAt) && now.Before(snapshot.ExpiresAt)
}

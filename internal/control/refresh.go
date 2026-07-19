package control

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
)

var (
	ErrNoSession        = errors.New("control: no refreshable session")
	ErrAuthorityExpired = errors.New("control: authority has expired")
)

// RefresherConfig configures the serialized control-plane coordinator. All
// state changes go through Manager; it is the sole publication path for a
// complete authority-and-lines generation.
type RefresherConfig struct {
	Client          *Client
	Manager         *state.Manager
	SelectorBuilder state.SelectorBuilder
	// CommitSnapshot is the single final publication hook. When supplied, it
	// must durably render/persist any last-good subscription state before it
	// calls Manager.Commit. Returning an error leaves Manager untouched.
	CommitSnapshot func(*state.RuntimeSnapshot) error

	// AuthorityLifetime is the conservative lifetime assigned after a complete
	// authority refresh. It defaults to the observed 24-hour refresh deadline.
	AuthorityLifetime time.Duration
	// MaxAttempts bounds retryable refresh requests. Login itself is never
	// retried, including after rejected credentials.
	MaxAttempts int
	BackoffMin  time.Duration
	BackoffMax  time.Duration
	Clock       func() time.Time
}

// Refresher serializes login and refresh with state.Manager's operation lease.
type Refresher struct {
	client         *Client
	manager        *state.Manager
	builder        state.SelectorBuilder
	commitSnapshot func(*state.RuntimeSnapshot) error
	lifetime       time.Duration
	attempts       int
	backoff        time.Duration
	maxBackoff     time.Duration
	clock          func() time.Time
}

// NewRefresher validates the collaborators required to publish snapshots.
func NewRefresher(cfg RefresherConfig) (*Refresher, error) {
	if cfg.Client == nil || cfg.Manager == nil || cfg.SelectorBuilder == nil {
		return nil, ErrNoSession
	}
	lifetime := cfg.AuthorityLifetime
	if lifetime <= 0 {
		lifetime = 24 * time.Hour
	}
	attempts := cfg.MaxAttempts
	if attempts <= 0 {
		attempts = 3
	}
	if attempts > 5 {
		attempts = 5
	}
	backoff := cfg.BackoffMin
	if backoff <= 0 {
		backoff = 250 * time.Millisecond
	}
	maxBackoff := cfg.BackoffMax
	if maxBackoff <= 0 || maxBackoff > 5*time.Second {
		maxBackoff = 5 * time.Second
	}
	if maxBackoff < backoff {
		return nil, fmt.Errorf("control: invalid backoff bounds")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	commitSnapshot := cfg.CommitSnapshot
	if commitSnapshot == nil {
		commitSnapshot = cfg.Manager.Commit
	}
	return &Refresher{
		client: cfg.Client, manager: cfg.Manager, builder: cfg.SelectorBuilder, commitSnapshot: commitSnapshot,
		lifetime: lifetime, attempts: attempts, backoff: backoff,
		maxBackoff: maxBackoff, clock: clock,
	}, nil
}

// Login performs config selection, one password-login attempt, then authority
// and line fetches concurrently. It publishes no provisional session: a
// snapshot is committed only after every protocol response validates.
func (r *Refresher) Login(ctx context.Context, input EmailLogin) (err error) {
	complete, err := r.manager.Begin(state.OperationLogin)
	if err != nil {
		return err
	}
	outcome := state.OutcomeFailed
	defer func() { complete(outcome) }()

	session, err := r.client.Login(ctx, input)
	// Strings are immutable and may be copied by the compiler, so this cannot
	// guarantee physical erasure. It does ensure this coordinator no longer
	// retains the caller's password while authority and line work proceeds.
	input.Password = ""
	if err != nil {
		return err
	}
	if err := r.manager.Transition(state.StateSyncing); err != nil {
		return err
	}
	authority, lines, err := r.fetchAuthorityAndLines(ctx, session, false)
	if err != nil {
		return err
	}
	if err := r.commit(session, authority, lines, state.NewAccountSummary(input.Account, false, time.Time{})); err != nil {
		return err
	}
	outcome = state.OutcomeSucceeded
	return nil
}

// Refresh refreshes client configuration, authority, and lines under one lease.
// It retains the prior complete generation on every failed response; retrying
// is bounded and restricted to non-rejection, non-schema failures.
func (r *Refresher) Refresh(ctx context.Context) (err error) {
	if expired, expireErr := r.ExpireIfNeeded(r.now()); expireErr != nil || expired {
		if expireErr != nil {
			return expireErr
		}
		return ErrAuthorityExpired
	}
	complete, err := r.manager.Begin(state.OperationRefresh)
	if err != nil {
		return err
	}
	outcome := state.OutcomeFailed
	defer func() { complete(outcome) }()

	current := r.manager.Current()
	if current == nil || !current.Session.Valid() {
		return ErrNoSession
	}
	userID, err := parsePositiveDecimal(current.Session.UserID)
	if err != nil {
		return ErrSchema
	}
	configuration, err := retry(ctx, r, func() (ClientConfig, error) {
		return r.client.FetchClientConfig(ctx)
	})
	if err != nil {
		return err
	}
	session := LoginSession{
		UserID:  userID,
		Token:   current.Session.LoginToken,
		APIBase: configuration.APIBase,
	}
	authority, lines, err := r.fetchAuthorityAndLines(ctx, session, true)
	if err != nil {
		return err
	}
	if err := r.commit(session, authority, lines, current.Account); err != nil {
		return err
	}
	outcome = state.OutcomeSucceeded
	return nil
}

// ExpireIfNeeded transitions a usable generation to expired before a new
// control operation starts. Existing connections retain their pinned snapshot.
func (r *Refresher) ExpireIfNeeded(now time.Time) (bool, error) {
	current := r.manager.Current()
	if current == nil || current.ExpiresAt.IsZero() || now.Before(current.ExpiresAt) {
		return false, nil
	}
	stateNow := r.manager.State()
	if stateNow == state.StateExpired {
		return true, nil
	}
	if stateNow != state.StateReady && stateNow != state.StateDegraded {
		return true, ErrAuthorityExpired
	}
	if err := r.manager.MarkExpired(now); err != nil {
		return false, err
	}
	return true, nil
}

func (r *Refresher) fetchAuthorityAndLines(ctx context.Context, session LoginSession, retryRequests bool) (Authority, Lines, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		authority *Authority
		lines     *Lines
		err       error
	}
	results := make(chan result, 2)
	go func() {
		var authority Authority
		var err error
		if retryRequests {
			authority, err = retry(childCtx, r, func() (Authority, error) { return r.client.FetchAuthority(childCtx, session) })
		} else {
			authority, err = r.client.FetchAuthority(childCtx, session)
		}
		if err != nil {
			cancel()
			results <- result{err: err}
			return
		}
		results <- result{authority: &authority}
	}()
	go func() {
		var lines Lines
		var err error
		if retryRequests {
			lines, err = retry(childCtx, r, func() (Lines, error) { return r.client.FetchLines(childCtx, session) })
		} else {
			lines, err = r.client.FetchLines(childCtx, session)
		}
		if err != nil {
			cancel()
			results <- result{err: err}
			return
		}
		results <- result{lines: &lines}
	}()

	var authority Authority
	var lines Lines
	for range 2 {
		result := <-results
		if result.err != nil {
			return Authority{}, Lines{}, result.err
		}
		if result.authority != nil {
			authority = *result.authority
		}
		if result.lines != nil {
			lines = *result.lines
		}
	}
	if authority.ProviderToken == "" || session.Token == "" || len(lines.Lines) == 0 {
		return Authority{}, Lines{}, ErrSchema
	}
	return authority, lines, nil
}

func (r *Refresher) commit(session LoginSession, authority Authority, lines Lines, account state.AccountSummary) error {
	if session.UserID <= 0 || session.Token == "" || authority.ProviderToken == "" || authority.ProviderExtension == "" {
		return ErrSchema
	}
	current := r.manager.Current()
	generation := uint64(1)
	var previous map[string]state.NodeRef
	if current != nil {
		generation = current.Generation + 1
		previous = current.Selectors
	}
	nodes, err := nodesFromLines(lines)
	if err != nil {
		return err
	}
	builtNodes, selectors, err := r.buildSelectors(generation, nodes, previous)
	if err != nil {
		return fmt.Errorf("control: build selectors: %w", err)
	}
	now := r.now().UTC()
	snapshot := &state.RuntimeSnapshot{
		Generation: generation,
		CreatedAt:  now,
		ExpiresAt:  now.Add(r.lifetime),
		Account:    account,
		Session: state.SessionSecrets{
			UserID:            formatUserID(session.UserID),
			LoginToken:        session.Token,
			ProviderToken:     authority.ProviderToken,
			TunnelPassword:    authority.EncryptKey,
			TunnelMethod:      authority.EncryptType,
			ProviderExtension: authority.ProviderExtension,
		},
		Nodes:     builtNodes,
		Selectors: selectors,
	}
	return r.commitSnapshot(snapshot)
}

func (r *Refresher) buildSelectors(snapshotGeneration uint64, nodes []state.Node, previous map[string]state.NodeRef) ([]state.Node, map[string]state.NodeRef, error) {
	tombstoneBuilder, hasTombstones := r.builder.(interface {
		BuildWithTombstones(uint64, []state.Node, map[string]state.NodeRef, time.Time) (selector.BuildResult, error)
	})
	if generationProvider, hasGenerations := r.builder.(interface{ Generations() []uint64 }); hasGenerations {
		if !hasTombstones {
			return nil, nil, fmt.Errorf("control: generation-aware selector builder lacks tombstones")
		}
		credentialGenerations := generationProvider.Generations()
		if len(credentialGenerations) == 0 {
			return nil, nil, fmt.Errorf("control: selector builder has no credential generation")
		}
		selectors := make(map[string]state.NodeRef, len(nodes)*len(credentialGenerations)+len(previous))
		seenGenerations := make(map[uint64]struct{}, len(credentialGenerations))
		var currentNodes []state.Node
		for index, credentialGeneration := range credentialGenerations {
			if credentialGeneration == 0 {
				return nil, nil, fmt.Errorf("control: selector builder has zero credential generation")
			}
			if _, duplicate := seenGenerations[credentialGeneration]; duplicate {
				return nil, nil, fmt.Errorf("control: selector builder repeats credential generation")
			}
			seenGenerations[credentialGeneration] = struct{}{}
			result, err := tombstoneBuilder.BuildWithTombstones(credentialGeneration, nodes, selectorsForGeneration(previous, credentialGeneration), r.now().UTC())
			if err != nil {
				return nil, nil, err
			}
			if index == 0 {
				// The current credential generation defines every Node.Selector.
				// Pending credentials remain valid through NodeRefs only.
				currentNodes = result.Nodes
			}
			for name, ref := range result.Selectors {
				if _, collision := selectors[name]; collision {
					return nil, nil, fmt.Errorf("control: selector collision across credential generations")
				}
				selectors[name] = ref
			}
		}
		return currentNodes, selectors, nil
	}
	if hasTombstones {
		result, err := tombstoneBuilder.BuildWithTombstones(snapshotGeneration, nodes, previous, r.now().UTC())
		if err != nil {
			return nil, nil, err
		}
		return result.Nodes, result.Selectors, nil
	}
	selectors, err := r.builder.Build(snapshotGeneration, nodes)
	if err != nil {
		return nil, nil, err
	}
	// A generic builder cannot retain its own historical state, so preserve
	// removed selectors as explicit tombstones here rather than remapping them.
	for name, ref := range previous {
		if _, exists := selectors[name]; !exists && (!ref.Tombstoned || ref.IsTombstoned(r.now())) {
			selectors[name] = state.NodeRef{
				Generation: snapshotGeneration, Tombstoned: true,
				TombstoneUntil: r.now().UTC().Add(24 * time.Hour),
			}
		}
	}
	byID := make(map[string]int, len(nodes))
	for index := range nodes {
		byID[nodes[index].ID] = index
	}
	for name, ref := range selectors {
		if ref.Tombstoned {
			continue
		}
		index, exists := byID[ref.NodeID]
		if !exists {
			return nil, nil, ErrSchema
		}
		nodes[index].Selector = name
	}
	return nodes, selectors, nil
}

func selectorsForGeneration(previous map[string]state.NodeRef, generation uint64) map[string]state.NodeRef {
	selected := make(map[string]state.NodeRef)
	for name, ref := range previous {
		if ref.Generation == generation {
			selected[name] = ref
		}
	}
	return selected
}

func nodesFromLines(lines Lines) ([]state.Node, error) {
	groups := make(map[string]string, len(lines.Groups))
	for _, group := range lines.Groups {
		groups[group.ID] = group.Name
	}
	seen := make(map[string]struct{}, len(lines.Lines))
	nodes := make([]state.Node, 0, len(lines.Lines))
	for _, line := range lines.Lines {
		identity, err := selector.Canonicalize(selector.NodeIdentity{
			Provider: line.Provider,
			Host:     line.Host,
			Port:     int(line.Port),
		})
		if err != nil {
			return nil, fmt.Errorf("%w: canonical node identity", ErrSchema)
		}
		id := nodeID(identity)
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		groupName := line.GroupName
		if groupName == "" {
			groupName = groups[line.GroupID]
		}
		nodes = append(nodes, state.Node{
			ID:        id,
			Provider:  identity.Provider,
			Host:      identity.Host,
			Port:      identity.Port,
			Name:      line.Label,
			Group:     groupName,
			Model:     line.Model,
			Weight:    line.Weight,
			Auto:      line.Auto,
			Eligible:  true,
			Health:    state.NodeHealthUnknown,
			UDPHealth: state.UDPHealthUnavailable,
		})
	}
	return nodes, nil
}

func nodeID(identity selector.CanonicalIdentity) string {
	sum := sha256.Sum256(identity.Fingerprint())
	return "node_" + base64.RawURLEncoding.EncodeToString(sum[:12])
}

func (r *Refresher) now() time.Time { return r.clock() }

// retry retries only failures that could be transient. It intentionally never
// retries login rejection, business rejection, cryptographic data errors, or a
// malformed server schema.
func retry[T any](ctx context.Context, r *Refresher, call func() (T, error)) (T, error) {
	var zero T
	for attempt := range r.attempts {
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		default:
		}
		value, err := call()
		if err == nil || !retryable(err) || attempt+1 == r.attempts {
			return value, err
		}
		delay := retryDelay(r, attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
	return zero, nil
}

func retryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrLoginRejected) || errors.Is(err, ErrBusinessStatus) ||
		errors.Is(err, ErrSchema) || errors.Is(err, ErrInvalidEnvelope) ||
		errors.Is(err, ErrInvalidPadding) || errors.Is(err, ErrMalformedCiphertext) ||
		errors.Is(err, ErrResponseTooLarge) || errors.Is(err, ErrUnsupportedCipher) || errors.Is(err, ErrInvalidLine) {
		return false
	}
	var status *httpStatusError
	if errors.As(err, &status) {
		return status.status == http.StatusRequestTimeout || status.status == http.StatusTooManyRequests || status.status >= http.StatusInternalServerError && status.status <= 599
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())
}

func retryDelay(r *Refresher, attempt int) time.Duration {
	base := r.backoff
	for range attempt {
		if base >= r.maxBackoff/2 {
			base = r.maxBackoff
			break
		}
		base *= 2
	}
	// Full jitter prevents synchronized retries. It cannot expose credentials.
	jitter, err := boundedRandom(r.client.random, int(base/time.Millisecond)+1)
	if err != nil {
		return base
	}
	return time.Duration(jitter) * time.Millisecond
}

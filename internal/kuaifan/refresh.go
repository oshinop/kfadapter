package kuaifan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	wireprofile "github.com/kfadapter/kfadapter/internal/kuaifan/profile"
	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
)

var (
	ErrNoSession        = errors.New("control: no refreshable session")
	ErrAuthorityExpired = errors.New("control: authority has expired")
)

// RefresherConfig configures the serialized KuaiFan coordinator. All state
// changes go through Manager; it is the sole publication path for a complete
// refreshed-session, authority, and line generation.
type RefresherConfig struct {
	IOSClient       *Client
	WindowsClient   *Client
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
	clients        [2]*Client
	manager        *state.Manager
	builder        state.SelectorBuilder
	commitSnapshot func(*state.RuntimeSnapshot) error
	lifetime       time.Duration
	attempts       int
	backoff        time.Duration
	maxBackoff     time.Duration
	clock          func() time.Time
}

// NewRefresher validates the two distinct profile clients required to publish
// an aggregate generation.
func NewRefresher(cfg RefresherConfig) (*Refresher, error) {
	if cfg.IOSClient == nil || cfg.WindowsClient == nil || cfg.Manager == nil || cfg.SelectorBuilder == nil ||
		cfg.IOSClient.Profile() != state.ClientProfileIOS || cfg.WindowsClient.Profile() != state.ClientProfileWindows {
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
		clients: [2]*Client{cfg.IOSClient, cfg.WindowsClient}, manager: cfg.Manager,
		builder: cfg.SelectorBuilder, commitSnapshot: commitSnapshot,
		lifetime: lifetime, attempts: attempts, backoff: backoff,
		maxBackoff: maxBackoff, clock: clock,
	}, nil
}

// Login authenticates both control profiles and publishes only after both
// authority/catalog branches form one validated aggregate generation.
func (r *Refresher) Login(ctx context.Context, input EmailLogin) (err error) {
	complete, err := r.manager.Begin(state.OperationLogin)
	if err != nil {
		return err
	}
	outcome := state.OutcomeFailed
	defer func() { complete(outcome) }()

	sessions, err := r.loginBoth(ctx, input)
	input.Password = ""
	if err != nil {
		return err
	}
	if err := r.manager.Transition(state.StateSyncing); err != nil {
		return err
	}
	profiles, err := r.fetchBothProfiles(ctx, sessions, false)
	if err != nil {
		return err
	}
	account, err := aggregateAccount(input.Account, profiles)
	if err != nil {
		return err
	}
	if err := r.commit(profiles, account); err != nil {
		return err
	}
	outcome = state.OutcomeSucceeded
	return nil
}

// Refresh rotates both login sessions and refreshes both catalogs under one
// lease. Any branch failure retains the prior complete generation.
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
	if current == nil || !current.Sessions.Valid() || current.Sessions.Windows == (state.SessionSecrets{}) {
		return ErrNoSession
	}
	sessions, err := r.refreshBoth(ctx, current.Sessions)
	if err != nil {
		return err
	}
	profiles, err := r.fetchBothProfiles(ctx, sessions, true)
	if err != nil {
		return err
	}
	account, err := aggregateAccountDisplay(current.Account.Display, profiles)
	if err != nil {
		return err
	}
	if err := r.commit(profiles, account); err != nil {
		return err
	}
	outcome = state.OutcomeSucceeded
	return nil
}

func (r *Refresher) loginBoth(ctx context.Context, input EmailLogin) ([2]LoginSession, error) {
	return parallelSessions(ctx, r.clients, func(child context.Context, client *Client) (LoginSession, error) {
		copyInput := input
		session, err := client.Login(child, copyInput)
		copyInput.Password = ""
		if err != nil {
			return LoginSession{}, err
		}
		if client.requiresPostLoginRefresh() {
			return client.RefreshSession(child, session)
		}
		return session, nil
	})
}

func (r *Refresher) refreshBoth(ctx context.Context, current state.ClientSessions) ([2]LoginSession, error) {
	return parallelSessions(ctx, r.clients, func(child context.Context, client *Client) (LoginSession, error) {
		stored, available := current.For(client.Profile())
		if !available {
			return LoginSession{}, ErrNoSession
		}
		userID, err := parsePositiveDecimal(stored.UserID)
		if err != nil {
			return LoginSession{}, ErrSchema
		}
		configuration, err := retry(child, r, func() (ClientConfig, error) {
			return client.FetchClientConfig(child)
		})
		if err != nil {
			return LoginSession{}, err
		}
		session := LoginSession{UserID: userID, Token: stored.LoginToken, APIBase: configuration.APIBase}
		return retry(child, r, func() (LoginSession, error) { return client.RefreshSession(child, session) })
	})
}

func parallelSessions(ctx context.Context, clients [2]*Client, call func(context.Context, *Client) (LoginSession, error)) ([2]LoginSession, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		index   int
		session LoginSession
		err     error
	}
	results := make(chan result, len(clients))
	for index, client := range clients {
		go func() {
			session, err := call(child, client)
			results <- result{index: index, session: session, err: err}
		}()
	}
	var sessions [2]LoginSession
	var firstErr error
	for range clients {
		result := <-results
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		sessions[result.index] = result.session
	}
	if firstErr != nil {
		return [2]LoginSession{}, firstErr
	}
	if sessions[0].UserID <= 0 || sessions[0].UserID != sessions[1].UserID {
		return [2]LoginSession{}, ErrSchema
	}
	return sessions, nil
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

type completeProfile struct {
	client    *Client
	session   LoginSession
	authority Authority
	lines     Lines
}

func (r *Refresher) fetchBothProfiles(ctx context.Context, sessions [2]LoginSession, retryRequests bool) ([2]completeProfile, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		index   int
		profile completeProfile
		err     error
	}
	results := make(chan result, len(r.clients))
	for index, client := range r.clients {
		go func() {
			authority, lines, err := r.fetchAuthorityAndLines(child, client, sessions[index], retryRequests)
			if err != nil {
				cancel()
			}
			results <- result{index: index, profile: completeProfile{client: client, session: sessions[index], authority: authority, lines: lines}, err: err}
		}()
	}
	var profiles [2]completeProfile
	for range r.clients {
		result := <-results
		if result.err != nil {
			return [2]completeProfile{}, result.err
		}
		profiles[result.index] = result.profile
	}
	return profiles, nil
}

func (r *Refresher) fetchAuthorityAndLines(ctx context.Context, client *Client, session LoginSession, retryRequests bool) (Authority, Lines, error) {
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
			authority, err = retry(childCtx, r, func() (Authority, error) { return client.FetchAuthority(childCtx, session) })
		} else {
			authority, err = client.FetchAuthority(childCtx, session)
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
			lines, err = retry(childCtx, r, func() (Lines, error) { return client.FetchLines(childCtx, session) })
		} else {
			lines, err = client.FetchLines(childCtx, session)
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

func aggregateAccount(account string, profiles [2]completeProfile) (state.AccountSummary, error) {
	return aggregateAccountDisplay(state.RedactAccount(account), profiles)
}

func aggregateAccountDisplay(display string, profiles [2]completeProfile) (state.AccountSummary, error) {
	if display == "" || profiles[0].session.UserID <= 0 || profiles[0].session.UserID != profiles[1].session.UserID {
		return state.AccountSummary{}, ErrSchema
	}
	isVIP := profiles[0].session.Profile.IsVIP && profiles[1].session.Profile.IsVIP
	vipEndsAt := time.Time{}
	if isVIP {
		vipEndsAt = profiles[0].session.Profile.VIPEndsAt
		if other := profiles[1].session.Profile.VIPEndsAt; vipEndsAt.IsZero() || !other.IsZero() && other.Before(vipEndsAt) {
			vipEndsAt = other
		}
		if vipEndsAt.IsZero() {
			return state.AccountSummary{}, ErrSchema
		}
	}
	return state.AccountSummary{Display: display, IsVIP: isVIP, VIPEndsAt: vipEndsAt}, nil
}

func (r *Refresher) commit(profiles [2]completeProfile, account state.AccountSummary) error {
	if profiles[0].session.UserID <= 0 || profiles[0].session.UserID != profiles[1].session.UserID {
		return ErrSchema
	}
	current := r.manager.Current()
	generation := uint64(1)
	var previous map[string]state.NodeRef
	if current != nil {
		generation = current.Generation + 1
		previous = current.Selectors
	}
	iosNodes, err := nodesFromLines(profiles[0].lines, state.ClientProfileIOS)
	if err != nil {
		return err
	}
	windowsNodes, err := nodesFromLines(profiles[1].lines, state.ClientProfileWindows)
	if err != nil {
		return err
	}
	nodes := mergeProfileNodes(iosNodes, windowsNodes)
	builtNodes, selectors, err := r.buildSelectors(generation, nodes, previous)
	if err != nil {
		return fmt.Errorf("control: build selectors: %w", err)
	}
	now := r.now().UTC()
	snapshot := &state.RuntimeSnapshot{
		Generation: generation, CreatedAt: now, ExpiresAt: now.Add(r.lifetime), Account: account,
		Sessions: state.ClientSessions{
			IOS:     sessionSecrets(profiles[0]),
			Windows: sessionSecrets(profiles[1]),
		},
		Nodes: builtNodes, Selectors: selectors,
	}
	return r.commitSnapshot(snapshot)
}

func sessionSecrets(profile completeProfile) state.SessionSecrets {
	return state.SessionSecrets{
		UserID: formatUserID(profile.session.UserID), LoginToken: profile.session.Token,
		ProviderToken: profile.authority.ProviderToken, TunnelPassword: profile.authority.EncryptKey,
		TunnelMethod: profile.authority.EncryptType, ProviderExtension: profile.authority.ProviderExtension,
	}
}

func mergeProfileNodes(ios, windows []state.Node) []state.Node {
	merged := make([]state.Node, 0, len(ios)+len(windows))
	seen := make(map[string]struct{}, len(ios)+len(windows))
	for _, profileNodes := range [][]state.Node{ios, windows} {
		for _, node := range profileNodes {
			if _, duplicate := seen[node.ID]; duplicate {
				continue
			}
			seen[node.ID] = struct{}{}
			merged = append(merged, node)
		}
	}
	return merged
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

func nodesFromLines(lines Lines, profile state.ClientProfile) ([]state.Node, error) {
	if !profile.Valid() {
		return nil, ErrSchema
	}
	groups := make(map[string]string, len(lines.Groups))
	for _, group := range lines.Groups {
		groups[group.ID] = group.Name
	}
	seen := make(map[string]struct{}, len(lines.Lines))
	nodes := make([]state.Node, 0, len(lines.Lines))
	for _, line := range lines.Lines {
		identity, err := selector.Canonicalize(selector.NodeIdentity{Provider: line.Provider, Host: line.Host, Port: int(line.Port)})
		if err != nil {
			return nil, fmt.Errorf("%w: canonical node identity", ErrSchema)
		}
		id := nodeID(identity, line.GroupID)
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		groupName := line.GroupName
		if groupName == "" {
			groupName = groups[line.GroupID]
		}
		nodes = append(nodes, state.Node{
			ID: id, Provider: identity.Provider, ClientProfile: profile, Host: identity.Host,
			Port: identity.Port, Name: line.Label, Group: groupName, Model: line.Model,
			Weight: line.Weight, Auto: line.Auto, Eligible: line.Eligible,
			Health: state.NodeHealthUnknown, UDPHealth: state.UDPHealthUnavailable,
		})
	}
	return nodes, nil
}

func nodeID(identity selector.CanonicalIdentity, groupID string) string {
	payload := []byte("kuaifan-line\x00" + groupID + "\x00" + identity.Provider + "\x00" + identity.Host + "\x00" + fmt.Sprintf("%d", identity.Port))
	sum := sha256.Sum256(payload)
	return "line_" + base64.RawURLEncoding.EncodeToString(sum[:12])
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
	jitter, err := wireprofile.RandomInt(r.clients[0].random, int(base/time.Millisecond)+1)
	if err != nil {
		return base
	}
	return time.Duration(jitter) * time.Millisecond
}

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/control"
	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/subscription"
	"github.com/kfadapter/kfadapter/internal/web"
)

const testAccessToken = "correct horse battery token"

type selectorRecorder struct {
	registry *selector.Registry
	err      error
}

func (s *selectorRecorder) SetSelectors(registry *selector.Registry) error {
	if s.err != nil {
		return s.err
	}
	s.registry = registry
	return nil
}

type inertRefresher struct{}

func (inertRefresher) Login(context.Context, control.EmailLogin) error { return errors.New("not used") }
func (inertRefresher) Refresh(context.Context) error                   { return errors.New("not used") }
func (inertRefresher) ExpireIfNeeded(time.Time) (bool, error)          { return false, nil }

type expiringRefresher struct{ manager *state.Manager }

func (expiringRefresher) Login(context.Context, control.EmailLogin) error {
	return errors.New("not used")
}
func (expiringRefresher) Refresh(context.Context) error { return errors.New("not used") }
func (r expiringRefresher) ExpireIfNeeded(now time.Time) (bool, error) {
	if err := r.manager.MarkExpired(now); err != nil {
		return false, err
	}
	return true, nil
}

type expiredErrorRefresher struct{}

func (expiredErrorRefresher) Login(context.Context, control.EmailLogin) error {
	return errors.New("not used")
}
func (expiredErrorRefresher) Refresh(context.Context) error { return errors.New("not used") }
func (expiredErrorRefresher) ExpireIfNeeded(time.Time) (bool, error) {
	return true, control.ErrAuthorityExpired
}

type refreshExpiringRefresher struct {
	manager *state.Manager
	now     func() time.Time
}

func (refreshExpiringRefresher) Login(context.Context, control.EmailLogin) error {
	return errors.New("not used")
}
func (r refreshExpiringRefresher) Refresh(context.Context) error {
	if err := r.manager.MarkExpired(r.now()); err != nil {
		return err
	}
	return control.ErrAuthorityExpired
}
func (refreshExpiringRefresher) ExpireIfNeeded(time.Time) (bool, error) { return false, nil }

type fakeSubscription struct {
	generation state.SubscriptionGeneration
	publishErr error
	rolledBack bool
}

func (s *fakeSubscription) PrepareRuntimeCommit(context.Context, string) (subscription.RuntimeCommitPlan, error) {
	return subscription.RuntimeCommitPlan{Generation: s.generation}, nil
}

func (s *fakeSubscription) CommitRuntimeSnapshot(context.Context, subscription.RuntimeCommitPlan, *state.RuntimeSnapshot) (func() error, error) {
	if s.publishErr != nil {
		return nil, s.publishErr
	}
	return func() error {
		s.rolledBack = true
		return nil
	}, nil
}

func (s *fakeSubscription) Metadata() (subscription.Metadata, error) {
	return subscription.Metadata{}, nil
}

type runtimeFixture struct {
	runtime     *Runtime
	manager     *state.Manager
	coordinator *SelectorCoordinator
	applier     *selectorRecorder
	persistent  state.PersistentState
}

func newRuntimeFixture(t *testing.T, store *state.SQLiteStore, subscriptions SubscriptionPublisher) runtimeFixture {
	t.Helper()
	persistent, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	var bindingKey []byte
	if persistent.AccessTokenInitialized() {
		bindingKey = persistent.AccessTokenVerifier.BindingKey()
	}
	manager, err := state.NewManagerWithSubscription(persistent.ActiveSession, persistent.Subscription, bindingKey)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := selector.NewRegistry(persistent.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	applier := &selectorRecorder{registry: registry}
	coordinator, err := NewSelectorCoordinator(applier, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if subscriptions == nil {
		subscriptions = &fakeSubscription{generation: persistent.Subscription}
	}
	runtime, err := NewRuntime(RuntimeConfig{
		Manager: manager, Store: store, Refresher: inertRefresher{}, Subscriptions: subscriptions,
		Selectors: coordinator, MutationMu: &sync.Mutex{}, SocksAddress: "127.0.0.1:10808", HTTPAddress: "127.0.0.1:10809",
		Version: "test", RefreshEvery: time.Hour, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtimeFixture{runtime: runtime, manager: manager, coordinator: coordinator, applier: applier, persistent: persistent}
}

func newTestStore(t *testing.T) *state.SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewSQLiteStore(filepath.Clean(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	return store
}

func newAtomicSubscription(t *testing.T, store *state.SQLiteStore) *subscription.Service {
	t.Helper()
	service, err := subscription.NewService(subscription.ServiceConfig{
		Store: store, SocksAddress: "127.0.0.1:10808", Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func accessErrorStatus(t *testing.T, err error) int {
	t.Helper()
	var public interface{ HTTPStatus() int }
	if !errors.As(err, &public) {
		t.Fatalf("access error has no public status: %v", err)
	}
	return public.HTTPStatus()
}

func TestRuntimeAccessSetupAndRestartAuthentication(t *testing.T) {
	store := newTestStore(t)
	fixture := newRuntimeFixture(t, store, nil)
	status, err := fixture.runtime.AccessStatus(context.Background())
	if err != nil || status.Initialized {
		t.Fatalf("initial access status = %#v, %v", status, err)
	}
	if err := fixture.runtime.AccessSetup(context.Background(), "  "+testAccessToken+"\t"); err != nil {
		t.Fatalf("AccessSetup: %v", err)
	}
	if err := fixture.runtime.AccessLogin(context.Background(), testAccessToken); err != nil {
		t.Fatalf("AccessLogin after setup: %v", err)
	}
	if err := fixture.runtime.AccessLogin(context.Background(), "wrong local token"); accessErrorStatus(t, err) != 401 {
		t.Fatalf("wrong token error = %v", err)
	}
	if err := fixture.runtime.AccessSetup(context.Background(), testAccessToken); accessErrorStatus(t, err) != 409 {
		t.Fatalf("second setup error = %v", err)
	}

	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.AccessTokenInitialized() || persisted.AccessTokenVerifier == nil || !persisted.VerifyAccessToken(testAccessToken) || persisted.VerifyAccessToken("wrong local token") {
		t.Fatal("SQLite state did not retain only a working access verifier")
	}

	fixture.runtime.Stop()
	restarted := newRuntimeFixture(t, store, nil)
	status, err = restarted.runtime.AccessStatus(context.Background())
	if err != nil || !status.Initialized {
		t.Fatalf("restart access status = %#v, %v", status, err)
	}
	if err := restarted.runtime.AccessLogin(context.Background(), testAccessToken); err != nil {
		t.Fatalf("restart AccessLogin: %v", err)
	}
}

func TestRuntimeAccessSetupIsSingleWinner(t *testing.T) {
	store := newTestStore(t)
	fixture := newRuntimeFixture(t, store, nil)
	results := make(chan error, 2)
	go func() { results <- fixture.runtime.AccessSetup(context.Background(), testAccessToken) }()
	go func() { results <- fixture.runtime.AccessSetup(context.Background(), testAccessToken+"x") }()
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("setup results = %v, %v", first, second)
	}
	failed := first
	if failed == nil {
		failed = second
	}
	if accessErrorStatus(t, failed) != 409 {
		t.Fatalf("losing setup error = %v", failed)
	}
	persistent, err := store.Load()
	if err != nil || !persistent.AccessTokenInitialized() {
		t.Fatalf("setup persistence = %#v, %v", persistent, err)
	}
}

func TestRuntimeAccessSetupRejectsInvalidToken(t *testing.T) {
	store := newTestStore(t)
	fixture := newRuntimeFixture(t, store, nil)
	if err := fixture.runtime.AccessSetup(context.Background(), "short"); accessErrorStatus(t, err) != 401 {
		t.Fatalf("invalid setup error = %v", err)
	}
	status, err := fixture.runtime.AccessStatus(context.Background())
	if err != nil || status.Initialized {
		t.Fatalf("invalid setup status = %#v, %v", status, err)
	}
}

func TestAccountChangeFailureRestoresSelectorAuthority(t *testing.T) {
	store := newTestStore(t)
	persistent, err := store.Update(func(candidate *state.PersistentState) error {
		if err := candidate.SetAccessToken(testAccessToken); err != nil {
			return err
		}
		_, err := state.EnsureSubscriptionAccountBinding(candidate, "account-a", time.Now().UTC())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	next := persistent.Clone()
	changed, err := state.EnsureSubscriptionAccountBinding(&next, "account-b", time.Now().UTC())
	if err != nil || !changed {
		t.Fatalf("account update = changed:%t err:%v", changed, err)
	}
	service := &fakeSubscription{generation: next.Subscription, publishErr: errors.New("cache write failed")}
	fixture := newRuntimeFixture(t, store, service)
	before := fixture.coordinator.Registry()

	complete, err := fixture.manager.Begin(state.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	defer complete(state.OutcomeFailed)
	if err := fixture.manager.Transition(state.StateSyncing); err != nil {
		t.Fatal(err)
	}
	built, err := before.BuildWithTombstones(persistent.Subscription.Generation, []state.Node{{
		ID: "node", Provider: "WIFIIN", Host: "node.example.test", Port: 1080, Eligible: true,
	}}, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &state.RuntimeSnapshot{
		Generation: 1, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(),
		Account: state.NewAccountSummary("account-b", false, time.Time{}),
		Session: state.SessionSecrets{UserID: "account-b", LoginToken: "login", ProviderToken: "provider", TunnelPassword: "tunnel", TunnelMethod: "aes-256-cfb", ProviderExtension: "|provider|cc.fancast.major|order|account-b|MAC|1.0.46"},
		Nodes:   built.Nodes, Selectors: built.Selectors,
	}
	if err := fixture.runtime.CommitControlSnapshotLocked(snapshot); err == nil {
		t.Fatal("account publish unexpectedly succeeded")
	}
	if fixture.coordinator.Registry() != before || fixture.applier.registry != before {
		t.Fatal("failed account publish did not restore the previous selector authority")
	}
}

func TestRuntimeCommitFailureRestoresPersistentAggregate(t *testing.T) {
	store := newTestStore(t)
	persistent, err := store.Update(func(candidate *state.PersistentState) error {
		if err := candidate.SetAccessToken(testAccessToken); err != nil {
			return err
		}
		_, err := state.EnsureSubscriptionAccountBinding(candidate, "account-a", time.Now().UTC())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &fakeSubscription{generation: persistent.Subscription}
	fixture := newRuntimeFixture(t, store, service)
	beforeRegistry := fixture.coordinator.Registry()
	before, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	complete, err := fixture.manager.Begin(state.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	defer complete(state.OutcomeFailed)
	if err := fixture.manager.Transition(state.StateSyncing); err != nil {
		t.Fatal(err)
	}
	built, err := beforeRegistry.BuildWithTombstones(persistent.Subscription.Generation, []state.Node{{
		ID: "ineligible", Provider: "WIFIIN", Host: "node.example.test", Port: 1080,
	}}, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &state.RuntimeSnapshot{
		Generation: 1, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(),
		Account: state.NewAccountSummary("account-a", false, time.Time{}),
		Session: state.SessionSecrets{UserID: "account-a", LoginToken: "login", ProviderToken: "provider", TunnelPassword: "tunnel", TunnelMethod: "aes-256-cfb", ProviderExtension: "|provider|cc.fancast.major|order|account-a|MAC|1.0.46"},
		Nodes:   built.Nodes, Selectors: built.Selectors,
	}
	if err := fixture.runtime.CommitControlSnapshotLocked(snapshot); err == nil {
		t.Fatal("ineligible snapshot unexpectedly committed")
	}
	after, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.ActiveSession != nil || after.Subscription.Generation != before.Subscription.Generation || after.Subscription.AccountBindingString() != before.Subscription.AccountBindingString() {
		t.Fatalf("failed commit changed durable aggregate: %#v", after)
	}
	if !service.rolledBack || fixture.coordinator.Registry() != beforeRegistry || fixture.applier.registry != beforeRegistry {
		t.Fatal("failed commit did not restore selector authority")
	}
}

func TestSameAccountBindingKeepsSubscriptionMaterial(t *testing.T) {
	persistent, err := state.NewPersistentState()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistent.SetAccessToken(testAccessToken); err != nil {
		t.Fatal(err)
	}
	changed, err := state.EnsureSubscriptionAccountBinding(&persistent, "account-a", time.Now().UTC())
	if err != nil || changed {
		t.Fatalf("first account bind = changed:%t err:%v", changed, err)
	}
	before := persistent.Clone()
	changed, err = state.EnsureSubscriptionAccountBinding(&persistent, "account-a", time.Now().Add(time.Minute).UTC())
	if err != nil || changed || persistent.Subscription.AccountBindingString() != before.Subscription.AccountBindingString() {
		t.Fatalf("same account changed durable subscription material: changed:%t err:%v", changed, err)
	}
}

func TestSameAccountRuntimeCommitKeepsSelectorCredentials(t *testing.T) {
	store := newTestStore(t)
	persistent, err := store.Update(func(candidate *state.PersistentState) error {
		if err := candidate.SetAccessToken(testAccessToken); err != nil {
			return err
		}
		_, err := state.EnsureSubscriptionAccountBinding(candidate, "account-a", time.Now().UTC())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	service := newAtomicSubscription(t, store)
	fixture := newRuntimeFixture(t, store, service)
	before := fixture.coordinator.Registry()
	identity := selector.NodeIdentity{Provider: "WIFIIN", Host: "node.example.test", Port: 1080}
	oldCredentials, ok := before.Credentials(persistent.Subscription.Generation, identity)
	if !ok {
		t.Fatal("initial selector credentials unavailable")
	}
	complete, err := fixture.manager.Begin(state.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	defer complete(state.OutcomeSucceeded)
	if err := fixture.manager.Transition(state.StateSyncing); err != nil {
		t.Fatal(err)
	}
	built, err := before.BuildWithTombstones(persistent.Subscription.Generation, []state.Node{{
		ID: "node", Provider: identity.Provider, Host: identity.Host, Port: uint16(identity.Port), Eligible: true,
	}}, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &state.RuntimeSnapshot{
		Generation: 1, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(),
		Account: state.NewAccountSummary("account-a", false, time.Time{}),
		Session: state.SessionSecrets{UserID: "account-a", LoginToken: "login", ProviderToken: "provider", TunnelPassword: "tunnel", TunnelMethod: "aes-256-cfb", ProviderExtension: "|provider|cc.fancast.major|order|account-a|MAC|1.0.46"},
		Nodes:   built.Nodes, Selectors: built.Selectors,
	}
	if err := fixture.runtime.CommitControlSnapshotLocked(snapshot); err != nil {
		t.Fatalf("same-account commit: %v", err)
	}
	after := fixture.coordinator.Registry()
	newCredentials, ok := after.Credentials(persistent.Subscription.Generation, identity)
	if !ok || oldCredentials != newCredentials {
		t.Fatalf("same account changed selector credentials: before=%#v after=%#v", oldCredentials, newCredentials)
	}
	if current := fixture.manager.Current(); current == nil || current.Session.UserID != "account-a" {
		t.Fatalf("same-account commit did not publish session: %#v", current)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ActiveSession == nil || persisted.ActiveSession.Generation != snapshot.Generation || persisted.ActiveSession.Account != snapshot.Account || persisted.ActiveSession.Session != snapshot.Session {
		t.Fatalf("same-account commit did not persist complete session: %#v", persisted.ActiveSession)
	}
	if persisted.LastGood.Generation != persisted.Subscription.Generation || len(persisted.LastGood.Nodes) != len(persisted.ActiveSession.Nodes) || !persisted.MatchesAccount(persisted.ActiveSession.Session.UserID) {
		t.Fatalf("committed SQLite aggregate is inconsistent: %#v", persisted)
	}
	for _, reference := range persisted.ActiveSession.Selectors {
		if reference.Generation != persisted.Subscription.Generation {
			t.Fatalf("active selector generation %d does not match subscription %d", reference.Generation, persisted.Subscription.Generation)
		}
	}
}

func TestRuntimeNodeDetailsUsesCurrentSelectorAuthority(t *testing.T) {
	store := newTestStore(t)
	persistent, err := store.Update(func(candidate *state.PersistentState) error {
		if err := candidate.SetAccessToken(testAccessToken); err != nil {
			return err
		}
		if _, err := state.EnsureSubscriptionAccountBinding(candidate, "account-a", time.Now().UTC()); err != nil {
			return err
		}
		candidate.Preferences.ExcludedNodeIDs["node"] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := newRuntimeFixture(t, store, newAtomicSubscription(t, store))
	identity := selector.NodeIdentity{Provider: "WIFIIN", Host: "node.example.test", Port: 1080}
	complete, err := fixture.manager.Begin(state.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	defer complete(state.OutcomeSucceeded)
	if err := fixture.manager.Transition(state.StateSyncing); err != nil {
		t.Fatal(err)
	}
	built, err := fixture.coordinator.Registry().BuildWithTombstones(persistent.Subscription.Generation, []state.Node{{
		ID: "node", Provider: identity.Provider, Host: identity.Host, Port: uint16(identity.Port), Name: "Node", Group: "Group", Eligible: true, Health: state.NodeHealthUnknown,
	}}, nil, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &state.RuntimeSnapshot{
		Generation: 1, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(),
		Account: state.NewAccountSummary("account-a", false, time.Time{}),
		Session: state.SessionSecrets{UserID: "account-a", LoginToken: "session-login-token", ProviderToken: "session-provider-token", TunnelPassword: "session-tunnel-password", TunnelMethod: "aes-256-cfb", ProviderExtension: "|session-provider-token|cc.fancast.major|order|account-a|MAC|1.0.46"},
		Nodes:   built.Nodes, Selectors: built.Selectors,
	}
	if err := fixture.runtime.CommitControlSnapshotLocked(snapshot); err != nil {
		t.Fatalf("CommitControlSnapshotLocked: %v", err)
	}
	current := fixture.manager.Current()
	if current == nil || current.Nodes[0].Excluded {
		t.Fatalf("persisted exclusion affected current node: %#v", current)
	}
	details, err := fixture.runtime.NodeDetails(context.Background(), "node")
	if err != nil {
		t.Fatalf("NodeDetails: %v", err)
	}
	credentials, ok := fixture.coordinator.Registry().Credentials(persistent.Subscription.Generation, identity)
	if !ok {
		t.Fatal("current selector credentials unavailable")
	}
	if details.ID != "node" || details.Name != "Node" || details.Group != "Group" || details.Provider != "WIFIIN" ||
		details.UpstreamHost != identity.Host || details.UpstreamPort != identity.Port || details.SocksAddress != "127.0.0.1:10808" ||
		details.SocksUsername != credentials.Selector || details.SocksPassword != credentials.Password || details.Health != string(state.NodeHealthUnknown) ||
		details.TCPLatencyMS != 0 || details.Generation != persistent.Subscription.Generation {
		t.Fatalf("node details = %#v", details)
	}
	body, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"session-login-token", "session-provider-token", "session-tunnel-password", "session-provider-extension"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatalf("node details exposed provider session secret %q", secret)
		}
	}
	if err := fixture.runtime.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := fixture.runtime.NodeDetails(context.Background(), "node"); err == nil {
		t.Fatal("NodeDetails accepted a signed-out session")
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ActiveSession != nil {
		t.Fatalf("logout retained durable session: %#v", persisted.ActiveSession)
	}
}

func seedDurableRuntimeSession(t *testing.T, store *state.SQLiteStore, createdAt, expiresAt time.Time) *state.RuntimeSnapshot {
	t.Helper()
	persistent, err := store.Update(func(candidate *state.PersistentState) error {
		if err := candidate.SetAccessToken(testAccessToken); err != nil {
			return err
		}
		_, err := state.EnsureSubscriptionAccountBinding(candidate, "expiry-account", createdAt)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := selector.NewRegistry(persistent.Subscription)
	if err != nil {
		t.Fatal(err)
	}
	built, err := registry.BuildWithTombstones(persistent.Subscription.Generation, []state.Node{{
		ID: "expiry-node", Provider: "WIFIIN", Host: "node.example.test", Port: 1080, Eligible: true,
	}}, nil, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &state.RuntimeSnapshot{
		Generation: 1, CreatedAt: createdAt, ExpiresAt: expiresAt,
		Account: state.NewAccountSummary("expiry-account", false, time.Time{}),
		Session: state.SessionSecrets{
			UserID: "expiry-account", LoginToken: "expiry-login", ProviderToken: "expiry-provider",
			TunnelPassword: "expiry-tunnel", TunnelMethod: "aes-256-cfb", ProviderExtension: "|expiry-provider|cc.fancast.major|order|expiry-account|MAC|1.0.46",
		},
		Nodes: built.Nodes, Selectors: built.Selectors,
	}
	if _, err := store.Update(func(candidate *state.PersistentState) error {
		candidate.ActiveSession = snapshot.Clone()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestNewRuntimeClearsExpiredDurableSession(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	seedDurableRuntimeSession(t, store, now.Add(-2*time.Hour), now.Add(-time.Hour))
	fixture := newRuntimeFixture(t, store, nil)
	if fixture.manager.State() != state.StateExpired {
		t.Fatalf("restored expired manager state = %s", fixture.manager.State())
	}
	persistent, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if persistent.ActiveSession != nil {
		t.Fatalf("startup retained expired durable authority: %#v", persistent.ActiveSession)
	}
}

func TestHeartbeatClearsNewlyExpiredDurableSession(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	snapshot := seedDurableRuntimeSession(t, store, now, now.Add(time.Hour))
	fixture := newRuntimeFixture(t, store, nil)
	fixture.runtime.now = func() time.Time { return snapshot.ExpiresAt.Add(time.Minute) }
	fixture.runtime.refresher = expiringRefresher{manager: fixture.manager}
	if err := fixture.runtime.Heartbeat(context.Background(), false); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	current := fixture.manager.Current()
	if fixture.manager.State() != state.StateExpired || current == nil || current.Session.Valid() {
		t.Fatalf("heartbeat manager state = %s, current = %#v", fixture.manager.State(), current)
	}
	persistent, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if persistent.ActiveSession != nil {
		t.Fatalf("heartbeat retained expired durable authority: %#v", persistent.ActiveSession)
	}
}

func TestHeartbeatClearsDurableSessionWhenExpiryReportsError(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	seedDurableRuntimeSession(t, store, now, now.Add(time.Hour))
	fixture := newRuntimeFixture(t, store, nil)
	fixture.runtime.refresher = expiredErrorRefresher{}
	err := fixture.runtime.Heartbeat(context.Background(), false)
	if !errors.Is(err, control.ErrAuthorityExpired) {
		t.Fatalf("Heartbeat error = %v", err)
	}
	persistent, loadErr := store.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if persistent.ActiveSession != nil {
		t.Fatalf("errored expiry retained durable authority: %#v", persistent.ActiveSession)
	}
}

func TestRefreshClearsDurableSessionWhenAuthorityExpires(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	seedDurableRuntimeSession(t, store, now, now.Add(time.Hour))
	fixture := newRuntimeFixture(t, store, nil)
	fixture.runtime.refresher = refreshExpiringRefresher{manager: fixture.manager, now: func() time.Time { return now.Add(time.Hour) }}
	err := fixture.runtime.Refresh(context.Background())
	if !errors.Is(err, control.ErrAuthorityExpired) {
		t.Fatalf("Refresh error = %v", err)
	}
	persistent, loadErr := store.Load()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if persistent.ActiveSession != nil {
		t.Fatalf("refresh expiry retained durable authority: %#v", persistent.ActiveSession)
	}
}

func TestRestoredMaximumRefreshPolicyRunsBeforeAuthorityExpiry(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	snapshot := seedDurableRuntimeSession(t, store, now, now.Add(maxRefreshPolicy))
	if _, err := store.Update(func(candidate *state.PersistentState) error {
		candidate.Preferences.RefreshPolicy = maxRefreshPolicy.String()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fixture := newRuntimeFixture(t, store, nil)
	deadline := snapshot.ExpiresAt.Add(-refreshExpirySafetyMargin)
	if fixture.runtime.RefreshEvery() != maxRefreshPolicy || !fixture.runtime.RefreshDue(deadline) || !state.SessionUsable(fixture.manager.Current(), deadline) {
		t.Fatalf("maximum refresh policy did not run before expiry: cadence=%s due=%t usable=%t", fixture.runtime.RefreshEvery(), fixture.runtime.RefreshDue(deadline), state.SessionUsable(fixture.manager.Current(), deadline))
	}
	status, err := fixture.runtime.Status(context.Background())
	if err != nil || !status.ControlPlane.LastRefreshAt.Equal(snapshot.CreatedAt) || !status.ControlPlane.NextRefreshAt.Equal(deadline) {
		t.Fatalf("restored maximum refresh schedule status=%#v err=%v", status.ControlPlane, err)
	}
}

func TestScheduledRefreshFailureRetriesWhileAuthorityRemainsUsable(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC()
	snapshot := seedDurableRuntimeSession(t, store, now, now.Add(maxRefreshPolicy))
	if _, err := store.Update(func(candidate *state.PersistentState) error {
		candidate.Preferences.RefreshPolicy = maxRefreshPolicy.String()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fixture := newRuntimeFixture(t, store, nil)
	firstAttempt := snapshot.ExpiresAt.Add(-refreshExpirySafetyMargin)
	fixture.runtime.now = func() time.Time { return firstAttempt }
	if !fixture.runtime.RefreshDue(firstAttempt) {
		t.Fatal("restored refresh was not due at the protected initial deadline")
	}
	if err := fixture.runtime.Heartbeat(context.Background(), true); err == nil {
		t.Fatal("transient refresh failure was unexpectedly successful")
	}
	retryAt := firstAttempt.Add(minRefreshPolicy)
	if !fixture.runtime.RefreshDue(retryAt) || !state.SessionUsable(fixture.manager.Current(), retryAt) {
		t.Fatalf("second refresh was not scheduled while authority remained usable: due=%t usable=%t", fixture.runtime.RefreshDue(retryAt), state.SessionUsable(fixture.manager.Current(), retryAt))
	}
}

var _ web.Backend = (*Runtime)(nil)

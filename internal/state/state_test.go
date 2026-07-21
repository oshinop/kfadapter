package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func runtimeSnapshot(generation uint64, user string, expiresAt time.Time) *RuntimeSnapshot {
	return &RuntimeSnapshot{
		Generation: generation,
		CreatedAt:  expiresAt.Add(-time.Hour),
		ExpiresAt:  expiresAt,
		Account:    AccountSummary{Display: "u•••@example.com", IsVIP: true},
		Sessions: ClientSessions{IOS: SessionSecrets{
			UserID: user, LoginToken: "login", ProviderToken: "provider",
			TunnelPassword: "tunnel", TunnelMethod: "aes-256-cfb", ProviderExtension: "|provider|cc.fancast.major|order|" + user + "|MAC|1.0.46",
		}},
		Nodes: []Node{{
			ID: "line-1", Selector: "n_example", Provider: "WIFIIN", Host: "node.example.com", Port: 11000,
			Eligible: true, Health: NodeHealthHealthy, UDPHealth: UDPHealthUnavailable,
		}},
		Selectors: map[string]NodeRef{"n_example": {NodeID: "line-1", Generation: 1}},
	}
}

const testAccessToken = "0123456789abcdef"

func initializedPersistentState(t *testing.T) PersistentState {
	t.Helper()
	persistent, err := NewPersistentState()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistent.SetAccessToken(testAccessToken); err != nil {
		t.Fatal(err)
	}
	return persistent
}

func boundSubscription(t *testing.T, userID string) SubscriptionGeneration {
	t.Helper()
	persistent := initializedPersistentState(t)
	if _, err := EnsureSubscriptionAccountBinding(&persistent, userID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return persistent.Subscription
}

func bindManager(t *testing.T, manager *Manager, userID string) SubscriptionGeneration {
	t.Helper()
	persistent := initializedPersistentState(t)
	if _, err := EnsureSubscriptionAccountBinding(&persistent, userID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := manager.ConfigureBindingKey(persistent.AccessTokenVerifier.BindingKey()); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	manager.subscription = persistent.Subscription.clone()
	manager.mu.Unlock()
	return persistent.Subscription
}

func TestAccountRedactionNeverPublishesLocalPart(t *testing.T) {
	summary := NewAccountSummary("user@example.com", true, time.Time{})
	if got, want := summary.Display, "u•••@example.com"; got != want {
		t.Fatalf("redacted display = %q, want %q", got, want)
	}
	if strings.Contains(summary.Display, "user") || RedactAccount("not-an-email") != "•••" {
		t.Fatalf("unsafe redaction: %q", summary.Display)
	}
}

func TestRuntimeStoreCopiesPublishedAndRetrievedSnapshots(t *testing.T) {
	now := time.Date(2026, 7, 15, 11, 0, 0, 0, time.UTC)
	original := runtimeSnapshot(1, "user-1", now.Add(time.Hour))
	store, err := NewRuntimeStore(original)
	if err != nil {
		t.Fatalf("NewRuntimeStore: %v", err)
	}
	original.Nodes[0].Host = "mutated.example"
	original.Selectors["n_example"] = NodeRef{Tombstoned: true, TombstoneUntil: now.Add(time.Hour)}
	original.Sessions.IOS.TunnelPassword = "mutated"

	first := store.Current()
	if first.Nodes[0].Host != "node.example.com" || first.Sessions.IOS.TunnelPassword != "tunnel" || first.Selectors["n_example"].Tombstoned {
		t.Fatalf("published view was mutated through input: %#v", first)
	}
	first.Nodes[0].Host = "caller-mutated.example"
	first.Selectors["n_example"] = NodeRef{Tombstoned: true, TombstoneUntil: now.Add(time.Hour)}
	first.Sessions.Wipe()
	second := store.Current()
	if second.Nodes[0].Host != "node.example.com" || !second.Sessions.Valid() || second.Selectors["n_example"].Tombstoned {
		t.Fatalf("stored view was mutated through Current result: %#v", second)
	}
}

func TestManagerSessionCurrentAdmitsOnlyCurrentAuthority(t *testing.T) {
	now := time.Date(2026, 7, 15, 11, 0, 0, 0, time.UTC)
	manager, err := NewManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	bindManager(t, manager, "user-1")
	loginFinish, err := manager.Begin(OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	first := runtimeSnapshot(1, "user-1", now.Add(time.Hour))
	if err := manager.Commit(first); err != nil {
		t.Fatal(err)
	}
	loginFinish(OutcomeSucceeded)
	pinned := manager.Current()
	if !manager.SessionCurrent(pinned, now) {
		t.Fatal("current usable snapshot was not admitted")
	}
	refreshFinish, err := manager.Begin(OperationRefresh)
	if err != nil {
		t.Fatal(err)
	}
	probe := runtimeSnapshot(2, "user-1", now.Add(time.Hour))
	probe.CreatedAt = now
	probe.Nodes[0].Health = NodeHealthUnhealthy
	if err := manager.Commit(probe); err != nil {
		t.Fatal(err)
	}
	refreshFinish(OutcomeSucceeded)
	if !manager.SessionCurrent(pinned, now) {
		t.Fatal("authority-equivalent health probe rejected pinned snapshot")
	}
	wrongExpiry := pinned.Clone()
	wrongExpiry.ExpiresAt = wrongExpiry.ExpiresAt.Add(time.Minute)
	if manager.SessionCurrent(wrongExpiry, now) {
		t.Fatal("different expiry was admitted")
	}
	probePinned := manager.Current()
	refreshFinish, err = manager.Begin(OperationRefresh)
	if err != nil {
		t.Fatal(err)
	}
	renewed := runtimeSnapshot(3, "user-1", now.Add(time.Hour))
	renewed.CreatedAt = now.Add(time.Minute)
	renewed.Sessions.IOS.TunnelPassword = "renewed-tunnel"
	if err := manager.Commit(renewed); err != nil {
		t.Fatal(err)
	}
	refreshFinish(OutcomeSucceeded)
	if manager.SessionCurrent(pinned, now) || manager.SessionCurrent(probePinned, now) {
		t.Fatal("renewed authority admitted stale snapshot")
	}
	current := manager.Current()
	if !manager.SessionCurrent(current, renewed.CreatedAt) {
		t.Fatal("renewed current authority was not admitted")
	}
	if err := manager.MarkExpired(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if manager.SessionCurrent(current, now.Add(2*time.Minute)) {
		t.Fatal("expired authority was admitted")
	}
	manager.SignOut()
	if manager.SessionCurrent(current, now.Add(2*time.Minute)) {
		t.Fatal("signed-out authority was admitted")
	}

	stateManager, err := NewManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	bindManager(t, stateManager, "user-1")
	stateLoginFinish, err := stateManager.Begin(OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateManager.Commit(runtimeSnapshot(1, "user-1", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	stateLoginFinish(OutcomeSucceeded)
	statePinned := stateManager.Current()
	if err := stateManager.Transition(StateDegraded); err != nil {
		t.Fatal(err)
	}
	if !stateManager.SessionCurrent(statePinned, now) {
		t.Fatal("degraded usable authority was rejected")
	}
	if err := stateManager.Transition(StateSyncing); err != nil {
		t.Fatal(err)
	}
	if !stateManager.SessionCurrent(statePinned, now) {
		t.Fatal("syncing usable authority was rejected")
	}
	if err := stateManager.Transition(StateError); err != nil {
		t.Fatal(err)
	}
	if stateManager.SessionCurrent(statePinned, now) {
		t.Fatal("error-state authority was admitted")
	}
}

func TestManagerRejectsInvalidTransitionsAndAccountRemap(t *testing.T) {
	manager, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	generation := bindManager(t, manager, "user-1")
	if err := manager.Transition(StateReady); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Transition signed_out -> ready = %v, want ErrInvalidTransition", err)
	}
	if _, err := manager.Begin(OperationRefresh); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Begin refresh while signed out = %v, want ErrInvalidTransition", err)
	}
	finish, err := manager.Begin(OperationLogin)
	if err != nil {
		t.Fatalf("Begin login: %v", err)
	}
	if _, err := manager.Begin(OperationLogin); !errors.Is(err, ErrOperationInProgress) {
		t.Fatalf("concurrent Begin = %v, want ErrOperationInProgress", err)
	}
	first := runtimeSnapshot(1, "user-1", time.Now().Add(time.Hour))
	if err := manager.Commit(first); err != nil {
		t.Fatalf("Commit first snapshot: %v", err)
	}
	finish(OutcomeSucceeded)
	if got := manager.State(); got != StateReady {
		t.Fatalf("state after commit = %s, want ready", got)
	}
	manager.SignOut()
	if SessionUsable(manager.Current(), time.Now()) {
		t.Fatal("signed out current snapshot can establish new tunnel")
	}
	if status := manager.Status(); status.Account.Display != "" {
		t.Fatalf("signout retained browser-visible account summary: %#v", status.Account)
	}
	second := runtimeSnapshot(2, "user-2", time.Now().Add(time.Hour))
	if err := manager.Commit(second); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("direct Commit while signed out = %v, want ErrInvalidTransition", err)
	}
	retry, err := manager.Begin(OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Commit(second); !errors.Is(err, ErrAccountChanged) {
		t.Fatalf("plain different-account Commit = %v, want ErrAccountChanged", err)
	}
	candidate, err := newSubscriptionGeneration(generation.Generation+1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	candidate.AccountBinding, err = accountBindingFor(manager.accountBindingKey, "user-2")
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := manager.InstallSubscriptionGeneration(candidate, "user-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Commit(second); err != nil {
		rollback()
		t.Fatalf("Commit changed account: %v", err)
	}
	retry(OutcomeSucceeded)
}

func TestDegradedMetadataCommitsDoNotClaimRecovery(t *testing.T) {
	now := time.Now().UTC()
	manager, err := NewManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	bindManager(t, manager, "user-1")
	loginFinish, err := manager.Begin(OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Commit(runtimeSnapshot(1, "user-1", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	loginFinish(OutcomeSucceeded)
	if err := manager.Transition(StateDegraded); err != nil {
		t.Fatal(err)
	}
	for index, kind := range []string{"probe", "preference", "rotation"} {
		snapshot := runtimeSnapshot(uint64(index+2), "user-1", now.Add(time.Hour))
		snapshot.Nodes[0].Name = kind
		if err := manager.Commit(snapshot); err != nil {
			t.Fatalf("%s metadata Commit: %v", kind, err)
		}
		if manager.State() != StateDegraded {
			t.Fatalf("%s metadata Commit changed state to %s, want degraded", kind, manager.State())
		}
	}
	refreshFinish, err := manager.Begin(OperationRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Commit(runtimeSnapshot(5, "user-1", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	refreshFinish(OutcomeSucceeded)
	if manager.State() != StateReady {
		t.Fatalf("successful refresh state = %s, want ready", manager.State())
	}
}

func TestNonReadyManagerPathsScrubUsableSessions(t *testing.T) {
	now := time.Now().UTC()
	newReadyManager := func(t *testing.T, expiresAt time.Time) (*Manager, *RuntimeSnapshot) {
		t.Helper()
		manager, err := NewManager(nil)
		if err != nil {
			t.Fatal(err)
		}
		bindManager(t, manager, "user-1")
		finish, err := manager.Begin(OperationLogin)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := runtimeSnapshot(1, "user-1", expiresAt)
		snapshot.CreatedAt = now.Add(-time.Hour)
		if err := manager.Commit(snapshot); err != nil {
			t.Fatal(err)
		}
		finish(OutcomeSucceeded)
		return manager, manager.Current()
	}

	t.Run("failed_login_from_error", func(t *testing.T) {
		manager, pinned := newReadyManager(t, now.Add(time.Hour))
		manager.mu.Lock()
		manager.state = StateError
		manager.mu.Unlock()
		finish, err := manager.Begin(OperationLogin)
		if err != nil {
			t.Fatal(err)
		}
		finish(OutcomeFailed)
		current := manager.Current()
		if manager.State() != StateSignedOut || current.Sessions != (ClientSessions{}) || SessionUsable(current, now) || len(current.Nodes) != 1 {
			t.Fatalf("failed login retained usable state: %s %#v", manager.State(), current)
		}
		if !pinned.Sessions.IOS.Valid() || pinned.Sessions.IOS.TunnelPassword != "tunnel" {
			t.Fatalf("failed login mutated pinned snapshot: %#v", pinned.Sessions.IOS)
		}
	})

	t.Run("expiry_from_error", func(t *testing.T) {
		manager, pinned := newReadyManager(t, now.Add(-time.Minute))
		manager.mu.Lock()
		manager.state = StateError
		manager.mu.Unlock()
		if err := manager.MarkExpired(now); err != nil {
			t.Fatal(err)
		}
		if err := manager.MarkExpired(now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		current := manager.Current()
		if manager.State() != StateExpired || current.Sessions != (ClientSessions{}) || SessionUsable(current, now) || len(current.Nodes) != 1 {
			t.Fatalf("error expiry retained usable state: %s %#v", manager.State(), current)
		}
		if !pinned.Sessions.IOS.Valid() || pinned.Sessions.IOS.TunnelPassword != "tunnel" {
			t.Fatalf("error expiry mutated pinned snapshot: %#v", pinned.Sessions.IOS)
		}
	})
}

func TestNewManagerScrubsUnusableInitialSessions(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name      string
		withNodes bool
		expiresAt time.Time
		partial   bool
		wantState ServiceState
	}{
		{"expired_complete_with_nodes", true, now.Add(-time.Minute), false, StateExpired},
		{"partial_with_nodes", true, now.Add(time.Hour), true, StateExpired},
		{"partial_without_nodes", false, now.Add(time.Hour), true, StateSignedOut},
	} {
		t.Run(test.name, func(t *testing.T) {
			initial := runtimeSnapshot(1, "user-1", test.expiresAt)
			initial.CreatedAt = now.Add(-time.Hour)
			if !test.withNodes {
				initial.Nodes = nil
				initial.Selectors = map[string]NodeRef{}
			}
			if test.partial {
				initial.Sessions.IOS.LoginToken = ""
			}
			caller := initial.Clone()
			manager, err := NewManager(initial)
			if err != nil {
				t.Fatal(err)
			}
			current := manager.Current()
			if manager.State() != test.wantState || current.Sessions != (ClientSessions{}) || SessionUsable(current, now) {
				t.Fatalf("unusable initial session was published: %s %#v", manager.State(), current)
			}
			if initial.Sessions != caller.Sessions {
				t.Fatalf("NewManager mutated caller session: %#v", initial.Sessions)
			}
			if test.withNodes && len(current.Nodes) != 1 {
				t.Fatalf("NewManager lost retained node metadata: %#v", current.Nodes)
			}
		})
	}
}

func TestNewManagerWithSubscriptionRejectsOfflineAndFutureAuthority(t *testing.T) {
	now := time.Now().UTC()
	persistent := initializedPersistentState(t)
	if _, err := EnsureSubscriptionAccountBinding(&persistent, "user-1", now); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name         string
		createdAt    time.Time
		expiresAt    time.Time
		wantState    ServiceState
		wantSnapshot bool
	}{
		{"offline_over_24_hours", now.Add(-26 * time.Hour), now.Add(-25 * time.Hour), StateExpired, true},
		{"future_issued", now.Add(time.Hour), now.Add(2 * time.Hour), StateSignedOut, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			initial := runtimeSnapshot(persistent.Subscription.Generation, "user-1", test.expiresAt)
			initial.CreatedAt = test.createdAt
			manager, err := NewManagerWithSubscription(initial, persistent.Subscription, persistent.AccessTokenVerifier.BindingKey())
			if err != nil {
				t.Fatalf("NewManagerWithSubscription: %v", err)
			}
			if manager.State() != test.wantState {
				t.Fatalf("state = %s, want %s", manager.State(), test.wantState)
			}
			current := manager.Current()
			if !test.wantSnapshot {
				if current != nil {
					t.Fatalf("future-issued snapshot retained: %#v", current)
				}
				return
			}
			if current == nil || current.Sessions != (ClientSessions{}) || !current.CreatedAt.Equal(test.createdAt) || !current.ExpiresAt.Equal(test.expiresAt) || SessionUsable(current, now) {
				t.Fatalf("expired startup did not retain only original non-secret metadata: %#v", current)
			}
		})
	}
}

func TestMarkExpiredWipesCurrentSessionAndRetainsPinnedDrainSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 15, 11, 0, 0, 0, time.UTC)
	manager, err := NewManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	bindManager(t, manager, "user-1")
	finish, err := manager.Begin(OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Commit(runtimeSnapshot(1, "user-1", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	finish(OutcomeSucceeded)
	pinned := manager.Current()
	if !SessionUsable(pinned, now.Add(time.Minute)) {
		t.Fatal("pre-expiry pinned snapshot is not usable")
	}
	if err := manager.MarkExpired(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	current := manager.Current()
	if current.Sessions != (ClientSessions{}) {
		t.Fatalf("expired current snapshot retained session secrets: %#v", current.Sessions)
	}
	if len(current.Nodes) != 1 || current.Nodes[0].ID != "line-1" || manager.State() != StateExpired {
		t.Fatalf("expiry did not retain non-secret node metadata/state: %#v / %s", current.Nodes, manager.State())
	}
	if SessionUsable(current, now.Add(2*time.Minute)) {
		t.Fatal("expired current snapshot can establish a new tunnel")
	}
	if !pinned.Sessions.IOS.Valid() || pinned.Sessions.IOS.TunnelPassword != "tunnel" {
		t.Fatalf("expiry altered previously pinned drain snapshot: %#v", pinned.Sessions.IOS)
	}
	retry, err := manager.Begin(OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	retry(OutcomeFailed)
	if current := manager.Current(); current.Sessions != (ClientSessions{}) {
		t.Fatalf("failed re-login resurrected session material: %#v", current.Sessions)
	}
}

func TestFailedRefreshAfterExpiryScrubsCurrentSessionIdempotently(t *testing.T) {
	now := time.Now().UTC()
	manager, err := NewManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	bindManager(t, manager, "user-1")
	loginFinish, err := manager.Begin(OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := runtimeSnapshot(1, "user-1", now.Add(-time.Minute))
	snapshot.CreatedAt = now.Add(-time.Hour)
	if err := manager.Commit(snapshot); err != nil {
		t.Fatal(err)
	}
	loginFinish(OutcomeSucceeded)
	pinned := manager.Current()
	refreshFinish, err := manager.Begin(OperationRefresh)
	if err != nil {
		t.Fatal(err)
	}
	refreshFinish(OutcomeFailed)
	current := manager.Current()
	if manager.State() != StateExpired || current.Sessions != (ClientSessions{}) || SessionUsable(current, now) {
		t.Fatalf("failed refresh did not publish secret-free expired state: %s %#v", manager.State(), current)
	}
	if len(current.Nodes) != 1 || current.Nodes[0].ID != "line-1" {
		t.Fatalf("failed refresh expiry lost node metadata: %#v", current.Nodes)
	}
	if !pinned.Sessions.IOS.Valid() || pinned.Sessions.IOS.TunnelPassword != "tunnel" {
		t.Fatalf("failed refresh expiry mutated pinned relay snapshot: %#v", pinned.Sessions.IOS)
	}
	if err := manager.MarkExpired(now.Add(time.Minute)); err != nil {
		t.Fatalf("first repeated MarkExpired: %v", err)
	}
	if err := manager.MarkExpired(now.Add(2 * time.Minute)); err != nil {
		t.Fatalf("second repeated MarkExpired: %v", err)
	}
	if current := manager.Current(); current.Sessions != (ClientSessions{}) || SessionUsable(current, now.Add(3*time.Minute)) {
		t.Fatalf("repeated expiry retained or revived session: %#v", current.Sessions)
	}
}

func TestManagerCommitRejectsResurrectionStates(t *testing.T) {
	newBoundReady := func(t *testing.T) (*Manager, PersistentState) {
		t.Helper()
		persistent := initializedPersistentState(t)
		if _, err := EnsureSubscriptionAccountBinding(&persistent, "user-1", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		manager, err := NewManagerWithSubscription(nil, persistent.Subscription, persistent.AccessTokenVerifier.BindingKey())
		if err != nil {
			t.Fatal(err)
		}
		finish, err := manager.Begin(OperationLogin)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Commit(runtimeSnapshot(1, "user-1", time.Now().Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
		finish(OutcomeSucceeded)
		return manager, persistent
	}
	for _, test := range []struct {
		name  string
		setup func(*testing.T) *Manager
	}{
		{"signed_out", func(t *testing.T) *Manager {
			manager, err := NewManager(nil)
			if err != nil {
				t.Fatal(err)
			}
			return manager
		}},
		{"expired", func(t *testing.T) *Manager {
			manager, _ := newBoundReady(t)
			if err := manager.MarkExpired(time.Now()); err != nil {
				t.Fatal(err)
			}
			return manager
		}},
		{"error", func(t *testing.T) *Manager {
			manager, _ := newBoundReady(t)
			if err := manager.Transition(StateSyncing); err != nil {
				t.Fatal(err)
			}
			if err := manager.Transition(StateError); err != nil {
				t.Fatal(err)
			}
			return manager
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := test.setup(t)
			before := manager.Current()
			err := manager.Commit(runtimeSnapshot(9, "user-1", time.Now().Add(time.Hour)))
			if !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("direct Commit = %v, want ErrInvalidTransition", err)
			}
			after := manager.Current()
			if manager.State() != StateSignedOut && manager.State() != StateExpired && manager.State() != StateError {
				t.Fatalf("Commit changed lifecycle state to %s", manager.State())
			}
			if (manager.State() == StateSignedOut || manager.State() == StateExpired) && after != nil && SessionUsable(after, time.Now()) {
				t.Fatalf("Commit resurrected usable session: %#v", after.Sessions)
			}
			if before != nil && (after == nil || after.Generation != before.Generation || after.Sessions != before.Sessions) {
				t.Fatalf("Commit replaced terminal-state snapshot: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestRuntimeSnapshotRequiresBoundedFiniteUsableSession(t *testing.T) {
	now := time.Now().UTC()
	base := runtimeSnapshot(1, "user-1", now.Add(time.Hour))
	base.CreatedAt = now
	if err := ValidateRuntimeSnapshot(base); err != nil {
		t.Fatal(err)
	}
	zeroExpiry := base.Clone()
	zeroExpiry.ExpiresAt = time.Time{}
	if SessionUsable(zeroExpiry, now) || !errors.Is(ValidateRuntimeSnapshot(zeroExpiry), ErrInvalidSnapshot) {
		t.Fatal("zero expiry snapshot was usable or valid")
	}
	longExpiry := base.Clone()
	longExpiry.ExpiresAt = now.Add(maxSessionLifetime + time.Second)
	if !errors.Is(ValidateRuntimeSnapshot(longExpiry), ErrInvalidSnapshot) {
		t.Fatal("overlong session lifetime accepted")
	}
	partial := base.Clone()
	partial.Sessions.IOS.ProviderToken = ""
	if !errors.Is(ValidateRuntimeSnapshot(partial), ErrInvalidSnapshot) {
		t.Fatal("partial future session accepted")
	}
	overNodes := base.Clone()
	overNodes.Nodes = make([]Node, maxRuntimeNodes+1)
	for index := range overNodes.Nodes {
		overNodes.Nodes[index] = Node{ID: strconv.Itoa(index), Provider: "WIFIIN", Host: "node.example", Port: 11000}
	}
	if !errors.Is(ValidateRuntimeSnapshot(overNodes), ErrInvalidSnapshot) {
		t.Fatal("oversized node list accepted")
	}
	overSelectors := base.Clone()
	overSelectors.Selectors = make(map[string]NodeRef, maxRuntimeSelectorRefs+1)
	for index := range maxRuntimeSelectorRefs + 1 {
		overSelectors.Selectors[strconv.Itoa(index)] = NodeRef{NodeID: "line-1", Generation: 1}
	}
	if !errors.Is(ValidateRuntimeSnapshot(overSelectors), ErrInvalidSnapshot) {
		t.Fatal("oversized selector map accepted")
	}
}

func TestManagerAccountBindingInstallIsVerifiedAndReversible(t *testing.T) {
	persistent := initializedPersistentState(t)
	manager, err := NewManagerWithSubscription(nil, persistent.Subscription, persistent.AccessTokenVerifier.BindingKey())
	if err != nil {
		t.Fatal(err)
	}
	finish, err := manager.Begin(OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureSubscriptionAccountBinding(&persistent, "user-1", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rollback, err := manager.InstallSubscriptionGeneration(persistent.Subscription, "user-1")
	if err != nil {
		t.Fatalf("InstallSubscriptionGeneration: %v", err)
	}
	rollback()
	rollback()
	if status := manager.AccountBindingStatus("user-1"); status != AccountBindingUnbound {
		t.Fatalf("rollback binding status = %s, want unbound", status)
	}
	rollback, err = manager.InstallSubscriptionGeneration(persistent.Subscription, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Commit(runtimeSnapshot(1, "user-1", time.Now().Add(time.Hour))); err != nil {
		rollback()
		t.Fatalf("Commit after matching first bind: %v", err)
	}
	finish(OutcomeSucceeded)
	if status := manager.AccountBindingStatus("user-1"); status != AccountBindingMatch {
		t.Fatalf("binding status = %s, want match", status)
	}
	wrong := persistent.Subscription.clone()
	wrong.AccountBinding, err = accountBindingFor(persistent.AccessTokenVerifier.BindingKey(), "user-2")
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := manager.Begin(OperationRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.InstallSubscriptionGeneration(wrong, "user-1"); !errors.Is(err, ErrAccountChanged) {
		t.Fatalf("mismatched installed account = %v, want ErrAccountChanged", err)
	}
	refresh(OutcomeFailed)
}

func TestSQLiteStoreRoundTripRestartAndNoRawAccessToken(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	persisted := validPersistentSubscriptionState(t)
	persisted.Preferences.RevealEndpoints = true
	persisted.Preferences.ExcludedNodeIDs["another-node"] = true
	persisted.ActiveSession = runtimeSnapshot(9, "user-1", time.Now().UTC().Add(time.Hour))
	persisted.ActiveSession.Sessions.Windows = SessionSecrets{
		UserID: "user-1", LoginToken: "windows-login", ProviderToken: "windows-provider",
		TunnelPassword: "wifiin1234", TunnelMethod: "aes-256-cfb",
		ProviderExtension: "|windows-provider|com.wifiin.sdk.invpn.win|windows-order|user-1|WINDOWS|4.3.30",
	}
	persisted.ActiveSession.Nodes = append(persisted.ActiveSession.Nodes, Node{
		ID: "line-windows", Selector: "n_windows", Provider: "WIFIIN", ClientProfile: ClientProfileWindows,
		Host: "windows.example", Port: 11000, Name: "windows", Group: "group", Eligible: true,
		Health: NodeHealthUnknown, UDPHealth: UDPHealthUnavailable,
	})
	persisted.ActiveSession.Selectors["n_windows"] = NodeRef{NodeID: "line-windows", Generation: persisted.Subscription.Generation}
	if err := store.Save(persisted); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatalf("NewSQLiteStore reopen: %v", err)
	}
	loaded, err := reopened.Load()
	if err != nil {
		t.Fatalf("Load after restart: %v", err)
	}
	if loaded.InstallationID != persisted.InstallationID || loaded.Preferences.RefreshPolicy != persisted.Preferences.RefreshPolicy || !loaded.Preferences.RevealEndpoints || !loaded.Preferences.ExcludedNodeIDs["another-node"] {
		t.Fatalf("persistent aggregate did not round trip: %#v", loaded)
	}
	if loaded.ActiveSession == nil || !loaded.ActiveSession.Sessions.Valid() ||
		loaded.ActiveSession.Sessions.IOS.ProviderToken != persisted.ActiveSession.Sessions.IOS.ProviderToken ||
		loaded.ActiveSession.Sessions.Windows != persisted.ActiveSession.Sessions.Windows ||
		len(loaded.ActiveSession.Nodes) != 2 || loaded.ActiveSession.Nodes[1].ClientProfile != ClientProfileWindows ||
		loaded.ActiveSession.Selectors["n_example"].Generation != loaded.Subscription.Generation {
		t.Fatalf("active session did not round trip: %#v", loaded.ActiveSession)
	}
	body, err := os.ReadFile(reopened.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(testAccessToken)) {
		t.Fatal("SQLite database retained the raw local access token")
	}
	info, err := os.Stat(reopened.Path())
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("state.db mode = %#o, want 0600", got)
	}
}

func TestSQLiteStoreMigratesSchemaV4ProfilesToIOS(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	persisted := validPersistentSubscriptionState(t)
	persisted.ActiveSession = runtimeSnapshot(persisted.Subscription.Generation, "user-1", time.Now().UTC().Add(time.Hour))
	if err := store.Save(persisted); err != nil {
		t.Fatal(err)
	}
	path := store.Path()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := openSQLite(path, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"DROP TABLE active_session_node_profiles",
		"DROP TABLE active_session_windows",
		"UPDATE schema_version SET version = 4 WHERE id = 1",
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := migrated.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ActiveSession == nil || len(loaded.ActiveSession.Nodes) != 1 || loaded.ActiveSession.Nodes[0].ClientProfile != ClientProfileIOS || loaded.ActiveSession.Sessions.Windows != (SessionSecrets{}) {
		t.Fatalf("migrated v4 active session = %#v", loaded.ActiveSession)
	}
	var version int
	if err := migrated.db.QueryRow("SELECT version FROM schema_version WHERE id = 1").Scan(&version); err != nil || version != sqliteSchemaVersion {
		t.Fatalf("migrated schema version = %d, err=%v", version, err)
	}
}

func TestSQLiteStoreEscapesDatabasePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state?query")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("intended state.db is empty")
	}
	if err := ValidateSQLiteFile(store.Path()); err != nil {
		t.Fatalf("ValidateSQLiteFile intended path: %v", err)
	}
	truncatedPath := filepath.Join(filepath.Dir(dir), "state")
	if _, err := os.Lstat(truncatedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("truncated SQLite path %q exists: %v", truncatedPath, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.InstallationID != created.InstallationID {
		t.Fatalf("installation after escaped-path restart = %q, want %q", loaded.InstallationID, created.InstallationID)
	}
}

func TestSQLiteStoreConfiguresReplacementConnections(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	check := func() {
		var foreignKeys, busyTimeout, secureDelete, synchronous int
		if err := store.db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatal(err)
		}
		if err := store.db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			t.Fatal(err)
		}
		if err := store.db.QueryRow("PRAGMA secure_delete").Scan(&secureDelete); err != nil {
			t.Fatal(err)
		}
		if err := store.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
			t.Fatal(err)
		}
		if foreignKeys != 1 || busyTimeout != 5000 || secureDelete != 1 || synchronous != 2 {
			t.Fatalf("SQLite connection pragmas = foreign_keys:%d busy_timeout:%d secure_delete:%d synchronous:%d", foreignKeys, busyTimeout, secureDelete, synchronous)
		}
	}
	check()
	connection, err := store.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.Raw(func(any) error { return driver.ErrBadConn })
	check()
}

func TestSQLiteStoreUpdateRollbackPreservesAggregate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(func(candidate *PersistentState) error {
		candidate.Preferences.RefreshPolicy = "30m"
		return errors.New("reject candidate")
	}); err == nil {
		t.Fatal("Update accepted callback failure")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.InstallationID != initial.InstallationID || loaded.Preferences.RefreshPolicy != "" {
		t.Fatalf("failed Update changed durable state: %#v", loaded)
	}
}

func TestSQLiteStoreRejectsCorruptionSchemaPermissionsAndSymlink(t *testing.T) {
	t.Run("corrupt_file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, sqliteStateFileName)
		if err := os.WriteFile(path, []byte("not a SQLite database"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ValidateSQLiteFile(path); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("ValidateSQLiteFile corrupt DB = %v, want ErrCorruptState", err)
		}
	})
	t.Run("schema", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := NewSQLiteStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadOrCreate(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("UPDATE schema_version SET version = ? WHERE id = 1", sqliteSchemaVersion+1); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("Load unsupported schema = %v, want ErrCorruptState", err)
		}
	})
	t.Run("wal_journal", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := NewSQLiteStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadOrCreate(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec("PRAGMA journal_mode = WAL"); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := ValidateSQLiteFile(store.Path()); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("ValidateSQLiteFile WAL database = %v, want ErrCorruptState", err)
		}
	})
	for name, mutation := range map[string]string{
		"altered_table":   "ALTER TABLE preferences ADD COLUMN injected TEXT",
		"unknown_trigger": "CREATE TRIGGER injected_trigger AFTER UPDATE ON preferences BEGIN SELECT 1; END",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			store, err := NewSQLiteStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.LoadOrCreate(); err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("Load modified schema = %v, want ErrCorruptState", err)
			}
		})
	}
	t.Run("permissions_and_symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := NewSQLiteStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadOrCreate(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(store.Path(), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); !errors.Is(err, ErrInsecureStatePath) {
			t.Fatalf("Load broad state.db = %v, want ErrInsecureStatePath", err)
		}
		if err := os.Chmod(store.Path(), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, "target.db")
		if err := os.WriteFile(target, []byte("unrelated"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(store.Path()); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, store.Path()); err != nil {
			t.Fatal(err)
		}
		reopened, err := NewSQLiteStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reopened.Load(); !errors.Is(err, ErrInsecureStatePath) {
			t.Fatalf("Load symlink state.db = %v, want ErrInsecureStatePath", err)
		}
	})
	t.Run("hard_link", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := NewSQLiteStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadOrCreate(); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(store.Path(), filepath.Join(dir, "state-copy.db")); err != nil {
			t.Fatal(err)
		}
		if err := ValidateSQLiteFile(store.Path()); !errors.Is(err, ErrInsecureStatePath) {
			t.Fatalf("ValidateSQLiteFile hard-linked database = %v, want ErrInsecureStatePath", err)
		}
	})
}

func TestSQLiteStoreCleansFailedInitialization(t *testing.T) {
	artifactPath := ""
	failingInitializer := func(_ *sql.DB, _ PersistentState) error {
		if artifactPath != "" {
			if err := os.WriteFile(artifactPath+"-journal", []byte("incomplete"), 0o600); err != nil {
				return err
			}
		}
		return errors.New("injected initialization failure")
	}
	t.Run("load_or_create_retry", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := NewSQLiteStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		artifactPath = store.Path()
		store.initializeState = failingInitializer
		if _, err := store.LoadOrCreate(); err == nil {
			t.Fatal("LoadOrCreate accepted injected initialization failure")
		}
		for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
			if _, err := os.Lstat(store.Path() + suffix); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("incomplete SQLite artifact %q remains: %v", suffix, err)
			}
		}
		store.initializeState = initializeSQLiteSchemaAndState
		created, err := store.LoadOrCreate()
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateSQLiteFile(store.Path()); err != nil {
			t.Fatalf("ValidateSQLiteFile after retry: %v", err)
		}
		info, err := os.Stat(store.Path())
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("direct state.db mode = %#o, want 0600", got)
		}
		if created.InstallationID == "" {
			t.Fatal("retry did not create an installation")
		}
	})
	t.Run("semantic_failure", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := NewSQLiteStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		reject := errors.New("subscription semantic rejection")
		if _, err := store.LoadOrCreate(func(PersistentState) error { return reject }); !errors.Is(err, reject) {
			t.Fatalf("LoadOrCreate semantic failure = %v, want rejection", err)
		}
		if _, err := os.Lstat(store.Path()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("semantic failure created state.db: %v", err)
		}
	})
	t.Run("unexpected_artifact", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "unexpected"), []byte("untrusted"), 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := NewSQLiteStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadOrCreate(); !errors.Is(err, ErrInsecureStatePath) {
			t.Fatalf("LoadOrCreate with unexpected artifact = %v, want ErrInsecureStatePath", err)
		}
		if _, err := os.Lstat(store.Path()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected artifact caused state.db creation: %v", err)
		}
	})
	t.Run("save_cleanup", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := NewSQLiteStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		artifactPath = store.Path()
		store.initializeState = failingInitializer
		if err := store.Save(validPersistentSubscriptionState(t)); err == nil {
			t.Fatal("Save accepted injected initialization failure")
		}
		if _, err := os.Lstat(store.Path()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Save retained incomplete state.db: %v", err)
		}
	})
}
func TestSQLiteRollbackJournalRemainsPrivate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE preferences SET refresh_policy = '23h' WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	journalPath := store.Path() + "-journal"
	if err := validateSecureStateFile(journalPath, maxSQLiteStateBytes); err != nil {
		t.Fatalf("active rollback journal is not private: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(journalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback journal remains after rollback: %v", err)
	}
}

func TestSQLiteStoreRestoresExpiresAndRevokesBrowserSessions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	csrf := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	expires := now.Add(time.Hour)
	if err := store.SaveBrowserSession(token, csrf, expires, 2); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	var restored []string
	if err := store.RestoreBrowserSessions(now, 2, func(gotToken, gotCSRF string, gotExpiry time.Time) error {
		if gotCSRF != csrf || !gotExpiry.Equal(expires) {
			t.Fatalf("restored browser session differs: %q %s", gotCSRF, gotExpiry)
		}
		restored = append(restored, gotToken)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0] != token {
		t.Fatalf("restored sessions = %#v", restored)
	}
	if err := store.RestoreBrowserSessions(now.Add(2*time.Hour), 2, func(string, string, time.Time) error {
		t.Fatal("expired browser session was restored")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveBrowserSession(token, csrf, now.Add(maxSessionLifetime+time.Second), 2); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("overlong browser session expiry error = %v, want ErrCorruptState", err)
	}
	if err := store.SaveBrowserSession(token, csrf, now.Add(time.Hour), 2); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteBrowserSession(token); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreBrowserSessions(now, 2, func(string, string, time.Time) error {
		t.Fatal("revoked browser session was restored")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExcludedNodeIDsAreStableAndValidated(t *testing.T) {
	persisted, err := NewPersistentState()
	if err != nil {
		t.Fatal(err)
	}
	if !(Node{Provider: "WIFIIN", Host: "node.example.test", Port: 1080, Eligible: true, Excluded: true}).TunnelEligible() {
		t.Fatal("excluded node flag still affects tunnel eligibility")
	}
	persisted.Preferences.ExcludedNodeIDs["stable-node-id"] = true
	clone := persisted.Clone()
	persisted.Preferences.ExcludedNodeIDs["another-node-id"] = true
	if !clone.Preferences.ExcludedNodeIDs["stable-node-id"] || clone.Preferences.ExcludedNodeIDs["another-node-id"] {
		t.Fatalf("excluded node IDs were not deep-copied: %#v", clone.Preferences)
	}
	clone.Preferences.ExcludedNodeIDs[""] = true
	if err := ValidatePersistentState(clone); err == nil {
		t.Fatal("accepted empty excluded node ID")
	}
}

func TestRefreshPolicyPersistsAndEnforcesBounds(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Preferences.RefreshPolicy != "" {
		t.Fatalf("default refresh policy = %q, want empty", persisted.Preferences.RefreshPolicy)
	}
	persisted.Preferences.RefreshPolicy = "30m"
	if err := store.Save(persisted); err != nil {
		t.Fatalf("Save refresh policy: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load refresh policy: %v", err)
	}
	if got := loaded.Preferences.RefreshPolicy; got != "30m" {
		t.Fatalf("persisted refresh policy = %q, want 30m", got)
	}
	for _, policy := range []string{"", "15m", "24h"} {
		candidate := loaded.Clone()
		candidate.Preferences.RefreshPolicy = policy
		if err := ValidatePersistentState(candidate); err != nil {
			t.Fatalf("valid refresh policy %q rejected: %v", policy, err)
		}
	}
	for _, policy := range []string{"14m59s", "24h1m", "not-a-duration", "-15m"} {
		candidate := loaded.Clone()
		candidate.Preferences.RefreshPolicy = policy
		if err := ValidatePersistentState(candidate); err == nil {
			t.Fatalf("invalid refresh policy %q accepted", policy)
		}
	}
}

func TestInstallationIDUsesLowercaseHexProtocolShape(t *testing.T) {
	persisted, err := NewPersistentState()
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted.InstallationID) != 32 {
		t.Fatalf("installation ID length = %d, want 32", len(persisted.InstallationID))
	}
	for index := range len(persisted.InstallationID) {
		value := persisted.InstallationID[index]
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			t.Fatalf("installation ID is not lowercase hex: %q", persisted.InstallationID)
		}
	}
	for _, installationID := range []string{
		strings.Repeat("a", 31),
		strings.Repeat("a", 31) + "A",
		strings.Repeat("a", 31) + "g",
		strings.Repeat("a", 33),
	} {
		candidate := persisted.Clone()
		candidate.InstallationID = installationID
		if err := ValidatePersistentState(candidate); err == nil {
			t.Fatalf("invalid installation ID %q accepted", installationID)
		}
	}
	candidate := persisted.Clone()
	candidate.InstallationID = strings.Repeat("0", 32)
	if err := ValidatePersistentState(candidate); err != nil {
		t.Fatalf("valid lowercase hex installation ID rejected: %v", err)
	}
}

func renderedSubscription(lines ...string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n") + "\n"))
}

func validPersistentSubscriptionState(t *testing.T) PersistentState {
	t.Helper()
	persisted := initializedPersistentState(t)
	if _, err := EnsureSubscriptionAccountBinding(&persisted, "user-1", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	node := PersistedNode{ID: "stable-node", Selector: "n_selector", Provider: "WIFIIN", Host: "node.example.com", Port: 11000, Name: "Alpha", Eligible: true}
	persisted.LastGood = LastGoodState{
		Generation:           persisted.Subscription.Generation,
		CreatedAt:            time.Date(2026, 7, 15, 11, 0, 0, 0, time.UTC),
		Nodes:                []PersistedNode{node},
		RenderedSubscription: renderedSubscription("socks5://n_selector:p_password@127.0.0.1:10808#Alpha"),
	}
	if err := ValidatePersistentState(persisted); err != nil {
		t.Fatalf("valid persisted subscription state rejected: %v", err)
	}
	return persisted
}

func TestPersistentActiveSessionAuthorityValidatesSemantically(t *testing.T) {
	valid := validPersistentSubscriptionState(t)
	valid.ActiveSession = runtimeSnapshot(valid.Subscription.Generation, "user-1", time.Now().UTC().Add(time.Hour))
	if err := ValidatePersistentState(valid); err != nil {
		t.Fatalf("valid active-session authority rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*SessionSecrets)
	}{
		{"unsupported_method", func(session *SessionSecrets) { session.TunnelMethod = "bogus" }},
		{"overlong_login_token", func(session *SessionSecrets) { session.LoginToken = strings.Repeat("x", maxSessionFieldBytes+1) }},
		{"malformed_extension", func(session *SessionSecrets) { session.ProviderExtension = "extension" }},
		{"provider_token_mismatch", func(session *SessionSecrets) { session.ProviderToken = "other-provider" }},
		{"extension_user_mismatch", func(session *SessionSecrets) {
			session.ProviderExtension = "|provider|cc.fancast.major|order|user-2|MAC|1.0.46"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid.Clone()
			test.mutate(&candidate.ActiveSession.Sessions.IOS)
			if err := ValidatePersistentState(candidate); err == nil {
				t.Fatal("invalid active-session authority accepted")
			}
		})
	}
}

func TestPersistentSubscriptionArtifactsValidateSemantically(t *testing.T) {
	valid := validPersistentSubscriptionState(t)
	for _, test := range []struct {
		name   string
		mutate func(*PersistentState)
	}{
		{"malformed_base64", func(p *PersistentState) { p.LastGood.RenderedSubscription = "%%%" }},
		{"oversized_body", func(p *PersistentState) {
			p.LastGood.RenderedSubscription = strings.Repeat("A", maxRenderedSubscriptionBytes+1)
		}},
		{"noncanonical_base64", func(p *PersistentState) { p.LastGood.RenderedSubscription += "\n" }},
		{"last_good_generation_mismatch", func(p *PersistentState) { p.LastGood.Generation++ }},
		{"incomplete_last_good", func(p *PersistentState) { p.LastGood.RenderedSubscription = "" }},
		{"invalid_node", func(p *PersistentState) { p.LastGood.Nodes[0].Port = 0 }},
		{"duplicate_node_id", func(p *PersistentState) {
			p.LastGood.Nodes = append(p.LastGood.Nodes, p.LastGood.Nodes[0])
			p.LastGood.RenderedSubscription = renderedSubscription(
				"socks5://n_selector:p_password@127.0.0.1:10808#Alpha",
				"socks5://n_two:p_two@127.0.0.1:10808#Beta",
			)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid.Clone()
			test.mutate(&candidate)
			if err := ValidatePersistentState(candidate); err == nil {
				t.Fatal("invalid persistent subscription artifact accepted")
			}
		})
	}
}

func TestSQLiteStoreRejectsSemanticSubscriptionCorruption(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	valid := validPersistentSubscriptionState(t)
	if err := store.Save(valid); err != nil {
		t.Fatal(err)
	}
	bad := valid.Clone()
	bad.LastGood.RenderedSubscription = "%%%"
	if err := store.Save(bad); err == nil {
		t.Fatal("Save committed semantically corrupt subscription state")
	}
	if _, err := store.db.Exec("UPDATE last_good SET rendered_subscription = '%%%' WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("Load semantic corruption = %v, want ErrCorruptState", err)
	}
}

func TestAccessTokenVerifierSetupAndValidation(t *testing.T) {
	persistent, err := NewPersistentState()
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"short", strings.Repeat("x", 129), string([]byte{0xff}) + strings.Repeat("x", 15)} {
		if err := persistent.SetAccessToken(token); !errors.Is(err, ErrInvalidAccessToken) {
			t.Fatalf("SetAccessToken(%q) = %v, want ErrInvalidAccessToken", token, err)
		}
	}
	if err := persistent.SetAccessToken("  " + testAccessToken + "\t"); err != nil {
		t.Fatal(err)
	}
	if !persistent.AccessTokenInitialized() || !persistent.VerifyAccessToken(testAccessToken) || persistent.VerifyAccessToken(testAccessToken+"x") {
		t.Fatal("verifier did not authenticate exactly the trimmed setup token")
	}
	if err := persistent.SetAccessToken(testAccessToken); !errors.Is(err, ErrAccessTokenAlreadyInitialized) {
		t.Fatalf("second setup = %v, want ErrAccessTokenAlreadyInitialized", err)
	}
	malformed := persistent.Clone()
	malformed.AccessTokenVerifier.Hash = malformed.AccessTokenVerifier.Hash[:31]
	if err := ValidatePersistentState(malformed); err == nil {
		t.Fatal("accepted malformed verifier hash")
	}
	malformed = persistent.Clone()
	malformed.AccessTokenVerifier.Parameters.Iterations++
	if err := ValidatePersistentState(malformed); err == nil {
		t.Fatal("accepted non-production Argon2id parameters")
	}
}

func TestSubscriptionBindingStabilityAndAccountChange(t *testing.T) {
	persistent := initializedPersistentState(t)
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	changed, err := EnsureSubscriptionAccountBinding(&persistent, "provider-user-a", now)
	if err != nil || changed {
		t.Fatalf("first binding = changed:%v err:%v", changed, err)
	}
	first := persistent.Subscription.clone()
	if got := first.AccountBindingString(); len(got) != 43 || strings.Contains(got, "=") {
		t.Fatalf("stable token = %q", got)
	}
	changed, err = EnsureSubscriptionAccountBinding(&persistent, "provider-user-a", now.Add(time.Minute))
	if err != nil || changed || !sameSubscriptionGeneration(first, persistent.Subscription) {
		t.Fatalf("same account changed subscription: changed=%v err=%v", changed, err)
	}
	persistent.LastGood = LastGoodState{Generation: first.Generation, CreatedAt: now, Nodes: []PersistedNode{{ID: "node", Selector: "selector", Provider: "WIFIIN", Host: "node.example", Port: 11000, Eligible: true}}, RenderedSubscription: renderedSubscription("socks5://selector:password@127.0.0.1:10808#Node")}
	persistent.ActiveSession = runtimeSnapshot(7, "provider-user-a", now.Add(time.Hour))
	changed, err = EnsureSubscriptionAccountBinding(&persistent, "provider-user-b", now.Add(2*time.Minute))
	if err != nil || !changed {
		t.Fatalf("changed account = changed:%v err:%v", changed, err)
	}
	if persistent.Subscription.Generation != first.Generation+1 || sameSubscriptionCredentials(first, persistent.Subscription) || persistent.Subscription.AccountBindingString() == first.AccountBindingString() || !lastGoodStateEmpty(persistent.LastGood) || persistent.ActiveSession != nil {
		t.Fatalf("account change did not replace account-bound authority: %#v", persistent)
	}
}

func TestUnboundStateRejectsCredentialBearingLastGood(t *testing.T) {
	persistent, err := NewPersistentState()
	if err != nil {
		t.Fatal(err)
	}
	persistent.LastGood = LastGoodState{Generation: 0, CreatedAt: time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC), Nodes: []PersistedNode{{ID: "node", Selector: "selector", Provider: "WIFIIN", Host: "node.example", Port: 11000, Eligible: true}}, RenderedSubscription: renderedSubscription("socks5://selector:password@127.0.0.1:10808#Node")}
	if err := ValidatePersistentState(persistent); err == nil {
		t.Fatal("unbound state accepted credential-bearing last-good subscription")
	}
}

func TestManagerBindingKeyConfiguresOnlyOnce(t *testing.T) {
	manager, err := NewManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, sha256.Size)
	const workers = 16
	var wait sync.WaitGroup
	var successes int
	var resultMu sync.Mutex
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			err := manager.ConfigureBindingKey(key)
			resultMu.Lock()
			defer resultMu.Unlock()
			if err == nil {
				successes++
			} else if !errors.Is(err, ErrBindingKeyAlreadyConfigured) {
				t.Errorf("ConfigureBindingKey = %v", err)
			}
		}()
	}
	wait.Wait()
	if successes != 1 {
		t.Fatalf("successful binding configurations = %d, want 1", successes)
	}
}

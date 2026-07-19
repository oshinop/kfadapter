package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
)

type selectorBuilderFunc func(uint64, []state.Node) (map[string]state.NodeRef, error)

func (f selectorBuilderFunc) Build(generation uint64, nodes []state.Node) (map[string]state.NodeRef, error) {
	return f(generation, nodes)
}

func TestRefresherCommitsOnlyCompleteGenerationAndPreservesLastGood(t *testing.T) {
	now := time.Now().UTC()
	manager := testBoundManager(t, completeSnapshot(now), "1")
	var mu sync.Mutex
	expectedAccount := manager.Current().Account
	calls := make(map[string]int)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		calls[request.URL.Path]++
		mu.Unlock()
		switch request.URL.Path {
		case "/v4/client/conf.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{"domain": map[string]any{"ws": "api.example"}})), nil
		case "/v4/invpn/getAuthority.do":
			authKey, err := AuthorityCodec().EncodeJSON(map[string]any{
				"userId": "1", "partnerKey": "", "encryptKey": "new-tunnel", "encryptType": "aes-256-cfb", "partnerStatus": "", "orderId": "o1",
			})
			if err != nil {
				t.Fatal(err)
			}
			return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": string(authKey), "token": "new-provider"})), nil
		case "/v4/invpn/getLines.do":
			return encryptedHTTPResponse(t, envelope(validLineFields("new.example", "g2"))), nil
		default:
			return nil, errors.New("unexpected route")
		}
	})
	client := testControlClient(t, transport)
	refresher, err := NewRefresher(RefresherConfig{
		Client: client, Manager: manager, SelectorBuilder: deterministicBuilder(),
		Clock: func() time.Time { return now }, MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := refresher.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	current := manager.Current()
	if current.Generation != 2 || current.Session.LoginToken != "old-login" || current.Session.ProviderToken != "new-provider" || current.Session.TunnelPassword != "new-tunnel" {
		t.Fatalf("snapshot mixed or failed to rotate authority: %#v", current)
	}
	if manager.State() != state.StateReady || len(current.Nodes) != 1 || current.Nodes[0].Host != "new.example" {
		t.Fatalf("state after complete refresh = %s, %#v", manager.State(), current)
	}
	if current.Account != expectedAccount {
		t.Fatalf("refresh changed account summary: got %#v, want %#v", current.Account, expectedAccount)
	}
	mu.Lock()
	if calls["/v4/client/conf.do"] != 1 || calls["/v4/invpn/getAuthority.do"] != 1 || calls["/v4/invpn/getLines.do"] != 1 {
		t.Fatalf("unexpected request calls: %#v", calls)
	}
	mu.Unlock()

	// A subsequent malformed authority response must leave this complete
	// generation intact and transition only to degraded.
	brokenClient := testControlClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v4/client/conf.do" {
			return encryptedHTTPResponse(t, envelope(map[string]any{"domain": map[string]any{"ws": "api.example"}})), nil
		}
		if request.URL.Path == "/v4/invpn/getAuthority.do" {
			return &http.Response{StatusCode: http.StatusOK, Body: ioNopString("not-encrypted"), Header: make(http.Header)}, nil
		}
		return encryptedHTTPResponse(t, envelope(validLineFields("another.example", "g2"))), nil
	}))
	broken, err := NewRefresher(RefresherConfig{Client: brokenClient, Manager: manager, SelectorBuilder: deterministicBuilder(), Clock: func() time.Time { return now }, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := broken.Refresh(context.Background()); err == nil {
		t.Fatal("malformed refresh unexpectedly succeeded")
	}
	preserved := manager.Current()
	if preserved.Generation != 2 || preserved.Session.ProviderToken != "new-provider" || preserved.Nodes[0].Host != "new.example" {
		t.Fatalf("last-good snapshot was changed on failure: %#v", preserved)
	}
	if manager.State() != state.StateDegraded {
		t.Fatalf("state = %s, want degraded", manager.State())
	}
}

func TestRefresherLoginPublishesOnlyAfterAuthorityAndLines(t *testing.T) {
	manager := testBoundManager(t, nil, "1")
	client := testControlClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v4/client/conf.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{"domain": map[string]any{"ws": "api.example"}})), nil
		case "/v4/user/login.do":
			return encryptedHTTPResponse(t, map[string]any{"status": 119, "msg": "", "fields": map[string]any{"token": "login", "userId": 1}}), nil
		case "/v4/invpn/getAuthority.do":
			authKey, err := AuthorityCodec().EncodeJSON(map[string]any{"userId": "1", "encryptKey": "tunnel", "encryptType": "aes-256-cfb", "orderId": "order"})
			if err != nil {
				t.Fatal(err)
			}
			return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": string(authKey), "token": "provider"})), nil
		case "/v4/invpn/getLines.do":
			return encryptedHTTPResponse(t, envelope(validLineFields("login.example", "group"))), nil
		default:
			return nil, errors.New("unexpected route")
		}
	}))
	refresher, err := NewRefresher(RefresherConfig{Client: client, Manager: manager, SelectorBuilder: deterministicBuilder(), MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := refresher.Login(context.Background(), EmailLogin{Account: "alice@example.test", Password: "password", InstallationID: "install", OSVersion: "test"}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	snapshot := manager.Current()
	if manager.State() != state.StateReady || snapshot == nil || snapshot.Generation != 1 || snapshot.Session.LoginToken != "login" || snapshot.Session.ProviderToken != "provider" || snapshot.Session.TunnelPassword != "tunnel" {
		t.Fatalf("published login snapshot = state %s, value %#v", manager.State(), snapshot)
	}
	if snapshot.Account.Display != "a•••@example.test" || snapshot.Nodes[0].Selector == "" {
		t.Fatalf("login snapshot metadata = %#v", snapshot)
	}
}

func TestRefresherUsesCredentialGenerationAcrossRuntimeRefreshes(t *testing.T) {
	now := time.Now().UTC()
	manager := testBoundManager(t, completeSnapshot(now), "1")
	registry := testRegistry(t)
	authKey, err := AuthorityCodec().EncodeJSON(map[string]any{"userId": "1", "encryptKey": "new-tunnel", "encryptType": "aes-256-cfb", "orderId": "order"})
	if err != nil {
		t.Fatal(err)
	}
	client := testControlClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v4/client/conf.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{"domain": map[string]any{"ws": "api.example"}})), nil
		case "/v4/invpn/getAuthority.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": string(authKey), "token": "provider"})), nil
		case "/v4/invpn/getLines.do":
			return encryptedHTTPResponse(t, envelope(validLineFields("node.example", "group"))), nil
		default:
			return nil, errors.New("unexpected route")
		}
	}))
	refresher, err := NewRefresher(RefresherConfig{Client: client, Manager: manager, SelectorBuilder: registry, Clock: func() time.Time { return now }, MaxAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := refresher.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
	}
	snapshot := manager.Current()
	if snapshot.Generation != 3 || len(snapshot.Nodes) != 1 {
		t.Fatalf("runtime refresh did not advance independently: %#v", snapshot)
	}
	for _, ref := range snapshot.Selectors {
		if ref.Generation != 1 {
			t.Fatalf("selector credential generation = %d, want 1", ref.Generation)
		}
	}
	credential, ok := registry.Credentials(1, selector.NodeIdentity{Provider: "WIFIIN", Host: "node.example", Port: 11000})
	if !ok || snapshot.Nodes[0].Selector != credential.Selector {
		t.Fatalf("node selector = %q, want current credential %q", snapshot.Nodes[0].Selector, credential.Selector)
	}
}

func TestRefresherPublishesCurrentCredentialSelectors(t *testing.T) {
	manager := testBoundManager(t, nil, "1")
	registry := testRegistry(t)
	refresher, err := NewRefresher(RefresherConfig{Client: testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network is not used")
	})), Manager: manager, SelectorBuilder: registry})
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := nodesFromLines(Lines{Groups: []Group{{ID: "group", Name: "group"}}, Lines: []Line{{Host: "node.example", Port: 11000, Provider: "WIFIIN", GroupID: "group"}}})
	if err != nil {
		t.Fatal(err)
	}
	builtNodes, selectors, err := refresher.buildSelectors(42, nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(builtNodes) != 1 || len(selectors) != 1 {
		t.Fatalf("nodes/selectors = %#v / %#v", builtNodes, selectors)
	}
	identity := selector.NodeIdentity{Provider: "WIFIIN", Host: "node.example", Port: 11000}
	current, currentOK := registry.Credentials(1, identity)
	if !currentOK || builtNodes[0].Selector != current.Selector {
		t.Fatalf("Node.Selector must use current credential: %#v", builtNodes[0])
	}
	if ref, ok := selectors[current.Selector]; !ok || ref.Generation != 1 || ref.NodeID != builtNodes[0].ID {
		t.Fatalf("current selector reference = %#v", ref)
	}
	if err := state.ValidateRuntimeSnapshot(&state.RuntimeSnapshot{
		Generation: 42, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		Session: state.SessionSecrets{UserID: "1", LoginToken: "login", ProviderToken: "provider", TunnelPassword: "tunnel", TunnelMethod: "aes-256-cfb", ProviderExtension: "|provider|cc.fancast.major|order|1|MAC|1.0.46"},
		Nodes:   builtNodes, Selectors: selectors,
	}); err != nil {
		t.Fatalf("current credential snapshot rejected: %v", err)
	}
	_, tombstones, err := refresher.buildSelectors(43, nil, selectors)
	if err != nil {
		t.Fatal(err)
	}
	if len(tombstones) != 1 {
		t.Fatalf("tombstones = %#v", tombstones)
	}
	for _, ref := range tombstones {
		if !ref.Tombstoned || ref.NodeID != "" || ref.Generation != 1 {
			t.Fatalf("credential generation tombstone = %#v", ref)
		}
	}
}

func TestNodesFromLinesUsesCanonicalSelectorIdentity(t *testing.T) {
	groups := []Group{{ID: "group", Name: "group"}}
	nodes, err := nodesFromLines(Lines{Groups: groups, Lines: []Line{
		{Host: "Node.Example.", Port: 11000, Provider: "wifiin", GroupID: "group"},
		{Host: "node.example", Port: 11000, Provider: "WIFIIN", GroupID: "group"},
		{Host: "2001:0db8:0:0:0:0:0:1", Port: 11000, Provider: "WIFIIN", GroupID: "group"},
		{Host: "2001:db8::1", Port: 11000, Provider: "WIFIIN", GroupID: "group"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("canonical equivalent lines yielded %d nodes: %#v", len(nodes), nodes)
	}
	byHost := make(map[string]state.Node, len(nodes))
	for _, node := range nodes {
		byHost[node.Host] = node
	}
	dns, dnsOK := byHost["node.example"]
	ip, ipOK := byHost["2001:db8::1"]
	if !dnsOK || !ipOK || dns.Provider != "WIFIIN" || dns.ID == "" || ip.ID == "" {
		t.Fatalf("canonical nodes = %#v", nodes)
	}
	canonicalDNS, err := nodesFromLines(Lines{Groups: groups, Lines: []Line{{Host: "node.example", Port: 11000, Provider: "WIFIIN", GroupID: "group"}}})
	if err != nil {
		t.Fatal(err)
	}
	canonicalIP, err := nodesFromLines(Lines{Groups: groups, Lines: []Line{{Host: "2001:db8::1", Port: 11000, Provider: "WIFIIN", GroupID: "group"}}})
	if err != nil {
		t.Fatal(err)
	}
	if dns.ID != canonicalDNS[0].ID || ip.ID != canonicalIP[0].ID {
		t.Fatalf("canonical identity changed stable IDs: dns %q/%q ip %q/%q", dns.ID, canonicalDNS[0].ID, ip.ID, canonicalIP[0].ID)
	}
	if _, err := nodesFromLines(Lines{Groups: groups, Lines: []Line{{Host: "node.example", Port: 0, Provider: "WIFIIN", GroupID: "group"}}}); !errors.Is(err, ErrSchema) {
		t.Fatalf("invalid selector identity error = %v, want ErrSchema", err)
	}
}

func TestRefresherCommitCallbackFailurePreservesManagerState(t *testing.T) {
	now := time.Now().UTC()
	manager := testBoundManager(t, completeSnapshot(now), "1")
	authKey, err := AuthorityCodec().EncodeJSON(map[string]any{"userId": "1", "encryptKey": "new-tunnel", "encryptType": "aes-256-cfb", "orderId": "order"})
	if err != nil {
		t.Fatal(err)
	}
	client := testControlClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v4/client/conf.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{})), nil
		case "/v4/invpn/getAuthority.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": string(authKey), "token": "provider"})), nil
		case "/v4/invpn/getLines.do":
			return encryptedHTTPResponse(t, envelope(validLineFields("new.example", "group"))), nil
		default:
			return nil, errors.New("unexpected route")
		}
	}))
	commitFailure := errors.New("render failed")
	callbackCalls := 0
	refresher, err := NewRefresher(RefresherConfig{
		Client: client, Manager: manager, SelectorBuilder: deterministicBuilder(), Clock: func() time.Time { return now }, MaxAttempts: 1,
		CommitSnapshot: func(snapshot *state.RuntimeSnapshot) error {
			callbackCalls++
			if snapshot.Generation != 2 || manager.Current().Generation != 1 {
				t.Fatalf("provisional manager publication: candidate=%d current=%#v", snapshot.Generation, manager.Current())
			}
			return commitFailure
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := refresher.Refresh(context.Background()); !errors.Is(err, commitFailure) {
		t.Fatalf("Refresh error = %v, want commit failure", err)
	}
	if callbackCalls != 1 || manager.Current().Generation != 1 || manager.State() != state.StateDegraded {
		t.Fatalf("callback failure changed manager state: calls=%d state=%s snapshot=%#v", callbackCalls, manager.State(), manager.Current())
	}
}

func TestRefresherLoginCommitCallbackFailureStaysSignedOut(t *testing.T) {
	manager := testBoundManager(t, nil, "1")
	authKey, err := AuthorityCodec().EncodeJSON(map[string]any{"userId": "1", "encryptKey": "tunnel", "encryptType": "aes-256-cfb", "orderId": "order"})
	if err != nil {
		t.Fatal(err)
	}
	client := testControlClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v4/client/conf.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{})), nil
		case "/v4/user/login.do":
			return encryptedHTTPResponse(t, map[string]any{"status": 119, "msg": "", "fields": map[string]any{"token": "login", "userId": 1}}), nil
		case "/v4/invpn/getAuthority.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{"authKey": string(authKey), "token": "provider"})), nil
		case "/v4/invpn/getLines.do":
			return encryptedHTTPResponse(t, envelope(validLineFields("new.example", "group"))), nil
		default:
			return nil, errors.New("unexpected route")
		}
	}))
	commitFailure := errors.New("persist failed")
	refresher, err := NewRefresher(RefresherConfig{
		Client: client, Manager: manager, SelectorBuilder: deterministicBuilder(), MaxAttempts: 1,
		CommitSnapshot: func(*state.RuntimeSnapshot) error { return commitFailure },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := refresher.Login(context.Background(), EmailLogin{Account: "a@example.test", Password: "password", InstallationID: "install", OSVersion: "test"}); !errors.Is(err, commitFailure) {
		t.Fatalf("Login error = %v, want commit failure", err)
	}
	if manager.Current() != nil || manager.State() != state.StateSignedOut {
		t.Fatalf("failed login published provisional state: %s %#v", manager.State(), manager.Current())
	}
}

func TestRefresherRejectedLoginIsSingleAttemptAndStaysSignedOut(t *testing.T) {
	manager := testBoundManager(t, nil, "1")
	var mu sync.Mutex
	calls := make(map[string]int)
	client := testControlClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		calls[request.URL.Path]++
		mu.Unlock()
		switch request.URL.Path {
		case "/v4/client/conf.do":
			return encryptedHTTPResponse(t, envelope(map[string]any{})), nil
		case "/v4/user/login.do":
			return encryptedHTTPResponse(t, map[string]any{"status": 401, "msg": "rejected", "fields": map[string]any{}}), nil
		default:
			return nil, errors.New("login should not fetch authority or lines")
		}
	}))
	refresher, err := NewRefresher(RefresherConfig{Client: client, Manager: manager, SelectorBuilder: deterministicBuilder(), MaxAttempts: 5})
	if err != nil {
		t.Fatal(err)
	}
	if err := refresher.Login(context.Background(), EmailLogin{Account: "a@example.test", Password: "secret", InstallationID: "id", OSVersion: "test"}); !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("Login error = %v, want ErrLoginRejected", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["/v4/user/login.do"] != 1 || calls["/v4/client/conf.do"] != 1 {
		t.Fatalf("rejected login retried: %#v", calls)
	}
	if manager.State() != state.StateSignedOut || manager.Current() != nil {
		t.Fatalf("rejected login changed state: %s %#v", manager.State(), manager.Current())
	}
}

func TestRefreshDoesNotRetryInvalidResponseEnvelopes(t *testing.T) {
	trailing, err := NormalCodec().Encode([]byte(`{"status":1,"msg":"","fields":{}} {}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		response  func() *http.Response
		wantCause error
	}{
		{name: "malformed", response: func() *http.Response {
			return &http.Response{StatusCode: http.StatusOK, Body: ioNopString("not-base64"), Header: make(http.Header)}
		}, wantCause: ErrMalformedCiphertext},
		{name: "trailing JSON", response: func() *http.Response {
			return &http.Response{StatusCode: http.StatusOK, ContentLength: int64(len(trailing)), Body: io.NopCloser(bytes.NewReader(trailing)), Header: make(http.Header)}
		}, wantCause: ErrTrailingJSON},
		{name: "wrong status type", response: func() *http.Response {
			return encryptedHTTPResponse(t, map[string]any{"status": "1", "msg": "", "fields": map[string]any{}})
		}},
		{name: "wrong fields type", response: func() *http.Response {
			return encryptedHTTPResponse(t, map[string]any{"status": 1, "msg": "", "fields": "not-an-object"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return test.response(), nil
			}))
			refresher := retryTestRefresher(t, client)
			_, err := retry(context.Background(), refresher, func() (ClientConfig, error) {
				return client.FetchClientConfig(context.Background())
			})
			if !errors.Is(err, ErrInvalidEnvelope) || test.wantCause != nil && !errors.Is(err, test.wantCause) {
				t.Fatalf("retry error = %v", err)
			}
			if calls != 1 {
				t.Fatalf("invalid response attempts = %d, want 1", calls)
			}
		})
	}
}

func TestRefreshRetriesOnlyRetryableHTTPStatuses(t *testing.T) {
	for _, test := range []struct {
		status   int
		attempts int
	}{
		{status: http.StatusUnauthorized, attempts: 1},
		{status: http.StatusForbidden, attempts: 1},
		{status: http.StatusNotFound, attempts: 1},
		{status: http.StatusRequestTimeout, attempts: 3},
		{status: http.StatusTooManyRequests, attempts: 3},
		{status: http.StatusInternalServerError, attempts: 3},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			calls := 0
			client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: test.status, Body: ioNopString(""), Header: make(http.Header)}, nil
			}))
			refresher := retryTestRefresher(t, client)
			_, err := retry(context.Background(), refresher, func() (ClientConfig, error) {
				return client.FetchClientConfig(context.Background())
			})
			var status *httpStatusError
			if !errors.Is(err, ErrHTTPStatus) || !errors.As(err, &status) || status.status != test.status {
				t.Fatalf("status error = %v", err)
			}
			if calls != test.attempts {
				t.Fatalf("status %d attempts = %d, want %d", test.status, calls, test.attempts)
			}
		})
	}
}

func TestRetryStopsWhenContextIsCancelled(t *testing.T) {
	client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network is not used")
	}))
	refresher := retryTestRefresher(t, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	_, err := retry(ctx, refresher, func() (struct{}, error) {
		calls++
		cancel()
		return struct{}{}, temporaryTransportError{}
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancelled retry = %v after %d calls", err, calls)
	}
}

type temporaryTransportError struct{}

func TestRetryRetriesTemporaryTransportFailures(t *testing.T) {
	client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network is not used")
	}))
	refresher := retryTestRefresher(t, client)
	calls := 0
	_, err := retry(context.Background(), refresher, func() (struct{}, error) {
		calls++
		return struct{}{}, temporaryTransportError{}
	})
	if _, ok := err.(temporaryTransportError); !ok || calls != 3 {
		t.Fatalf("temporary retry = %v after %d calls", err, calls)
	}
}

func (temporaryTransportError) Error() string   { return "temporary transport failure" }
func (temporaryTransportError) Timeout() bool   { return true }
func (temporaryTransportError) Temporary() bool { return true }

func retryTestRefresher(t *testing.T, client *Client) *Refresher {
	t.Helper()
	return &Refresher{client: client, attempts: 3, backoff: time.Millisecond, maxBackoff: time.Millisecond}
}

func TestRefresherMarksExpiredBeforeRefresh(t *testing.T) {
	now := time.Now().UTC()
	manager := testBoundManager(t, nil, "1")
	snapshot := completeSnapshot(now)
	complete, err := manager.Begin(state.OperationLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Commit(snapshot); err != nil {
		t.Fatal(err)
	}
	complete(state.OutcomeSucceeded)
	client := testControlClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("expired state must not request upstream")
	}))
	refresher, err := NewRefresher(RefresherConfig{Client: client, Manager: manager, SelectorBuilder: deterministicBuilder(), Clock: func() time.Time { return snapshot.ExpiresAt.Add(time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := refresher.Refresh(context.Background()); !errors.Is(err, ErrAuthorityExpired) {
		t.Fatalf("Refresh error = %v, want ErrAuthorityExpired", err)
	}
	if manager.State() != state.StateExpired {
		t.Fatalf("state = %s, want expired", manager.State())
	}
}

func testBoundManager(t *testing.T, initial *state.RuntimeSnapshot, userID string) *state.Manager {
	t.Helper()
	persistent, err := state.NewPersistentState()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistent.SetAccessToken("0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if _, err := state.EnsureSubscriptionAccountBinding(&persistent, userID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	manager, err := state.NewManagerWithSubscription(initial, persistent.Subscription, persistent.AccessTokenVerifier.BindingKey())
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func testControlClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	client, err := NewClient(Config{
		httpClient: &http.Client{Transport: transport}, BootstrapBase: "https://bootstrap.example",
		AllowedAPIHosts: []string{"bootstrap.example", "api.example"}, Random: bytes.NewReader(bytes.Repeat([]byte{0}, 256)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func completeSnapshot(now time.Time) *state.RuntimeSnapshot {
	return &state.RuntimeSnapshot{
		Generation: 1, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Account: state.AccountSummary{Display: "u•••@example.test", IsVIP: true, VIPEndsAt: now.Add(48 * time.Hour)},
		Session:   state.SessionSecrets{UserID: "1", LoginToken: "old-login", ProviderToken: "old-provider", TunnelPassword: "old-tunnel", TunnelMethod: "aes-256-cfb", ProviderExtension: "|old-provider|cc.fancast.major|old|1|MAC|1.0.46"},
		Nodes:     []state.Node{{ID: "node-old", Selector: "selector-old", Provider: "WIFIIN", Host: "old.example", Port: 11000, Name: "old", Group: "g", Eligible: true, Health: state.NodeHealthUnknown, UDPHealth: state.UDPHealthUnavailable}},
		Selectors: map[string]state.NodeRef{"selector-old": {NodeID: "node-old", Generation: 1}},
	}
}

func deterministicBuilder() state.SelectorBuilder {
	return selectorBuilderFunc(func(generation uint64, nodes []state.Node) (map[string]state.NodeRef, error) {
		result := make(map[string]state.NodeRef, len(nodes))
		for index := range nodes {
			result["selector-"+nodes[index].ID] = state.NodeRef{NodeID: nodes[index].ID, Generation: generation}
		}
		return result, nil
	})
}

func testRegistry(t *testing.T) *selector.Registry {
	t.Helper()
	current := state.SubscriptionGeneration{
		Generation: 1, SelectorKey: bytes.Repeat([]byte{1}, 32), ProxyAuthKey: bytes.Repeat([]byte{2}, 32), ActivatedAt: time.Now().UTC(),
	}
	registry, err := selector.NewRegistry(current)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func envelope(fields map[string]any) map[string]any {
	return map[string]any{"status": 1, "msg": "", "fields": fields}
}

func validLineFields(host, groupID string) map[string]any {
	return map[string]any{
		"groups": []any{map[string]any{"id": groupID, "name": "group"}},
		"lines":  []any{map[string]any{"text": "line", "host": host, "port": 11000, "provider": "WIFIIN", "groupId": groupID}},
	}
}

func ioNopString(value string) io.ReadCloser { return io.NopCloser(bytes.NewBufferString(value)) }

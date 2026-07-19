package subscription

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
)

func TestRenderDeterministicPaddedBase64AndEscaping(t *testing.T) {
	body, count, err := Render([]Link{
		{Selector: "n_z", Password: "p:two", Name: "Zulu #2", Group: "B", Eligible: true},
		{Selector: "n_b", Password: "p@one", Name: "Alpha One", Group: "A", Eligible: true},
		{Selector: "n_disabled", Password: "p_disabled", Name: "Ignored", Group: "A", Eligible: false},
	}, "127.0.0.1:10808")
	if err != nil || count != 2 {
		t.Fatalf("Render = (%q, %d, %v)", body, count, err)
	}
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	want := "socks5://n_b:p%40one@127.0.0.1:10808#Alpha%20One\n" +
		"socks5://n_z:p%3Atwo@127.0.0.1:10808#Zulu%20%232\n"
	if string(decoded) != want || body != base64.StdEncoding.EncodeToString(decoded) {
		t.Fatalf("deterministic render = %q", decoded)
	}
}

func TestRenderAcceptsCanonicalAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0:10808", "192.0.2.10:10808", "[2001:db8::10]:10808", "adapter.example.com:10808"} {
		t.Run(address, func(t *testing.T) {
			body, count, err := Render([]Link{{Selector: "node", Password: "secret", Name: "Proxy", Eligible: true}}, address)
			if err != nil || count != 1 {
				t.Fatalf("Render = (%q, %d, %v)", body, count, err)
			}
			decoded, err := base64.StdEncoding.DecodeString(body)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := string(decoded), "socks5://node:secret@"+address+"#Proxy\n"; got != want {
				t.Fatalf("render = %q, want %q", got, want)
			}
		})
	}
}

func TestSubscriptionUsesReachedHostForWildcardListener(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	service, store := newBoundTestServiceAt(t, &now, "account-one", "0.0.0.0:10808")
	publish(t, service, testSnapshot("LAN"))
	url, _, err := service.SubscriptionURL("http://192.0.2.10:10809")
	if err != nil {
		t.Fatal(err)
	}
	binding := bindingFromURL(t, url)
	request := httptest.NewRequest(http.MethodGet, url, nil)
	response := httptest.NewRecorder()
	service.ServeSubscriptionAt(response, request, binding, "192.0.2.10:10808")
	if response.Code != http.StatusOK {
		t.Fatalf("subscription response = %d", response.Code)
	}
	decoded, err := base64.StdEncoding.DecodeString(response.Body.String())
	if err != nil || !strings.Contains(string(decoded), "@192.0.2.10:10808#LAN") {
		t.Fatalf("reached-host subscription = %q, %v", decoded, err)
	}
	secondURL, _, err := service.SubscriptionURL("http://198.51.100.20:10809")
	if err != nil || bindingFromURL(t, secondURL) != binding {
		t.Fatalf("stable multihomed URL = %q, %v", secondURL, err)
	}
	secondRequest := httptest.NewRequest(http.MethodGet, secondURL, nil)
	secondResponse := httptest.NewRecorder()
	service.ServeSubscriptionAt(secondResponse, secondRequest, binding, "198.51.100.20:10808")
	secondDecoded, err := base64.StdEncoding.DecodeString(secondResponse.Body.String())
	if err != nil || !strings.Contains(string(secondDecoded), "@198.51.100.20:10808#LAN") {
		t.Fatalf("second reached-host subscription = %q, %v", secondDecoded, err)
	}
	persisted, err := store.Load()
	if err != nil || persisted.LastGood.RenderedSubscription != secondResponse.Body.String() {
		t.Fatalf("persisted reached-host body mismatch: %v", err)
	}
	restarted, err := NewService(ServiceConfig{Store: store, SocksAddress: "0.0.0.0:10808", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.socksAddress != "198.51.100.20:10808" {
		t.Fatalf("restarted SOCKS address = %q", restarted.socksAddress)
	}
}

func TestSubscriptionUsesConfiguredHostname(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	service, store := newBoundTestServiceAt(t, &now, "account-one", "0.0.0.0:10808")
	publish(t, service, testSnapshot("Hostname"))
	url, _, err := service.SubscriptionURL("http://adapter.example.com:10809")
	if err != nil {
		t.Fatal(err)
	}
	binding := bindingFromURL(t, url)
	request := httptest.NewRequest(http.MethodGet, url, nil)
	response := httptest.NewRecorder()
	service.ServeSubscriptionAt(response, request, binding, "adapter.example.com:10808")
	if response.Code != http.StatusOK {
		t.Fatalf("subscription response = %d", response.Code)
	}
	decoded, err := base64.StdEncoding.DecodeString(response.Body.String())
	if err != nil || !strings.Contains(string(decoded), "@adapter.example.com:10808#Hostname") {
		t.Fatalf("hostname subscription = %q, %v", decoded, err)
	}
	restarted, err := NewService(ServiceConfig{Store: store, SocksAddress: "0.0.0.0:10808", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.socksAddress != "adapter.example.com:10808" {
		t.Fatalf("restarted SOCKS address = %q", restarted.socksAddress)
	}
}

func TestWriteSubscriptionBodyStreamsBoundedChunks(t *testing.T) {
	body := strings.Repeat("x", subscriptionResponseChunkBytes*2+17)
	writer := &chunkWriter{}
	written, err := writeSubscriptionBody(writer, body)
	if err != nil || written != len(body) || writer.total != len(body) || writer.max > subscriptionResponseChunkBytes || writer.writes != 3 {
		t.Fatalf("streaming = written %d total %d max %d writes %d err %v", written, writer.total, writer.max, writer.writes, err)
	}
}

func TestStableURLRefreshBodyAndExactFetchProof(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	service, store := newBoundTestService(t, &now, "account-one")
	first := testSnapshot("Alpha")
	publish(t, service, first)
	url, generation, err := service.SubscriptionURL("http://127.0.0.1:10809/")
	if err != nil || generation == 0 || !strings.HasPrefix(url, "http://127.0.0.1:10809/sub/") {
		t.Fatalf("SubscriptionURL = (%q, %d, %v)", url, generation, err)
	}
	binding := bindingFromURL(t, url)
	firstResponse := serveBinding(service, binding)
	if firstResponse.Code != http.StatusOK || firstResponse.Body.Len() == 0 {
		t.Fatalf("initial serve = %d %q", firstResponse.Code, firstResponse.Body.String())
	}
	if metadata, _ := service.Metadata(); metadata.ReloadRecommended || metadata.LastFetchedGeneration != generation || !metadata.LastFetchedAt.Equal(now) {
		t.Fatalf("initial fetch metadata = %#v", metadata)
	}

	now = now.Add(time.Minute)
	publish(t, service, testSnapshot("Beta"))
	refreshedURL, refreshedGeneration, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil || refreshedURL != url || refreshedGeneration != generation {
		t.Fatalf("same-account URL changed: (%q, %d, %v), want (%q, %d)", refreshedURL, refreshedGeneration, err, url, generation)
	}
	if metadata, _ := service.Metadata(); !metadata.ReloadRecommended {
		t.Fatalf("body refresh did not request consumer reload: %#v", metadata)
	}
	refreshed := serveBinding(service, binding)
	if refreshed.Code != http.StatusOK || !strings.Contains(decodedSubscription(t, refreshed.Body.String()), "Beta") {
		t.Fatalf("refreshed body = %d %q", refreshed.Code, refreshed.Body.String())
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.LastGood.FetchedGeneration != generation || !persisted.LastGood.FetchedAt.Equal(now) {
		t.Fatalf("exact body fetch proof = %#v", persisted.LastGood)
	}
}

func TestUnchangedBodyRefreshRetainsValidFetchProof(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	service, store := newBoundTestService(t, &now, "account-one")
	publish(t, service, testSnapshot("Alpha"))

	url, generation, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	binding := bindingFromURL(t, url)
	initialResponse := serveBinding(service, binding)
	if initialResponse.Code != http.StatusOK || initialResponse.Body.Len() == 0 {
		t.Fatalf("initial serve = %d %q", initialResponse.Code, initialResponse.Body.String())
	}
	before, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !before.LastGood.FetchedAt.Equal(now) {
		t.Fatalf("initial fetch proof = %#v", before.LastGood)
	}

	now = now.Add(time.Minute)
	publish(t, service, testSnapshot("Alpha"))

	refreshedURL, refreshedGeneration, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil || refreshedURL != url || refreshedGeneration != generation {
		t.Fatalf("same-node refresh URL = (%q, %d, %v), want (%q, %d)", refreshedURL, refreshedGeneration, err, url, generation)
	}
	refreshedResponse := serveBinding(service, binding)
	if refreshedResponse.Code != http.StatusOK || refreshedResponse.Body.String() != initialResponse.Body.String() {
		t.Fatalf("same-node refresh body = %d %q, want %q", refreshedResponse.Code, refreshedResponse.Body.String(), initialResponse.Body.String())
	}
	after, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !after.LastGood.CreatedAt.Equal(before.LastGood.CreatedAt) || !after.LastGood.FetchedAt.Equal(before.LastGood.FetchedAt) || after.LastGood.FetchedAt.Before(after.LastGood.CreatedAt) || after.LastGood.FetchedGeneration != generation || after.LastGood.RenderedSubscription != initialResponse.Body.String() {
		t.Fatalf("same-node refresh state = %#v, want retained valid fetch proof %#v", after.LastGood, before.LastGood)
	}
}

func TestLegacyExcludedNodeIsRestoredAtStartup(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	service, store := newBoundTestService(t, &now, "account-one")
	persistent, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	nodes := []state.PersistedNode{
		{ID: "node-excluded", Provider: "WIFIIN", Host: "excluded.example.test", Port: 11000, Name: "Excluded", Group: "Test", Eligible: true, Excluded: true},
		{ID: "node-live", Provider: "WIFIIN", Host: "live.example.test", Port: 11001, Name: "Live", Group: "Test", Eligible: true},
	}
	for index := range nodes {
		credential, deriveErr := selector.Derive(selector.NodeIdentity{Provider: nodes[index].Provider, Host: nodes[index].Host, Port: int(nodes[index].Port)}, persistent.Subscription.SelectorKey, persistent.Subscription.ProxyAuthKey)
		if deriveErr != nil {
			t.Fatal(deriveErr)
		}
		nodes[index].Selector = credential.Selector
	}
	legacyBody, count, _, err := service.renderPersistedNodesAtWithLegacyExclusions(nodes, persistent.Subscription, "127.0.0.1:10808", true)
	if err != nil || count != 1 {
		t.Fatalf("legacy render = (%q, %d, %v)", legacyBody, count, err)
	}
	if _, err := store.Update(func(candidate *state.PersistentState) error {
		candidate.LastGood = state.LastGoodState{
			Generation: candidate.Subscription.Generation, CreatedAt: now, Nodes: nodes, RenderedSubscription: legacyBody,
		}
		return nil
	}); err != nil {
		t.Fatalf("persist legacy subscription: %v", err)
	}
	legacyPersistent, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePersistentState(legacyPersistent); err != nil {
		t.Fatalf("offline validation rejected legacy excluded body: %v", err)
	}
	restarted, err := NewService(ServiceConfig{Store: store, SocksAddress: "127.0.0.1:10808", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("NewService legacy state: %v", err)
	}
	metadata, err := restarted.Metadata()
	if err != nil || metadata.NodeCount != 2 {
		t.Fatalf("legacy metadata = %#v, %v", metadata, err)
	}
	updated, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if updated.LastGood.RenderedSubscription == legacyBody || !strings.Contains(decodedSubscription(t, updated.LastGood.RenderedSubscription), "Excluded") {
		t.Fatalf("legacy excluded node was not restored: %q", updated.LastGood.RenderedSubscription)
	}
}

func TestAccountChangeInvalidatesOldBinding(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	service, _ := newBoundTestService(t, &now, "account-one")
	publish(t, service, testSnapshot("Alpha"))
	oldURL, oldGeneration, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	oldBinding := bindingFromURL(t, oldURL)
	candidate, rollback, err := service.PublishAccount(context.Background(), "account-two")
	if err != nil {
		t.Fatal(err)
	}
	if rollback == nil || candidate.Generation != oldGeneration+1 {
		t.Fatalf("account cutover candidate = %#v", candidate)
	}
	if response := serveBinding(service, oldBinding); response.Code != http.StatusNotFound || response.Body.Len() != 0 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("old account binding = %d %#v %q", response.Code, response.Header(), response.Body.String())
	}
	publish(t, service, testSnapshot("Beta"))
	newURL, newGeneration, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil || newGeneration != candidate.Generation || newURL == oldURL {
		t.Fatalf("new account URL = (%q, %d, %v)", newURL, newGeneration, err)
	}
	if response := serveBinding(service, bindingFromURL(t, newURL)); response.Code != http.StatusOK {
		t.Fatalf("new account binding = %d", response.Code)
	}
}

func TestCanonicalSubscriptionPathRejectsLegacySuffixes(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	service, _ := newBoundTestService(t, &now, "account-one")
	publish(t, service, testSnapshot("Alpha"))
	url, _, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	binding := bindingFromURL(t, url)
	if response := serveBinding(service, binding); response.Code != http.StatusOK || response.Body.Len() == 0 {
		t.Fatalf("canonical subscription path = %d %q", response.Code, response.Body.String())
	}
	for _, path := range []string{
		"/sub/" + binding + "/subscription",
		"/sub/" + binding + "/",
	} {
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:10809"+path, nil)
		response := httptest.NewRecorder()
		service.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || response.Body.Len() != 0 || response.Header().Get("Content-Length") != "0" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("legacy subscription path %s = %d %#v %q", path, response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestMalformedPathsRemainUniformEmpty404(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	service, _ := newBoundTestService(t, &now, "account-one")
	publish(t, service, testSnapshot("Alpha"))
	url, _, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	binding := bindingFromURL(t, url)
	for _, path := range []string{
		"/sub/" + binding[:42],
		"/sub/" + strings.Repeat("=", 43),
		"/sub/" + binding + "/extra",
		"/sub//subscription",
	} {
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:10809"+path, nil)
		response := httptest.NewRecorder()
		service.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || response.Body.Len() != 0 || response.Header().Get("Content-Length") != "0" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s = %d %#v %q", path, response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestPartialWriteDoesNotProveFetch(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	service, store := newBoundTestService(t, &now, "account-one")
	publish(t, service, testSnapshot("Alpha"))
	url, _, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	writer := &shortWriter{writeN: 1}
	request := httptest.NewRequest(http.MethodGet, url, nil)
	service.ServeSubscription(writer, request, bindingFromURL(t, url))
	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.LastGood.FetchedAt.IsZero() || persisted.LastGood.FetchedGeneration != 0 || len(persisted.LastGood.FetchedBodyHash) != 0 {
		t.Fatalf("partial write persisted proof: %#v", persisted.LastGood)
	}
}

func TestConcurrentRefreshAndFetchRemainWholeAndStable(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	service, _ := newBoundTestService(t, &now, "account-one")
	publish(t, service, testSnapshot("Alpha"))
	url, generation, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil {
		t.Fatal(err)
	}
	binding := bindingFromURL(t, url)
	start := make(chan struct{})
	errors := make(chan error, 80)
	var workers sync.WaitGroup
	for range 64 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			response := serveBinding(service, binding)
			if response.Code == http.StatusServiceUnavailable && response.Body.Len() == 0 && response.Header().Get("Retry-After") == "1" {
				return
			}
			if response.Code != http.StatusOK || response.Body.Len() == 0 {
				errors <- fmtError("serve", response.Code)
			}
		}()
	}
	for index := range 16 {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			if err := service.PublishSnapshot(testSnapshot("Name" + strconv.Itoa(index))); err != nil {
				errors <- err
			}
		}(index)
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	finalURL, finalGeneration, err := service.SubscriptionURL("http://127.0.0.1:10809")
	if err != nil || finalURL != url || finalGeneration != generation {
		t.Fatalf("concurrent stable URL = (%q, %d, %v)", finalURL, finalGeneration, err)
	}
}

func TestValidatePersistentStateRejectsTamperedAuthority(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	service, store := newBoundTestService(t, &now, "account-one")
	plan, err := service.PrepareRuntimeCommit(context.Background(), "account-one")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := selector.NewRegistry(plan.Generation)
	if err != nil {
		t.Fatal(err)
	}
	built, err := registry.BuildWithTombstones(plan.Generation.Generation, []state.Node{{
		ID: "active-node", Provider: "WIFIIN", Host: "node.example.test", Port: 1080, Name: "Active", Group: "Test", Eligible: true,
	}}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &state.RuntimeSnapshot{
		Generation: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		Account: state.NewAccountSummary("account-one", false, time.Time{}),
		Session: state.SessionSecrets{UserID: "account-one", LoginToken: "login", ProviderToken: "provider", TunnelPassword: "tunnel", TunnelMethod: "aes-256-cfb", ProviderExtension: "|provider|cc.fancast.major|order|account-one|MAC|1.0.46"},
		Nodes:   built.Nodes, Selectors: built.Selectors,
	}
	if _, err := service.CommitRuntimeSnapshot(context.Background(), plan, snapshot); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePersistentState(persisted); err != nil {
		t.Fatalf("valid persisted authority: %v", err)
	}
	tamperedBody := persisted.Clone()
	tamperedBody.LastGood.RenderedSubscription += "x"
	if err := ValidatePersistentState(tamperedBody); err == nil {
		t.Fatal("tampered rendered subscription was accepted")
	}
	tamperedSelector := persisted.Clone()
	tamperedSelector.ActiveSession.Nodes[0].Selector = "tampered-selector"
	if err := ValidatePersistentState(tamperedSelector); err == nil {
		t.Fatal("tampered active selector was accepted")
	}
	missingLastGood := persisted.Clone()
	missingLastGood.LastGood = state.LastGoodState{}
	if err := ValidatePersistentState(missingLastGood); err == nil {
		t.Fatal("active session without rendered subscription was accepted")
	}
	tamperedProjection := persisted.Clone()
	tamperedProjection.ActiveSession.Nodes[0].Name = "Different"
	if err := ValidatePersistentState(tamperedProjection); err == nil {
		t.Fatal("mismatched LastGood and active node projection was accepted")
	}
	tamperedAlias := persisted.Clone()
	tamperedAlias.ActiveSession.Selectors["extra-selector"] = state.NodeRef{NodeID: tamperedAlias.ActiveSession.Nodes[0].ID, Generation: tamperedAlias.Subscription.Generation}
	if err := ValidatePersistentState(tamperedAlias); err == nil {
		t.Fatal("extra live selector alias was accepted")
	}
}

func newBoundTestService(t *testing.T, now *time.Time, account string) (*Service, *state.SQLiteStore) {
	return newBoundTestServiceAt(t, now, account, "127.0.0.1:10808")
}

func newBoundTestServiceAt(t *testing.T, now *time.Time, account, socksAddress string) (*Service, *state.SQLiteStore) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewSQLiteStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	persistent, err := state.NewPersistentState()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistent.SetAccessToken("0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(persistent); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{Store: store, SocksAddress: socksAddress, Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.PublishAccount(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	return service, store
}

func testSnapshot(name string) *state.RuntimeSnapshot {
	return &state.RuntimeSnapshot{Nodes: []state.Node{{
		ID: "node-one", Provider: "WIFIIN", Host: "node.example.com", Port: 11000,
		Name: name, Group: "Test", Eligible: true,
	}}}
}

func publish(t *testing.T, service *Service, snapshot *state.RuntimeSnapshot) {
	t.Helper()
	if err := service.PublishSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
}

func bindingFromURL(t *testing.T, value string) string {
	t.Helper()
	parts := strings.Split(value, "/")
	if len(parts) != 5 || parts[3] != "sub" || !validBinding(parts[4]) {
		t.Fatalf("invalid subscription URL %q", value)
	}
	return parts[4]
}

func serveBinding(service *Service, binding string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:10809/sub/"+binding, nil)
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	return response
}

func decodedSubscription(t *testing.T, body string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(decoded)
}

type shortWriter struct {
	header http.Header
	writeN int
}

func (w *shortWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (*shortWriter) WriteHeader(int) {}
func (w *shortWriter) Write(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, nil
	}
	return w.writeN, nil
}

type chunkWriter struct {
	total  int
	max    int
	writes int
}

func (w *chunkWriter) Write(body []byte) (int, error) {
	w.total += len(body)
	w.writes++
	if len(body) > w.max {
		w.max = len(body)
	}
	return len(body), nil
}

type testError struct {
	operation string
	status    int
}

func (e testError) Error() string { return e.operation + " status " + strconv.Itoa(e.status) }
func fmtError(operation string, status int) error {
	return testError{operation: operation, status: status}
}

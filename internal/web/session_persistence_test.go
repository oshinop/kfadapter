package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type persistedBrowserSession struct {
	csrf      string
	expiresAt time.Time
}

type fakeBrowserSessionPersistence struct {
	mu           sync.Mutex
	sessions     map[string]persistedBrowserSession
	restoreErr   error
	saveErr      error
	deleteErr    error
	restoreCalls int
	saveCalls    int
	deleteCalls  int
}

func (p *fakeBrowserSessionPersistence) RestoreBrowserSessions(now time.Time, max int, add func(token, csrf string, expiresAt time.Time) error) error {
	p.mu.Lock()
	p.restoreCalls++
	if p.restoreErr != nil {
		err := p.restoreErr
		p.mu.Unlock()
		return err
	}
	rows := make(map[string]persistedBrowserSession, len(p.sessions))
	for token, session := range p.sessions {
		if now.Before(session.expiresAt) {
			rows[token] = session
			continue
		}
		delete(p.sessions, token)
	}
	p.mu.Unlock()

	count := 0
	for token, session := range rows {
		if count >= max {
			break
		}
		if err := add(token, session.csrf, session.expiresAt); err != nil {
			return err
		}
		count++
	}
	return nil
}

func (p *fakeBrowserSessionPersistence) SaveBrowserSession(token, csrf string, expiresAt time.Time, _ int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saveCalls++
	if p.saveErr != nil {
		return p.saveErr
	}
	if p.sessions == nil {
		p.sessions = make(map[string]persistedBrowserSession)
	}
	p.sessions[token] = persistedBrowserSession{csrf: csrf, expiresAt: expiresAt}
	return nil
}

func (p *fakeBrowserSessionPersistence) DeleteBrowserSession(token string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deleteCalls++
	if p.deleteErr != nil {
		return p.deleteErr
	}
	delete(p.sessions, token)
	return nil
}

func newPersistentTestAPI(t *testing.T, now func() time.Time, backend *fakeBackend, persistence BrowserSessionPersistence) *API {
	t.Helper()
	config := testConfig()
	config.Now = now
	config.SessionTTL = time.Hour
	api, err := NewAPI(config, Dependencies{
		Backend:       backend,
		Subscriptions: newFakeSubscriptions(),
		Sessions:      persistence,
	})
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func TestBrowserSessionPersistsAcrossAPIRecreationUntilExpiry(t *testing.T) {
	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	persistence := &fakeBrowserSessionPersistence{}
	backend := &fakeBackend{}
	clock := func() time.Time { return now }

	api := newPersistentTestAPI(t, clock, backend, persistence)
	cookie, csrf := establish(t, api)
	api = newPersistentTestAPI(t, clock, backend, persistence)

	restored := request(api, http.MethodGet, "/api/v1/access/status", "", cookie, "")
	assertAccessStatus(t, restored, true, true, true)
	var response struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(restored.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.CSRFToken != csrf {
		t.Fatalf("restored csrf = %q, want original csrf", response.CSRFToken)
	}

	now = now.Add(2 * time.Hour)
	expiredAPI := newPersistentTestAPI(t, clock, backend, persistence)
	if response := request(expiredAPI, http.MethodGet, "/api/v1/status", "", cookie, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("expired restored session status = %d", response.Code)
	}
}

func TestBrowserSessionLockRevokesDurablyAcrossAPIRecreation(t *testing.T) {
	now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
	persistence := &fakeBrowserSessionPersistence{}
	backend := &fakeBackend{}
	clock := func() time.Time { return now }
	api := newPersistentTestAPI(t, clock, backend, persistence)
	cookie, csrf := establish(t, api)

	locked := requestWithCSRF(api, http.MethodPost, "/api/v1/access/logout", `{}`, cookie, csrf)
	if locked.Code != http.StatusNoContent || !strings.Contains(locked.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("access lock = %d %#v", locked.Code, locked.Header())
	}
	persistence.mu.Lock()
	_, persisted := persistence.sessions[cookie.Value]
	persistence.mu.Unlock()
	if persisted {
		t.Fatal("locked browser session remains persisted")
	}

	recreated := newPersistentTestAPI(t, clock, backend, persistence)
	if response := request(recreated, http.MethodGet, "/api/v1/status", "", cookie, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked restored session status = %d", response.Code)
	}
}

func TestBrowserSessionPersistenceFailuresFailClosed(t *testing.T) {
	t.Run("restore failure prevents startup", func(t *testing.T) {
		_, err := NewAPI(testConfig(), Dependencies{Sessions: &fakeBrowserSessionPersistence{restoreErr: errors.New("restore failed")}})
		if err == nil {
			t.Fatal("NewAPI succeeded with failed session restoration")
		}
	})

	t.Run("corrupt restored row prevents startup", func(t *testing.T) {
		now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
		persistence := &fakeBrowserSessionPersistence{sessions: map[string]persistedBrowserSession{
			"corrupt": {csrf: "corrupt", expiresAt: now.Add(time.Hour)},
		}}
		config := testConfig()
		config.Now = func() time.Time { return now }
		_, err := NewAPI(config, Dependencies{Sessions: persistence})
		if err == nil {
			t.Fatal("NewAPI succeeded with corrupt browser session row")
		}
	})

	t.Run("overlong restored row prevents startup", func(t *testing.T) {
		now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
		secret := strings.Repeat("A", 43)
		persistence := &fakeBrowserSessionPersistence{sessions: map[string]persistedBrowserSession{
			secret: {csrf: secret, expiresAt: now.Add(2 * time.Hour)},
		}}
		config := testConfig()
		config.Now = func() time.Time { return now }
		config.SessionTTL = time.Hour
		_, err := NewAPI(config, Dependencies{Sessions: persistence})
		if err == nil {
			t.Fatal("NewAPI succeeded with overlong restored browser session")
		}
	})

	t.Run("save failure does not authenticate", func(t *testing.T) {
		persistence := &fakeBrowserSessionPersistence{saveErr: errors.New("save failed")}
		backend := &fakeBackend{}
		api := newPersistentTestAPI(t, time.Now, backend, persistence)
		response := request(api, http.MethodPost, "/api/v1/access/setup", `{"token":"`+validTestToken+`"}`, nil, testOrigin)
		if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 {
			t.Fatalf("session save failure = %d %#v", response.Code, response.Header())
		}
	})

	t.Run("delete failure preserves live durable session", func(t *testing.T) {
		now := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
		persistence := &fakeBrowserSessionPersistence{}
		backend := &fakeBackend{}
		clock := func() time.Time { return now }
		api := newPersistentTestAPI(t, clock, backend, persistence)
		cookie, csrf := establish(t, api)
		persistence.mu.Lock()
		persistence.deleteErr = errors.New("delete failed")
		persistence.mu.Unlock()

		locked := requestWithCSRF(api, http.MethodPost, "/api/v1/access/logout", `{}`, cookie, csrf)
		if locked.Code != http.StatusServiceUnavailable || locked.Header().Get("Cache-Control") != "no-store" || locked.Header().Get("Set-Cookie") != "" {
			t.Fatalf("session delete failure = %d %#v", locked.Code, locked.Header())
		}
		if response := request(api, http.MethodGet, "/api/v1/status", "", cookie, ""); response.Code != http.StatusOK {
			t.Fatalf("session revoked in memory after failed durable delete = %d", response.Code)
		}
		recreated := newPersistentTestAPI(t, clock, backend, persistence)
		if response := request(recreated, http.MethodGet, "/api/v1/status", "", cookie, ""); response.Code != http.StatusOK {
			t.Fatalf("session missing after failed durable delete and recreation = %d", response.Code)
		}
	})
}

func TestBrowserSessionPersistenceIsOptional(t *testing.T) {
	backend := &fakeBackend{}
	api, err := NewAPI(testConfig(), Dependencies{Backend: backend, Subscriptions: newFakeSubscriptions()})
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := establish(t, api)
	if response := request(api, http.MethodGet, "/api/v1/status", "", cookie, ""); response.Code != http.StatusOK {
		t.Fatalf("nil persistence authenticated status = %d", response.Code)
	}
	locked := requestWithCSRF(api, http.MethodPost, "/api/v1/access/logout", `{}`, cookie, csrf)
	if locked.Code != http.StatusNoContent {
		t.Fatalf("nil persistence access lock = %d", locked.Code)
	}
	if response := request(api, http.MethodGet, "/api/v1/status", "", cookie, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("nil persistence revoked status = %d", response.Code)
	}
}

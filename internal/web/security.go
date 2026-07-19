package web

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "kfadapter_session"
	csrfHeaderName    = "X-CSRF-Token"
	defaultJSONLimit  = 64 << 10
	accessTokenLimit  = 4 << 10
)

type browserSession struct {
	csrf      string
	expiresAt time.Time
	done      chan struct{}
}

type accessAttempt struct {
	failures  int
	windowEnd time.Time
	blockedTo time.Time
	inFlight  bool
}

type accessAdmission uint8

const (
	accessAdmitted accessAdmission = iota
	accessBusy
	accessRateLimited
)

// loginAttempt is keyed exclusively by the opaque browser session token. It
// never stores an account identifier, password, or backend error detail.
type loginAttempt struct {
	failures  int
	windowEnd time.Time
	inFlight  bool
}

type loginAdmission uint8

const (
	loginAdmitted loginAdmission = iota
	loginBusy
	loginRateLimited
	loginSessionInactive
)

type sessionStore struct {
	mu             sync.Mutex
	sessions       map[string]browserSession
	pending        map[string]struct{}
	accessAttempts map[string]accessAttempt
	loginAttempts  map[string]loginAttempt
	persistence    BrowserSessionPersistence
	now            func() time.Time
	random         io.Reader
	ttl            time.Duration
	max            int
}

func newSessionStore(now func() time.Time, random io.Reader, ttl time.Duration, max int, persistence BrowserSessionPersistence) (*sessionStore, error) {
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	if max <= 0 {
		max = 128
	}
	store := &sessionStore{
		sessions:       make(map[string]browserSession),
		pending:        make(map[string]struct{}),
		accessAttempts: make(map[string]accessAttempt),
		loginAttempts:  make(map[string]loginAttempt),
		persistence:    persistence,
		now:            now,
		random:         random,
		ttl:            ttl,
		max:            max,
	}
	if persistence == nil {
		return store, nil
	}
	restoredAt := now().UTC()
	if err := persistence.RestoreBrowserSessions(restoredAt, max, func(token, csrf string, expiresAt time.Time) error {
		return store.restore(restoredAt, token, csrf, expiresAt)
	}); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *sessionStore) restore(now time.Time, token, csrf string, expiresAt time.Time) error {
	if !validBrowserSessionSecret(token) || !validBrowserSessionSecret(csrf) || !now.Before(expiresAt) || expiresAt.After(now.Add(s.ttl)) {
		return errors.New("invalid persisted browser session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= s.max {
		return errors.New("restored browser session limit exceeded")
	}
	if _, exists := s.sessions[token]; exists {
		return errors.New("duplicate persisted browser session")
	}
	s.sessions[token] = browserSession{csrf: csrf, expiresAt: expiresAt.UTC(), done: make(chan struct{})}
	return nil
}

func (s *sessionStore) create() (string, browserSession, error) {
	// Entropy reads are deliberately outside s.mu: a blocked entropy source must
	// not prevent a concurrent access request from observing its admission.
	for range 4 {
		token, err := randomToken(s.random, 32)
		if err != nil {
			return "", browserSession{}, err
		}
		csrf, err := randomToken(s.random, 32)
		if err != nil {
			return "", browserSession{}, err
		}
		session := browserSession{csrf: csrf, expiresAt: s.now().UTC().Add(s.ttl), done: make(chan struct{})}

		s.mu.Lock()
		expired := s.pruneLocked()
		if len(s.sessions)+len(s.pending) >= s.max {
			s.mu.Unlock()
			s.deleteBrowserSessions(expired)
			return "", browserSession{}, errors.New("browser session limit reached")
		}
		if _, collision := s.sessions[token]; collision {
			s.mu.Unlock()
			s.deleteBrowserSessions(expired)
			continue
		}
		if _, collision := s.pending[token]; collision {
			s.mu.Unlock()
			s.deleteBrowserSessions(expired)
			continue
		}
		s.pending[token] = struct{}{}
		s.mu.Unlock()
		s.deleteBrowserSessions(expired)

		if s.persistence != nil {
			err = s.persistence.SaveBrowserSession(token, csrf, session.expiresAt, s.max)
		}
		s.mu.Lock()
		delete(s.pending, token)
		usable := err == nil && s.now().Before(session.expiresAt)
		if usable {
			s.sessions[token] = session
		}
		s.mu.Unlock()
		if err != nil {
			return "", browserSession{}, err
		}
		if !usable {
			s.deleteBrowserSessions([]string{token})
			return "", browserSession{}, errors.New("browser session expired before persistence")
		}
		return token, session, nil
	}
	return "", browserSession{}, errors.New("browser session token collision")
}

func (s *sessionStore) valid(token string) (browserSession, bool) {
	if token == "" {
		return browserSession{}, false
	}
	s.mu.Lock()
	session, ok := s.sessions[token]
	expired := ok && !s.now().Before(session.expiresAt)
	if !ok || expired {
		if expired {
			s.removeSessionLocked(token)
		}
		s.mu.Unlock()
		if expired {
			s.deleteBrowserSessions([]string{token})
		}
		return browserSession{}, false
	}
	s.mu.Unlock()
	return session, true
}

func (s *sessionStore) revoke(token string) error {
	if token == "" {
		return nil
	}
	if s.persistence != nil {
		if err := s.persistence.DeleteBrowserSession(token); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.removeSessionLocked(token)
	s.mu.Unlock()
	return nil
}

func (s *sessionStore) deleteBrowserSessions(tokens []string) {
	if s.persistence == nil {
		return
	}
	for _, token := range tokens {
		if token != "" {
			_ = s.persistence.DeleteBrowserSession(token)
		}
	}
}

// matches verifies that the exact session which started a stream remains
// active. It also closes the session done signal at expiry.
func (s *sessionStore) matches(token string, expected browserSession) bool {
	if token == "" || expected.done == nil {
		return false
	}
	s.mu.Lock()
	session, ok := s.sessions[token]
	expired := ok && !s.now().Before(session.expiresAt)
	matches := ok && session.done == expected.done && !expired
	if expired {
		s.removeSessionLocked(token)
	}
	s.mu.Unlock()
	if expired {
		s.deleteBrowserSessions([]string{token})
	}
	return matches
}

func (s *sessionStore) removeSessionLocked(token string) {
	if session, ok := s.sessions[token]; ok {
		delete(s.sessions, token)
		if session.done != nil {
			close(session.done)
		}
	}
	delete(s.loginAttempts, token)
}

// beginAccess reserves the one verifier operation in flight for a source.
// Concurrent attempts are rejected before they reach the backend.
func (s *sessionStore) beginAccess(client string) (accessAdmission, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trimAccessAttemptsLocked()
	now := s.now()
	attempt, tracked := s.accessAttempts[client]
	if !tracked && len(s.accessAttempts) >= 1024 {
		return accessRateLimited, time.Second
	}
	if attempt.inFlight {
		return accessBusy, 0
	}
	if now.Before(attempt.blockedTo) {
		return accessRateLimited, attempt.blockedTo.Sub(now)
	}
	if !attempt.windowEnd.IsZero() && !now.Before(attempt.windowEnd) {
		attempt = accessAttempt{}
	}
	attempt.inFlight = true
	s.accessAttempts[client] = attempt
	return accessAdmitted, 0
}

// finishAccess releases a reservation and records only failed verification.
func (s *sessionStore) finishAccess(client string, successful, countedFailure bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempt, reserved := s.accessAttempts[client]
	if !reserved || !attempt.inFlight {
		return
	}
	attempt.inFlight = false
	if successful || !countedFailure {
		delete(s.accessAttempts, client)
		return
	}
	now := s.now()
	if attempt.windowEnd.IsZero() || !now.Before(attempt.windowEnd) {
		attempt.failures = 0
		attempt.windowEnd = now.Add(time.Minute)
	}
	attempt.failures++
	if attempt.failures >= 5 {
		attempt.failures = 0
		attempt.windowEnd = now.Add(time.Minute)
		attempt.blockedTo = now.Add(time.Minute)
	}
	s.accessAttempts[client] = attempt
	s.trimAccessAttemptsLocked()
}

// beginLogin atomically checks the per-session failure window and reserves the
// only backend login slot for that browser session. Concurrent attempts never
// reach the backend and do not count as credential failures.
func (s *sessionStore) beginLogin(token string) (loginAdmission, time.Duration) {
	s.mu.Lock()
	expired := s.pruneLocked()
	if _, active := s.sessions[token]; !active {
		s.mu.Unlock()
		s.deleteBrowserSessions(expired)
		return loginSessionInactive, 0
	}
	now := s.now()
	attempt := s.loginAttempts[token]
	if attempt.inFlight {
		s.mu.Unlock()
		s.deleteBrowserSessions(expired)
		return loginBusy, 0
	}
	if !attempt.windowEnd.IsZero() && !now.Before(attempt.windowEnd) {
		attempt = loginAttempt{}
	}
	if attempt.failures >= 5 {
		s.mu.Unlock()
		s.deleteBrowserSessions(expired)
		return loginRateLimited, attempt.windowEnd.Sub(now)
	}
	attempt.inFlight = true
	s.loginAttempts[token] = attempt
	s.mu.Unlock()
	s.deleteBrowserSessions(expired)
	return loginAdmitted, 0
}

// finishLogin releases a prior login reservation exactly once. It never
// recreates login state for a session that logout or expiry removed in flight.
func (s *sessionStore) finishLogin(token string, successful, countedFailure bool) {
	s.mu.Lock()
	session, active := s.sessions[token]
	if !active {
		delete(s.loginAttempts, token)
		s.mu.Unlock()
		return
	}
	if !s.now().Before(session.expiresAt) {
		s.removeSessionLocked(token)
		s.mu.Unlock()
		s.deleteBrowserSessions([]string{token})
		return
	}
	attempt, reserved := s.loginAttempts[token]
	if !reserved || !attempt.inFlight {
		s.mu.Unlock()
		return
	}
	if successful {
		delete(s.loginAttempts, token)
		s.mu.Unlock()
		return
	}
	now := s.now()
	if !attempt.windowEnd.IsZero() && !now.Before(attempt.windowEnd) {
		attempt.failures = 0
		attempt.windowEnd = time.Time{}
	}
	attempt.inFlight = false
	if countedFailure {
		if attempt.windowEnd.IsZero() {
			attempt.windowEnd = now.Add(time.Minute)
		}
		if attempt.failures < 5 {
			attempt.failures++
		}
	}
	if attempt.failures == 0 {
		delete(s.loginAttempts, token)
		s.mu.Unlock()
		return
	}
	s.loginAttempts[token] = attempt
	s.mu.Unlock()
}

func (s *sessionStore) pruneLocked() []string {
	now := s.now()
	var expired []string
	for token, session := range s.sessions {
		if !now.Before(session.expiresAt) {
			s.removeSessionLocked(token)
			expired = append(expired, token)
		}
	}
	for token := range s.loginAttempts {
		if _, active := s.sessions[token]; !active {
			delete(s.loginAttempts, token)
		}
	}
	s.trimAccessAttemptsLocked()
	s.trimLoginAttemptsLocked()
	return expired
}

func (s *sessionStore) trimAccessAttemptsLocked() {
	now := s.now()
	for client, attempt := range s.accessAttempts {
		if !attempt.inFlight && !now.Before(attempt.windowEnd) && !now.Before(attempt.blockedTo) {
			delete(s.accessAttempts, client)
		}
	}
	if len(s.accessAttempts) <= 1024 {
		return
	}
	for client, attempt := range s.accessAttempts {
		if attempt.inFlight {
			continue
		}
		delete(s.accessAttempts, client)
		if len(s.accessAttempts) <= 1024 {
			return
		}
	}
}

func (s *sessionStore) trimLoginAttemptsLocked() {
	now := s.now()
	for token, attempt := range s.loginAttempts {
		if !attempt.inFlight && !now.Before(attempt.windowEnd) {
			delete(s.loginAttempts, token)
		}
	}
	for len(s.loginAttempts) > s.max {
		removed := false
		for token, attempt := range s.loginAttempts {
			if attempt.inFlight {
				continue
			}
			delete(s.loginAttempts, token)
			removed = true
			break
		}
		if !removed {
			return
		}
	}
}

func randomToken(random io.Reader, bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validBrowserSessionSecret(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func exactSecretEqual(expected, given string) bool {
	if expected == "" || len(expected) != len(given) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(given)) == 1
}

func clientIdentity(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		// Every loopback representation shares one access-token budget. Separate
		// 127/8 and ::1 keys would let the same local process bypass throttling.
		return "loopback"
	}
	if host == "" {
		return "unknown"
	}
	return host
}

func isJSONContentType(header string) bool {
	mediaType, _, err := mime.ParseMediaType(header)
	return err == nil && mediaType == "application/json"
}

func readJSONBody(w http.ResponseWriter, r *http.Request, limit int, target any) error {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		return errContentType
	}
	if limit <= 0 {
		limit = defaultJSONLimit
	}
	body := http.MaxBytesReader(w, r.Body, int64(limit)+1)
	defer body.Close()
	raw, err := io.ReadAll(body)
	if raw != nil {
		defer clear(raw)
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errBodyTooLarge
		}
		return errMalformedJSON
	}
	if len(raw) > limit {
		return errBodyTooLarge
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errMalformedJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errMalformedJSON
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errMalformedJSON
	}
	return nil
}

func originAllowed(header, expected string) bool {
	if header == "" || header != expected {
		return false
	}
	parsed, err := url.Parse(header)
	return err == nil && parsed.Scheme == "http" && parsed.Host != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func setSecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

func setNoStore(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
}

func setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/api/v1",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/api/v1",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func retryAfterHeader(header http.Header, delay time.Duration) {
	seconds := int(delay.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	header.Set("Retry-After", strconv.Itoa(seconds))
}

func redactDiagnostic(value any) any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return map[string]any{"diagnostic": "redacted"}
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return map[string]any{"diagnostic": "redacted"}
	}
	return redactDiagnosticValue(decoded, "")
}

func redactDiagnosticValue(value any, key string) any {
	if diagnosticSecretKey(key) {
		return "redacted"
	}
	switch typed := value.(type) {
	case map[string]any:
		redacted := make(map[string]any, len(typed))
		for childKey, child := range typed {
			redacted[childKey] = redactDiagnosticValue(child, childKey)
		}
		return redacted
	case []any:
		redacted := make([]any, len(typed))
		for index, child := range typed {
			redacted[index] = redactDiagnosticValue(child, key)
		}
		return redacted
	case string:
		if strings.Contains(typed, "socks5://") || strings.Contains(typed, "/sub/") || looksLikeSelectorCredential(typed) {
			return "redacted"
		}
	}
	return value
}

func diagnosticSecretKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	for _, secret := range []string{"account", "password", "token", "authkey", "encryptkey", "providerextension", "capability", "accesskey", "selectorkey", "proxyauthkey", "credential", "session", "secret", "endpoint", "address", "host", "url"} {
		if strings.Contains(normalized, secret) {
			return true
		}
	}
	return false
}

func looksLikeSelectorCredential(value string) bool {
	return (strings.HasPrefix(value, "n_") && len(value) == 18) || (strings.HasPrefix(value, "p_") && len(value) == 26)
}

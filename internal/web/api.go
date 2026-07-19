// Package web provides the loopback browser control plane. It intentionally
// depends only on consumer-owned interfaces so cmd can wire control, state,
// SOCKS, and subscription implementations without an import cycle.
package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	errContentType   = errors.New("content type must be application/json")
	errBodyTooLarge  = errors.New("request body is too large")
	errMalformedJSON = errors.New("request body must be one JSON object")
)

type publicProblemError interface {
	error
	Code() string
	HTTPStatus() int
}

// Config defines the local HTTP boundary. ListenAddress is a canonical numeric
// loopback or wildcard bind address. PublicAddress is the canonical numeric
// loopback address shown to browsers and users.
type Config struct {
	ListenAddress string
	PublicAddress string
	Version       string
	StartedAt     time.Time
	Now           func() time.Time
	Random        io.Reader
	SessionTTL    time.Duration
	MaxSessions   int
	// MaxConnections bounds all accepted local HTTP connections. Zero defaults
	// to 128; values above 1024 are rejected.
	MaxConnections int
	// ReadTimeout bounds request headers plus JSON body delivery. WriteTimeout
	// bounds regular responses; SSE refreshes and clears a per-write deadline so
	// its idle lifetime is not limited by that server-wide bound.
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	JSONBodyLimit    int
	SSEMaxClients    int
	SSEMaxEventBytes int
	SSEHeartbeat     time.Duration
}

// BrowserSessionPersistence stores only opaque browser-session and CSRF
// secrets. It never receives provider credentials or local access tokens.
type BrowserSessionPersistence interface {
	RestoreBrowserSessions(now time.Time, max int, add func(token, csrf string, expiresAt time.Time) error) error
	SaveBrowserSession(token, csrf string, expiresAt time.Time, max int) error
	DeleteBrowserSession(token string) error
}

// Dependencies are injected by cmd. Backend implementations normally adapt
// control/state/SOCKS services; this package never receives their secrets.
type Dependencies struct {
	Backend       Backend
	Subscriptions SubscriptionService
	Liveness      Liveness
	Sessions      BrowserSessionPersistence
}

// Liveness reports process component health for the unauthenticated /healthz
// endpoint. It must not inspect or disclose account/upstream readiness.
type Liveness interface {
	Healthy() bool
}

// Backend is the browser-safe facade over control, state, and SOCKS services.
// NodeDetails may return only locally derived SOCKS credentials; provider and subscription authority stays hidden.
type Backend interface {
	AccessStatus(context.Context) (AccessStatus, error)
	AccessSetup(context.Context, string) error
	AccessLogin(context.Context, string) error
	Status(context.Context) (Status, error)
	Nodes(context.Context) ([]Node, error)
	NodeDetails(context.Context, string) (NodeDetails, error)
	Login(context.Context, LoginInput) (Account, error)
	Logout(context.Context) error
	Refresh(context.Context) error
	Probe(context.Context, string) (ProbeResult, error)
	Diagnostics(context.Context) (any, error)
}

// EventSource is an optional Backend capability. Subscribe must return a
// bounded source owned by the state layer and a cancellation function.
type EventSource interface {
	Subscribe(context.Context) (<-chan Event, func(), error)
}

// SubscriptionService is the browser-safe facade over the state-backed
// subscription service. It exposes a stable account-bound URL only after the
// API has authenticated the browser session.
type SubscriptionService interface {
	Metadata(context.Context) (SubscriptionMetadata, error)
	SubscriptionURL(context.Context, string) (SubscriptionURL, error)
	ServeSubscription(http.ResponseWriter, *http.Request, string)
}

// AccessStatus is deliberately limited to initialization state. The API adds
// browser-session authentication information without exposing verifier data.
type AccessStatus struct {
	Initialized bool `json:"initialized"`
}

// SubscriptionURL is a reusable, account-bound subscription endpoint.
type SubscriptionURL struct {
	URL        string `json:"url"`
	Generation uint64 `json:"generation"`
}

// Status is the browser-safe operational state.
type Status struct {
	State        string               `json:"state"`
	Version      string               `json:"version,omitempty"`
	Deployment   Deployment           `json:"deployment"`
	Account      *Account             `json:"account,omitempty"`
	ControlPlane ControlPlaneStatus   `json:"controlPlane"`
	DataPlane    DataPlaneStatus      `json:"dataPlane"`
	Nodes        NodeCounts           `json:"nodes"`
	Subscription SubscriptionMetadata `json:"subscription"`
}

type Deployment struct {
	Mode      string    `json:"mode,omitempty"`
	StartedAt time.Time `json:"startedAt,omitempty"`
}

type Account struct {
	Display   string    `json:"display,omitempty"`
	IsVIP     bool      `json:"isVip"`
	VIPEndsAt time.Time `json:"vipEndsAt,omitempty"`
}

// LoginInput carries provider credentials transiently to the runtime.
type LoginInput struct {
	Account  string
	Password string
}

type ControlPlaneStatus struct {
	LastRefreshAt time.Time `json:"lastRefreshAt,omitempty"`
	NextRefreshAt time.Time `json:"nextRefreshAt,omitempty"`
}

type DataPlaneStatus struct {
	SocksAddress string `json:"socksAddress,omitempty"`
	UDPMode      string `json:"udpMode"`
}

type NodeCounts struct {
	Total    int `json:"total"`
	Eligible int `json:"eligible"`
	Healthy  int `json:"healthy"`
}

// Node is deliberately limited to browser-safe node presentation data.
type Node struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Group        string `json:"group"`
	Provider     string `json:"provider"`
	Health       string `json:"health"`
	TCPLatencyMS int    `json:"tcpLatencyMs,omitempty"`
	UDPHealth    string `json:"udpHealth"`
	Eligible     bool   `json:"eligible"`
}

// NodeDetails is an authenticated, on-demand local SOCKS connection profile.
// Its credentials are derived locally and are never provider tunnel secrets.
type NodeDetails struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Group         string `json:"group"`
	Provider      string `json:"provider"`
	UpstreamHost  string `json:"upstreamHost"`
	UpstreamPort  int    `json:"upstreamPort"`
	SocksAddress  string `json:"socksAddress"`
	SocksUsername string `json:"socksUsername"`
	SocksPassword string `json:"socksPassword"`
	Health        string `json:"health"`
	TCPLatencyMS  int    `json:"tcpLatencyMs"`
	Generation    uint64 `json:"generation"`
}

// ProbeResult reports the latest bounded TCP probe for one node.
type ProbeResult struct {
	NodeID       string    `json:"nodeId"`
	Health       string    `json:"health"`
	TCPLatencyMS int       `json:"tcpLatencyMs,omitempty"`
	ProbedAt     time.Time `json:"probedAt"`
}

// SubscriptionMetadata intentionally excludes subscription URLs and selector
// credentials. It matches the metadata shown by the Subscription screen.
type SubscriptionMetadata struct {
	Active                bool      `json:"active"`
	Generation            uint64    `json:"generation"`
	NodeCount             int       `json:"nodeCount"`
	LastFetchedAt         time.Time `json:"lastFetchedAt,omitempty"`
	LastFetchedGeneration uint64    `json:"lastFetchedGeneration,omitempty"`
	ReloadRecommended     bool      `json:"reloadRecommended"`
}

// Event is a coarse, browser-safe SSE event. Data is validated and bounded by
// the server before it is placed on the wire.
type Event struct {
	Type string
	Data any
}

type API struct {
	config        Config
	backend       Backend
	subscriptions SubscriptionService
	liveness      Liveness
	host          string
	origin        string
	sessions      *sessionStore
	sseSlots      chan struct{}
}

// NewAPI creates a hardened browser handler. The browser endpoint is always
// the exact canonical numeric loopback public address, even when the listener
// is wildcard-bound for a container bridge.
func NewAPI(config Config, dependencies Dependencies) (*API, error) {
	if config.ListenAddress == "" {
		config.ListenAddress = "127.0.0.1:10809"
	}
	if err := validateListenAddress(config.ListenAddress); err != nil {
		return nil, err
	}
	if err := validateLoopbackHost(config.PublicAddress); err != nil {
		return nil, err
	}
	if !sameListenerPort(config.ListenAddress, config.PublicAddress) {
		return nil, errors.New("listen and public HTTP ports must match")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.JSONBodyLimit <= 0 {
		config.JSONBodyLimit = defaultJSONLimit
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 10 * time.Second
	} else if config.ReadTimeout < 0 || config.ReadTimeout > 30*time.Second {
		return nil, errors.New("invalid HTTP read timeout")
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 15 * time.Second
	} else if config.WriteTimeout < 0 || config.WriteTimeout > 30*time.Second {
		return nil, errors.New("invalid HTTP write timeout")
	}
	if config.SSEMaxClients <= 0 {
		config.SSEMaxClients = 8
	}
	if config.SSEMaxEventBytes <= 0 {
		config.SSEMaxEventBytes = 4 << 10
	}
	if config.SSEHeartbeat <= 0 {
		config.SSEHeartbeat = 15 * time.Second
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 128
	} else if config.MaxConnections < 1 || config.MaxConnections > 1024 {
		return nil, errors.New("invalid HTTP connection limit")
	}
	if config.StartedAt.IsZero() {
		config.StartedAt = config.Now().UTC()
	}
	sessions, err := newSessionStore(config.Now, config.Random, config.SessionTTL, config.MaxSessions, dependencies.Sessions)
	if err != nil {
		return nil, fmt.Errorf("restore browser sessions: %w", err)
	}
	return &API{
		config: config, backend: dependencies.Backend, subscriptions: dependencies.Subscriptions,
		liveness: dependencies.Liveness, host: config.PublicAddress, origin: "http://" + config.PublicAddress,
		sessions: sessions,
		sseSlots: make(chan struct{}, config.SSEMaxClients),
	}, nil
}

// ServeHTTP is intentionally free of request logging. In particular, invalid
// subscription paths are never formatted into a log message.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())
	if r.Host != a.host {
		setNoStore(w.Header())
		a.writeProblem(w, http.StatusBadRequest, "invalid_host", "Invalid Host", "")
		return
	}
	if r.URL.Path == "/healthz" {
		a.health(w, r)
		return
	}
	if r.URL.Path == "/sub" || strings.HasPrefix(r.URL.Path, "/sub/") {
		binding, ok := subscriptionPath(r.URL.Path)
		if !ok || a.subscriptions == nil {
			writeEmptyNotFound(w)
			return
		}
		a.subscriptions.ServeSubscription(w, r, binding)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1" {
		setNoStore(w.Header())
		a.serveAPI(w, r)
		return
	}
	a.serveAsset(w, r)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		a.writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", "")
		return
	}
	setNoStore(w.Header())
	if a.liveness != nil && !a.liveness.Healthy() {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, "unhealthy\n")
		}
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "ok\n")
	}
}

func (a *API) serveAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/access/status":
		a.accessStatus(w, r)
		return
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/access/setup":
		a.access(w, r, true)
		return
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/access/login":
		a.access(w, r, false)
		return
	}
	if r.URL.Path == "/api/v1/auth/session" {
		writeEmptyNotFound(w)
		return
	}
	if !knownAPIPath(r.URL.Path) {
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found", "")
		return
	}
	token, session, ok := a.authenticate(r)
	if !ok {
		a.writeProblem(w, http.StatusUnauthorized, "not_authenticated", "Authentication required", "")
		return
	}
	if r.URL.Path == "/api/v1/events" && !originAllowed(r.Header.Get("Origin"), a.origin) {
		a.writeProblem(w, http.StatusForbidden, "invalid_origin", "Invalid Origin", "")
		return
	}
	if stateChanging(r.Method) {
		if !originAllowed(r.Header.Get("Origin"), a.origin) {
			a.writeProblem(w, http.StatusForbidden, "invalid_origin", "Invalid Origin", "")
			return
		}
		if !isJSONContentType(r.Header.Get("Content-Type")) {
			a.writeProblem(w, http.StatusUnsupportedMediaType, "invalid_content_type", "Unsupported Content Type", "")
			return
		}
		if !exactSecretEqual(session.csrf, r.Header.Get(csrfHeaderName)) {
			a.writeProblem(w, http.StatusForbidden, "csrf_failed", "CSRF validation failed", "")
			return
		}
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/status":
		a.status(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/nodes":
		a.nodes(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") && strings.HasSuffix(r.URL.Path, "/details"):
		a.nodeDetails(w, r, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"), "/details"))
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/nodes/") && strings.HasSuffix(r.URL.Path, "/probe"):
		a.probe(w, r, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/"), "/probe"))
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/login":
		a.login(w, r, token)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/auth/logout":
		a.accountLogout(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/access/logout":
		a.lock(w, r, token)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/control/refresh":
		a.refresh(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/subscription":
		a.subscriptionMetadata(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/subscription/url":
		a.subscriptionURL(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/events":
		a.events(w, r, token, session)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/diagnostics/export":
		a.diagnostics(w, r)
	default:
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found", "")
	}
}

func (a *API) accessStatus(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	status, err := a.backend.AccessStatus(r.Context())
	if err != nil {
		a.writeAccessError(w, err)
		return
	}
	response := struct {
		Initialized   bool       `json:"initialized"`
		Authenticated bool       `json:"authenticated"`
		CSRFToken     string     `json:"csrfToken,omitempty"`
		ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	}{Initialized: status.Initialized}
	if _, session, authenticated := a.authenticate(r); authenticated {
		response.Authenticated = true
		response.CSRFToken = session.csrf
		expiresAt := session.expiresAt
		response.ExpiresAt = &expiresAt
	}
	a.writeJSON(w, http.StatusOK, response)
}

func (a *API) access(w http.ResponseWriter, r *http.Request, setup bool) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if !originAllowed(r.Header.Get("Origin"), a.origin) {
		a.writeProblem(w, http.StatusForbidden, "invalid_origin", "Invalid Origin", "")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := readJSONBody(w, r, accessTokenLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	defer clearString(&body.Token)
	body.Token = strings.TrimSpace(body.Token)
	client := clientIdentity(r.RemoteAddr)
	admission, retry := a.sessions.beginAccess(client)
	switch admission {
	case accessBusy:
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, http.StatusTooManyRequests, "access_in_progress", "Access request in progress", "")
		return
	case accessRateLimited:
		retryAfterHeader(w.Header(), retry)
		a.writeProblem(w, http.StatusTooManyRequests, "access_rate_limited", "Too Many Requests", "")
		return
	}
	successful, countedFailure := false, false
	defer func() { a.sessions.finishAccess(client, successful, countedFailure) }()
	if !validAccessToken(body.Token) {
		countedFailure = true
		a.writeProblem(w, http.StatusUnauthorized, "invalid_access_token", "Authentication required", "")
		return
	}
	var err error
	if setup {
		err = a.backend.AccessSetup(r.Context(), body.Token)
	} else {
		err = a.backend.AccessLogin(r.Context(), body.Token)
	}
	if err != nil {
		countedFailure = accessFailureCounts(err)
		a.writeAccessError(w, err)
		return
	}
	successful = true
	token, session, err := a.sessions.create()
	if err != nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "session_unavailable", "Session unavailable", "")
		return
	}
	status := http.StatusOK
	if setup {
		status = http.StatusCreated
	}
	setSessionCookie(w, token, session.expiresAt)
	a.writeJSON(w, status, struct {
		Initialized   bool      `json:"initialized"`
		Authenticated bool      `json:"authenticated"`
		CSRFToken     string    `json:"csrfToken"`
		ExpiresAt     time.Time `json:"expiresAt"`
	}{Initialized: true, Authenticated: true, CSRFToken: session.csrf, ExpiresAt: session.expiresAt})
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	status, err := a.backend.Status(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "status_unavailable", http.StatusServiceUnavailable)
		return
	}
	status.Account = redactAccount(status.Account)
	status.Version = firstNonEmpty(status.Version, a.config.Version)
	if status.Deployment.StartedAt.IsZero() {
		status.Deployment.StartedAt = a.config.StartedAt
	}
	if a.subscriptions != nil {
		metadata, err := a.subscriptions.Metadata(r.Context())
		if err != nil {
			a.writeBackendError(w, err, "subscription_unavailable", http.StatusServiceUnavailable)
			return
		}
		status.Subscription = metadata
	}
	a.writeJSON(w, http.StatusOK, status)
}

func (a *API) nodes(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	nodes, err := a.backend.Nodes(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "nodes_unavailable", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, struct {
		Nodes []Node `json:"nodes"`
	}{Nodes: nodes})
}

func (a *API) nodeDetails(w http.ResponseWriter, r *http.Request, id string) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if !validResourceID(id) {
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found", "")
		return
	}
	details, err := a.backend.NodeDetails(r.Context(), id)
	if err != nil {
		a.writeBackendError(w, err, "node_details_unavailable", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, details)
}

func (a *API) login(w http.ResponseWriter, r *http.Request, token string) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	var body struct {
		Account  string `json:"account"`
		Password string `json:"password"`
	}
	if err := readJSONBody(w, r, a.config.JSONBodyLimit, &body); err != nil {
		a.writeBodyError(w, err)
		return
	}
	defer clearString(&body.Password)
	if !validEmail(body.Account) || body.Password == "" {
		a.writeProblem(w, http.StatusBadRequest, "invalid_login", "Invalid login", "")
		return
	}
	admission, retry := a.sessions.beginLogin(token)
	switch admission {
	case loginBusy:
		w.Header().Set("Retry-After", "1")
		a.writeProblem(w, http.StatusTooManyRequests, "login_in_progress", "Login already in progress", "")
		return
	case loginRateLimited:
		retryAfterHeader(w.Header(), retry)
		a.writeProblem(w, http.StatusTooManyRequests, "login_rate_limited", "Too Many Requests", "")
		return
	case loginSessionInactive:
		a.writeProblem(w, http.StatusUnauthorized, "not_authenticated", "Authentication required", "")
		return
	}
	successful, countedFailure := false, false
	defer func() { a.sessions.finishLogin(token, successful, countedFailure) }()
	account, err := a.backend.Login(r.Context(), LoginInput{Account: body.Account, Password: body.Password})
	if err != nil {
		countedFailure = loginFailureCounts(err)
		a.writeBackendError(w, err, "login_failed", http.StatusUnauthorized)
		return
	}
	successful = true
	a.writeJSON(w, http.StatusOK, redactAccount(&account))
}

func (a *API) accountLogout(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	if err := a.backend.Logout(r.Context()); err != nil {
		a.writeBackendError(w, err, "logout_failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) lock(w http.ResponseWriter, r *http.Request, token string) {
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	if err := a.revokeBrowserSession(token); err != nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "session_unavailable", "Session unavailable", "")
		return
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) revokeBrowserSession(token string) error {
	return a.sessions.revoke(token)
}

func (a *API) refresh(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	if err := a.backend.Refresh(r.Context()); err != nil {
		a.writeBackendError(w, err, "refresh_failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (a *API) probe(w http.ResponseWriter, r *http.Request, id string) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if !validResourceID(id) {
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found", "")
		return
	}
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	result, err := a.backend.Probe(r.Context(), id)
	if err != nil {
		a.writeBackendError(w, err, "probe_failed", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, result)
}

func (a *API) subscriptionMetadata(w http.ResponseWriter, r *http.Request) {
	if a.subscriptions == nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "subscription_unavailable", "Subscription unavailable", "")
		return
	}
	metadata, err := a.subscriptions.Metadata(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "subscription_unavailable", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, metadata)
}

func (a *API) subscriptionURL(w http.ResponseWriter, r *http.Request) {
	if a.subscriptions == nil {
		a.writeProblem(w, http.StatusServiceUnavailable, "subscription_unavailable", "Subscription unavailable", "")
		return
	}
	subscriptionURL, err := a.subscriptions.SubscriptionURL(r.Context(), a.baseURL())
	if err != nil {
		a.writeBackendError(w, err, "subscription_unavailable", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, subscriptionURL)
}

func (a *API) diagnostics(w http.ResponseWriter, r *http.Request) {
	if a.backend == nil {
		a.backendUnavailable(w)
		return
	}
	if err := a.requireEmptyJSON(w, r); err != nil {
		a.writeBodyError(w, err)
		return
	}
	diagnostic, err := a.backend.Diagnostics(r.Context())
	if err != nil {
		a.writeBackendError(w, err, "diagnostics_unavailable", http.StatusServiceUnavailable)
		return
	}
	redacted := redactDiagnostic(diagnostic)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		a.writeProblem(w, http.StatusInternalServerError, "diagnostics_unavailable", "Diagnostics unavailable", "")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"kfadapter-diagnostics.json\"")
	w.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func (a *API) writeSSE(w http.ResponseWriter, flusher http.Flusher, payload string) bool {
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(a.config.WriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return false
	}
	defer controller.SetWriteDeadline(time.Time{})
	if _, err := io.WriteString(w, payload); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func (a *API) events(w http.ResponseWriter, r *http.Request, token string, session browserSession) {
	if !a.sessions.matches(token, session) {
		a.writeProblem(w, http.StatusUnauthorized, "not_authenticated", "Authentication required", "")
		return
	}
	source, ok := a.backend.(EventSource)
	if !ok {
		a.writeProblem(w, http.StatusServiceUnavailable, "events_unavailable", "Events unavailable", "")
		return
	}
	select {
	case a.sseSlots <- struct{}{}:
		defer func() { <-a.sseSlots }()
	default:
		a.writeProblem(w, http.StatusTooManyRequests, "sse_capacity", "Event capacity reached", "")
		return
	}
	streamContext, stopStream := context.WithCancel(r.Context())
	defer stopStream()
	events, cancel, err := source.Subscribe(streamContext)
	if err != nil {
		a.writeBackendError(w, err, "events_unavailable", http.StatusServiceUnavailable)
		return
	}
	defer cancel()
	flusher, ok := w.(http.Flusher)
	if !ok {
		a.writeProblem(w, http.StatusInternalServerError, "streaming_unavailable", "Streaming unavailable", "")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	if !a.writeSSE(w, flusher, "retry: 1000\n\n") {
		return
	}
	heartbeat := time.NewTicker(a.config.SSEHeartbeat)
	defer heartbeat.Stop()
	checkEvery := a.config.SSEHeartbeat
	if checkEvery > 15*time.Second {
		checkEvery = 15 * time.Second
	}
	sessionCheck := time.NewTicker(checkEvery)
	defer sessionCheck.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-session.done:
			return
		case <-sessionCheck.C:
			if !a.sessions.matches(token, session) {
				return
			}
		case <-heartbeat.C:
			if !a.writeSSE(w, flusher, ": keepalive\n\n") {
				return
			}
		case event, open := <-events:
			if !open {
				return
			}
			if !a.sessions.matches(token, session) {
				return
			}
			if event.Type == "" || strings.ContainsAny(event.Type, "\r\n") {
				continue
			}
			payload, err := json.Marshal(redactDiagnostic(event.Data))
			if err != nil || len(payload) > a.config.SSEMaxEventBytes {
				continue
			}
			if !a.writeSSE(w, flusher, fmt.Sprintf("event: %s\ndata: %s\n\n", event.Type, payload)) {
				return
			}
		}
	}
}

func (a *API) authenticate(r *http.Request) (string, browserSession, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", browserSession{}, false
	}
	session, ok := a.sessions.valid(cookie.Value)
	return cookie.Value, session, ok
}

func (a *API) requireEmptyJSON(w http.ResponseWriter, r *http.Request) error {
	var body struct{}
	return readJSONBody(w, r, a.config.JSONBodyLimit, &body)
}

func (a *API) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *API) writeProblem(w http.ResponseWriter, status int, code, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail,omitempty"`
	}{Code: code, Status: status, Title: title, Detail: detail})
}

func (a *API) writeBodyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errContentType):
		a.writeProblem(w, http.StatusUnsupportedMediaType, "invalid_content_type", "Unsupported Content Type", "")
	case errors.Is(err, errBodyTooLarge):
		a.writeProblem(w, http.StatusRequestEntityTooLarge, "body_too_large", "Request body too large", "")
	default:
		a.writeProblem(w, http.StatusBadRequest, "invalid_json", "Invalid JSON", "")
	}
}

func (a *API) writeBackendError(w http.ResponseWriter, err error, fallback string, status int) {
	var public publicProblemError
	if errors.As(err, &public) {
		code := public.Code()
		if code == "" {
			code = fallback
		}
		publicStatus := public.HTTPStatus()
		if publicStatus >= 400 && publicStatus <= 599 {
			status = publicStatus
		}
		a.writeProblem(w, status, code, problemTitle(status), "")
		return
	}
	a.writeProblem(w, status, fallback, problemTitle(status), "")
}

func (a *API) writeAccessError(w http.ResponseWriter, err error) {
	var public publicProblemError
	if errors.As(err, &public) {
		switch public.HTTPStatus() {
		case http.StatusConflict:
			a.writeProblem(w, http.StatusConflict, "access_initialized", "Conflict", "")
			return
		case http.StatusUnauthorized:
			a.writeProblem(w, http.StatusUnauthorized, "invalid_access_token", "Authentication required", "")
			return
		}
	}
	a.writeProblem(w, http.StatusServiceUnavailable, "access_unavailable", "Service unavailable", "")
}

func accessFailureCounts(err error) bool {
	var public publicProblemError
	return errors.As(err, &public) && public.HTTPStatus() == http.StatusUnauthorized
}

func loginFailureCounts(err error) bool {
	var public publicProblemError
	return !errors.As(err, &public) || public.Code() == "login_rejected"
}

func (a *API) backendUnavailable(w http.ResponseWriter) {
	a.writeProblem(w, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "")
}

func (a *API) baseURL() string { return "http://" + a.config.PublicAddress }

func validateLoopbackHost(hostport string) error {
	ip, err := canonicalNumericAddress(hostport)
	if err != nil || !ip.IsLoopback() {
		return errors.New("public address must be a canonical numeric loopback address with a port")
	}
	return nil
}

func validateListenAddress(hostport string) error {
	ip, err := canonicalNumericAddress(hostport)
	if err != nil || (!ip.IsLoopback() && !ip.IsUnspecified()) {
		return errors.New("listen address must be a canonical numeric loopback or wildcard address with a port")
	}
	return nil
}

func canonicalNumericAddress(hostport string) (netip.Addr, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || host == "" || port == "" {
		return netip.Addr{}, errors.New("host and port are required")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || strconv.FormatUint(parsedPort, 10) != port {
		return netip.Addr{}, errors.New("port must be canonical")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.String() != host {
		return netip.Addr{}, errors.New("address must be canonical")
	}
	return ip, nil
}

func sameListenerPort(listenAddress, publicAddress string) bool {
	_, listenPort, listenErr := net.SplitHostPort(listenAddress)
	_, publicPort, publicErr := net.SplitHostPort(publicAddress)
	return listenErr == nil && publicErr == nil && listenPort == publicPort
}

func subscriptionPath(requestPath string) (string, bool) {
	parts := strings.Split(requestPath, "/")
	if len(parts) != 3 || parts[0] != "" || parts[1] != "sub" || len(parts[2]) != 43 {
		return "", false
	}
	binding, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(binding) != 32 || base64.RawURLEncoding.EncodeToString(binding) != parts[2] {
		return "", false
	}
	clear(binding)
	return parts[2], true
}

func knownAPIPath(requestPath string) bool {
	switch requestPath {
	case "/api/v1/status", "/api/v1/nodes", "/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/access/logout", "/api/v1/control/refresh", "/api/v1/subscription", "/api/v1/subscription/url", "/api/v1/events", "/api/v1/diagnostics/export":
		return true
	}
	return strings.HasPrefix(requestPath, "/api/v1/nodes/") && (strings.HasSuffix(requestPath, "/details") || strings.HasSuffix(requestPath, "/probe"))
}

func stateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func validEmail(value string) bool {
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && strings.Contains(value, "@") && !strings.ContainsAny(value, "\r\n")
}

func validResourceID(value string) bool {
	return value != "" && value == path.Base(value) && !strings.ContainsAny(value, "\r\n") && len(value) <= 256
}

func validAccessToken(token string) bool {
	return utf8.ValidString(token) && len(token) >= 16 && len(token) <= 128
}

func redactAccount(account *Account) *Account {
	if account == nil {
		return nil
	}
	clone := *account
	clone.Display = maskAccount(clone.Display)
	return &clone
}

func maskAccount(account string) string {
	if account == "" {
		return ""
	}
	if strings.Contains(account, "•••") {
		return account
	}
	at := strings.IndexByte(account, '@')
	if at > 0 {
		return string([]rune(account[:at])[0]) + "•••" + account[at:]
	}
	runes := []rune(account)
	if len(runes) == 0 {
		return ""
	}
	return string(runes[0]) + "•••"
}

func clearString(value *string) {
	if value == nil || *value == "" {
		return
	}
	bytes := []byte(*value)
	clear(bytes)
	*value = ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func problemTitle(status int) string {
	return http.StatusText(status)
}

func writeEmptyNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNotFound)
}

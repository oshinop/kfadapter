package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kfadapter/kfadapter/internal/control"
	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/subscription"
	"github.com/kfadapter/kfadapter/internal/web"
)

const (
	defaultProbeTimeout       = 5 * time.Second
	minRefreshPolicy          = 15 * time.Minute
	maxRefreshPolicy          = 24 * time.Hour
	refreshExpirySafetyMargin = 30 * time.Minute
	refreshRetryAttemptBudget = 5 * time.Minute
)

// CompatibilityOSVersion is the legacy LSMinimumSystemVersion client
// fingerprint accepted by the provider. It is fixed so the service never
// reveals its host operating system.
const CompatibilityOSVersion = "10.15\n"

var errRuntimeStopped = errors.New("app: runtime stopped")

// ErrProbeBusy is returned immediately when all bounded direct-probe slots are
// in use. Callers must retry later rather than creating an unbounded dial queue.
var ErrProbeBusy = errors.New("app: probe capacity reached")

// ErrStaleProbe means a refresh or node replacement invalidated the pinned
// probe target before its result could be applied.
var ErrStaleProbe = errors.New("app: stale probe")

// accessError is a browser-safe access-token failure. It retains the internal
// cause for Go callers while exposing only a stable public classification.
type accessError struct {
	cause  error
	code   string
	status int
}

func (e *accessError) Error() string {
	switch e.code {
	case "access_initialized":
		return "access token already initialized"
	case "access_invalid":
		return "access token rejected"
	default:
		return "access unavailable"
	}
}

func (e *accessError) Unwrap() error   { return e.cause }
func (e *accessError) Code() string    { return e.code }
func (e *accessError) HTTPStatus() int { return e.status }

func classifyAccessSetupError(cause error) error {
	switch {
	case errors.Is(cause, state.ErrAccessTokenAlreadyInitialized):
		return &accessError{cause: cause, code: "access_initialized", status: http.StatusConflict}
	case errors.Is(cause, state.ErrInvalidAccessToken):
		return &accessError{cause: cause, code: "access_invalid", status: http.StatusUnauthorized}
	default:
		return &accessError{cause: cause, code: "access_unavailable", status: http.StatusServiceUnavailable}
	}
}

func invalidAccessError() error {
	return &accessError{cause: state.ErrInvalidAccessToken, code: "access_invalid", status: http.StatusUnauthorized}
}

type staleProbeError struct{}

func (staleProbeError) Error() string   { return "probe result is stale" }
func (staleProbeError) Unwrap() error   { return ErrStaleProbe }
func (staleProbeError) Code() string    { return "stale_probe" }
func (staleProbeError) HTTPStatus() int { return http.StatusConflict }

// loginError exposes only a stable browser-safe problem classification. The
// wrapped cause remains available to Go callers for errors.Is, but its text is
// never suitable for transport or diagnostics.
type loginError struct {
	cause  error
	code   string
	status int
}

func (e *loginError) Error() string {
	switch e.code {
	case "login_rejected":
		return "login rejected"
	case "operation_in_progress":
		return "login operation in progress"
	default:
		return "login unavailable"
	}
}

func (e *loginError) Unwrap() error   { return e.cause }
func (e *loginError) Code() string    { return e.code }
func (e *loginError) HTTPStatus() int { return e.status }

func classifyLoginError(cause error) error {
	switch {
	case errors.Is(cause, control.ErrLoginRejected):
		return &loginError{cause: cause, code: "login_rejected", status: http.StatusUnauthorized}
	case errors.Is(cause, state.ErrOperationInProgress):
		return &loginError{cause: cause, code: "operation_in_progress", status: http.StatusConflict}
	default:
		return &loginError{cause: cause, code: "login_unavailable", status: http.StatusServiceUnavailable}
	}
}

// Refresher is the non-secret control-plane contract Runtime needs. The
// production control.Refresher satisfies it; the narrow interface makes the
// browser facade testable without a network client.
type Refresher interface {
	Login(context.Context, control.EmailLogin) error
	Refresh(context.Context) error
	ExpireIfNeeded(time.Time) (bool, error)
}

// SubscriptionPublisher prepares and atomically persists the subscription,
// rendered LastGood body, and active provider authority for one control commit.
type SubscriptionPublisher interface {
	PrepareRuntimeCommit(context.Context, string) (subscription.RuntimeCommitPlan, error)
	CommitRuntimeSnapshot(context.Context, subscription.RuntimeCommitPlan, *state.RuntimeSnapshot) (func() error, error)
	Metadata() (subscription.Metadata, error)
}

// RuntimeConfig wires production stateful collaborators. Values which can
// reveal account, tunnel, selector, or subscription material are deliberately
// absent from this configuration.
type RuntimeConfig struct {
	Manager       *state.Manager
	Store         *state.SQLiteStore
	Refresher     Refresher
	Subscriptions SubscriptionPublisher
	Selectors     *SelectorCoordinator
	MutationMu    *sync.Mutex

	SocksAddress    string
	HTTPAddress     string
	Version         string
	OSVersion       string
	StartedAt       time.Time
	Now             func() time.Time
	DialContext     func(context.Context, string, string) (net.Conn, error)
	ProbeTimeout    time.Duration
	RefreshEvery    time.Duration
	ProbeConcurrent int
	EventClients    int
	EventBuffer     int
}

// Runtime is the sole browser-safe facade over state, control,
// durable preferences, and subscription publishing.
type Runtime struct {
	manager       *state.Manager
	store         *state.SQLiteStore
	refresher     Refresher
	subscriptions SubscriptionPublisher
	selectors     *SelectorCoordinator

	socksAddress string
	httpAddress  string
	version      string
	osVersion    string
	startedAt    time.Time
	now          func() time.Time
	dial         func(context.Context, string, string) (net.Conn, error)
	probeTimeout time.Duration
	probeSlots   chan struct{}

	mutations     *sync.Mutex
	mu            sync.RWMutex
	refreshEvery  time.Duration
	lastRefreshAt time.Time
	nextRefreshAt time.Time
	alive         atomic.Bool
	events        *eventHub
}

// NewRuntime validates the dependencies needed by every web.Backend method.
func NewRuntime(config RuntimeConfig) (*Runtime, error) {
	if config.Manager == nil || config.Store == nil || config.Refresher == nil || config.Subscriptions == nil || config.Selectors == nil {
		return nil, errors.New("app: runtime requires manager, store, refresher, subscription service, and selector coordinator")
	}
	if config.OSVersion == "" {
		config.OSVersion = CompatibilityOSVersion
	}
	if config.OSVersion != CompatibilityOSVersion {
		return nil, errors.New("app: unsupported control compatibility version")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.StartedAt.IsZero() {
		config.StartedAt = config.Now().UTC()
	}
	if config.DialContext == nil {
		dialer := &net.Dialer{}
		config.DialContext = dialer.DialContext
	}
	if config.ProbeTimeout <= 0 || config.ProbeTimeout > 10*time.Second {
		config.ProbeTimeout = defaultProbeTimeout
	}
	if config.ProbeConcurrent <= 0 {
		config.ProbeConcurrent = 8
	}
	if config.ProbeConcurrent > 32 {
		config.ProbeConcurrent = 32
	}
	if config.RefreshEvery < minRefreshPolicy || config.RefreshEvery > maxRefreshPolicy {
		config.RefreshEvery = 23 * time.Hour
	}
	persistent, err := config.Store.Load()
	if err != nil {
		return nil, err
	}
	if persistent.Preferences.RefreshPolicy != "" {
		refreshEvery, err := parseRefreshPolicy(persistent.Preferences.RefreshPolicy)
		if err != nil {
			return nil, err
		}
		config.RefreshEvery = refreshEvery
	}
	mutationMu := config.MutationMu
	if mutationMu == nil {
		mutationMu = &sync.Mutex{}
	}
	runtimeNow := config.Now().UTC()
	if persistent.ActiveSession != nil && !state.SessionUsable(persistent.ActiveSession, runtimeNow) {
		managerState := config.Manager.State()
		if managerState == state.StateReady || managerState == state.StateDegraded {
			if err := config.Manager.MarkExpired(runtimeNow); err != nil {
				return nil, err
			}
		}
		persistent, err = config.Store.Update(func(candidate *state.PersistentState) error {
			candidate.ActiveSession = nil
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	lastRefreshAt, nextRefreshAt := time.Time{}, time.Time{}
	if state.SessionUsable(persistent.ActiveSession, runtimeNow) {
		lastRefreshAt = persistent.ActiveSession.CreatedAt.UTC()
		nextRefreshAt = boundedRefreshAt(lastRefreshAt, persistent.ActiveSession.ExpiresAt, config.RefreshEvery)
	}
	runtime := &Runtime{
		manager: config.Manager, store: config.Store, refresher: config.Refresher,
		subscriptions: config.Subscriptions, selectors: config.Selectors,
		socksAddress: config.SocksAddress, httpAddress: config.HTTPAddress,
		version: config.Version, osVersion: config.OSVersion,
		startedAt: config.StartedAt.UTC(), now: config.Now, dial: config.DialContext,
		probeTimeout: config.ProbeTimeout, probeSlots: make(chan struct{}, config.ProbeConcurrent), mutations: mutationMu,
		refreshEvery: config.RefreshEvery, lastRefreshAt: lastRefreshAt, nextRefreshAt: nextRefreshAt,
		events: newEventHub(config.EventClients, config.EventBuffer),
	}
	runtime.alive.Store(true)
	return runtime, nil
}

// Healthy implements web.Liveness. It intentionally answers only process
// liveness; a signed-out or degraded account is still healthy.
func (r *Runtime) Healthy() bool { return r != nil && r.alive.Load() }

// Stop makes the facade unavailable, then wipes only the in-memory session
// before it closes browser events. Durable control authority remains available
// to the next process; existing relays retain only snapshots they pinned before
// this call and are drained by the process supervisor.
func (r *Runtime) Stop() {
	if r == nil {
		return
	}
	r.alive.Store(false)
	r.mutations.Lock()
	r.manager.SignOut()
	r.mutations.Unlock()
	r.events.close()
}

// RefreshEvery returns the bounded, in-memory refresh cadence.
func (r *Runtime) RefreshEvery() time.Duration {
	if r == nil || !r.alive.Load() {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.refreshEvery
}

// RefreshDue reports whether a previously scheduled authenticated refresh is
// due. A zero schedule means no login has completed in this process.
func (r *Runtime) RefreshDue(now time.Time) bool {
	if r == nil || !r.alive.Load() {
		return false
	}
	r.mu.RLock()
	next := r.nextRefreshAt
	r.mu.RUnlock()
	return !next.IsZero() && !now.Before(next)
}

// AccessStatus reports only whether an access-token verifier is configured.
// Browser-session fields are added by web and never stored here.
func (r *Runtime) AccessStatus(context.Context) (web.AccessStatus, error) {
	if r == nil {
		return web.AccessStatus{}, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return web.AccessStatus{}, errRuntimeStopped
	}
	persistent, err := r.store.Load()
	if err != nil {
		return web.AccessStatus{}, err
	}
	return web.AccessStatus{Initialized: persistent.AccessTokenInitialized()}, nil
}

// AccessSetup atomically commits the first local access-token verifier, then
// gives the manager the verifier-derived account-binding key. The raw token is
// only an input to the state mutator and is never retained by Runtime.
func (r *Runtime) AccessSetup(_ context.Context, token string) error {
	if r == nil {
		return classifyAccessSetupError(errors.New("runtime unavailable"))
	}
	if !r.alive.Load() {
		return classifyAccessSetupError(errRuntimeStopped)
	}
	r.mutations.Lock()
	defer r.mutations.Unlock()
	if !r.alive.Load() {
		return classifyAccessSetupError(errRuntimeStopped)
	}
	persistent, err := r.store.Update(func(candidate *state.PersistentState) error {
		return candidate.SetAccessToken(token)
	})
	if err != nil {
		return classifyAccessSetupError(err)
	}
	if persistent.AccessTokenVerifier == nil {
		return classifyAccessSetupError(errors.New("access verifier was not persisted"))
	}
	if err := r.manager.ConfigureBindingKey(persistent.AccessTokenVerifier.BindingKey()); err != nil {
		// The verifier is already durable. Startup will retry this deterministic
		// configuration before accepting a login, rather than risking a reset.
		return classifyAccessSetupError(err)
	}
	r.publishState()
	return nil
}

// AccessLogin verifies a submitted access token against the durable Argon2id
// verifier. Verification is constant-time within state and returns one public
// failure for unset, malformed, and mismatched tokens.
func (r *Runtime) AccessLogin(_ context.Context, token string) error {
	if r == nil {
		return classifyAccessSetupError(errors.New("runtime unavailable"))
	}
	if !r.alive.Load() {
		return classifyAccessSetupError(errRuntimeStopped)
	}
	r.mutations.Lock()
	defer r.mutations.Unlock()
	if !r.alive.Load() {
		return classifyAccessSetupError(errRuntimeStopped)
	}
	persistent, err := r.store.Load()
	if err != nil {
		return classifyAccessSetupError(err)
	}
	if !persistent.VerifyAccessToken(token) {
		return invalidAccessError()
	}
	return nil
}

// Status returns only redacted state and local listener information.
func (r *Runtime) Status(context.Context) (web.Status, error) {
	if r == nil {
		return web.Status{}, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return web.Status{}, errRuntimeStopped
	}
	status := r.manager.Status()
	metadata, err := r.subscriptionMetadata()
	if err != nil {
		return web.Status{}, err
	}
	r.mu.RLock()
	lastRefreshAt, nextRefreshAt := r.lastRefreshAt, r.nextRefreshAt
	r.mu.RUnlock()
	result := web.Status{
		State:        string(status.State),
		Version:      r.version,
		Deployment:   web.Deployment{Mode: "container", StartedAt: r.startedAt},
		ControlPlane: web.ControlPlaneStatus{LastRefreshAt: lastRefreshAt, NextRefreshAt: nextRefreshAt},
		DataPlane:    web.DataPlaneStatus{SocksAddress: r.socksAddress, UDPMode: "disabled_unverified"},
		Nodes:        web.NodeCounts{Total: status.NodeTotal, Eligible: status.Eligible},
		Subscription: metadata,
	}
	if status.Account.Display != "" {
		result.Account = &web.Account{Display: status.Account.Display, IsVIP: status.Account.IsVIP, VIPEndsAt: status.Account.VIPEndsAt}
	}
	if current := r.manager.Current(); current != nil {
		for _, node := range current.Nodes {
			if node.Health == state.NodeHealthHealthy {
				result.Nodes.Healthy++
			}
		}
	}
	return result, nil
}

// Nodes maps immutable state into the routine browser-safe node summary.
func (r *Runtime) Nodes(context.Context) ([]web.Node, error) {
	if r == nil {
		return nil, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return nil, errRuntimeStopped
	}
	current := r.manager.Current()
	if current == nil {
		return []web.Node{}, nil
	}
	result := make([]web.Node, 0, len(current.Nodes))
	for _, node := range current.Nodes {
		latency := 0
		if node.TCPRTT > 0 {
			latency = int(node.TCPRTT.Round(time.Millisecond) / time.Millisecond)
		}
		result = append(result, web.Node{
			ID: node.ID, Name: node.Name, Group: node.Group, Provider: node.Provider,
			Health: string(node.Health), TCPLatencyMS: latency, UDPHealth: string(node.UDPHealth),
			Eligible: node.Eligible,
		})
	}
	return result, nil
}

// NodeDetails returns the selected node's upstream route and the local SOCKS
// credentials currently authorized for it. The credentials are derived only
// after the active runtime snapshot and selector generation agree.
func (r *Runtime) NodeDetails(_ context.Context, nodeID string) (web.NodeDetails, error) {
	if r == nil {
		return web.NodeDetails{}, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return web.NodeDetails{}, errRuntimeStopped
	}
	r.mutations.Lock()
	defer r.mutations.Unlock()
	if !r.alive.Load() {
		return web.NodeDetails{}, errRuntimeStopped
	}
	current := r.manager.Current()
	if !state.SessionUsable(current, r.now()) {
		return web.NodeDetails{}, errors.New("app: no usable node snapshot")
	}
	node, found := current.NodeByID(nodeID)
	if !found {
		return web.NodeDetails{}, errors.New("app: node not found")
	}
	ref, found := current.Selectors[node.Selector]
	if !found || ref.Tombstoned || ref.NodeID != node.ID || ref.Generation == 0 {
		return web.NodeDetails{}, errors.New("app: node selector authority is stale")
	}
	registry := r.selectors.Registry()
	if registry == nil {
		return web.NodeDetails{}, errors.New("app: node selector authority is unavailable")
	}
	credentials, authorized := registry.Credentials(ref.Generation, selector.NodeIdentity{
		Provider: node.Provider,
		Host:     node.Host,
		Port:     int(node.Port),
	})
	if !authorized || credentials.Selector != node.Selector {
		return web.NodeDetails{}, errors.New("app: node selector authority is stale")
	}
	latency := 0
	if node.TCPRTT > 0 {
		latency = int(node.TCPRTT.Round(time.Millisecond) / time.Millisecond)
	}
	return web.NodeDetails{
		ID: node.ID, Name: node.Name, Group: node.Group, Provider: node.Provider,
		UpstreamHost: node.Host, UpstreamPort: int(node.Port),
		SocksAddress: r.socksAddress, SocksUsername: credentials.Selector, SocksPassword: credentials.Password,
		Health: string(node.Health), TCPLatencyMS: latency, Generation: ref.Generation,
	}, nil
}

// Login derives the installation identity and locally administered synthetic
// MAC solely from protected persistent randomness. It never reads hardware
// identifiers. The request password reference is dropped before control work;
// the local control input is dropped as soon as the refresher returns.
func (r *Runtime) Login(ctx context.Context, input web.LoginInput) (web.Account, error) {
	if r == nil {
		return web.Account{}, classifyLoginError(errors.New("runtime unavailable"))
	}
	if !r.alive.Load() {
		return web.Account{}, classifyLoginError(errRuntimeStopped)
	}
	r.mutations.Lock()
	defer r.mutations.Unlock()
	if !r.alive.Load() {
		return web.Account{}, classifyLoginError(errRuntimeStopped)
	}
	persistent, err := r.store.Load()
	if err != nil {
		return web.Account{}, classifyLoginError(err)
	}
	login := control.EmailLogin{
		Account: input.Account, Password: input.Password, InstallationID: persistent.InstallationID,
		MAC: syntheticMAC(persistent.InstallationID), OSVersion: r.osVersion,
	}
	input.Password = ""
	err = r.refresher.Login(ctx, login)
	login.Password = ""
	if err != nil {
		r.publish("state", lifecycleEvent{State: string(r.manager.State())})
		return web.Account{}, classifyLoginError(err)
	}
	current := r.manager.Current()
	if current == nil || !current.Session.Valid() {
		return web.Account{}, classifyLoginError(errors.New("login did not publish a complete session"))
	}
	account := web.Account{Display: current.Account.Display, IsVIP: current.Account.IsVIP, VIPEndsAt: current.Account.VIPEndsAt}
	r.recordRefresh()
	r.publishState()
	return account, nil
}

// Logout clears durable provider authority before invalidating new tunnel
// setup in state.Manager. Retained snapshot references remain available to
// existing relays until their drain.
func (r *Runtime) Logout(context.Context) error {
	if r == nil {
		return errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return errRuntimeStopped
	}
	r.mutations.Lock()
	defer r.mutations.Unlock()
	if !r.alive.Load() {
		return errRuntimeStopped
	}
	if _, err := r.store.Update(func(candidate *state.PersistentState) error {
		candidate.ActiveSession = nil
		return nil
	}); err != nil {
		return err
	}
	r.manager.SignOut()
	r.publishState()
	return nil
}

// Refresh verifies a complete control callback commit. The control callback
// persists the rendered subscription before it makes the snapshot current.
func (r *Runtime) Refresh(ctx context.Context) error {
	if r == nil {
		return errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return errRuntimeStopped
	}
	r.mutations.Lock()
	defer r.mutations.Unlock()
	if !r.alive.Load() {
		return errRuntimeStopped
	}
	before := r.manager.Current()
	if err := r.refresher.Refresh(ctx); err != nil {
		if r.manager.State() == state.StateExpired {
			if clearErr := r.clearActiveSession(); clearErr != nil {
				return errors.Join(err, clearErr)
			}
		}
		r.publish("refresh", refreshEvent{State: string(r.manager.State()), Complete: false})
		return err
	}
	current := r.manager.Current()
	if current == nil || before == nil || current.Generation <= before.Generation || !current.Session.Valid() {
		return errors.New("app: refresh did not commit a new complete generation")
	}
	r.recordRefresh()
	r.publish("refresh", refreshEvent{State: string(r.manager.State()), Generation: current.Generation, Complete: true})
	return nil
}

// Heartbeat expires stale authority and invokes a bounded refresh only for an
// authenticated service.
func (r *Runtime) Heartbeat(ctx context.Context, refresh bool) error {
	if r == nil {
		return errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return errRuntimeStopped
	}
	r.mutations.Lock()
	if !r.alive.Load() {
		r.mutations.Unlock()
		return errRuntimeStopped
	}
	expired, err := r.refresher.ExpireIfNeeded(r.now())
	if expired {
		if clearErr := r.clearActiveSession(); clearErr != nil {
			if err != nil {
				err = errors.Join(err, clearErr)
			} else {
				err = clearErr
			}
		}
	}
	r.mutations.Unlock()

	if err != nil {
		return err
	}
	if expired {
		r.publishState()
		return nil
	}
	if !refresh {
		return nil
	}
	stateNow := r.manager.State()
	if stateNow != state.StateReady && stateNow != state.StateDegraded {
		return nil
	}
	if err := r.Refresh(ctx); err != nil {
		// This path is reached only by the periodic worker. Manual Refresh
		// remains immediate, while a failed scheduled refresh cannot create a
		// minute-by-minute control-plane retry storm.
		r.scheduleRefreshRetry()
		return err
	}
	return nil
}

// Probe measures only one bounded direct TCP connection to the selected
// upstream node. It never starts SOCKS authentication or sends a destination.
func (r *Runtime) Probe(ctx context.Context, nodeID string) (web.ProbeResult, error) {
	if r == nil {
		return web.ProbeResult{}, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return web.ProbeResult{}, errRuntimeStopped
	}
	select {
	case r.probeSlots <- struct{}{}:
		defer func() { <-r.probeSlots }()
	default:
		return web.ProbeResult{}, ErrProbeBusy
	}
	r.mutations.Lock()
	if !r.alive.Load() {
		r.mutations.Unlock()
		return web.ProbeResult{}, errRuntimeStopped
	}
	current := r.manager.Current()
	if !state.SessionUsable(current, r.now()) {
		r.mutations.Unlock()
		return web.ProbeResult{}, errors.New("app: no usable node snapshot")
	}
	node, found := current.NodeByID(nodeID)
	if !found || !node.TunnelEligible() {
		r.mutations.Unlock()
		return web.ProbeResult{}, errors.New("app: node unavailable")
	}
	target := probeTarget{generation: current.Generation, id: node.ID, selector: node.Selector, provider: node.Provider, host: node.Host, port: node.Port}
	r.mutations.Unlock()

	probeCtx, cancel := context.WithTimeout(ctx, r.probeTimeout)
	defer cancel()
	started := r.now()
	connection, dialErr := r.dial(probeCtx, "tcp", net.JoinHostPort(node.Host, strconv.Itoa(int(node.Port))))
	finished := r.now().UTC()
	latency := finished.Sub(started)
	if latency < 0 {
		latency = 0
	}
	if connection != nil {
		_ = connection.Close()
	}
	health := state.NodeHealthHealthy
	if dialErr != nil {
		health = state.NodeHealthUnhealthy
	}
	result := web.ProbeResult{NodeID: nodeID, Health: string(health), ProbedAt: finished}
	if latency > 0 {
		result.TCPLatencyMS = int(latency.Round(time.Millisecond) / time.Millisecond)
	}

	r.mutations.Lock()
	if !r.alive.Load() {
		r.mutations.Unlock()
		return web.ProbeResult{}, errRuntimeStopped
	}
	latest := r.manager.Current()
	if !target.matches(latest) || !state.SessionUsable(latest, r.now()) {
		r.mutations.Unlock()
		return result, staleProbeError{}
	}
	updated, updateErr := r.updateProbe(latest, nodeID, health, latency, finished)
	r.mutations.Unlock()
	if updateErr != nil {
		return result, updateErr
	}
	if updated != nil {
		r.publish("probe", probeEvent{NodeID: nodeID, Health: string(health), TCPLatencyMS: result.TCPLatencyMS, ProbedAt: finished})
		r.publishState()
	}
	if dialErr != nil {
		return result, errors.New("app: direct TCP probe failed")
	}
	return result, nil
}

type probeTarget struct {
	generation uint64
	id         string
	selector   string
	provider   string
	host       string
	port       uint16
}

func (target probeTarget) matches(snapshot *state.RuntimeSnapshot) bool {
	if snapshot == nil || snapshot.Generation != target.generation {
		return false
	}
	node, found := snapshot.NodeByID(target.id)
	return found && node.ID == target.id && node.Selector == target.selector && node.Provider == target.provider && node.Host == target.host && node.Port == target.port
}

func (r *Runtime) updateProbe(current *state.RuntimeSnapshot, nodeID string, health state.NodeHealth, latency time.Duration, observed time.Time) (*state.RuntimeSnapshot, error) {
	if current == nil || !current.Session.Valid() {
		return nil, errors.New("app: no active node snapshot")
	}
	next := current.Clone()
	next.Generation++
	next.CreatedAt = observed
	for index := range next.Nodes {
		if next.Nodes[index].ID == nodeID {
			next.Nodes[index].Health = health
			next.Nodes[index].TCPRTT = latency
			next.Nodes[index].ProbedAt = observed
			break
		}
	}
	if err := r.manager.Commit(next); err != nil {
		return nil, err
	}
	return next, nil
}

// CommitControlSnapshotLocked is control.Refresher's sole final publication
// callback. Runtime Login and Refresh already hold mutations; it publishes the
// completed control snapshot while keeping subscription, selector, and runtime
// authority coherent through compensating rollback.
func (r *Runtime) CommitControlSnapshotLocked(snapshot *state.RuntimeSnapshot) error {
	if r == nil || snapshot == nil || !snapshot.Session.Valid() {
		return errors.New("app: incomplete control snapshot")
	}
	if !r.alive.Load() {
		return errRuntimeStopped
	}
	candidate := snapshot.Clone()
	plan, err := r.subscriptions.PrepareRuntimeCommit(context.Background(), candidate.Session.UserID)
	if err != nil {
		return err
	}
	rollbackManager, err := r.manager.InstallSubscriptionGeneration(plan.Generation, candidate.Session.UserID)
	if err != nil {
		return err
	}
	if rollbackManager == nil {
		rollbackManager = func() {}
	}
	rebuilt, rollbackSelectors, err := r.selectors.InstallGeneration(plan.Generation, candidate)
	if err != nil {
		rollbackManager()
		return err
	}
	if rollbackSelectors == nil {
		rollbackSelectors = func() {}
	}
	rollbackPersistent, err := r.subscriptions.CommitRuntimeSnapshot(context.Background(), plan, rebuilt)
	if err != nil {
		rollbackSelectors()
		rollbackManager()
		return err
	}
	if rollbackPersistent == nil {
		rollbackPersistent = func() error { return nil }
	}
	abort := func(cause error) error {
		rollbackSelectors()
		rollbackManager()
		if rollbackErr := rollbackPersistent(); rollbackErr != nil {
			return errors.Join(cause, rollbackErr)
		}
		return cause
	}
	if err := r.manager.Commit(rebuilt); err != nil {
		return abort(err)
	}
	return nil
}

func parseRefreshPolicy(value string) (time.Duration, error) {
	interval, err := time.ParseDuration(value)
	if err != nil || interval < minRefreshPolicy || interval > maxRefreshPolicy {
		return 0, errors.New("app: refresh policy must be between 15m and 24h")
	}
	return interval, nil
}

// Diagnostics returns a closed, redacted report. It intentionally omits
// account identifiers, node endpoints, selectors, capabilities, credentials,
// provider extensions, and all persistent-state content.
func (r *Runtime) Diagnostics(context.Context) (any, error) {
	if r == nil {
		return nil, errors.New("app: runtime unavailable")
	}
	if !r.alive.Load() {
		return nil, errRuntimeStopped
	}
	status := r.manager.Status()
	return struct {
		Version       string    `json:"version"`
		State         string    `json:"state"`
		Generation    uint64    `json:"generation"`
		StartedAt     time.Time `json:"startedAt"`
		RefreshPolicy string    `json:"refreshPolicy"`
		UDPMode       string    `json:"udpMode"`
		Redacted      bool      `json:"redacted"`
	}{
		Version: r.version, State: string(status.State), Generation: status.Generation,
		StartedAt: r.startedAt, RefreshPolicy: r.RefreshEvery().String(), UDPMode: "disabled_unverified", Redacted: true,
	}, nil
}

// Subscribe implements web.EventSource using a bounded, lossy per-client hub.
func (r *Runtime) Subscribe(ctx context.Context) (<-chan web.Event, func(), error) {
	if r == nil || !r.Healthy() {
		return nil, nil, errors.New("app: event source unavailable")
	}
	return r.events.subscribe(ctx)
}

func (r *Runtime) subscriptionMetadata() (web.SubscriptionMetadata, error) {
	if r == nil || !r.alive.Load() {
		return web.SubscriptionMetadata{}, errRuntimeStopped
	}
	metadata, err := r.subscriptions.Metadata()
	if err != nil {
		return web.SubscriptionMetadata{}, err
	}
	result := web.SubscriptionMetadata{
		Active: metadata.Active, Generation: metadata.Generation, NodeCount: metadata.NodeCount,
		LastFetchedAt: metadata.LastFetchedAt, LastFetchedGeneration: metadata.LastFetchedGeneration,
		ReloadRecommended: metadata.ReloadRecommended,
	}
	return result, nil
}

func boundedRefreshAt(base, expiresAt time.Time, every time.Duration) time.Time {
	next := base.Add(every)
	if expiresAt.IsZero() {
		return next
	}
	deadline := expiresAt.UTC().Add(-refreshExpirySafetyMargin)
	if next.After(deadline) {
		return deadline
	}
	return next
}

func (r *Runtime) recordRefresh() {
	now := r.now().UTC()
	expiresAt := time.Time{}
	if current := r.manager.Current(); current != nil {
		expiresAt = current.ExpiresAt
	}
	r.mu.Lock()
	r.lastRefreshAt = now
	r.nextRefreshAt = boundedRefreshAt(now, expiresAt, r.refreshEvery)
	r.mu.Unlock()
}

func (r *Runtime) scheduleRefreshRetry() {
	if r == nil {
		return
	}
	now := r.now().UTC()
	expiresAt := time.Time{}
	if current := r.manager.Current(); current != nil {
		expiresAt = current.ExpiresAt
	}
	next := now.Add(minRefreshPolicy)
	if !expiresAt.IsZero() {
		deadline := expiresAt.UTC().Add(-refreshRetryAttemptBudget)
		if !deadline.After(now) {
			r.mu.Lock()
			r.nextRefreshAt = time.Time{}
			r.mu.Unlock()
			return
		}
		if next.After(deadline) {
			next = deadline
		}
	}
	r.mu.Lock()
	if r.nextRefreshAt.IsZero() || r.nextRefreshAt.Before(next) {
		r.nextRefreshAt = next
	}
	r.mu.Unlock()
}

func (r *Runtime) clearActiveSession() error {
	if r == nil {
		return errors.New("app: runtime unavailable")
	}
	_, err := r.store.Update(func(candidate *state.PersistentState) error {
		candidate.ActiveSession = nil
		return nil
	})
	return err
}

func (r *Runtime) publishState() {
	if r == nil {
		return
	}
	status := r.manager.Status()
	r.publish("state", lifecycleEvent{State: string(status.State), Generation: status.Generation})
}

func (r *Runtime) publish(kind string, data any) {
	if r != nil {
		r.events.publish(web.Event{Type: kind, Data: data})
	}
}

func syntheticMAC(installationID string) string {
	sum := sha256.Sum256([]byte("kfadapter-synthetic-mac\x00" + installationID))
	bytes := sum[:6]
	bytes[0] = (bytes[0] | 0x02) &^ 0x01 // local, never multicast
	return hex.EncodeToString(bytes)
}

type lifecycleEvent struct {
	State      string `json:"state"`
	Generation uint64 `json:"generation,omitempty"`
}

type refreshEvent struct {
	State      string `json:"state"`
	Generation uint64 `json:"generation,omitempty"`
	Complete   bool   `json:"complete"`
}

type probeEvent struct {
	NodeID       string    `json:"nodeId"`
	Health       string    `json:"health"`
	TCPLatencyMS int       `json:"tcpLatencyMs,omitempty"`
	ProbedAt     time.Time `json:"probedAt"`
}

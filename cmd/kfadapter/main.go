// kfadapter is the container-only local KuaiFan-to-SOCKS adapter runtime.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/kfadapter/kfadapter/internal/app"
	"github.com/kfadapter/kfadapter/internal/config"
	"github.com/kfadapter/kfadapter/internal/control"
	"github.com/kfadapter/kfadapter/internal/lifecycle"
	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/socks"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/subscription"
	"github.com/kfadapter/kfadapter/internal/web"
)

const (
	configPath     = "./config.yml"
	stateDirectory = "./data"
)

// version is overwritten by Docker's -ldflags at build time.
var version = "devel"

var requireContainer = lifecycle.RequireContainer

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 || arguments[0] == "serve" || strings.HasPrefix(arguments[0], "-") {
		if err := serve(commandArgs(arguments)); err != nil {
			// Never render underlying control/state errors: they could retain
			// endpoint or upstream service context in a future implementation.
			fmt.Fprintln(stderr, "kfadapter: service stopped")
			return 1
		}
		return 0
	}
	switch arguments[0] {
	case "healthcheck":
		if err := healthcheck(arguments[1:]); err != nil {
			fmt.Fprintln(stderr, "kfadapter: healthcheck failed")
			return 1
		}
		return 0
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "validate-config":
		if err := validateConfig(arguments[1:]); err != nil {
			fmt.Fprintln(stderr, "kfadapter: invalid configuration")
			return 1
		}
		fmt.Fprintln(stdout, "configuration valid")
		return 0
	case "validate-state":
		if err := validateState(arguments[1:]); err != nil {
			fmt.Fprintln(stderr, "kfadapter: invalid state")
			return 1
		}
		fmt.Fprintln(stdout, "state valid")
		return 0
	default:
		fmt.Fprintln(stderr, "kfadapter: unknown command")
		return 2
	}
}

func commandArgs(arguments []string) []string {
	if len(arguments) > 0 && arguments[0] == "serve" {
		return arguments[1:]
	}
	return arguments
}

func loadConfig(arguments []string) (config.Config, error) {
	if len(arguments) != 0 {
		return config.Config{}, errors.New("configuration arguments are not supported")
	}
	return config.Load(configPath)
}

func validateConfig(arguments []string) error {
	_, err := loadConfig(arguments)
	return err
}

// validateState delegates secure file, integrity, schema, and aggregate
// validation to the SQLite state store without creating or modifying a file.
func validateState(arguments []string) error {
	flags := flag.NewFlagSet("validate-state", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("file", "", "")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || strings.TrimSpace(*path) == "" {
		return errors.New("invalid validate-state arguments")
	}
	return state.ValidateSQLiteFile(*path, subscription.ValidatePersistentState)
}

func healthcheck(arguments []string) error {
	cfg, err := loadConfig(arguments)
	if err != nil {
		return err
	}
	managementURL := "http://" + cfg.ManagementAddress() + "/healthz"
	proxyAddress := cfg.ProxyAddress()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, managementURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("management endpoint not live")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return err
	}
	return connection.Close()
}

func serve(arguments []string) error {
	cfg, err := loadConfig(arguments)
	if err != nil {
		return err
	}
	if err := requireContainer(); err != nil {
		return err
	}
	adapter, err := newAdapter(cfg)
	if err != nil {
		return err
	}
	return adapter.run()
}

type adapter struct {
	runtime            *app.Runtime
	manager            *state.Manager
	store              *state.SQLiteStore
	httpServer         *http.Server
	httpListener       net.Listener
	socksServer        *socks.Server
	socksListener      net.Listener
	startupLog         io.Writer
	managementEndpoint string
	proxyEndpoint      string
}

func newAdapter(cfg config.Config) (*adapter, error) {
	return newAdapterAtStateDirectory(cfg, stateDirectory)
}

func newAdapterAtStateDirectory(cfg config.Config, stateDirectory string) (result *adapter, err error) {
	store, err := state.NewSQLiteStore(stateDirectory)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = store.Close()
		}
	}()
	persistent, err := store.LoadOrCreate(subscription.ValidatePersistentState)
	if err != nil {
		return nil, err
	}
	if persistent.ActiveSession != nil && !state.SessionUsable(persistent.ActiveSession, time.Now().UTC()) {
		persistent, err = store.Update(func(candidate *state.PersistentState) error {
			candidate.ActiveSession = nil
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	var bindingKey []byte
	if persistent.AccessTokenInitialized() {
		if persistent.AccessTokenVerifier == nil {
			return nil, errors.New("access verifier missing")
		}
		bindingKey = persistent.AccessTokenVerifier.BindingKey()
	}
	manager, err := state.NewManagerWithSubscription(persistent.ActiveSession, persistent.Subscription, bindingKey)
	if err != nil {
		return nil, err
	}
	registry, err := selector.NewRegistry(persistent.Subscription)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: cfg.Proxy.DialTimeout.Value()}
	mutationMu := &sync.Mutex{}
	socksServer, err := socks.New(socks.Config{
		Snapshots: manager, Selectors: registry, DialContext: dialer.DialContext,
		HandshakeTimeout: cfg.Proxy.HandshakeTimeout.Value(),
	})
	if err != nil {
		return nil, err
	}
	coordinator, err := app.NewSelectorCoordinator(socksServer, registry, time.Now)
	if err != nil {
		return nil, err
	}
	proxyAddress := cfg.ProxyAddress()
	managementAddress := cfg.ManagementAddress()
	subscriptionService, err := subscription.NewService(subscription.ServiceConfig{
		Store: store, SocksAddress: proxyAddress, Now: time.Now, MutationLocker: mutationMu,
	})
	if err != nil {
		return nil, err
	}
	location, err := configuredLocation()
	if err != nil {
		return nil, err
	}
	client, err := control.NewClient(control.Config{
		Location: location, RequestTimeout: cfg.Provider.RequestTimeout.Value(),
	})
	if err != nil {
		return nil, err
	}
	var runtimeFacade *app.Runtime
	refresher, err := control.NewRefresher(control.RefresherConfig{
		Client: client, Manager: manager, SelectorBuilder: coordinator,
		CommitSnapshot: func(snapshot *state.RuntimeSnapshot) error {
			if runtimeFacade == nil {
				return errors.New("runtime snapshot committer unavailable")
			}
			return runtimeFacade.CommitControlSnapshotLocked(snapshot)
		},
		AuthorityLifetime: 24 * time.Hour, MaxAttempts: 3,
	})
	if err != nil {
		return nil, err
	}
	startedAt := time.Now().UTC()
	runtimeFacade, err = app.NewRuntime(app.RuntimeConfig{
		Manager: manager, Store: store, Refresher: refresher, Subscriptions: subscriptionService,
		Selectors: coordinator, MutationMu: mutationMu, SocksAddress: proxyAddress, HTTPAddress: managementAddress,
		Version: version, OSVersion: app.CompatibilityOSVersion, StartedAt: startedAt,
		RefreshEvery: cfg.Provider.RefreshInterval.Value(), ProbeTimeout: cfg.Proxy.DialTimeout.Value(),
	})
	if err != nil {
		return nil, err
	}
	server, api, err := web.NewHTTPServer(web.Config{
		ListenAddress: cfg.Management.Listen, PublicAddress: managementAddress,
		Version: version, StartedAt: startedAt, SessionTTL: cfg.Management.SessionTTL.Value(),
	}, web.Dependencies{Backend: runtimeFacade, Subscriptions: web.NewSubscriptionAdapter(subscriptionService), Sessions: store, Liveness: runtimeFacade})
	if err != nil {
		return nil, err
	}
	httpListener, err := api.Listen()
	if err != nil {
		return nil, err
	}
	socksListener, err := net.Listen("tcp", cfg.Proxy.Listen)
	if err != nil {
		_ = httpListener.Close()
		return nil, err
	}
	return &adapter{runtime: runtimeFacade, manager: manager, store: store, httpServer: server, httpListener: httpListener, socksServer: socksServer, socksListener: socksListener, startupLog: os.Stdout, managementEndpoint: "http://" + managementAddress, proxyEndpoint: "socks5://" + proxyAddress}, nil
}

func configuredLocation() (*time.Location, error) {
	zone := os.Getenv("TZ")
	if zone == "" {
		zone = "Asia/Shanghai"
	}
	return time.LoadLocation(zone)
}

// adapterDrainTimeout leaves a ten-second margin before Compose's 30-second
// stop grace period so internal cleanup completes before Docker SIGKILL.
var adapterDrainTimeout = 20 * time.Second

func newAdapterSupervisor(workers []lifecycle.Worker) (*lifecycle.Supervisor, error) {
	return lifecycle.New(workers, adapterDrainTimeout)
}

func (d *adapter) run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	return d.runContext(ctx)
}

func (d *adapter) runContext(ctx context.Context) (result error) {
	defer func() {
		if err := d.store.Close(); err != nil && result == nil {
			result = err
		}
	}()
	supervisor, err := newAdapterSupervisor([]lifecycle.Worker{
		{Name: "proxy", Run: d.runSOCKS, Shutdown: d.shutdownSOCKS},
		{Name: "management", Run: d.runWeb, Shutdown: d.shutdownWeb},
		{Name: "heartbeat", Run: d.runHeartbeat, Shutdown: func(context.Context) error { d.runtime.Stop(); return nil }},
		{Name: "watchdog", Run: lifecycle.Watchdog(10*time.Second, 3, d.watchdog)},
	})
	if err != nil {
		return err
	}
	if d.startupLog != nil {
		_, _ = fmt.Fprintf(d.startupLog, "kfadapter: ready management=%s proxy=%s\n", d.managementEndpoint, d.proxyEndpoint)
	}
	return supervisor.Run(ctx)
}

func (d *adapter) runSOCKS(ctx context.Context) error {
	return d.socksServer.Serve(ctx, d.socksListener)
}

func (d *adapter) shutdownSOCKS(ctx context.Context) error {
	return d.socksServer.Shutdown(ctx)
}

func (d *adapter) runWeb(ctx context.Context) error {
	err := d.httpServer.Serve(d.httpListener)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

func (d *adapter) shutdownWeb(ctx context.Context) error {
	return d.httpServer.Shutdown(ctx)
}

func (d *adapter) runHeartbeat(ctx context.Context) error {
	expiryTicker := time.NewTicker(time.Minute)
	defer expiryTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-expiryTicker.C:
			// Refresh failures are normal degraded-control-plane events; they
			// must not stop an otherwise healthy local adapter.
			_ = d.runtime.Heartbeat(ctx, d.runtime.RefreshDue(now))
		}
	}
}

func (d *adapter) watchdog(context.Context) error {
	if !d.runtime.Healthy() {
		return errors.New("runtime is stopped")
	}
	_, err := d.store.Load()
	return err
}

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/config"
	"github.com/kfadapter/kfadapter/internal/lifecycle"
	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
	"github.com/kfadapter/kfadapter/internal/subscription"
)

func TestHealthcheckUsesWorkingDirectoryConfig(t *testing.T) {
	for _, test := range []struct {
		name string
		bind string
	}{
		{name: "ipv4", bind: "127.0.0.1:0"},
		{name: "ipv6", bind: "[::1]:0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			managementListener, err := net.Listen("tcp", test.bind)
			if err != nil {
				if test.name == "ipv6" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer managementListener.Close()
			proxyListener, err := net.Listen("tcp", test.bind)
			if err != nil {
				t.Fatal(err)
			}
			defer proxyListener.Close()
			managementServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet || request.URL.Path != "/healthz" {
					http.NotFound(writer, request)
					return
				}
				writer.WriteHeader(http.StatusOK)
			})}
			go func() { _ = managementServer.Serve(managementListener) }()
			defer managementServer.Shutdown(context.Background())
			// Some isolated build sandboxes can bind ::1 even when its loopback route is unusable.
			if test.name == "ipv6" {
				connection, err := net.DialTimeout("tcp", managementListener.Addr().String(), 250*time.Millisecond)
				if err != nil {
					t.Skipf("IPv6 loopback connectivity unavailable: %v", err)
				}
				_ = connection.Close()
			}
			accepted := make(chan struct{}, 1)
			go func() {
				connection, err := proxyListener.Accept()
				if err == nil {
					accepted <- struct{}{}
					_ = connection.Close()
				}
			}()
			writeWorkingConfig(t, managementListener.Addr().String(), proxyListener.Addr().String())
			var stdout, stderr bytes.Buffer
			if code := run([]string{"healthcheck"}, &stdout, &stderr); code != 0 {
				t.Fatalf("healthcheck exit %d: %s", code, stderr.String())
			}
			select {
			case <-accepted:
			case <-time.After(time.Second):
				t.Fatal("healthcheck did not connect to configured proxy listener")
			}
		})
	}
}

func TestHealthcheckUsesConfiguredWildcardListeners(t *testing.T) {
	managementListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer managementListener.Close()
	proxyListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()
	managementServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/healthz" {
			http.NotFound(writer, request)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})}
	go func() { _ = managementServer.Serve(managementListener) }()
	defer managementServer.Shutdown(context.Background())
	accepted := make(chan struct{}, 1)
	go func() {
		connection, err := proxyListener.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = connection.Close()
		}
	}()
	writeWorkingConfig(t, managementListener.Addr().String(), proxyListener.Addr().String())
	var stdout, stderr bytes.Buffer
	if code := run([]string{"healthcheck"}, &stdout, &stderr); code != 0 {
		t.Fatalf("healthcheck exit %d: %s", code, stderr.String())
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("healthcheck did not probe the configured wildcard proxy endpoint")
	}
}

func TestHealthcheckAndValidateConfigRejectPathOverrides(t *testing.T) {
	if err := healthcheck([]string{"--config", "/tmp/alternate.yml"}); err == nil {
		t.Fatal("healthcheck accepted a configurable path")
	}
	if err := validateConfig([]string{"--config", "/tmp/alternate.yml"}); err == nil {
		t.Fatal("validate-config accepted a configurable path")
	}
}

func TestValidateConfigUsesWorkingDirectory(t *testing.T) {
	writeWorkingConfig(t, "127.0.0.1:10809", "127.0.0.1:10808")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"validate-config"}, &stdout, &stderr); code != 0 || stdout.String() != "configuration valid\n" || stderr.Len() != 0 {
		t.Fatalf("validate-config result code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestValidateConfigCreatesDefaultFile(t *testing.T) {
	t.Chdir(t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := run([]string{"validate-config"}, &stdout, &stderr); code != 0 || stdout.String() != "configuration valid\n" || stderr.Len() != 0 {
		t.Fatalf("validate-config result code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat default config: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("default config mode = %s", info.Mode())
	}
}

func TestValidateListenInterfaceAddresses(t *testing.T) {
	tests := []struct {
		name      string
		listen    string
		addresses []netip.Addr
		wantError bool
	}{
		{name: "assigned IPv4", listen: "192.0.2.10", addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
		{name: "unassigned IPv4", listen: "192.0.2.20", addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}, wantError: true},
		{name: "IPv4 wildcard", listen: "0.0.0.0", addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{name: "IPv4 wildcard without IPv4 NIC", listen: "0.0.0.0", addresses: []netip.Addr{netip.MustParseAddr("::1")}, wantError: true},
		{name: "IPv6 wildcard", listen: "::", addresses: []netip.Addr{netip.MustParseAddr("::1")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateListenInterfaceAddresses(test.listen, test.addresses)
			if (err != nil) != test.wantError {
				t.Fatalf("validation error = %v, wantError %t", err, test.wantError)
			}
		})
	}
}

func TestVersionCommandPrintsOnlyVersion(t *testing.T) {
	previous := version
	version = "1.2.3"
	t.Cleanup(func() { version = previous })

	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 || stdout.String() != "1.2.3\n" || stderr.Len() != 0 {
		t.Fatalf("version result code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func writeWorkingConfig(t *testing.T, managementAddress, proxyAddress string) {
	t.Helper()
	t.Chdir(t.TempDir())
	management := netip.MustParseAddrPort(managementAddress)
	proxy := netip.MustParseAddrPort(proxyAddress)
	if management.Addr() != proxy.Addr() {
		t.Fatalf("test listeners do not share an address: %s and %s", managementAddress, proxyAddress)
	}
	body := "listenAddr: \"" + management.Addr().String() + "\"\nmanagement:\n  port: " + config.Port(management.Port()).String() + "\nproxy:\n  port: " + config.Port(proxy.Port()).String() + "\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestValidateStateStrictOfflineFile(t *testing.T) {
	validPath := validPersistentStateFile(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"validate-state", "--file", validPath}, &stdout, &stderr); code != 0 || stdout.String() != "state valid\n" || stderr.Len() != 0 {
		t.Fatalf("valid state result code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	cases := []struct {
		name string
		path string
		body []byte
	}{
		{name: "missing", path: filepath.Join(t.TempDir(), "secret-missing-state.db")},
		{name: "directory", path: t.TempDir()},
		{name: "corrupt", body: []byte("not a sqlite database")},
		{name: "empty", body: nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := test.path
			if path == "" {
				path = filepath.Join(t.TempDir(), "state.db")
				if err := os.WriteFile(path, test.body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			assertInvalidStateCommand(t, []string{"validate-state", "--file", path})
		})
	}
	symlink := filepath.Join(t.TempDir(), "state-link.db")
	if err := os.Symlink(validPath, symlink); err != nil {
		t.Fatal(err)
	}
	assertInvalidStateCommand(t, []string{"validate-state", "--file", symlink})
	assertInvalidStateCommand(t, []string{"validate-state", "--file", validPath, "extra"})
}

func TestValidateStateRejectsSemanticallyInvalidSQLRows(t *testing.T) {
	t.Run("unsupported active-session method", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		_, _ = seedBoundActiveSession(t, dir, "127.0.0.1:1080")
		path := filepath.Join(dir, "state.db")
		execSQLiteMutation(t, path, "UPDATE active_session SET session_tunnel_method = 'bogus' WHERE id = 1")
		assertInvalidStateCommand(t, []string{"validate-state", "--file", path})
	})

	t.Run("overlong browser-session expiry", func(t *testing.T) {
		path := validPersistentStateFile(t)
		secret := strings.Repeat("A", 43)
		execSQLiteMutation(t, path, "INSERT INTO browser_sessions (token, csrf, expires_at_ns) VALUES (?, ?, ?)", secret, secret, time.Now().UTC().Add(48*time.Hour).UnixNano())
		assertInvalidStateCommand(t, []string{"validate-state", "--file", path})
	})
}

func execSQLiteMutation(t *testing.T, path, statement string, arguments ...any) {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(statement, arguments...); err != nil {
		_ = database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func validPersistentStateFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	path := store.Path()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertInvalidStateCommand(t *testing.T, arguments []string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := run(arguments, &stdout, &stderr); code == 0 {
		t.Fatal("invalid state was accepted")
	}
	if stdout.Len() != 0 || stderr.String() != "kfadapter: invalid state\n" || strings.Contains(stderr.String(), "secret") {
		t.Fatalf("state validation leaked detail stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestServeRejectsBareProcessAtSeam(t *testing.T) {
	writeWorkingConfig(t, "127.0.0.1:10809", "127.0.0.1:10808")
	previous := requireContainer
	requireContainer = func() error { return errors.New("bare process") }
	t.Cleanup(func() { requireContainer = previous })
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code == 0 {
		t.Fatal("bare-process serve unexpectedly succeeded")
	}
	if strings.Contains(stderr.String(), "bare process") {
		t.Fatal("serve rendered internal deployment error")
	}
}

func TestNewAdapterBindsBridgeWildcardListeners(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	managementAddress := freeLoopbackAddress(t)
	proxyAddress := freeLoopbackAddress(t)
	_, managementPort, err := net.SplitHostPort(managementAddress)
	if err != nil {
		t.Fatal(err)
	}
	_, proxyPort, err := net.SplitHostPort(proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testAdapterConfig(net.JoinHostPort("0.0.0.0", managementPort), net.JoinHostPort("0.0.0.0", proxyPort))
	adapter, err := newAdapterAtStateDirectory(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		adapter.runtime.Stop()
		_ = adapter.httpListener.Close()
		_ = adapter.socksListener.Close()
	})
	for _, listener := range []struct {
		name  string
		value net.Listener
		port  string
	}{
		{name: "management", value: adapter.httpListener, port: managementPort},
		{name: "proxy", value: adapter.socksListener, port: proxyPort},
	} {
		host, port, err := net.SplitHostPort(listener.value.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if (host != "0.0.0.0" && host != "::") || port != listener.port {
			t.Fatalf("%s listener = %q, want wildcard port %q", listener.name, listener.value.Addr(), listener.port)
		}
	}
	var startup bytes.Buffer
	adapter.startupLog = &startup
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- adapter.runContext(ctx) }()

	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+managementPort+"/healthz", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	request.Host = "0.0.0.0:" + managementPort
	response, requestErr := (&http.Client{Timeout: time.Second}).Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	proxyConnection, proxyErr := net.DialTimeout("tcp", "127.0.0.1:"+proxyPort, time.Second)
	if proxyConnection != nil {
		_ = proxyConnection.Close()
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("adapter shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("adapter did not shut down")
	}
	if requestErr != nil || response == nil || response.StatusCode != http.StatusOK {
		t.Fatalf("wildcard management request response=%v err=%v", response, requestErr)
	}
	if proxyErr != nil {
		t.Fatalf("wildcard proxy connection: %v", proxyErr)
	}
	wantStartup := "kfadapter: ready management=http://0.0.0.0:" + managementPort + " proxy=socks5://0.0.0.0:" + proxyPort + "\n"
	if startup.String() != wantStartup {
		t.Fatalf("startup log = %q, want %q", startup.String(), wantStartup)
	}
}

func TestAdapterLifecycleShutdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	managementAddress := freeLoopbackAddress(t)
	proxyAddress := freeLoopbackAddress(t)
	cfg := testAdapterConfig(managementAddress, proxyAddress)
	adapter, err := newAdapterAtStateDirectory(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	var startup bytes.Buffer
	adapter.startupLog = &startup
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- adapter.runContext(ctx) }()
	time.Sleep(25 * time.Millisecond)
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("adapter shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("adapter did not complete bounded shutdown")
	}
	if adapter.runtime.Healthy() {
		t.Fatal("runtime remained live after shutdown")
	}
	connection, err := net.DialTimeout("tcp", proxyAddress, 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("SOCKS accepted a new connection after shutdown")
	}
	if got, want := startup.String(), "kfadapter: ready management=http://"+managementAddress+" proxy=socks5://"+proxyAddress+"\n"; got != want {
		t.Fatalf("startup log = %q, want %q", got, want)
	}
}

func TestAdapterSupervisorUsesInternalDrainDeadline(t *testing.T) {
	if adapterDrainTimeout != 20*time.Second {
		t.Fatalf("production drain timeout = %s, want 20s", adapterDrainTimeout)
	}
	previous := adapterDrainTimeout
	adapterDrainTimeout = 20 * time.Millisecond
	t.Cleanup(func() { adapterDrainTimeout = previous })
	blocked := make(chan struct{})
	cleanupExpired := make(chan struct{})
	supervisor, err := newAdapterSupervisor([]lifecycle.Worker{{
		Name: "blocked",
		Run: func(ctx context.Context) error {
			<-ctx.Done()
			<-blocked
			return ctx.Err()
		},
		Shutdown: func(ctx context.Context) error {
			<-ctx.Done()
			close(cleanupExpired)
			return ctx.Err()
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	startedAt := time.Now()
	go func() { returned <- supervisor.Run(ctx) }()
	cancel()
	select {
	case <-cleanupExpired:
	case <-time.After(time.Second):
		t.Fatal("internal drain deadline did not cancel cleanup")
	}
	select {
	case err := <-returned:
		if err == nil || !strings.Contains(err.Error(), "shutdown exceeded 20ms") {
			t.Fatalf("supervisor return = %v", err)
		}
		if elapsed := time.Since(startedAt); elapsed >= time.Second {
			t.Fatalf("internal drain took %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor did not return before external stop grace")
	}
	close(blocked)
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func TestRunRejectsRemovedURLCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"ui" + "-url"}, &stdout, &stderr); code != 2 {
		t.Fatalf("removed command exit = %d, stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.String() != "kfadapter: unknown command\n" {
		t.Fatalf("removed command output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
func TestNewAdapterUsesRelativeStateDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	adapter, err := newAdapter(adapterTestConfig(t))
	if err != nil {
		t.Fatalf("newAdapter: %v", err)
	}
	defer closeAdapter(adapter)

	info, err := os.Stat(filepath.Join(stateDirectory, "state.db"))
	if err != nil {
		t.Fatalf("stat SQLite state: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("SQLite state mode = %s", info.Mode())
	}
	persistent, err := adapter.store.Load()
	if err != nil {
		t.Fatalf("load bootstrapped SQLite state: %v", err)
	}
	if err := subscription.ValidatePersistentState(persistent); err != nil {
		t.Fatalf("bootstrapped SQLite state is invalid: %v", err)
	}
}

func TestNewAdapterRejectsUnassignedListenBeforeCreatingState(t *testing.T) {
	const unassigned = "192.0.2.1"
	if err := validateListenInterface(unassigned); err == nil {
		t.Skipf("documentation address %s is assigned on this host", unassigned)
	}
	directory := t.TempDir()
	cfg := adapterTestConfig(t)
	cfg.ListenAddr = unassigned
	adapter, err := newAdapterAtStateDirectory(cfg, directory)
	if err == nil {
		closeAdapter(adapter)
		t.Fatal("adapter started with an unassigned listen address")
	}
	if !strings.Contains(err.Error(), "not assigned") {
		t.Fatalf("startup error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(directory, "state.db")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("startup created state before NIC validation: %v", statErr)
	}
}

func TestNewAdapterRejectsInvalidSQLiteState(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.db"), []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := newAdapterAtStateDirectory(adapterTestConfig(t), dir)
	if err == nil {
		closeAdapter(adapter)
		t.Fatal("invalid SQLite state unexpectedly started adapter")
	}
}

func TestNewAdapterClearsExpiredSessionBeforeLaterStartupFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := adapterTestConfig(t)
	_, _ = seedBoundActiveSession(t, dir, cfg.ProxyAddress())
	store, err := state.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := store.Update(func(candidate *state.PersistentState) error {
		candidate.ActiveSession.CreatedAt = now.Add(-2 * time.Hour)
		candidate.ActiveSession.ExpiresAt = now.Add(-time.Hour)
		return nil
	}); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TZ", "Invalid/KFAdapter-Time-Zone")
	if adapter, err := newAdapterAtStateDirectory(cfg, dir); err == nil {
		closeAdapter(adapter)
		t.Fatal("invalid timezone unexpectedly started adapter")
	}
	reopened, err := state.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persistent, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if persistent.ActiveSession != nil {
		t.Fatalf("startup failure retained expired provider secrets: %#v", persistent.ActiveSession)
	}
}

func TestNewAdapterRestoresAndClearsPersistedProviderSession(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := adapterTestConfig(t)
	snapshot, persistent := seedBoundActiveSession(t, dir, cfg.ProxyAddress())
	selectorName := snapshot.Nodes[0].Selector

	adapter, err := newAdapterAtStateDirectory(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	assertRestoredAdapterSession(t, adapter, snapshot, persistent.Subscription.Generation, selectorName)
	closeAdapter(adapter)

	restarted, err := newAdapterAtStateDirectory(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	assertRestoredAdapterSession(t, restarted, snapshot, persistent.Subscription.Generation, selectorName)
	if err := restarted.runtime.Logout(context.Background()); err != nil {
		closeAdapter(restarted)
		t.Fatalf("Logout: %v", err)
	}
	cleared, err := restarted.store.Load()
	if err != nil {
		closeAdapter(restarted)
		t.Fatal(err)
	}
	if cleared.ActiveSession != nil {
		closeAdapter(restarted)
		t.Fatal("logout retained a durable provider session")
	}
	closeAdapter(restarted)

	signedOut, err := newAdapterAtStateDirectory(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAdapter(signedOut)
	if signedOut.manager.State() != state.StateSignedOut {
		t.Fatalf("state after logout restart = %s", signedOut.manager.State())
	}
	if current := signedOut.manager.Current(); current != nil && current.Session.Valid() {
		t.Fatalf("logout restart retained session authority: %#v", current)
	}
}

func seedBoundActiveSession(t *testing.T, dir, socksAddress string) (*state.RuntimeSnapshot, state.PersistentState) {
	t.Helper()
	store, err := state.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	persistent, err := store.LoadOrCreate()
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	const account = "adapter@example.test"
	now := time.Now().UTC()
	persistent, err = store.Update(func(candidate *state.PersistentState) error {
		if err := candidate.SetAccessToken("correct horse battery token"); err != nil {
			return err
		}
		_, err := state.EnsureSubscriptionAccountBinding(candidate, account, now)
		return err
	})
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	service, err := subscription.NewService(subscription.ServiceConfig{Store: store, SocksAddress: socksAddress, Now: func() time.Time { return now }})
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	plan, err := service.PrepareRuntimeCommit(context.Background(), account)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	registry, err := selector.NewRegistry(plan.Generation)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	built, err := registry.BuildWithTombstones(plan.Generation.Generation, []state.Node{{
		ID: "restored-node", Provider: "WIFIIN", Host: "node.example.test", Port: 1080, Eligible: true,
	}}, nil, now)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	snapshot := &state.RuntimeSnapshot{
		Generation: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		Account: state.NewAccountSummary(account, true, now.Add(24*time.Hour)),
		Session: state.SessionSecrets{UserID: account, LoginToken: "restored-login", ProviderToken: "restored-provider", TunnelPassword: "restored-tunnel", TunnelMethod: "aes-256-cfb", ProviderExtension: "|restored-provider|cc.fancast.major|order|" + account + "|MAC|1.0.46"},
		Nodes:   built.Nodes, Selectors: built.Selectors,
	}
	if _, err := service.CommitRuntimeSnapshot(context.Background(), plan, snapshot); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	persistent, err = store.Load()
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return snapshot, persistent
}

func assertRestoredAdapterSession(t *testing.T, adapter *adapter, expected *state.RuntimeSnapshot, subscriptionGeneration uint64, selectorName string) {
	t.Helper()
	if adapter.manager.State() != state.StateReady {
		t.Fatalf("restored manager state = %s", adapter.manager.State())
	}
	current := adapter.manager.Current()
	if current == nil || current.Account != expected.Account || current.Session != expected.Session {
		t.Fatalf("restored session = %#v", current)
	}
	status, err := adapter.runtime.Status(context.Background())
	if err != nil || !status.ControlPlane.LastRefreshAt.Equal(expected.CreatedAt) || !status.ControlPlane.NextRefreshAt.Equal(expected.ExpiresAt.Add(-30*time.Minute)) {
		t.Fatalf("restored refresh schedule status=%#v err=%v", status.ControlPlane, err)
	}
	pin, err := adapter.manager.CompactPin(selectorName, subscriptionGeneration, time.Now().UTC())
	if err != nil || pin.Node.ID != expected.Nodes[0].ID || pin.Session != expected.Session {
		t.Fatalf("restored node authority pin=%#v err=%v", pin, err)
	}
}

func TestNewAdapterRestartsWithConfiguredAccessVerifier(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := adapterTestConfig(t)
	adapter, err := newAdapterAtStateDirectory(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.runtime.AccessSetup(context.Background(), "correct horse battery token"); err != nil {
		closeAdapter(adapter)
		t.Fatalf("AccessSetup: %v", err)
	}
	closeAdapter(adapter)

	restarted, err := newAdapterAtStateDirectory(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAdapter(restarted)
	if err := restarted.runtime.AccessLogin(context.Background(), "correct horse battery token"); err != nil {
		t.Fatalf("AccessLogin after restart: %v", err)
	}
}

func adapterTestConfig(t *testing.T) config.Config {
	t.Helper()
	return testAdapterConfig(freeLoopbackAddress(t), freeLoopbackAddress(t))
}

func testAdapterConfig(managementListen, proxyListen string) config.Config {
	management := netip.MustParseAddrPort(managementListen)
	proxy := netip.MustParseAddrPort(proxyListen)
	if management.Addr() != proxy.Addr() {
		panic("test listeners must share an address")
	}
	return config.Config{
		ListenAddr: management.Addr().String(),
		Management: config.Management{
			Port: config.Port(management.Port()), SessionTTL: config.Duration(time.Minute),
		},
		Proxy: config.Proxy{
			Port: config.Port(proxy.Port()), DialTimeout: config.Duration(time.Second), HandshakeTimeout: config.Duration(time.Second),
		},
		Provider: config.Provider{RequestTimeout: config.Duration(time.Second), RefreshInterval: config.Duration(time.Hour)},
	}
}

func closeAdapter(adapter *adapter) {
	if adapter == nil {
		return
	}
	adapter.runtime.Stop()
	_ = adapter.httpListener.Close()
	_ = adapter.socksListener.Close()
	_ = adapter.store.Close()
}

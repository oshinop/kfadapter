package socks

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/kuaifan/wifiin"
	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
)

func TestSOCKSConnectAddressFormsAndSelectorIsolation(t *testing.T) {
	fixture := newSOCKSFixture(t)
	server := fixture.newServer(t)
	for _, tc := range []struct {
		name       string
		credential selector.Credentials
		request    []byte
		wantHost   string
		wantNode   string
	}{
		{"ipv4", fixture.first, socksRequest(addressIPv4, []byte{203, 0, 113, 7}, 443), "203.0.113.7", fixture.nodeOne.Host},
		{"ipv6", fixture.second, socksRequest(addressIPv6, net.ParseIP("2001:db8::5").To16(), 53), "2001:db8::5", fixture.nodeTwo.Host},
		{"domain", fixture.first, socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 8443), "example.com", fixture.nodeOne.Host},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, done := startConnection(t, server)
			defer client.Close()
			socksAuthenticate(t, client, tc.credential)
			if _, err := client.Write(tc.request); err != nil {
				t.Fatal(err)
			}
			if code := readReplyCode(t, client); code != replySucceeded {
				select {
				case err := <-done:
					t.Fatalf("CONNECT reply = %#x, handler error = %v", code, err)
				case <-time.After(time.Second):
					t.Fatalf("CONNECT reply = %#x", code)
				}
			}
			response := make([]byte, len("tunnel-response"))
			if _, err := io.ReadFull(client, response); err != nil {
				t.Fatal(err)
			}
			if got := string(response); got != "tunnel-response" {
				t.Fatalf("tunnel response = %q", got)
			}
			_ = client.Close()
			awaitHandle(t, done)

			call := fixture.lastCall(t)
			if call.upstream != net.JoinHostPort(tc.wantNode, "11000") {
				t.Fatalf("dialed %q, want selected upstream %q", call.upstream, net.JoinHostPort(tc.wantNode, "11000"))
			}
			if call.targetHost != tc.wantHost {
				t.Fatalf("header target host = %q, want %q", call.targetHost, tc.wantHost)
			}
		})
	}
}

func TestSOCKSSeparatesRuntimeAndCredentialGenerations(t *testing.T) {
	fixture := newSOCKSFixture(t)
	runtimeSnapshot := fixture.snapshot.Clone()
	runtimeSnapshot.Generation = 77 // Refresh generation is not subscription generation.
	server, err := New(Config{
		Snapshots:        snapshotFixture{snapshot: runtimeSnapshot},
		Selectors:        fixture.registry,
		DialContext:      fixture.dial,
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, done := startConnection(t, server)
	socksAuthenticate(t, client, fixture.first)
	if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
		t.Fatal(err)
	}
	if code := readReplyCode(t, client); code != replySucceeded {
		t.Fatalf("independent-generation CONNECT reply = %#x", code)
	}
	_ = client.Close()
	awaitHandle(t, done)
	if calls := fixture.callCount(); calls != 1 {
		t.Fatalf("independent generations did not reach selected upstream: %d dials", calls)
	}

	wrongCredentialGeneration := fixture.snapshot.Clone()
	wrongCredentialGeneration.Generation = 77
	ref := wrongCredentialGeneration.Selectors[fixture.first.Selector]
	ref.Generation++
	wrongCredentialGeneration.Selectors[fixture.first.Selector] = ref
	server, err = New(Config{
		Snapshots:        snapshotFixture{snapshot: wrongCredentialGeneration},
		Selectors:        fixture.registry,
		DialContext:      fixture.dial,
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, done = startConnection(t, server)
	defer client.Close()
	if _, err := client.Write([]byte{version5, 1, methodUserPassword}); err != nil {
		t.Fatal(err)
	}
	readExact(t, client, []byte{version5, methodUserPassword})
	writeUserPassword(t, client, fixture.first.Selector, fixture.first.Password)
	readExact(t, client, []byte{version1929, 1})
	awaitHandle(t, done)
	if calls := fixture.callCount(); calls != 1 {
		t.Fatalf("cross-credential-generation selector emitted a fallback dial")
	}
}

func TestSOCKSDelayedServerIVWaitsForFirstApplicationWrite(t *testing.T) {
	fixture := newSOCKSFixture(t)
	const ivTimeout = 25 * time.Millisecond
	observedApplication := make(chan struct{}, 1)
	server, err := New(Config{
		Snapshots: snapshotFixture{snapshot: fixture.snapshot},
		Selectors: fixture.registry,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			client, upstream := net.Pipe()
			go delayedIVAfterApplication(upstream, fixture.tunnelPassword, observedApplication)
			return client, nil
		},
		HandshakeTimeout: ivTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, done := startConnection(t, server)
	defer client.Close()
	socksAuthenticate(t, client, fixture.first)
	if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
		t.Fatal(err)
	}
	if code := readReplyCode(t, client); code != replySucceeded {
		t.Fatalf("CONNECT reply = %#x", code)
	}
	time.Sleep(3 * ivTimeout)
	if _, err := client.Write([]byte("HEAD")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-observedApplication:
	case <-time.After(time.Second):
		t.Fatal("upstream did not observe application ciphertext")
	}
	response := make([]byte, len("HTTP/1.1 200\r\n"))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if got := string(response); got != "HTTP/1.1 200\r\n" {
		t.Fatalf("decrypted response = %q", got)
	}
	_ = client.Close()
	awaitHandle(t, done)
}

func TestSOCKSDelayedServerIVTimesOutAfterFirstApplicationWrite(t *testing.T) {
	fixture := newSOCKSFixture(t)
	const ivTimeout = 25 * time.Millisecond
	server, err := New(Config{
		Snapshots: snapshotFixture{snapshot: fixture.snapshot},
		Selectors: fixture.registry,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			client, upstream := net.Pipe()
			go noIVAfterAcknowledgement(upstream)
			return client, nil
		},
		HandshakeTimeout: ivTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, done := startConnection(t, server)
	defer client.Close()
	socksAuthenticate(t, client, fixture.first)
	if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
		t.Fatal(err)
	}
	if code := readReplyCode(t, client); code != replySucceeded {
		t.Fatalf("CONNECT reply = %#x", code)
	}
	if _, err := client.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var byteRead [1]byte
	if _, err := client.Read(byteRead[:]); err == nil {
		t.Fatal("missing delayed server IV did not close the relay")
	}
	awaitHandle(t, done)
}

func TestSOCKSMaxConnectionsRejectsAndRecovers(t *testing.T) {
	fixture := newSOCKSFixture(t)
	var dialMu sync.Mutex
	dials := 0
	server, err := New(Config{
		Snapshots: snapshotFixture{snapshot: fixture.snapshot},
		Selectors: fixture.registry,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialMu.Lock()
			dials++
			dialMu.Unlock()
			client, upstream := net.Pipe()
			go holdWIFIINHandshake(upstream)
			return client, nil
		},
		HandshakeTimeout: time.Second,
		MaxConnections:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, listener) }()
	defer func() {
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve did not stop")
		}
	}()

	connect := func() net.Conn {
		client, dialErr := net.Dial("tcp", listener.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		socksAuthenticate(t, client, fixture.first)
		if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
			t.Fatal(err)
		}
		if code := readReplyCode(t, client); code != replySucceeded {
			t.Fatalf("CONNECT reply = %#x", code)
		}
		return client
	}

	first := connect()
	overLimit, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = overLimit.SetDeadline(time.Now().Add(time.Second))
	_, _ = overLimit.Write([]byte{version5, 1, methodUserPassword})
	var one [1]byte
	if _, err := overLimit.Read(one[:]); err == nil {
		t.Fatal("over-limit client was not closed")
	}
	_ = overLimit.Close()
	dialMu.Lock()
	currentDials := dials
	dialMu.Unlock()
	if currentDials != 1 {
		t.Fatalf("over-limit connection dialed %d upstreams, want 1 total", currentDials)
	}
	_ = first.Close()
	waitForSlots(t, server, 0)

	second := connect()
	_ = second.Close()
	dialMu.Lock()
	currentDials = dials
	dialMu.Unlock()
	if currentDials != 2 {
		t.Fatalf("released capacity did not dial exactly one new upstream: %d", currentDials)
	}
}

func TestSOCKSSetupDeadlineReleasesSilentGreetingSlots(t *testing.T) {
	for _, tc := range []struct {
		name    string
		partial []byte
	}{
		{"silent", nil},
		{"partial_greeting", []byte{version5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSOCKSFixture(t)
			server, err := New(Config{
				Snapshots:        snapshotFixture{snapshot: fixture.snapshot},
				Selectors:        fixture.registry,
				DialContext:      fixture.dial,
				HandshakeTimeout: 25 * time.Millisecond,
				MaxConnections:   1,
			})
			if err != nil {
				t.Fatal(err)
			}
			listener, cancel, serveDone := startServing(t, server)
			defer stopServing(t, cancel, serveDone)
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if len(tc.partial) != 0 {
				if _, err := client.Write(tc.partial); err != nil {
					t.Fatal(err)
				}
			}
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			var one [1]byte
			if _, err := client.Read(one[:]); err == nil {
				t.Fatal("silent setup connection was not closed at deadline")
			}
			waitForSlots(t, server, 0)
			if calls := fixture.callCount(); calls != 0 {
				t.Fatalf("timed-out greeting dialed %d upstreams", calls)
			}

			recovery, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer recovery.Close()
			socksAuthenticate(t, recovery, fixture.first)
			if _, err := recovery.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
				t.Fatal(err)
			}
			if code := readReplyCode(t, recovery); code != replySucceeded {
				t.Fatalf("recovery CONNECT reply = %#x", code)
			}
			if calls := fixture.callCount(); calls != 1 {
				t.Fatalf("recovered slot dialed %d upstreams, want one", calls)
			}
		})
	}
}

func TestSOCKSSupervisorCancelStopsAcceptsButKeepsPartialHandlers(t *testing.T) {
	for _, stage := range []string{"auth", "request"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newSOCKSFixture(t)
			server, err := New(Config{
				Snapshots:        snapshotFixture{snapshot: fixture.snapshot},
				Selectors:        fixture.registry,
				DialContext:      fixture.dial,
				HandshakeTimeout: time.Second,
				MaxConnections:   1,
			})
			if err != nil {
				t.Fatal(err)
			}
			listener, cancel, serveDone := startServing(t, server)
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write([]byte{version5, 1, methodUserPassword}); err != nil {
				t.Fatal(err)
			}
			readExact(t, client, []byte{version5, methodUserPassword})
			if stage == "auth" {
				if _, err := client.Write([]byte{version1929, 4, 'n'}); err != nil {
					t.Fatal(err)
				}
			} else {
				writeUserPassword(t, client, fixture.first.Selector, fixture.first.Password)
				readExact(t, client, []byte{version1929, 0})
				if _, err := client.Write([]byte{version5, commandConnect}); err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			awaitServe(t, serveDone)
			_ = client.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
			var one [1]byte
			if _, err := client.Read(one[:]); !isTimeout(err) {
				t.Fatalf("supervisor cancellation closed partial %s handler: %v", stage, err)
			}
			waitForSlots(t, server, 1)
			if calls := fixture.callCount(); calls != 0 {
				t.Fatalf("partial %s setup dialed %d upstreams", stage, calls)
			}
			_ = client.Close()
			waitForSlots(t, server, 0)
			if err := server.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown after drained partial handler: %v", err)
			}
		})
	}
}

func TestSOCKSSupervisorCancelDoesNotInterruptEstablishedRelay(t *testing.T) {
	fixture := newSOCKSFixture(t)
	releaseUpstream := make(chan struct{})
	server, err := New(Config{
		Snapshots: snapshotFixture{snapshot: fixture.snapshot},
		Selectors: fixture.registry,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			client, upstream := net.Pipe()
			go func() {
				defer upstream.Close()
				if err := readOutboundWIFIINHeader(upstream); err != nil {
					return
				}
				if _, err := upstream.Write([]byte{0, 0, 0}); err != nil {
					return
				}
				<-releaseUpstream
			}()
			return client, nil
		},
		HandshakeTimeout: time.Second,
		MaxConnections:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, cancel, serveDone := startServing(t, server)
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer close(releaseUpstream)
	socksAuthenticate(t, client, fixture.first)
	if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
		t.Fatal(err)
	}
	if code := readReplyCode(t, client); code != replySucceeded {
		t.Fatalf("CONNECT reply = %#x, want success", code)
	}
	cancel()
	awaitServe(t, serveDone)
	_ = client.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	var one [1]byte
	if _, err := client.Read(one[:]); !isTimeout(err) {
		t.Fatalf("supervisor cancellation interrupted established relay: %v", err)
	}
	waitForSlots(t, server, 1)
	_ = client.Close()
	waitForSlots(t, server, 0)
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown after relay drain: %v", err)
	}
}

func TestSOCKSRevalidatesStalledSessionBeforeDial(t *testing.T) {
	type scenario struct {
		name          string
		prepare       func(*state.RuntimeSnapshot) *state.RuntimeSnapshot
		waitForExpiry bool
		wantSuccess   bool
	}
	scenarios := []scenario{
		{
			name: "current_session_expired",
			prepare: func(snapshot *state.RuntimeSnapshot) *state.RuntimeSnapshot {
				snapshot.ExpiresAt = time.Now().Add(-time.Second)
				return snapshot
			},
		},
		{
			name:    "signed_out",
			prepare: func(*state.RuntimeSnapshot) *state.RuntimeSnapshot { return nil },
		},
		{
			name: "relogin",
			prepare: func(snapshot *state.RuntimeSnapshot) *state.RuntimeSnapshot {
				snapshot.Generation++
				snapshot.CreatedAt = time.Now().UTC()
				snapshot.Sessions.IOS.LoginToken = "different-login-token"
				return snapshot
			},
		},
		{
			name: "refresh",
			prepare: func(snapshot *state.RuntimeSnapshot) *state.RuntimeSnapshot {
				snapshot.Generation++
				snapshot.CreatedAt = time.Now().UTC()
				snapshot.Sessions.IOS.ProviderToken = "renewed-provider-token"
				return snapshot
			},
		},
		{
			name: "pinned_snapshot_expired",
			prepare: func(snapshot *state.RuntimeSnapshot) *state.RuntimeSnapshot {
				snapshot.ExpiresAt = time.Now().Add(25 * time.Millisecond)
				return snapshot
			},
			waitForExpiry: true,
		},
		{
			name: "probe_clone",
			prepare: func(snapshot *state.RuntimeSnapshot) *state.RuntimeSnapshot {
				snapshot.Generation++
				snapshot.CreatedAt = time.Now().UTC()
				snapshot.Nodes[0].Health = state.NodeHealthHealthy
				return snapshot
			},
			wantSuccess: true,
		},
		{
			name:        "legacy_exclusion_ignored",
			wantSuccess: true,
			prepare: func(snapshot *state.RuntimeSnapshot) *state.RuntimeSnapshot {
				snapshot.Nodes[0].Excluded = true
				return snapshot
			},
		},
		{
			name: "node_replaced",
			prepare: func(snapshot *state.RuntimeSnapshot) *state.RuntimeSnapshot {
				snapshot.Nodes[0].Host = "127.0.0.99"
				return snapshot
			},
		},
	}
	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSOCKSFixture(t)
			initial := fixture.snapshot.Clone()
			if tc.waitForExpiry {
				initial = tc.prepare(initial)
			}
			source := &mutableSnapshotSource{snapshot: initial}
			server, err := New(Config{Snapshots: source, Selectors: fixture.registry, DialContext: fixture.dial, HandshakeTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			client, done := startConnection(t, server)
			defer client.Close()
			socksAuthenticate(t, client, fixture.first)
			if tc.waitForExpiry {
				time.Sleep(50 * time.Millisecond)
			} else {
				source.Set(tc.prepare(fixture.snapshot.Clone()))
			}
			if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
				t.Fatal(err)
			}
			code := readReplyCode(t, client)
			if tc.wantSuccess {
				if code != replySucceeded {
					t.Fatalf("probe clone CONNECT reply = %#x", code)
				}
				_ = client.Close()
			} else if code != replyGeneralFailure {
				t.Fatalf("stale session CONNECT reply = %#x, want %#x", code, replyGeneralFailure)
			}
			awaitHandle(t, done)
			if calls := fixture.callCount(); tc.wantSuccess && calls != 1 {
				t.Fatalf("probe clone dialed %d upstreams, want one", calls)
			} else if !tc.wantSuccess && calls != 0 {
				t.Fatalf("stale session dialed %d upstreams", calls)
			}
		})
	}
}

func TestSOCKSFinalAdmissionRejectsInvalidatedHandshake(t *testing.T) {
	type invalidate func(t *testing.T, manager *state.Manager, server *Server, fixture *socksFixture)
	cases := []struct {
		name       string
		invalidate invalidate
	}{
		{
			name:       "logout",
			invalidate: func(_ *testing.T, manager *state.Manager, _ *Server, _ *socksFixture) { manager.SignOut() },
		},
		{
			name: "expired",
			invalidate: func(t *testing.T, manager *state.Manager, _ *Server, _ *socksFixture) {
				if err := manager.MarkExpired(time.Now()); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "stopped_error_state",
			invalidate: func(t *testing.T, manager *state.Manager, _ *Server, _ *socksFixture) {
				_, err := manager.Begin(state.OperationRefresh)
				if err != nil {
					t.Fatal(err)
				}
				if err := manager.Transition(state.StateError); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "authority_refresh",
			invalidate: func(t *testing.T, manager *state.Manager, _ *Server, fixture *socksFixture) {
				next := fixture.snapshot.Clone()
				next.Generation++
				next.CreatedAt = next.CreatedAt.Add(time.Second)
				next.Sessions.IOS.ProviderToken = "refreshed-provider-token"
				for selectorName, ref := range next.Selectors {
					ref.Generation = next.Generation
					next.Selectors[selectorName] = ref
				}
				if err := manager.Commit(next); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "selector_rotation",
			invalidate: func(t *testing.T, _ *state.Manager, server *Server, _ *socksFixture) {
				generation := state.SubscriptionGeneration{Generation: 2, SelectorKey: make([]byte, 32), ProxyAuthKey: make([]byte, 32), ActivatedAt: time.Now()}
				for index := range generation.SelectorKey {
					generation.SelectorKey[index] = byte(0x40 + index)
					generation.ProxyAuthKey[index] = byte(0x60 + index)
				}
				registry, err := selector.NewRegistry(generation)
				if err != nil {
					t.Fatal(err)
				}
				if err := server.SetSelectors(registry); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSOCKSFixture(t)
			manager := fixture.newManager(t)
			gate := newACKGate()
			server, err := New(Config{Snapshots: manager, Selectors: fixture.registry, DialContext: gate.Dial, HandshakeTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			client, done := startConnection(t, server)
			defer client.Close()
			socksAuthenticate(t, client, fixture.first)
			if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
				t.Fatal(err)
			}
			gate.waitForHeader(t)
			tc.invalidate(t, manager, server, fixture)
			gate.releaseACK()
			if code := readReplyCode(t, client); code != replyGeneralFailure {
				t.Fatalf("final admission reply = %#x, want %#x", code, replyGeneralFailure)
			}
			awaitHandle(t, done)
		})
	}
}

func TestSOCKSFinalAdmissionCheckWinsAndRelayDrains(t *testing.T) {
	fixture := newSOCKSFixture(t)
	manager := fixture.newManager(t)
	gate := newACKGate()
	server, err := New(Config{Snapshots: manager, Selectors: fixture.registry, DialContext: gate.Dial, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client, done := startConnection(t, server)
	defer client.Close()
	socksAuthenticate(t, client, fixture.first)
	if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
		t.Fatal(err)
	}
	gate.waitForHeader(t)
	gate.releaseACK()
	if code := readReplyCode(t, client); code != replySucceeded {
		t.Fatalf("admitted handshake reply = %#x", code)
	}
	manager.SignOut()
	if _, err := client.Write([]byte("GET")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.applicationSeen:
	case <-time.After(time.Second):
		t.Fatal("post-admission logout interrupted pinned tunnel")
	}
	_ = client.Close()
	awaitHandle(t, done)
}

func TestSOCKSCompactPinsRemainBoundedForLargeSelectorSet(t *testing.T) {
	smallManager, smallSelectors := newCompactPinManager(t, 1)
	largeManager, largeSelectors := newCompactPinManager(t, 4096)
	now := time.Now()

	assertPin := func(manager *state.Manager, selectorName string) {
		t.Helper()
		pin, err := manager.CompactPin(selectorName, 1, now)
		if err != nil {
			t.Fatal(err)
		}
		if pin.Node.ID == "" || pin.Ref.Generation != 1 || pin.Session.TunnelPassword == "" {
			t.Fatalf("incomplete compact pin: %#v", pin)
		}
	}
	assertPin(smallManager, smallSelectors[0])
	assertPin(largeManager, largeSelectors[len(largeSelectors)-1])

	smallAllocs := testing.AllocsPerRun(100, func() {
		_, err := smallManager.CompactPin(smallSelectors[0], 1, now)
		if err != nil {
			panic(err)
		}
	})
	largeAllocs := testing.AllocsPerRun(100, func() {
		_, err := largeManager.CompactPin(largeSelectors[len(largeSelectors)-1], 1, now)
		if err != nil {
			panic(err)
		}
	})
	if largeAllocs > smallAllocs+1 {
		t.Fatalf("compact pin allocations grew with selector map: small %.2f, large %.2f", smallAllocs, largeAllocs)
	}

	var group sync.WaitGroup
	pinErrors := make(chan error, 256)
	for index := range 256 {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			selectorName := largeSelectors[(index*47)%len(largeSelectors)]
			pin, err := largeManager.CompactPin(selectorName, 1, now)
			if err != nil {
				pinErrors <- err
				return
			}
			if pin.Node.ID == "" || pin.Ref.Generation != 1 {
				pinErrors <- errors.New("incomplete compact pin")
			}
		}(index)
	}
	group.Wait()
	close(pinErrors)
	for err := range pinErrors {
		t.Fatal(err)
	}
}

func newCompactPinManager(t *testing.T, nodeCount int) (*state.Manager, []string) {
	t.Helper()
	fixture := newSOCKSFixture(t)
	snapshot := fixture.snapshot.Clone()
	snapshot.Nodes = make([]state.Node, nodeCount)
	snapshot.Selectors = make(map[string]state.NodeRef, nodeCount*3)
	selectors := make([]string, 0, nodeCount*3)
	for nodeIndex := range nodeCount {
		nodeID := "node-" + strconv.Itoa(nodeIndex)
		snapshot.Nodes[nodeIndex] = state.Node{ID: nodeID, Provider: "WIFIIN", Host: "127.0.0.1", Port: 11000, Eligible: true}
		for refIndex := range 3 {
			selectorName := "selector-" + strconv.Itoa(nodeIndex*3+refIndex)
			snapshot.Selectors[selectorName] = state.NodeRef{NodeID: nodeID, Generation: 1}
			selectors = append(selectors, selectorName)
		}
	}
	manager, err := state.NewManagerWithSubscription(snapshot, fixture.subscription, fixture.bindingKey)
	if err != nil {
		t.Fatal(err)
	}
	return manager, selectors
}
func TestSOCKSRejectsInvalidAuthenticationWithoutDial(t *testing.T) {
	fixture := newSOCKSFixture(t)
	server, err := New(Config{Snapshots: snapshotFixture{snapshot: fixture.snapshot}, Selectors: fixture.registry, DialContext: fixture.dial})
	if err != nil {
		t.Fatal(err)
	}
	client, done := startConnection(t, server)
	defer client.Close()

	if _, err := client.Write([]byte{version5, 1, methodUserPassword}); err != nil {
		t.Fatal(err)
	}
	readExact(t, client, []byte{version5, methodUserPassword})
	badPassword := fixture.first.Password[:len(fixture.first.Password)-1] + "A"
	writeUserPassword(t, client, fixture.first.Selector, badPassword)
	readExact(t, client, []byte{version1929, 1})
	awaitHandle(t, done)
	if calls := fixture.callCount(); calls != 0 {
		t.Fatalf("invalid authentication dialed %d upstreams", calls)
	}
}

func TestSOCKSDoesNotRetryFailedSelectedUpstream(t *testing.T) {
	fixture := newSOCKSFixture(t)
	calls := 0
	server, err := New(Config{
		Snapshots: snapshotFixture{snapshot: fixture.snapshot},
		Selectors: fixture.registry,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			calls++
			return nil, syscall.ECONNREFUSED
		},
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, done := startConnection(t, server)
	defer client.Close()
	socksAuthenticate(t, client, fixture.first)
	if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
		t.Fatal(err)
	}
	if code := readReplyCode(t, client); code != replyConnectionRefused {
		t.Fatalf("failed dial reply = %#x, want %#x", code, replyConnectionRefused)
	}
	awaitHandle(t, done)
	if calls != 1 {
		t.Fatalf("failed selected upstream was dialed %d times, want one", calls)
	}
}

func TestSOCKSBoundsInjectedDialContext(t *testing.T) {
	t.Run("timeout_releases_slot", func(t *testing.T) {
		fixture := newSOCKSFixture(t)
		dialOutcome := make(chan error, 1)
		server, err := New(Config{
			Snapshots: snapshotFixture{snapshot: fixture.snapshot},
			Selectors: fixture.registry,
			DialContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				<-ctx.Done()
				dialOutcome <- ctx.Err()
				return nil, ctx.Err()
			},
			HandshakeTimeout: 25 * time.Millisecond,
			MaxConnections:   1,
		})
		if err != nil {
			t.Fatal(err)
		}
		listener, cancel, serveDone := startServing(t, server)
		defer stopServing(t, cancel, serveDone)
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		socksAuthenticate(t, client, fixture.first)
		if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
			t.Fatal(err)
		}
		if code := readReplyCode(t, client); code != replyTTLExpired {
			t.Fatalf("timed-out dial reply = %#x, want %#x", code, replyTTLExpired)
		}
		select {
		case err := <-dialOutcome:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("dial context error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("dial did not observe timeout context")
		}
		waitForSlots(t, server, 0)
	})

	t.Run("shutdown_deadline_forces_dial", func(t *testing.T) {
		fixture := newSOCKSFixture(t)
		dialStarted := make(chan struct{}, 1)
		dialOutcome := make(chan error, 1)
		server, err := New(Config{
			Snapshots: snapshotFixture{snapshot: fixture.snapshot},
			Selectors: fixture.registry,
			DialContext: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				dialStarted <- struct{}{}
				<-ctx.Done()
				dialOutcome <- ctx.Err()
				return nil, ctx.Err()
			},
			HandshakeTimeout: time.Second,
			MaxConnections:   1,
		})
		if err != nil {
			t.Fatal(err)
		}
		listener, cancel, serveDone := startServing(t, server)
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		socksAuthenticate(t, client, fixture.first)
		if _, err := client.Write(socksRequest(addressDomain, append([]byte{11}, []byte("example.com")...), 443)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-dialStarted:
		case <-time.After(time.Second):
			t.Fatal("dial did not start")
		}
		cancel()
		awaitServe(t, serveDone)
		select {
		case err := <-dialOutcome:
			t.Fatalf("supervisor cancellation interrupted dial: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancelShutdown()
		if err := server.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Shutdown error = %v, want deadline exceeded", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		var one [1]byte
		if _, err := client.Read(one[:]); err == nil {
			t.Fatal("shutdown deadline did not close dial-blocked client")
		}
		select {
		case err := <-dialOutcome:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("forced dial cancellation error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("shutdown deadline did not cancel dial")
		}
		waitForSlots(t, server, 0)
		_ = client.Close()
	})
}
func TestSOCKSServeDoesNotImposeListenerAddressPolicy(t *testing.T) {
	fixture := newSOCKSFixture(t)
	listener := addressOnlyListener{address: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 10808}}
	if err := fixture.newServer(t).Serve(context.Background(), listener); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve error = %v, want listener Accept error", err)
	}
}

func TestSOCKSRejectsBindWithoutUpstreamTraffic(t *testing.T) {
	fixture := newSOCKSFixture(t)
	server := fixture.newServer(t)
	client, done := startConnection(t, server)
	defer client.Close()
	socksAuthenticate(t, client, fixture.first)
	request := socksRequest(addressIPv4, []byte{0, 0, 0, 0}, 0)
	request[1] = commandBind
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if code := readReplyCode(t, client); code != replyCommandUnsupported {
		t.Fatalf("BIND reply = %#x, want %#x", code, replyCommandUnsupported)
	}
	awaitHandle(t, done)
	if calls := fixture.callCount(); calls != 0 {
		t.Fatalf("unsupported command emitted %d upstream dial(s)", calls)
	}
}

func TestSOCKSUDPAssociateRelaysOverWIFIINUOT(t *testing.T) {
	fixture := newSOCKSFixture(t)
	server := fixture.newServer(t)
	client, done := startConnection(t, server)
	socksAuthenticate(t, client, fixture.first)
	request := socksRequest(addressIPv4, []byte{0, 0, 0, 0}, 0)
	request[1] = commandUDP
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != version5 || reply[1] != replySucceeded || reply[2] != 0 || reply[3] != addressIPv4 {
		t.Fatalf("UDP ASSOCIATE reply = %x", reply)
	}
	proxyAddress := &net.UDPAddr{IP: net.IP(append([]byte(nil), reply[4:8]...)), Port: int(binary.BigEndian.Uint16(reply[8:]))}
	udpClient, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	datagram := []byte{0, 0, 0, addressIPv4, 192, 0, 2, 1, 0, 53, 'd', 'n', 's', '-', 'q', 'u', 'e', 'r', 'y'}
	if _, err := udpClient.WriteToUDP(datagram, proxyAddress); err != nil {
		t.Fatal(err)
	}
	if err := udpClient.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 512)
	n, _, err := udpClient.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(response[:n]) != string(datagram) {
		t.Fatalf("UDP response = %x, want %x", response[:n], datagram)
	}
	call := fixture.lastCall(t)
	if call.targetHost != fixture.nodeOne.Host {
		t.Fatalf("UOT handshake target = %q, want selected node %q", call.targetHost, fixture.nodeOne.Host)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	awaitHandle(t, done)
}

func TestSOCKSRejectsUnsupportedAddressType(t *testing.T) {
	fixture := newSOCKSFixture(t)
	server := fixture.newServer(t)
	client, done := startConnection(t, server)
	defer client.Close()
	socksAuthenticate(t, client, fixture.first)
	if _, err := client.Write([]byte{version5, commandConnect, 0, 0x09}); err != nil {
		t.Fatal(err)
	}
	if code := readReplyCode(t, client); code != replyAddressUnsupported {
		t.Fatalf("address reply = %#x, want %#x", code, replyAddressUnsupported)
	}
	awaitHandle(t, done)
	if calls := fixture.callCount(); calls != 0 {
		t.Fatalf("unsupported address dialed %d upstreams", calls)
	}
}

type snapshotFixture struct{ snapshot *state.RuntimeSnapshot }

func (s snapshotFixture) CompactPin(selectorName string, generation uint64, now time.Time) (state.TunnelPin, error) {
	return compactPin(s.snapshot, selectorName, generation, now)
}

func (s snapshotFixture) SessionCurrentPin(pin state.TunnelPin, now time.Time) bool {
	if s.snapshot == nil || !state.SessionUsable(s.snapshot, now) {
		return false
	}
	return samePinAuthority(pin, state.TunnelPin{Session: s.snapshot.Sessions.IOS, ExpiresAt: s.snapshot.ExpiresAt})
}

type mutableSnapshotSource struct {
	mu       sync.Mutex
	snapshot *state.RuntimeSnapshot
}

func (s *mutableSnapshotSource) CompactPin(selectorName string, generation uint64, now time.Time) (state.TunnelPin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return compactPin(s.snapshot, selectorName, generation, now)
}

func (s *mutableSnapshotSource) SessionCurrentPin(pin state.TunnelPin, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snapshot == nil || !state.SessionUsable(s.snapshot, now) {
		return false
	}
	return samePinAuthority(pin, state.TunnelPin{Session: s.snapshot.Sessions.IOS, ExpiresAt: s.snapshot.ExpiresAt})
}

func (s *mutableSnapshotSource) Set(snapshot *state.RuntimeSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = snapshot
}

func compactPin(snapshot *state.RuntimeSnapshot, selectorName string, generation uint64, now time.Time) (state.TunnelPin, error) {
	if snapshot == nil || generation == 0 || !state.SessionUsable(snapshot, now) {
		return state.TunnelPin{}, state.ErrSelectorUnknown
	}
	node, ref, err := snapshot.ResolveSelector(selectorName, now)
	if err != nil || ref.Generation != generation {
		return state.TunnelPin{}, state.ErrSelectorUnknown
	}
	return state.TunnelPin{Session: snapshot.Sessions.IOS.Clone(), ExpiresAt: snapshot.ExpiresAt, Node: node, Ref: ref}, nil
}

type dialCall struct {
	upstream   string
	targetHost string
}

type socksFixture struct {
	t              *testing.T
	snapshot       *state.RuntimeSnapshot
	subscription   state.SubscriptionGeneration
	bindingKey     []byte
	registry       *selector.Registry
	first, second  selector.Credentials
	nodeOne        state.Node
	nodeTwo        state.Node
	providerExtra  string
	tunnelPassword string

	mu    sync.Mutex
	calls []dialCall
}

func newSOCKSFixture(t *testing.T) *socksFixture {
	t.Helper()
	now := time.Now().UTC()
	selectorKey := make([]byte, 32)
	proxyKey := make([]byte, 32)
	for i := range selectorKey {
		selectorKey[i] = byte(i)
		proxyKey[i] = byte(0x20 + i)
	}
	persistent, err := state.NewPersistentState()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistent.SetAccessToken("0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	generation := state.SubscriptionGeneration{Generation: 1, SelectorKey: selectorKey, ProxyAuthKey: proxyKey, ActivatedAt: now}
	persistent.Subscription = generation
	if _, err := state.EnsureSubscriptionAccountBinding(&persistent, "user", now); err != nil {
		t.Fatal(err)
	}
	generation = persistent.Subscription
	bindingKey := persistent.AccessTokenVerifier.BindingKey()
	registry, err := selector.NewRegistry(generation)
	if err != nil {
		t.Fatal(err)
	}
	nodeOne := state.Node{ID: "one", Provider: "WIFIIN", Host: "127.0.0.11", Port: 11000, Eligible: true}
	nodeTwo := state.Node{ID: "two", Provider: "WIFIIN", Host: "127.0.0.12", Port: 11000, Eligible: true}
	first, ok := registry.Credentials(1, selector.NodeIdentity{NodeID: nodeOne.ID, Provider: nodeOne.Provider, Host: nodeOne.Host, Port: int(nodeOne.Port)})
	if !ok {
		t.Fatal("first credential unavailable")
	}
	second, ok := registry.Credentials(1, selector.NodeIdentity{NodeID: nodeTwo.ID, Provider: nodeTwo.Provider, Host: nodeTwo.Host, Port: int(nodeTwo.Port)})
	if !ok {
		t.Fatal("second credential unavailable")
	}
	nodeOne.Selector, nodeTwo.Selector = first.Selector, second.Selector
	providerExtra, err := wifiin.ProviderExtension("provider-token", "order", "user")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &state.RuntimeSnapshot{
		Generation: 1,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Hour),
		Sessions: state.ClientSessions{IOS: state.SessionSecrets{
			UserID:            "user",
			LoginToken:        "login-token",
			ProviderToken:     "provider-token",
			TunnelPassword:    "tunnel-password",
			TunnelMethod:      "aes-256-cfb",
			ProviderExtension: "|provider-token|cc.fancast.major|order|user|MAC|1.0.46",
		}},
		Nodes: []state.Node{nodeOne, nodeTwo},
		Selectors: map[string]state.NodeRef{
			first.Selector:  {NodeID: nodeOne.ID, Generation: 1},
			second.Selector: {NodeID: nodeTwo.ID, Generation: 1},
		},
	}
	return &socksFixture{t: t, snapshot: snapshot, subscription: generation, bindingKey: bindingKey, registry: registry, first: first, second: second, nodeOne: nodeOne, nodeTwo: nodeTwo, providerExtra: providerExtra, tunnelPassword: "tunnel-password"}
}

func (f *socksFixture) newManager(t *testing.T) *state.Manager {
	t.Helper()
	manager, err := state.NewManagerWithSubscription(f.snapshot, f.subscription, f.bindingKey)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func (f *socksFixture) newServer(t *testing.T) *Server {
	t.Helper()
	server, err := New(Config{
		Snapshots:        snapshotFixture{snapshot: f.snapshot},
		Selectors:        f.registry,
		DialContext:      f.dial,
		HandshakeTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func (f *socksFixture) dial(_ context.Context, network, upstream string) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("unexpected network")
	}
	client, server := net.Pipe()
	go f.serveUpstream(server, upstream)
	return client, nil
}

func (f *socksFixture) serveUpstream(connection net.Conn, upstream string) {
	defer connection.Close()
	var prefix [3]byte
	if _, err := io.ReadFull(connection, prefix[:]); err != nil || (prefix[0] != wifiin.OuterType && prefix[0] != wifiin.UOTOuterType) {
		return
	}
	encryptedLength := int(binary.BigEndian.Uint16(prefix[1:]))
	if encryptedLength < wifiin.IVSize {
		return
	}
	rest := make([]byte, encryptedLength+2)
	if _, err := io.ReadFull(connection, rest); err != nil {
		return
	}
	key := wifiin.DeriveKey(f.tunnelPassword)
	decrypt, err := wifiin.NewDecrypter(key[:], rest[:wifiin.IVSize])
	if err != nil {
		return
	}
	plain := make([]byte, encryptedLength-wifiin.IVSize)
	decrypt.XORKeyStream(plain, rest[wifiin.IVSize:encryptedLength])
	targetHost := strings.TrimSuffix(string(plain), f.providerExtra)
	f.mu.Lock()
	f.calls = append(f.calls, dialCall{upstream: upstream, targetHost: targetHost})
	f.mu.Unlock()

	serverIV := []byte("0123456789abcdef")
	encrypt, err := wifiin.NewEncrypter(key[:], serverIV)
	if err != nil {
		return
	}
	if prefix[0] == wifiin.OuterType {
		response := []byte("tunnel-response")
		encrypt.XORKeyStream(response, response)
		_, _ = connection.Write(append(append([]byte{0, 0, 0}, serverIV...), response...))
		return
	}
	if _, err := connection.Write([]byte{0, 0, 0}); err != nil {
		return
	}
	uotReader, err := wifiin.NewUOTReader(&cipher.StreamReader{S: decrypt, R: connection})
	if err != nil {
		return
	}
	uotWriter, err := wifiin.NewUOTWriter(&cipher.StreamWriter{S: encrypt, W: connection})
	if err != nil {
		return
	}
	serverIVSent := false
	for {
		datagram := make([]byte, maxUDPDatagramSize)
		n, flowID, err := uotReader.ReadSOCKSDatagram(datagram)
		if err != nil {
			return
		}
		if !serverIVSent {
			if _, err := connection.Write(serverIV); err != nil {
				return
			}
			serverIVSent = true
		}
		if err := uotWriter.WriteSOCKSDatagram(flowID, datagram[:n]); err != nil {
			return
		}
	}
}

func holdWIFIINHandshake(connection net.Conn) {
	defer connection.Close()
	var prefix [3]byte
	if _, err := io.ReadFull(connection, prefix[:]); err != nil || prefix[0] != wifiin.OuterType {
		return
	}
	encryptedLength := int(binary.BigEndian.Uint16(prefix[1:]))
	if encryptedLength < wifiin.IVSize {
		return
	}
	if _, err := io.CopyN(io.Discard, connection, int64(encryptedLength+2)); err != nil {
		return
	}
	if _, err := connection.Write(append([]byte{0, 0, 0}, []byte("0123456789abcdef")...)); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, connection)
}

func delayedIVAfterApplication(connection net.Conn, password string, observed chan<- struct{}) {
	defer connection.Close()
	if err := readOutboundWIFIINHeader(connection); err != nil {
		return
	}
	if _, err := connection.Write([]byte{0, 0, 0}); err != nil {
		return
	}
	var applicationCiphertext [4]byte
	if _, err := io.ReadFull(connection, applicationCiphertext[:]); err != nil {
		return
	}
	observed <- struct{}{}
	key := wifiin.DeriveKey(password)
	serverIV := []byte("fedcba9876543210")
	encrypt, err := wifiin.NewEncrypter(key[:], serverIV)
	if err != nil {
		return
	}
	response := []byte("HTTP/1.1 200\r\n")
	encrypt.XORKeyStream(response, response)
	_, _ = connection.Write(append(serverIV, response...))
}

func noIVAfterAcknowledgement(connection net.Conn) {
	defer connection.Close()
	if err := readOutboundWIFIINHeader(connection); err != nil {
		return
	}
	if _, err := connection.Write([]byte{0, 0, 0}); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, connection)
}

type ackGate struct {
	headerSeen      chan struct{}
	applicationSeen chan struct{}
	release         chan struct{}
	once            sync.Once
}

func newACKGate() *ackGate {
	return &ackGate{headerSeen: make(chan struct{}, 1), applicationSeen: make(chan struct{}, 1), release: make(chan struct{})}
}

func (g *ackGate) Dial(context.Context, string, string) (net.Conn, error) {
	client, upstream := net.Pipe()
	go func() {
		defer upstream.Close()
		if err := readOutboundWIFIINHeader(upstream); err != nil {
			return
		}
		g.headerSeen <- struct{}{}
		<-g.release
		if _, err := upstream.Write([]byte{0, 0, 0}); err != nil {
			return
		}
		var firstApplication [1]byte
		if _, err := upstream.Read(firstApplication[:]); err != nil {
			return
		}
		g.applicationSeen <- struct{}{}
		_, _ = io.Copy(io.Discard, upstream)
	}()
	return client, nil
}

func (g *ackGate) waitForHeader(t *testing.T) {
	t.Helper()
	select {
	case <-g.headerSeen:
	case <-time.After(time.Second):
		t.Fatal("WIFIIN header did not reach ACK gate")
	}
}

func (g *ackGate) releaseACK() {
	g.once.Do(func() { close(g.release) })
}

func readOutboundWIFIINHeader(connection net.Conn) error {
	var prefix [3]byte
	if _, err := io.ReadFull(connection, prefix[:]); err != nil {
		return err
	}
	if prefix[0] != wifiin.OuterType {
		return errors.New("unexpected WIFIIN outer type")
	}
	encryptedLength := int(binary.BigEndian.Uint16(prefix[1:]))
	if encryptedLength < wifiin.IVSize {
		return errors.New("short WIFIIN encrypted header")
	}
	_, err := io.CopyN(io.Discard, connection, int64(encryptedLength+2))
	return err
}

func (f *socksFixture) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *socksFixture) lastCall(t *testing.T) dialCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("expected upstream dial")
	}
	return f.calls[len(f.calls)-1]
}

func startServing(t *testing.T, server *Server) (net.Listener, context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	return listener, cancel, done
}

func awaitServe(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
}

func isTimeout(err error) bool {
	var networkErr net.Error
	return err != nil && errors.As(err, &networkErr) && networkErr.Timeout()
}

func stopServing(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	awaitServe(t, done)
}

func waitForSlots(t *testing.T, server *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(server.slots) != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(server.slots); got != want {
		t.Fatalf("active SOCKS slots = %d, want %d", got, want)
	}
}

func startConnection(t *testing.T, server *Server) (net.Conn, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		client.Close()
		listener.Close()
		t.Fatal(err)
	}
	_ = listener.Close()
	done := make(chan error, 1)
	go func() { done <- server.HandleConn(context.Background(), accepted) }()
	return client, done
}

func socksAuthenticate(t *testing.T, connection net.Conn, credential selector.Credentials) {
	t.Helper()
	if _, err := connection.Write([]byte{version5, 1, methodUserPassword}); err != nil {
		t.Fatal(err)
	}
	readExact(t, connection, []byte{version5, methodUserPassword})
	writeUserPassword(t, connection, credential.Selector, credential.Password)
	readExact(t, connection, []byte{version1929, 0})
}

func writeUserPassword(t *testing.T, connection net.Conn, username, password string) {
	t.Helper()
	if len(username) > 255 || len(password) > 255 {
		t.Fatal("test credential too long")
	}
	payload := make([]byte, 0, 3+len(username)+len(password))
	payload = append(payload, version1929, byte(len(username)))
	payload = append(payload, username...)
	payload = append(payload, byte(len(password)))
	payload = append(payload, password...)
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
}

func socksRequest(atyp byte, address []byte, port uint16) []byte {
	request := []byte{version5, commandConnect, 0, atyp}
	request = append(request, address...)
	request = append(request, byte(port>>8), byte(port))
	return request
}

func readReplyCode(t *testing.T, connection net.Conn) byte {
	t.Helper()
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[0] != version5 || header[2] != 0 {
		t.Fatalf("malformed reply %x", header)
	}
	var remaining int
	switch header[3] {
	case addressIPv4:
		remaining = 6
	case addressIPv6:
		remaining = 18
	case addressDomain:
		var size [1]byte
		if _, err := io.ReadFull(connection, size[:]); err != nil {
			t.Fatal(err)
		}
		remaining = int(size[0]) + 2
	default:
		t.Fatalf("unsupported reply address type %#x", header[3])
	}
	if _, err := io.CopyN(io.Discard, connection, int64(remaining)); err != nil {
		t.Fatal(err)
	}
	return header[1]
}

func readExact(t *testing.T, connection net.Conn, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(connection, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("read %x, want %x", got, want)
	}
}

func awaitHandle(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SOCKS handler did not return")
	}
}

type addressOnlyListener struct {
	address net.Addr
}

func (l addressOnlyListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l addressOnlyListener) Close() error              { return nil }
func (l addressOnlyListener) Addr() net.Addr            { return l.address }

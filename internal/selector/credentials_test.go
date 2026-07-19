package selector

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/state"
)

func bytesFromHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func normativeGeneration(t *testing.T, generation uint64) state.SubscriptionGeneration {
	t.Helper()
	return state.SubscriptionGeneration{
		Generation:   generation,
		SelectorKey:  bytesFromHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		ProxyAuthKey: bytesFromHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
	}
}

func TestLiteralSelectorCredentialVectorAndSingleGeneration(t *testing.T) {
	current := normativeGeneration(t, 1)
	registry, err := NewRegistry(current)
	if err != nil {
		t.Fatal(err)
	}
	identity := NodeIdentity{Provider: "WIFIIN", Host: "node.example.com", Port: 11000}
	canonical, err := Canonicalize(identity)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(canonical.Fingerprint()), "76310057494649494e006e6f64652e6578616d706c652e636f6d003131303030"; got != want {
		t.Fatalf("fingerprint = %s", got)
	}
	credential, err := Derive(identity, current.SelectorKey, current.ProxyAuthKey)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Selector != "n_dRrYzOwvhk-TZ2ud" || credential.Password != "p_I-rMzJLcPbFGcNNUwQcLNg8R" {
		t.Fatalf("credential = %#v", credential)
	}
	if generations := registry.Generations(); len(generations) != 1 || generations[0] != 1 {
		t.Fatalf("Generations = %#v", generations)
	}
	if generation, ok := registry.Authenticate(credential.Selector, credential.Password); !ok || generation != 1 {
		t.Fatalf("Authenticate = (%d, %v)", generation, ok)
	}
	if _, ok := registry.Credentials(2, identity); ok {
		t.Fatal("registry exposed a non-current credential generation")
	}
}

func TestAccountCutoverUsesReplacementRegistry(t *testing.T) {
	first := normativeGeneration(t, 1)
	second := normativeGeneration(t, 2)
	second.SelectorKey[0] ^= 0xff
	second.ProxyAuthKey[0] ^= 0xff
	oldRegistry, err := NewRegistry(first)
	if err != nil {
		t.Fatal(err)
	}
	newRegistry, err := NewRegistry(second)
	if err != nil {
		t.Fatal(err)
	}
	identity := NodeIdentity{Provider: "WIFIIN", Host: "node.example.com", Port: 11000}
	oldCredentials, ok := oldRegistry.Credentials(1, identity)
	if !ok {
		t.Fatal("old credentials unavailable")
	}
	newCredentials, ok := newRegistry.Credentials(2, identity)
	if !ok || newCredentials == oldCredentials {
		t.Fatalf("new credentials = %#v, ok=%v", newCredentials, ok)
	}
	if _, ok := newRegistry.Authenticate(oldCredentials.Selector, oldCredentials.Password); ok {
		t.Fatal("replacement registry accepted old account credential")
	}
	if generation, ok := newRegistry.Authenticate(newCredentials.Selector, newCredentials.Password); !ok || generation != 2 {
		t.Fatalf("new authentication = (%d, %v)", generation, ok)
	}
}

func TestTombstonesRemainGenerationBoundAndDeterministic(t *testing.T) {
	now := time.Date(2026, 7, 16, 11, 0, 0, 0, time.UTC)
	registry, err := NewRegistry(normativeGeneration(t, 7))
	if err != nil {
		t.Fatal(err)
	}
	node := state.Node{ID: "stable", Provider: "WIFIIN", Host: "node.example.com", Port: 11000, Eligible: true}
	first, err := registry.BuildWithTombstones(7, []state.Node{node}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := registry.BuildWithTombstones(7, nil, first.Selectors, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(removed.Nodes) != 0 || len(removed.Selectors) != 1 {
		t.Fatalf("removed result = %#v", removed)
	}
	for name, ref := range removed.Selectors {
		if !ref.Tombstoned || ref.Generation != 7 || ref.NodeID != "" || !ref.IsTombstoned(now.Add(time.Minute)) {
			t.Fatalf("invalid tombstone %q: %#v", name, ref)
		}
	}
	resurrected, err := registry.BuildWithTombstones(7, []state.Node{node}, removed.Selectors, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(resurrected.Nodes) != 0 {
		t.Fatalf("active tombstone allowed selector remap: %#v", resurrected)
	}
	if _, err := registry.BuildWithTombstones(8, []state.Node{node}, nil, now); !errors.Is(err, ErrUnknownGeneration) {
		t.Fatalf("wrong generation error = %v", err)
	}
}

func TestRegistryConcurrentReadsAreRaceSafe(t *testing.T) {
	registry, err := NewRegistry(normativeGeneration(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	identity := NodeIdentity{Provider: "WIFIIN", Host: "node.example.com", Port: 11000}
	credential, ok := registry.Credentials(1, identity)
	if !ok {
		t.Fatal("credentials unavailable")
	}
	node := state.Node{ID: "node", Provider: "WIFIIN", Host: "node.example.com", Port: 11000, Eligible: true}
	var wait sync.WaitGroup
	errors := make(chan error, 64)
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if generation, ok := registry.AuthenticateAt(credential.Selector, credential.Password, time.Now()); !ok || generation != 1 {
				errors <- fmt.Errorf("authentication = (%d, %v)", generation, ok)
			}
			if _, err := registry.BuildWithTombstones(1, []state.Node{node}, nil, time.Now()); err != nil {
				errors <- err
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

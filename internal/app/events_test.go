package app

import (
	"context"
	"testing"
	"time"
)

func TestEventSubscriptionCancelStopsBackgroundWatcher(t *testing.T) {
	hub := newEventHub(1, 1)
	events, cancel, err := hub.subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("cancelled event channel remained open")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled event channel did not close")
	}
	waitForHubWatchers(t, hub)
	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.clients) != 0 {
		t.Fatalf("cancelled subscriber retained: %d", len(hub.clients))
	}
}

func TestEventHubCloseRacesSubscriberCancel(t *testing.T) {
	hub := newEventHub(1, 1)
	_, cancel, err := hub.subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		cancel()
		close(done)
	}()
	hub.close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("subscriber cancel raced with close")
	}
	waitForHubWatchers(t, hub)
}

func waitForHubWatchers(t *testing.T, hub *eventHub) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		hub.watchers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event watcher leaked")
	}
}

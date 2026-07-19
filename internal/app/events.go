package app

import (
	"context"
	"errors"
	"sync"

	"github.com/kfadapter/kfadapter/internal/web"
)

const (
	defaultEventClients = 16
	defaultEventBuffer  = 8
)

// eventHub is intentionally lossy for slow clients: state transitions are
// coarse and the latest browser request remains authoritative, while an
// bounded queue could otherwise exhaust the process.
type eventHub struct {
	mu       sync.Mutex
	clients  map[uint64]*eventSubscriber
	nextID   uint64
	capacity int
	buffer   int
	closed   bool
	watchers sync.WaitGroup
}

type eventSubscriber struct {
	events chan web.Event
	done   chan struct{}
}

func newEventHub(capacity, buffer int) *eventHub {
	if capacity <= 0 {
		capacity = defaultEventClients
	}
	if buffer <= 0 {
		buffer = defaultEventBuffer
	}
	return &eventHub{clients: make(map[uint64]*eventSubscriber), capacity: capacity, buffer: buffer}
}

func (h *eventHub) subscribe(ctx context.Context) (<-chan web.Event, func(), error) {
	if h == nil {
		return nil, nil, errors.New("app: event hub unavailable")
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, nil, errors.New("app: event hub stopped")
	}
	if len(h.clients) >= h.capacity {
		h.mu.Unlock()
		return nil, nil, errors.New("app: event client capacity reached")
	}
	h.nextID++
	id := h.nextID
	subscriber := &eventSubscriber{events: make(chan web.Event, h.buffer), done: make(chan struct{})}
	h.clients[id] = subscriber
	h.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			h.mu.Lock()
			if existing, ok := h.clients[id]; ok {
				delete(h.clients, id)
				close(existing.events)
				close(existing.done)
			}
			h.mu.Unlock()
		})
	}
	if ctx != nil {
		h.watchers.Add(1)
		go func() {
			defer h.watchers.Done()
			select {
			case <-ctx.Done():
				cancel()
			case <-subscriber.done:
			}
		}()
	}
	return subscriber.events, cancel, nil
}

func (h *eventHub) publish(event web.Event) {
	if h == nil || !safeEventType(event.Type) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	for _, subscriber := range h.clients {
		select {
		case subscriber.events <- event:
		default:
			// Drop this event only for the stalled browser. No internal state or
			// secret material is retained in a retry queue.
		}
	}
}

func (h *eventHub) close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for id, subscriber := range h.clients {
		delete(h.clients, id)
		close(subscriber.events)
		close(subscriber.done)
	}
}

func safeEventType(value string) bool {
	switch value {
	case "state", "refresh", "probe":
		return true
	default:
		return false
	}
}

// Package app wires stateful collaborators into browser-safe and
// process-safe operations.
package app

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kfadapter/kfadapter/internal/selector"
	"github.com/kfadapter/kfadapter/internal/state"
)

// SelectorApplier installs the complete immutable SOCKS credential registry.
type SelectorApplier interface {
	SetSelectors(*selector.Registry) error
}

// SelectorCoordinator makes a new account-derived registry visible to control
// and SOCKS at the same instant, with a compensating rollback for a later
// persistence or runtime commit failure.
type SelectorCoordinator struct {
	socks SelectorApplier
	now   func() time.Time

	mu       sync.RWMutex
	registry *selector.Registry
}

func NewSelectorCoordinator(socks SelectorApplier, registry *selector.Registry, now func() time.Time) (*SelectorCoordinator, error) {
	if registry == nil {
		return nil, errors.New("app: selector registry is required")
	}
	if now == nil {
		now = time.Now
	}
	return &SelectorCoordinator{socks: socks, now: now, registry: registry}, nil
}

// Registry returns the current immutable registry. Callers must not mutate it.
func (c *SelectorCoordinator) Registry() *selector.Registry {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.registry
}

// Build implements state.SelectorBuilder.
func (c *SelectorCoordinator) Build(generation uint64, nodes []state.Node) (map[string]state.NodeRef, error) {
	registry := c.Registry()
	if registry == nil {
		return nil, selector.ErrUnknownGeneration
	}
	return registry.Build(generation, nodes)
}

// BuildWithTombstones retains removed selectors only within the current
// account-derived credential generation.
func (c *SelectorCoordinator) BuildWithTombstones(generation uint64, nodes []state.Node, previous map[string]state.NodeRef, now time.Time) (selector.BuildResult, error) {
	registry := c.Registry()
	if registry == nil {
		return selector.BuildResult{}, selector.ErrUnknownGeneration
	}
	return registry.BuildWithTombstones(generation, nodes, previous, now)
}

// Generations reports the one credential generation accepted by this process.
func (c *SelectorCoordinator) Generations() []uint64 {
	registry := c.Registry()
	if registry == nil {
		return nil
	}
	return registry.Generations()
}

// InstallGeneration builds and installs a new immutable registry before the
// caller publishes its matching snapshot. The returned rollback is idempotent.
func (c *SelectorCoordinator) InstallGeneration(generation state.SubscriptionGeneration, snapshot *state.RuntimeSnapshot) (*state.RuntimeSnapshot, func(), error) {
	if c == nil || snapshot == nil {
		return nil, nil, errors.New("app: selector installation requires coordinator and snapshot")
	}
	nextRegistry, err := selector.NewRegistry(generation)
	if err != nil {
		return nil, nil, fmt.Errorf("app: build selector registry: %w", err)
	}
	previous := make(map[string]state.NodeRef)
	for name, ref := range snapshot.Selectors {
		if ref.Generation == generation.Generation {
			previous[name] = ref
		}
	}
	result, err := nextRegistry.BuildWithTombstones(generation.Generation, snapshot.Nodes, previous, c.now().UTC())
	if err != nil {
		return nil, nil, fmt.Errorf("app: build selector snapshot: %w", err)
	}
	next := snapshot.Clone()
	next.Nodes = result.Nodes
	next.Selectors = result.Selectors

	c.mu.Lock()
	previousRegistry := c.registry
	if c.socks != nil {
		if err := c.socks.SetSelectors(nextRegistry); err != nil {
			c.mu.Unlock()
			return nil, nil, fmt.Errorf("app: install selector registry: %w", err)
		}
	}
	c.registry = nextRegistry
	c.mu.Unlock()

	var once sync.Once
	rollback := func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.socks != nil && previousRegistry != nil {
				_ = c.socks.SetSelectors(previousRegistry)
			}
			c.registry = previousRegistry
		})
	}
	return next, rollback, nil
}

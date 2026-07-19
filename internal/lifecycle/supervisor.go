// Package lifecycle coordinates critical daemon workers and bounded shutdown.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

type Worker struct {
	Name     string
	Run      func(context.Context) error
	Shutdown func(context.Context) error
}

type Supervisor struct {
	workers      []Worker
	drainTimeout time.Duration
}

func New(workers []Worker, drainTimeout time.Duration) (*Supervisor, error) {
	if len(workers) == 0 {
		return nil, errors.New("at least one critical worker is required")
	}
	if drainTimeout <= 0 {
		return nil, errors.New("drain timeout must be positive")
	}
	seen := make(map[string]struct{}, len(workers))
	for _, worker := range workers {
		if worker.Name == "" || worker.Run == nil {
			return nil, errors.New("every critical worker needs a name and Run function")
		}
		if _, ok := seen[worker.Name]; ok {
			return nil, fmt.Errorf("duplicate worker %q", worker.Name)
		}
		seen[worker.Name] = struct{}{}
	}
	return &Supervisor{workers: append([]Worker(nil), workers...), drainTimeout: drainTimeout}, nil
}

type workerResult struct {
	name string
	err  error
}

// Run blocks until the parent is cancelled or a critical worker returns. An
// unexpected worker return cancels all peers, performs bounded shutdown, and is
// returned as an error so the container restart policy can recover the service.
func (s *Supervisor) Run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	results := make(chan workerResult, len(s.workers))
	var running sync.WaitGroup
	for _, worker := range s.workers {
		worker := worker
		running.Add(1)
		go func() {
			defer running.Done()
			results <- workerResult{name: worker.Name, err: worker.Run(ctx)}
		}()
	}

	var cause error
	select {
	case <-parent.Done():
		cause = parent.Err()
	case result := <-results:
		if result.err == nil {
			cause = fmt.Errorf("critical worker %s stopped unexpectedly", result.name)
		} else if parent.Err() == nil {
			cause = fmt.Errorf("critical worker %s failed: %w", result.name, result.err)
		} else {
			cause = parent.Err()
		}
	}
	cancel()

	drainCtx, drainCancel := context.WithTimeout(context.Background(), s.drainTimeout)
	defer drainCancel()
	var shutdown sync.WaitGroup
	for index := len(s.workers) - 1; index >= 0; index-- {
		if s.workers[index].Shutdown == nil {
			continue
		}
		worker := s.workers[index]
		shutdown.Add(1)
		go func() {
			defer shutdown.Done()
			_ = worker.Shutdown(drainCtx)
		}()
	}
	shutdownDone := make(chan struct{})
	go func() {
		shutdown.Wait()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
	case <-drainCtx.Done():
		if cause == nil || errors.Is(cause, context.Canceled) {
			cause = fmt.Errorf("shutdown exceeded %s", s.drainTimeout)
		}
	}

	workersDone := make(chan struct{})
	go func() {
		running.Wait()
		close(workersDone)
	}()
	select {
	case <-workersDone:
	case <-drainCtx.Done():
	}

	if parent.Err() != nil && (errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded)) {
		return nil
	}
	return cause
}

// Watchdog returns a critical worker function that exits after threshold
// consecutive failed probes. A successful probe resets the failure count.
func Watchdog(interval time.Duration, threshold int, probe func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if interval <= 0 || threshold <= 0 || probe == nil {
			return errors.New("invalid watchdog configuration")
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		failures := 0
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				probeCtx, cancel := context.WithTimeout(ctx, interval)
				err := probe(probeCtx)
				cancel()
				if err == nil {
					failures = 0
					continue
				}
				failures++
				if failures >= threshold {
					return fmt.Errorf("liveness probe failed %d consecutive times: %w", failures, err)
				}
			}
		}
	}
}

// RequireContainer rejects unsupported bare-process starts. Native-Linux host
// validation is performed by scripts/preflight.sh because Docker Desktop cannot
// be reliably distinguished from inside its Linux VM without a Docker socket.
func RequireContainer() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("production requires a Linux container, got %s", runtime.GOOS)
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return nil
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return nil
	}
	return errors.New("bare-process execution rejected: container marker absent")
}

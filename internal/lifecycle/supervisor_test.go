package lifecycle

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnexpectedWorkerExitIsFatalAndDrains(t *testing.T) {
	var stopped atomic.Bool
	supervisor, err := New([]Worker{
		{
			Name: "listener",
			Run:  func(context.Context) error { return nil },
			Shutdown: func(context.Context) error {
				stopped.Store(true)
				return nil
			},
		},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = supervisor.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "stopped unexpectedly") {
		t.Fatalf("expected fatal worker exit, got %v", err)
	}
	if !stopped.Load() {
		t.Fatal("shutdown was not called")
	}
}

func TestParentCancellationIsClean(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	supervisor, err := New([]Worker{{
		Name: "worker",
		Run: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := supervisor.Run(ctx); err != nil {
		t.Fatalf("cancellation should be clean: %v", err)
	}
}

func TestWorkerCancellationWithLiveParentIsFatal(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			supervisor, err := New([]Worker{{
				Name: "worker",
				Run:  func(context.Context) error { return cause },
			}}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			err = supervisor.Run(context.Background())
			if !errors.Is(err, cause) || !strings.Contains(err.Error(), "critical worker worker failed") {
				t.Fatalf("live-parent cancellation was suppressed: %v", err)
			}
		})
	}
}

func TestSiblingCancellationPreservesOriginalFailure(t *testing.T) {
	primary := errors.New("listener failed")
	supervisor, err := New([]Worker{
		{Name: "listener", Run: func(context.Context) error { return primary }},
		{Name: "peer", Run: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = supervisor.Run(context.Background())
	if !errors.Is(err, primary) || !strings.Contains(err.Error(), "listener failed") {
		t.Fatalf("sibling cancellation replaced primary failure: %v", err)
	}
}

func TestWatchdogResetsAndEventuallyFails(t *testing.T) {
	var calls atomic.Int32
	probeErr := errors.New("down")
	probe := func(context.Context) error {
		switch calls.Add(1) {
		case 1, 3, 4:
			return probeErr
		default:
			return nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := Watchdog(time.Millisecond, 2, probe)(ctx)
	if err == nil || !strings.Contains(err.Error(), "2 consecutive") {
		t.Fatalf("expected threshold failure, got %v", err)
	}
}

func TestNewRejectsInvalidWorkers(t *testing.T) {
	if _, err := New(nil, time.Second); err == nil {
		t.Fatal("expected empty worker rejection")
	}
	if _, err := New([]Worker{{Name: "same", Run: func(context.Context) error { return nil }}, {Name: "same", Run: func(context.Context) error { return nil }}}, time.Second); err == nil {
		t.Fatal("expected duplicate rejection")
	}
}

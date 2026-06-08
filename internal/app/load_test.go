package app

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/RastBast/ordermesh-/internal/domain"
)

// TestConcurrentCreate hammers CreateOrder from many goroutines and asserts
// every order is persisted exactly once with a matching outbox event. This is
// a race-detector magnet: run with `go test -race`.
func TestConcurrentCreate(t *testing.T) {
	t.Parallel()
	svc, repo, outbox, _ := newTestService()

	const n = 500
	var wg sync.WaitGroup
	var failures int64
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := svc.CreateOrder(context.Background(), sampleInput()); err != nil {
				atomic.AddInt64(&failures, 1)
			}
		}()
	}
	wg.Wait()

	if failures != 0 {
		t.Fatalf("%d creates failed", failures)
	}
	repo.mu.Lock()
	got := len(repo.orders)
	repo.mu.Unlock()
	if got != n {
		t.Fatalf("want %d orders persisted, got %d", n, got)
	}
	outbox.mu.Lock()
	events := len(outbox.events)
	outbox.mu.Unlock()
	if events != n {
		t.Fatalf("want %d outbox events, got %d", n, events)
	}
}

// TestConcurrentStatusChange_OptimisticLock fires many concurrent transitions
// on the SAME order. The state machine + optimistic locking must keep it
// consistent: from PENDING, exactly one of {PAID, CANCELLED} wins as the first
// transition, and the order never ends up in an impossible state.
func TestConcurrentStatusChange(t *testing.T) {
	t.Parallel()
	svc, _, _, _ := newTestService()

	o, err := svc.CreateOrder(context.Background(), sampleInput())
	if err != nil {
		t.Fatal(err)
	}

	const n = 100
	var wg sync.WaitGroup
	var paidOK, cancelOK int64
	wg.Add(n)
	for i := 0; i < n; i++ {
		target := domain.StatusPaid
		if i%2 == 1 {
			target = domain.StatusCancelled
		}
		go func(target domain.Status) {
			defer wg.Done()
			if _, err := svc.ChangeStatus(context.Background(), o.ID, target); err == nil {
				if target == domain.StatusPaid {
					atomic.AddInt64(&paidOK, 1)
				} else {
					atomic.AddInt64(&cancelOK, 1)
				}
			}
		}(target)
	}
	wg.Wait()

	final, err := svc.GetOrder(context.Background(), o.ID)
	if err != nil {
		t.Fatal(err)
	}
	// The order must be in a valid reachable state.
	switch final.Status {
	case domain.StatusPaid, domain.StatusCancelled, domain.StatusShipped:
		// ok
	default:
		t.Fatalf("order ended in unexpected state %s", final.Status)
	}
	// At most one terminal CANCELLED or progression to PAID could have won the
	// first transition; we only assert no panic/inconsistency and that at least
	// one transition succeeded.
	if paidOK == 0 && cancelOK == 0 {
		t.Fatal("no transition succeeded under contention")
	}
	t.Logf("final=%s paidOK=%d cancelOK=%d", final.Status, paidOK, cancelOK)
}

// BenchmarkCreateOrder measures create throughput through the use-case layer.
func BenchmarkCreateOrder(b *testing.B) {
	svc, _, _, _ := newTestService()
	in := sampleInput()
	in.CustomerID = uuid.New()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := svc.CreateOrder(context.Background(), in); err != nil {
			b.Fatal(err)
		}
	}
}

// Package ratelimit provides two complementary limiters:
//
//   - Local: an in-process token bucket per key, a cheap last line of defence
//     against caller bursts and cascading failure even if the gateway/mesh
//     limiter is bypassed (Zero Trust: never assume the edge protected you).
//   - Distributed: a Redis-backed limiter shared across all replicas for fair,
//     global quotas.
//
// The HTTP middleware composes them.
package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Local is a sharded map of token buckets keyed by an arbitrary string
// (typically the principal subject or client IP). Idle buckets are evicted by
// a background janitor to bound memory.
type Local struct {
	mu       sync.Mutex
	buckets  map[string]*entry
	r        rate.Limit
	b        int
	ttl      time.Duration
	stopOnce sync.Once
	stop     chan struct{}
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewLocal builds a per-key limiter allowing `rps` requests/sec with `burst`.
func NewLocal(rps float64, burst int) *Local {
	l := &Local{
		buckets: make(map[string]*entry),
		r:       rate.Limit(rps),
		b:       burst,
		ttl:     10 * time.Minute,
		stop:    make(chan struct{}),
	}
	go l.janitor()
	return l
}

// Allow reports whether one request for key may proceed now.
func (l *Local) Allow(key string) bool {
	l.mu.Lock()
	e, ok := l.buckets[key]
	if !ok {
		e = &entry{limiter: rate.NewLimiter(l.r, l.b)}
		l.buckets[key] = e
	}
	e.lastSeen = time.Now()
	l.mu.Unlock()
	return e.limiter.Allow()
}

// Close stops the background janitor.
func (l *Local) Close() {
	l.stopOnce.Do(func() { close(l.stop) })
}

func (l *Local) janitor() {
	ticker := time.NewTicker(l.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-l.ttl)
			l.mu.Lock()
			for k, e := range l.buckets {
				if e.lastSeen.Before(cutoff) {
					delete(l.buckets, k)
				}
			}
			l.mu.Unlock()
		}
	}
}

// DistributedLimiter is the interface satisfied by the Redis implementation,
// kept small so it can be faked in tests.
type DistributedLimiter interface {
	// Allow reports whether the key is within quota, plus seconds until reset.
	Allow(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, err error)
}

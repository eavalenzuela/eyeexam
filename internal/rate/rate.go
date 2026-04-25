// Package rate provides the two limiters that gate test execution: a global
// token bucket on test starts and a per-host concurrency semaphore. Both are
// in-process; the M1 single-shot CLI does not coordinate across processes.
package rate

import (
	"context"
	"sync"
	"time"
)

// Limiter is the global tests-per-second limiter. Implemented as a simple
// token bucket with capacity 1; refills at the configured rate.
type Limiter struct {
	mu        sync.Mutex
	interval  time.Duration
	nextReady time.Time
}

// NewLimiter returns a limiter that allows one event per interval. An
// interval of 0 disables rate limiting.
func NewLimiter(perSecond float64) *Limiter {
	if perSecond <= 0 {
		return &Limiter{}
	}
	return &Limiter{interval: time.Duration(float64(time.Second) / perSecond)}
}

// Wait blocks until a token is available or ctx is cancelled.
func (l *Limiter) Wait(ctx context.Context) error {
	if l.interval == 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	wait := time.Duration(0)
	if now.Before(l.nextReady) {
		wait = l.nextReady.Sub(now)
	}
	l.nextReady = now.Add(wait).Add(l.interval)
	l.mu.Unlock()

	if wait == 0 {
		return ctx.Err()
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

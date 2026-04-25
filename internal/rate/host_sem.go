package rate

import (
	"context"
	"sync"
)

// HostSemaphore enforces per-host concurrency caps. Each host is keyed by an
// opaque string (the host id). The Acquire/Release pair is the safe usage.
type HostSemaphore struct {
	mu       sync.Mutex
	capacity int
	chans    map[string]chan struct{}
}

func NewHostSemaphore(capacity int) *HostSemaphore {
	if capacity < 1 {
		capacity = 1
	}
	return &HostSemaphore{capacity: capacity, chans: make(map[string]chan struct{})}
}

func (h *HostSemaphore) lease(hostID string) chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.chans[hostID]
	if !ok {
		c = make(chan struct{}, h.capacity)
		h.chans[hostID] = c
	}
	return c
}

// Acquire blocks until a slot is available for hostID or ctx is cancelled.
func (h *HostSemaphore) Acquire(ctx context.Context, hostID string) error {
	c := h.lease(hostID)
	select {
	case c <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns a slot for hostID. Must pair with a successful Acquire.
func (h *HostSemaphore) Release(hostID string) {
	h.mu.Lock()
	c, ok := h.chans[hostID]
	h.mu.Unlock()
	if !ok {
		return
	}
	select {
	case <-c:
	default:
	}
}

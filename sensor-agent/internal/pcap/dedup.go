package pcap

import (
	"sync"
	"time"
)

// dedupKey uniquely identifies an alert for deduplication purposes.
type dedupKey struct {
	communityID string
	sid         string
	sensorID    string
}

// dedupEntry holds the expiry time for a dedup cache entry.
type dedupEntry struct {
	expiresAt time.Time
}

// dedupCache is an in-memory deduplication cache keyed on
// (community_id, sid, sensor_id) with a configurable TTL.
// A background goroutine sweeps expired entries.
type dedupCache struct {
	mu      sync.Mutex
	entries map[dedupKey]dedupEntry
	window  time.Duration
	stopCh  chan struct{}
}

// newDedupCache creates a new deduplication cache with the given TTL window
// and starts a background sweep goroutine. Call stop() to shut it down.
func newDedupCache(window time.Duration) *dedupCache {
	if window <= 0 {
		window = 30 * time.Second
	}
	dc := &dedupCache{
		entries: make(map[dedupKey]dedupEntry),
		window:  window,
		stopCh:  make(chan struct{}),
	}
	go dc.sweepLoop()
	return dc
}

// IsDuplicate returns true if the (communityID, sid, sensorID) tuple was seen
// within the dedup window. If it is not a duplicate, the entry is recorded and
// false is returned.
func (dc *dedupCache) IsDuplicate(communityID, sid, sensorID string) bool {
	key := dedupKey{communityID: communityID, sid: sid, sensorID: sensorID}
	now := time.Now()

	dc.mu.Lock()
	defer dc.mu.Unlock()

	if entry, ok := dc.entries[key]; ok {
		if now.Before(entry.expiresAt) {
			return true
		}
	}
	dc.entries[key] = dedupEntry{expiresAt: now.Add(dc.window)}
	return false
}

// Size returns the current number of entries in the cache.
func (dc *dedupCache) Size() int {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return len(dc.entries)
}

// stop shuts down the background sweep goroutine.
func (dc *dedupCache) stop() {
	close(dc.stopCh)
}

// sweepLoop runs periodically and removes expired entries from the cache.
func (dc *dedupCache) sweepLoop() {
	// Sweep at half the window interval so entries don't linger too long.
	interval := dc.window / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dc.sweep()
		case <-dc.stopCh:
			return
		}
	}
}

// sweep removes all expired entries from the cache.
func (dc *dedupCache) sweep() {
	now := time.Now()
	dc.mu.Lock()
	defer dc.mu.Unlock()
	for k, v := range dc.entries {
		if now.After(v.expiresAt) {
			delete(dc.entries, k)
		}
	}
}

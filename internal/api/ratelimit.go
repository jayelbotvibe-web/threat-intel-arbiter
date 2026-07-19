package api

import (
	"log"
	"sync"
	"time"
)

// rateLimiter provides per-IP and per-account rate limiting for login attempts.
type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time // keyed by "ip:" + ip or "user:" + username
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{attempts: make(map[string][]time.Time)}
	go rl.evictor(5 * time.Minute)
	return rl
}

// allow returns true if the request should be allowed.
// After maxAttempts within window, returns false.
func (rl *rateLimiter) allow(key string, maxAttempts int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	// Filter attempts within window
	var recent []time.Time
	for _, t := range rl.attempts[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	rl.attempts[key] = recent

	if len(recent) >= maxAttempts {
		return false
	}
	rl.attempts[key] = append(rl.attempts[key], now)
	return true
}

// reset clears attempts for a key (called on successful login).
func (rl *rateLimiter) reset(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.attempts, key)
}

// evictor periodically removes keys whose all timestamps are older than
// the longest window (5 minutes). This prevents memory-exhaustion DoS
// from attacker-controlled username/IP flooding.
func (rl *rateLimiter) evictor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		rl.evict()
	}
}

func (rl *rateLimiter) evict() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	for key, times := range rl.attempts {
		hasRecent := false
		for _, t := range times {
			if t.After(cutoff) {
				hasRecent = true
				break
			}
		}
		if !hasRecent {
			delete(rl.attempts, key)
		}
	}
	if len(rl.attempts) == 0 {
		return
	}
	log.Printf("ratelimit: eviction tick — %d active keys", len(rl.attempts))
}

// size returns the current number of tracked keys (for testing).
func (rl *rateLimiter) size() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.attempts)
}

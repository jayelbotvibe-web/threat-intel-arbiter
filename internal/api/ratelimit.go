package api

import (
	"sync"
	"time"
)

// rateLimiter provides per-IP and per-account rate limiting for login attempts.
type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time // keyed by "ip:" + ip or "user:" + username
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{attempts: make(map[string][]time.Time)}
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

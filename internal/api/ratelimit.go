package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/sandrorichi/webapp-template/internal/auth"
	"github.com/sandrorichi/webapp-template/internal/httputil"
)

const (
	// rateLimitRate is the sustained request rate per authenticated subject.
	rateLimitRate = time.Second / 2 // 2 requests per second
	// rateLimitBurst is the maximum number of requests a subject can make in a
	// burst before the limiter throttles them.
	rateLimitBurst = 10
	// rateLimitMaxBuckets bounds the in-memory map so the limiter cannot grow
	// without bound if many distinct subjects make requests.
	rateLimitMaxBuckets = 10000
	// rateLimitBucketTTL is how long an idle bucket is retained before cleanup.
	rateLimitBucketTTL = time.Hour
	// rateLimitCleanupInterval is how often a full sweep for stale buckets runs.
	rateLimitCleanupInterval = time.Minute
)

// clock abstracts time for testability.
type clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// rateLimiter is a simple in-memory token-bucket rate limiter keyed by
// authenticated subject. It is intentionally stdlib-only and is suitable for
// a small internal app with a handful of admins.
//
// Buckets are lazily cleaned up after rateLimitBucketTTL of inactivity and the
// total number of buckets is capped at rateLimitMaxBuckets to prevent
// unbounded memory growth.
type rateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	rate        time.Duration
	burst       int
	lastCleanup time.Time
	clock       clock
}

type bucket struct {
	tokens int
	last   time.Time
}

func newRateLimiter(rate time.Duration, burst int) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		clock:   realClock{},
	}
}

// allow reports whether one request from subject is permitted under the bucket.
func (rl *rateLimiter) allow(subject string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.clock.Now()
	if now.Sub(rl.lastCleanup) >= rateLimitCleanupInterval {
		rl.cleanupLocked(now)
		rl.lastCleanup = now
	}

	b, ok := rl.buckets[subject]
	if !ok {
		if len(rl.buckets) >= rateLimitMaxBuckets {
			rl.evictOldestLocked()
		}
		b = &bucket{tokens: rl.burst}
		rl.buckets[subject] = b
	}

	elapsed := now.Sub(b.last)
	b.last = now

	b.tokens += int(elapsed / rl.rate)
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}

	if b.tokens > 0 {
		b.tokens--
		return true
	}
	return false
}

// cleanupLocked removes buckets whose last-use timestamp is older than
// rateLimitBucketTTL. The caller must hold rl.mu.
func (rl *rateLimiter) cleanupLocked(now time.Time) {
	for k, b := range rl.buckets {
		if now.Sub(b.last) >= rateLimitBucketTTL {
			delete(rl.buckets, k)
		}
	}
}

// evictOldestLocked removes the least-recently-used bucket to keep the map
// under rateLimitMaxBuckets. The caller must hold rl.mu.
func (rl *rateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, b := range rl.buckets {
		if oldest.IsZero() || b.last.Before(oldest) {
			oldest = b.last
			oldestKey = k
		}
	}
	if oldestKey != "" {
		delete(rl.buckets, oldestKey)
	}
}

// adminMiddleware returns an http.Handler that rate-limits authenticated admin
// mutations by principal subject. It must be installed after auth.Middleware so
// that a Principal is present in the request context.
func (rl *rateLimiter) adminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			httputil.WriteProblem(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
			return
		}
		if !rl.allow(principal.Subject) {
			httputil.WriteProblem(w, http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests), "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

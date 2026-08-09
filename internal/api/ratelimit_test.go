package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sandrorichi/webapp-template/internal/auth"
)

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(time.Hour, 2) // 1 token per hour, burst of 2

	subject := "user-1"
	if !rl.allow(subject) {
		t.Fatal("first request should be allowed")
	}
	if !rl.allow(subject) {
		t.Fatal("second request within burst should be allowed")
	}
	if rl.allow(subject) {
		t.Fatal("third request should be rejected")
	}

	// A different subject has its own bucket.
	if !rl.allow("user-2") {
		t.Fatal("request from different subject should be allowed")
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	rl := newRateLimiter(time.Hour, 1)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rl.adminMiddleware(inner)

	withPrincipal := func(p auth.Principal, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
		})
	}

	makeRequest := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/config/key", nil)
		rec := httptest.NewRecorder()
		p := auth.Principal{Subject: "s1"}
		withPrincipal(p, handler).ServeHTTP(rec, req)
		return rec
	}

	if rec := makeRequest(); rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec.Code)
	}
	if rec := makeRequest(); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", rec.Code)
	}
}

type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time { return c.now }

func TestRateLimiterEvictsStaleBuckets(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := newRateLimiter(time.Hour, 2)
	rl.clock = fakeClock{now: start}

	// Allow creates a bucket for "user-1".
	if !rl.allow("user-1") {
		t.Fatal("first request should be allowed")
	}
	if len(rl.buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(rl.buckets))
	}

	// Move time past the bucket TTL and run cleanup.
	rl.clock = fakeClock{now: start.Add(rateLimitBucketTTL + time.Second)}
	rl.cleanupLocked(rl.clock.Now())
	if len(rl.buckets) != 0 {
		t.Fatalf("buckets after cleanup = %d, want 0", len(rl.buckets))
	}
}

func TestRateLimiterCapsBuckets(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Make cleanup a no-op by setting a recent lastCleanup.
	rl := &rateLimiter{
		buckets:     make(map[string]*bucket),
		rate:        time.Hour,
		burst:       1,
		lastCleanup: now,
		clock:       fakeClock{now: now},
	}

	// Fill to the cap.
	for i := 0; i < rateLimitMaxBuckets; i++ {
		rl.buckets[fmt.Sprintf("user-%d", i)] = &bucket{tokens: 1, last: time.Now().Add(-time.Duration(i) * time.Second)}
	}
	// The oldest bucket is user-<cap-1> because of the decreasing timestamps.
	oldestKey := fmt.Sprintf("user-%d", rateLimitMaxBuckets-1)
	if _, ok := rl.buckets[oldestKey]; !ok {
		t.Fatalf("test setup error: oldest key %s not present", oldestKey)
	}

	// A new subject should evict the oldest bucket.
	if !rl.allow("new-user") {
		t.Fatal("new request should be allowed")
	}
	if len(rl.buckets) != rateLimitMaxBuckets {
		t.Fatalf("buckets = %d, want %d", len(rl.buckets), rateLimitMaxBuckets)
	}
	if _, ok := rl.buckets[oldestKey]; ok {
		t.Fatalf("oldest bucket %s should have been evicted", oldestKey)
	}
}

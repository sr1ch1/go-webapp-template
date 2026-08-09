package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// render returns the full exposition output of r, including runtime metrics.
func render(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	r.Render(&b)
	return b.String()
}

func TestCounterVec(t *testing.T) {
	reg := NewRegistry()
	c := reg.CounterVec("http_requests_total", "Total requests.", "method", "route")
	c.Inc("GET", "/api/me")
	c.Inc("GET", "/api/me")
	c.Add(1, "POST", "/api/config")

	want := `# HELP http_requests_total Total requests.
# TYPE http_requests_total counter
http_requests_total{method="GET",route="/api/me"} 2
http_requests_total{method="POST",route="/api/config"} 1
`
	if got := render(t, reg); !strings.Contains(got, want) {
		t.Errorf("output missing expected block:\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestGauge(t *testing.T) {
	reg := NewRegistry()
	g := reg.Gauge("queue_depth", "Pending jobs.")
	g.Inc()
	g.Inc()
	g.Dec()
	g.Set(7)

	want := "# HELP queue_depth Pending jobs.\n# TYPE queue_depth gauge\nqueue_depth 7\n"
	if got := render(t, reg); !strings.Contains(got, want) {
		t.Errorf("output missing expected block:\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestHistogramVec(t *testing.T) {
	reg := NewRegistry()
	// Buckets are passed unsorted on purpose; the registry must sort them.
	h := reg.HistogramVec("http_request_duration_seconds", "Latency.", []float64{1, 0.1}, "method")
	h.Observe(0.05, "GET")
	h.Observe(0.5, "GET")
	h.Observe(5, "GET")

	want := `# HELP http_request_duration_seconds Latency.
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="GET",le="0.1"} 1
http_request_duration_seconds_bucket{method="GET",le="1"} 2
http_request_duration_seconds_bucket{method="GET",le="+Inf"} 3
http_request_duration_seconds_sum{method="GET"} 5.55
http_request_duration_seconds_count{method="GET"} 3
`
	if got := render(t, reg); !strings.Contains(got, want) {
		t.Errorf("output missing expected block:\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestLabelEscaping(t *testing.T) {
	reg := NewRegistry()
	c := reg.CounterVec("escaped", "Escapes.", "label")
	c.Inc("a\"b\\c\nd")

	want := "escaped{label=\"a\\\"b\\\\c\\nd\"} 1\n"
	if got := render(t, reg); !strings.Contains(got, want) {
		t.Errorf("output missing escaped series:\nwant: %q\ngot:\n%s", want, got)
	}
}

func TestRegistrationPanics(t *testing.T) {
	mustPanic := func(t *testing.T, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Error("expected panic")
			}
		}()
		fn()
	}

	t.Run("duplicate name", func(t *testing.T) {
		reg := NewRegistry()
		reg.CounterVec("dup", "First.")
		mustPanic(t, func() { reg.Gauge("dup", "Second.") })
	})

	t.Run("wrong label count on counter", func(t *testing.T) {
		reg := NewRegistry()
		c := reg.CounterVec("c", "Help.", "a", "b")
		mustPanic(t, func() { c.Inc("only-one") })
	})

	t.Run("wrong label count on histogram", func(t *testing.T) {
		reg := NewRegistry()
		h := reg.HistogramVec("h", "Help.", []float64{1}, "a")
		mustPanic(t, func() { h.Observe(0.5) })
	})

	t.Run("histogram without buckets", func(t *testing.T) {
		reg := NewRegistry()
		mustPanic(t, func() { reg.HistogramVec("h", "Help.", nil) })
	})
}

func TestHandler(t *testing.T) {
	reg := NewRegistry()
	reg.CounterVec("requests_total", "Total.").Inc()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q, want Prometheus text format", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"requests_total 1", "go_goroutines ", "go_memstats_alloc_bytes "} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}

func TestEmptyRegistry(t *testing.T) {
	got := render(t, NewRegistry())
	if !strings.Contains(got, "go_goroutines") {
		t.Errorf("empty registry should still render runtime metrics, got:\n%s", got)
	}
}

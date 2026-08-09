package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/sr1ch1/webapp-template/internal/metrics"
)

// durationBuckets are the latency histogram bounds in seconds.
var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// httpMetricsSet groups the metrics the HTTP middleware records.
type httpMetricsSet struct {
	registry *metrics.Registry
	requests *metrics.CounterVec
	duration *metrics.HistogramVec
	active   *metrics.Gauge
}

func newHTTPMetrics() *httpMetricsSet {
	reg := metrics.NewRegistry()
	return &httpMetricsSet{
		registry: reg,
		requests: reg.CounterVec("http_requests_total", "Total HTTP requests on the authenticated chain.", "method", "route", "status"),
		duration: reg.HistogramVec("http_request_duration_seconds", "HTTP request latency in seconds on the authenticated chain.", durationBuckets, "method", "route"),
		active:   reg.Gauge("http_active_requests", "In-flight HTTP requests on the authenticated chain."),
	}
}

// middleware records request count, latency, and the in-flight gauge. The
// route label is the matched ServeMux pattern, keeping cardinality bounded;
// requests rejected before routing (auth, CSRF, body size) are labeled "-".
func (m *httpMetricsSet) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.active.Inc()
		defer m.active.Dec()

		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		route := r.Pattern
		if route == "" {
			route = "-"
		}
		m.requests.Inc(r.Method, route, strconv.Itoa(recorder.status))
		m.duration.Observe(time.Since(start).Seconds(), r.Method, route)
	})
}

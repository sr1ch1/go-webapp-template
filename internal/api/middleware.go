package api

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sandrorichi/webapp-template/internal/auth"
	"github.com/sandrorichi/webapp-template/internal/httputil"
)

// requestID assigns every request a random 16-byte hex ID, exposed via the
// X-Request-Id response header and carried in the context for log lines.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			// crypto/rand failure is fatal enough to refuse the request.
			httputil.WriteProblem(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
			return
		}
		id := hex.EncodeToString(buf)
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(httputil.WithRequestID(r.Context(), id)))
	})
}

// statusRecorder captures the response status code for access logging and
// metrics. It forwards http.Flusher and implements Unwrap so handlers can
// stream (e.g. SSE) through the wrapper, whether they flush via a direct
// type assertion or via http.ResponseController.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

// Flush streams any buffered data to the client. The stdlib server's
// response writer always implements http.Flusher; the guard only covers
// exotic underlying writers.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying writer to http.ResponseController, which
// probes optional interfaces (Flush, Hijack, ...) on the unwrapped writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// logging emits one structured access log line per request: INFO for normal
// routes, DEBUG for the unauthenticated probes.
func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", httputil.RequestIDFromContext(r.Context()),
		}
		if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
			attrs = append(attrs, "subject", principal.Subject)
		}
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			log.Debug("request", attrs...)
		} else {
			log.Info("request", attrs...)
		}
	})
}

// securityHeaders sets the template's strict headers on every response. The
// API additionally opts out of caching. When disableHSTS is true, the
// Strict-Transport-Security header is omitted for local HTTP development.
func securityHeaders(disableHSTS bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if !disableHSTS {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// maxRequestBodyBytes is the maximum request body the application will read.
// Anything larger is rejected with 413 Payload Too Large.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

// maxBody limits the request body size for routes that may read a body. GET
// and HEAD are skipped; for other methods the wrapped body returns
// http.MaxBytesError once the limit is exceeded.
func maxBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// CSRF guards state-changing requests. The Identity Provider attaches the
// caller's identity to any browser request — including cross-site ones — so
// cookies being absent is not enough. Mutations must carry a custom header a
// cross-site form cannot set (X-Requested-With: fetch or htmx's HX-Request),
// and Fetch Metadata is honored when the browser sends it.
func csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-Requested-With") != "fetch" && r.Header.Get("HX-Request") != "true" {
			httputil.WriteProblem(w, http.StatusForbidden, http.StatusText(http.StatusForbidden), "")
			return
		}
		switch r.Header.Get("Sec-Fetch-Site") {
		case "", "same-origin", "same-site", "none":
			// Absent (non-browser clients) or trustworthy.
		default:
			httputil.WriteProblem(w, http.StatusForbidden, http.StatusText(http.StatusForbidden), "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

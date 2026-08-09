package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sr1ch1/webapp-template/internal/auth"
	"github.com/sr1ch1/webapp-template/internal/httputil"
	"github.com/sr1ch1/webapp-template/internal/store"
	"github.com/sr1ch1/webapp-template/internal/version"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})
	return st
}

// withPrincipal injects a Principal, standing in for the auth middleware.
func withPrincipal(p auth.Principal, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	})
}

func TestVersionHandler(t *testing.T) {
	oldVersion, oldCommit, oldBuildTime := version.Version, version.Commit, version.BuildTime
	version.Version = "1.2.3"
	version.Commit = "abc123"
	version.BuildTime = "2025-01-01T00:00:00Z"
	t.Cleanup(func() {
		version.Version, version.Commit, version.BuildTime = oldVersion, oldCommit, oldBuildTime
	})

	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	rec := httptest.NewRecorder()
	versionHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if got["version"] != "1.2.3" || got["commit"] != "abc123" || got["build_time"] != "2025-01-01T00:00:00Z" {
		t.Errorf("unexpected body: %v", got)
	}
	if _, ok := got["buildTime"]; ok {
		t.Error("body uses camelCase; JSON must be snake_case")
	}
}

func TestStatusRecorderUnwrap(t *testing.T) {
	inner := httptest.NewRecorder()
	s := &statusRecorder{ResponseWriter: inner, status: http.StatusOK}
	if got := s.Unwrap(); got != inner {
		t.Errorf("Unwrap() = %v, want the wrapped ResponseWriter %v", got, inner)
	}
	// ResponseController relies on Unwrap to find optional interfaces on the
	// underlying writer.
	if err := http.NewResponseController(s).Flush(); err != nil {
		t.Errorf("ResponseController.Flush through Unwrap: %v", err)
	}
}

func TestMeHandler(t *testing.T) {
	p := auth.Principal{Subject: "s1", Email: "a@example.com", DisplayName: "Ada", Roles: []string{"admin"}}
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rec := httptest.NewRecorder()
	withPrincipal(p, http.HandlerFunc(me)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if got["subject"] != "s1" || got["display_name"] != "Ada" {
		t.Errorf("unexpected body: %v", got)
	}
	if _, ok := got["displayName"]; ok {
		t.Error("body uses camelCase; JSON must be snake_case")
	}
}

func TestPutConfigInvalidKey(t *testing.T) {
	st := openStore(t)
	handler := auth.RequireRole("admin")(putConfig(st))

	req := httptest.NewRequest(http.MethodPut, "/api/config/bad/key", strings.NewReader(`{"value":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("key", "bad/key")
	rec := httptest.NewRecorder()
	p := auth.Principal{Subject: "s1", Roles: []string{"admin"}}
	withPrincipal(p, handler).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRequireRole(t *testing.T) {
	st := openStore(t)
	handler := auth.RequireRole("admin")(putConfig(st))

	t.Run("admin allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/config/site_name", strings.NewReader(`{"value":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("key", "site_name")
		rec := httptest.NewRecorder()
		p := auth.Principal{Subject: "s1", Roles: []string{"admin"}}
		withPrincipal(p, handler).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("non-admin gets vague 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/config/site_name", strings.NewReader(`{"value":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("key", "site_name")
		rec := httptest.NewRecorder()
		p := auth.Principal{Subject: "s2", Roles: []string{}}
		withPrincipal(p, handler).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		assertProblemShape(t, rec)
	})
}

func TestPutConfigContentType(t *testing.T) {
	st := openStore(t)
	handler := auth.RequireRole("admin")(putConfig(st))

	t.Run("missing content type rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/config/site_name", strings.NewReader(`{"value":"x"}`))
		req.SetPathValue("key", "site_name")
		rec := httptest.NewRecorder()
		p := auth.Principal{Subject: "s1", Roles: []string{"admin"}}
		withPrincipal(p, handler).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415", rec.Code)
		}
	})

	t.Run("non-json content type rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/config/site_name", strings.NewReader(`value=x`))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetPathValue("key", "site_name")
		rec := httptest.NewRecorder()
		p := auth.Principal{Subject: "s1", Roles: []string{"admin"}}
		withPrincipal(p, handler).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415", rec.Code)
		}
	})

	t.Run("json with charset accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/config/site_name", strings.NewReader(`{"value":"x"}`))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.SetPathValue("key", "site_name")
		rec := httptest.NewRecorder()
		p := auth.Principal{Subject: "s1", Roles: []string{"admin"}}
		withPrincipal(p, handler).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})
}

func TestReadyz(t *testing.T) {
	t.Run("store healthy", func(t *testing.T) {
		st := openStore(t)
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()
		readyz(st).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decoding body: %v", err)
		}
		if got["status"] != "ok" {
			t.Errorf("unexpected body: %v", got)
		}
	})

	t.Run("store down gives vague 503", func(t *testing.T) {
		st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "app.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()
		readyz(st).ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
		assertProblemShape(t, rec)
	})
}

func TestMeHandlerNoPrincipal(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rec := httptest.NewRecorder()
	me(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertProblemShape(t, rec)
}

func TestListConfig(t *testing.T) {
	t.Run("lists entries", func(t *testing.T) {
		st := openStore(t)
		if err := st.SetConfig(context.Background(), "site_name", "demo"); err != nil {
			t.Fatalf("SetConfig: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
		rec := httptest.NewRecorder()
		listConfig(st).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var got []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decoding body: %v", err)
		}
		// The store seeds a default entry, so look for ours specifically.
		found := false
		for _, e := range got {
			if e["key"] == "site_name" && e["value"] == "demo" {
				found = true
			}
		}
		if !found {
			t.Errorf("site_name=demo not found in body: %v", got)
		}
	})

	t.Run("store error gives vague 500", func(t *testing.T) {
		st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "app.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
		rec := httptest.NewRecorder()
		listConfig(st).ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
		assertProblemShape(t, rec)
	})
}

func TestPutConfigBody(t *testing.T) {
	p := auth.Principal{Subject: "s1", Roles: []string{"admin"}}
	newRequest := func(body string) (*http.Request, *httptest.ResponseRecorder) {
		req := httptest.NewRequest(http.MethodPut, "/api/config/site_name", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("key", "site_name")
		return req, httptest.NewRecorder()
	}

	t.Run("malformed JSON rejected", func(t *testing.T) {
		st := openStore(t)
		req, rec := newRequest(`{"value":`)
		withPrincipal(p, putConfig(st)).ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		assertProblemShape(t, rec)
		var problem map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
			t.Fatalf("decoding problem body: %v", err)
		}
		if problem["detail"] != "invalid request body" {
			t.Errorf("detail = %v, want %q", problem["detail"], "invalid request body")
		}
	})

	t.Run("oversized body rejected", func(t *testing.T) {
		st := openStore(t)
		req, rec := newRequest(`{"value":"` + strings.Repeat("x", 64) + `"}`)
		req.Body = http.MaxBytesReader(rec, req.Body, 8)
		withPrincipal(p, putConfig(st)).ServeHTTP(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
		assertProblemShape(t, rec)
	})

	t.Run("store error gives vague 500", func(t *testing.T) {
		st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "app.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}

		req, rec := newRequest(`{"value":"x"}`)
		withPrincipal(p, putConfig(st)).ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
		assertProblemShape(t, rec)
	})
}

func TestWriteJSONEncodeError(t *testing.T) {
	// An unencodable value exercises the error branch; the status is already
	// written by then, so the handler can only log and move on.
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, make(chan int))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestCSRFMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := csrf(inner)

	newRequest := func() *http.Request {
		return httptest.NewRequest(http.MethodPut, "/api/config/key", nil)
	}

	t.Run("mutation without custom header rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newRequest())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("cross-site fetch metadata rejected", func(t *testing.T) {
		req := newRequest()
		req.Header.Set("HX-Request", "true")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("HX-Request accepted", func(t *testing.T) {
		req := newRequest()
		req.Header.Set("HX-Request", "true")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("X-Requested-With fetch accepted", func(t *testing.T) {
		req := newRequest()
		req.Header.Set("X-Requested-With", "fetch")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("GET passes without headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})
}

// assertProblemShape checks the RFC 9457 problem-details contract.
func assertProblemShape(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var problem map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decoding problem body: %v", err)
	}
	for _, field := range []string{"type", "title", "status"} {
		if _, ok := problem[field]; !ok {
			t.Errorf("problem body missing %q: %v", field, problem)
		}
	}
	if status, ok := problem["status"].(float64); !ok || int(status) != rec.Code {
		t.Errorf("problem status = %v, response status = %d", problem["status"], rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("api route gets no-store", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		rec := httptest.NewRecorder()
		securityHeaders(false, inner).ServeHTTP(rec, req)
		h := rec.Header()
		if got := h.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
			t.Errorf("CSP = %q", got)
		}
		if h.Get("X-Frame-Options") != "DENY" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("headers = %v", h)
		}
		if got := h.Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
			t.Errorf("HSTS = %q", got)
		}
		if got := h.Get("Permissions-Policy"); got == "" {
			t.Errorf("Permissions-Policy not set")
		}
		if h.Get("Cache-Control") != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store on /api/*", h.Get("Cache-Control"))
		}
	})

	t.Run("non-api route cached normally", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		securityHeaders(false, inner).ServeHTTP(rec, req)
		if h := rec.Header().Get("Cache-Control"); h != "" {
			t.Errorf("Cache-Control = %q, want unset outside /api/*", h)
		}
	})

	t.Run("HSTS omitted when disabled", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		securityHeaders(true, inner).ServeHTTP(rec, req)
		if h := rec.Header().Get("Strict-Transport-Security"); h != "" {
			t.Errorf("Strict-Transport-Security = %q, want unset when disabled", h)
		}
	})
}

func TestRequestIDHeader(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	requestID(inner).ServeHTTP(rec, req)
	if id := rec.Header().Get("X-Request-Id"); len(id) != 32 {
		t.Errorf("X-Request-Id = %q, want 32 hex chars", id)
	}
}

func TestRequestIDContext(t *testing.T) {
	// The generated ID must be carried in the request context so handlers and
	// log lines can correlate with the X-Request-Id response header.
	var ctxID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = httputil.RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	requestID(inner).ServeHTTP(rec, req)

	if ctxID == "" {
		t.Fatal("request ID missing from context")
	}
	if got := rec.Header().Get("X-Request-Id"); got != ctxID {
		t.Errorf("X-Request-Id = %q, context ID = %q, want equal", got, ctxID)
	}
}

func TestRequestIDIncomingHeaderIgnored(t *testing.T) {
	// The middleware always generates a fresh ID; a client-supplied
	// X-Request-Id must not be trusted or echoed back.
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "client-supplied")
	rec := httptest.NewRecorder()
	requestID(inner).ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-Id"); got == "client-supplied" {
		t.Errorf("X-Request-Id = %q, want a fresh server-generated ID", got)
	}
}

func TestLoggingWithPrincipal(t *testing.T) {
	// A principal in context adds the subject attribute to the access log.
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	p := auth.Principal{Subject: "s1"}
	withPrincipal(p, logging(log, inner)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := buf.String(); !strings.Contains(got, `"subject":"s1"`) {
		t.Errorf("log line missing subject attribute: %s", got)
	}
}

func TestStatusRecorderStreaming(t *testing.T) {
	// SSE handlers flush through the middleware wrappers; statusRecorder must
	// forward http.Flusher and cooperate with http.ResponseController.
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Error("wrapped writer does not implement http.Flusher")
			return
		}
		if _, err := fmt.Fprint(w, "data: hello\n\n"); err != nil {
			t.Errorf("write: %v", err)
		}
		f.Flush()
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("ResponseController.Flush: %v", err)
		}
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	logging(testLogger(), inner).ServeHTTP(rec, req)

	if got := rec.Body.String(); got != "data: hello\n\n" {
		t.Errorf("body = %q, want SSE frame", got)
	}
	if !rec.Flushed {
		t.Error("response was not flushed through the wrapper")
	}
}

func TestHTTPMetricsMiddleware(t *testing.T) {
	m := newHTTPMetrics()
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	handler := m.middleware(inner)

	req := httptest.NewRequest(http.MethodPut, "/api/config/site_name", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var b strings.Builder
	m.registry.Render(&b)
	got := b.String()
	// No ServeMux ran in this test, so the route label is "-".
	for _, want := range []string{
		`http_requests_total{method="PUT",route="-",status="201"} 1`,
		`http_request_duration_seconds_count{method="PUT",route="-"} 1`,
		"http_active_requests 0\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("metrics output missing %q:\n%s", want, got)
		}
	}
}

func TestMaxBodyMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			httputil.WriteProblem(w, http.StatusRequestEntityTooLarge, http.StatusText(http.StatusRequestEntityTooLarge), "")
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := maxBody(inner)

	t.Run("GET skips limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", strings.NewReader(strings.Repeat("x", maxRequestBodyBytes+1)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("POST under limit accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("small"))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("POST over limit rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", maxRequestBodyBytes+1)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
	})
}

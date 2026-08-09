package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubProvider is a fake Provider that returns a fixed principal or error.
type stubProvider struct {
	principal Principal
	err       error
}

func (s stubProvider) Name() string   { return "stub" }
func (s stubProvider) Header() string { return "X-Stub" }
func (s stubProvider) Authenticate(_ context.Context, _ *http.Request) (Principal, error) {
	return s.principal, s.err
}

func TestWithPrincipalContextRoundTrip(t *testing.T) {
	want := Principal{Subject: "subject-1", Email: "ada@example.com", Roles: []string{"admin"}}
	ctx := WithPrincipal(context.Background(), want)

	got, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("PrincipalFromContext found no principal, want one")
	}
	if got.Subject != want.Subject || got.Email != want.Email {
		t.Errorf("principal = %+v, want %+v", got, want)
	}
}

func TestPrincipalFromContextMissing(t *testing.T) {
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("PrincipalFromContext on empty context succeeded, want not-ok")
	}
}

func TestMiddleware(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("success stores principal in context", func(t *testing.T) {
		want := Principal{Subject: "subject-1", Roles: []string{"admin"}}
		handler := Middleware(stubProvider{principal: want}, log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, ok := PrincipalFromContext(r.Context())
			if !ok {
				t.Error("principal missing from request context")
			}
			if got.Subject != want.Subject {
				t.Errorf("subject = %q, want %q", got.Subject, want.Subject)
			}
			w.WriteHeader(http.StatusNoContent)
		}))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusNoContent {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
		}
	})

	t.Run("failure answers a vague 401 problem", func(t *testing.T) {
		nextRan := false
		handler := Middleware(stubProvider{err: errors.New("no token in header")}, log)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			nextRan = true
		}))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if nextRan {
			t.Error("next handler ran despite failed authentication")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("Content-Type = %q, want application/problem+json", ct)
		}
		var problem map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&problem); err != nil {
			t.Fatalf("decoding problem body: %v", err)
		}
		if problem["title"] != http.StatusText(http.StatusUnauthorized) {
			t.Errorf("title = %v, want %q", problem["title"], http.StatusText(http.StatusUnauthorized))
		}
		if detail, ok := problem["detail"]; ok {
			t.Errorf("detail must be absent on failure responses, got %v", detail)
		}
	})
}

func TestRequireRole(t *testing.T) {
	cases := []struct {
		name      string
		principal *Principal // nil: no principal in context
		role      string
		wantCode  int
	}{
		{name: "allowed with matching role", principal: &Principal{Subject: "s", Roles: []string{"admin"}}, role: "admin", wantCode: http.StatusNoContent},
		{name: "forbidden without matching role", principal: &Principal{Subject: "s", Roles: []string{"editor"}}, role: "admin", wantCode: http.StatusForbidden},
		{name: "forbidden with no roles", principal: &Principal{Subject: "s"}, role: "admin", wantCode: http.StatusForbidden},
		{name: "forbidden without principal", principal: nil, role: "admin", wantCode: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextRan := false
			handler := RequireRole(tc.role)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextRan = true
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.principal != nil {
				req = req.WithContext(WithPrincipal(req.Context(), *tc.principal))
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			if wantNext := tc.wantCode == http.StatusNoContent; nextRan != wantNext {
				t.Errorf("next handler ran = %v, want %v", nextRan, wantNext)
			}
		})
	}
}

func TestHasRole(t *testing.T) {
	p := Principal{Subject: "s", Roles: []string{"admin", "editor"}}
	cases := []struct {
		name string
		role string
		want bool
	}{
		{name: "present", role: "admin", want: true},
		{name: "absent", role: "viewer", want: false},
		{name: "empty role", role: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.HasRole(tc.role); got != tc.want {
				t.Errorf("HasRole(%q) = %v, want %v", tc.role, got, tc.want)
			}
		})
	}

	t.Run("nil roles", func(t *testing.T) {
		if (Principal{}).HasRole("admin") {
			t.Error("HasRole on principal without roles succeeded, want false")
		}
	})
}

func TestJWTProviderName(t *testing.T) {
	p, err := NewJWTProvider(JWTConfig{
		Header:    "X-Test-Jwt",
		Issuer:    testIssuer,
		Audience:  testAudience,
		Algorithm: AlgRS256,
		JWKSURL:   "http://localhost/jwks",
	})
	if err != nil {
		t.Fatalf("NewJWTProvider: %v", err)
	}
	if want := "jwt:" + testIssuer; p.Name() != want {
		t.Errorf("Name = %q, want %q", p.Name(), want)
	}
}

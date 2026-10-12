package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewProviderPomerium(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(t, ecJWK(t, "pomerium-key", &key.PublicKey))

	p, err := NewProvider("pomerium", Settings{
		PomeriumJWKSURL:  jwks.URL,
		PomeriumIssuer:   "app.example.com",
		PomeriumAudience: "app.example.com",
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.Header() != "X-Pomerium-Jwt-Assertion" {
		t.Errorf("Header = %q, want X-Pomerium-Jwt-Assertion", p.Header())
	}

	now := time.Now()
	claims := map[string]any{
		"sub":    "test-subject",
		"iss":    "app.example.com",
		"aud":    "app.example.com",
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"email":  "test@example.com",
		"name":   "Test User",
		"groups": []string{"admin", "viewers"},
	}
	token := signES256(t, key, "pomerium-key", claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Pomerium-Jwt-Assertion", token)
	principal, err := p.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.Subject != "test-subject" {
		t.Errorf("Subject = %q, want test-subject", principal.Subject)
	}
	if principal.Email != "test@example.com" {
		t.Errorf("Email = %q, want test@example.com", principal.Email)
	}
	if principal.DisplayName != "Test User" {
		t.Errorf("DisplayName = %q, want Test User", principal.DisplayName)
	}
	if len(principal.Roles) != 2 || principal.Roles[0] != "admin" || principal.Roles[1] != "viewers" {
		t.Errorf("Roles = %v, want [admin viewers]", principal.Roles)
	}
}

func TestNewProviderPomeriumRolePrefix(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(t, ecJWK(t, "pomerium-key", &key.PublicKey))

	p, err := NewProvider("pomerium", Settings{
		PomeriumJWKSURL:    jwks.URL,
		PomeriumIssuer:     "app.example.com",
		PomeriumAudience:   "app.example.com",
		PomeriumRolePrefix: "/",
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	now := time.Now()
	claims := map[string]any{
		"sub":    "test-subject",
		"iss":    "app.example.com",
		"aud":    "app.example.com",
		"exp":    now.Add(time.Hour).Unix(),
		"iat":    now.Unix(),
		"groups": []string{"/admins", "/viewers"},
	}
	token := signES256(t, key, "pomerium-key", claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Pomerium-Jwt-Assertion", token)
	principal, err := p.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(principal.Roles) != 2 || principal.Roles[0] != "admins" || principal.Roles[1] != "viewers" {
		t.Errorf("Roles = %v, want [admins viewers]", principal.Roles)
	}
}

func TestNewProviderPomeriumCustomHeaderAndAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	jwks := newJWKSServer(t, rsaJWK("pomerium-key", &rsaKey.PublicKey))

	p, err := NewProvider("pomerium", Settings{
		PomeriumJWKSURL:   jwks.URL,
		PomeriumIssuer:    "app.example.com",
		PomeriumAudience:  "app.example.com",
		PomeriumHeader:    "X-Test-Auth",
		PomeriumAlgorithm: AlgRS256,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.Header() != "X-Test-Auth" {
		t.Errorf("Header = %q, want X-Test-Auth", p.Header())
	}

	now := time.Now()
	claims := map[string]any{
		"sub": "test-subject",
		"iss": "app.example.com",
		"aud": "app.example.com",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	token := signRS256(t, rsaKey, "pomerium-key", claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Test-Auth", token)
	principal, err := p.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.Subject != "test-subject" {
		t.Errorf("Subject = %q, want test-subject", principal.Subject)
	}
}

func TestNewProviderPomeriumMissingSettings(t *testing.T) {
	cases := []struct {
		name     string
		settings Settings
	}{
		{
			name:     "missing JWKS URL",
			settings: Settings{PomeriumIssuer: "app.example.com", PomeriumAudience: "app.example.com"},
		},
		{
			name:     "missing issuer",
			settings: Settings{PomeriumJWKSURL: "http://localhost/jwks", PomeriumAudience: "app.example.com"},
		},
		{
			name:     "missing audience",
			settings: Settings{PomeriumJWKSURL: "http://localhost/jwks", PomeriumIssuer: "app.example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewProvider("pomerium", tc.settings)
			if err == nil {
				t.Fatal("NewProvider succeeded, want error")
			}
		})
	}
}

func TestTrimRolePrefix(t *testing.T) {
	if got := trimRolePrefix("")("admin"); got != "admin" {
		t.Errorf(`trimRolePrefix("")("admin") = %q, want admin`, got)
	}
	if got := trimRolePrefix("/")("/admins"); got != "admins" {
		t.Errorf(`trimRolePrefix("/")("/admins") = %q, want admins`, got)
	}
	if got := trimRolePrefix("/")("admin"); got != "admin" {
		t.Errorf(`trimRolePrefix("/")("admin") = %q, want admin (no prefix, unchanged)`, got)
	}
}

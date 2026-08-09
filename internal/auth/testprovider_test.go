package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewProviderTest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(t, rsaJWK("test-key", &key.PublicKey))

	p, err := NewProvider("test", Settings{
		TestIssuer:   "https://test.example.com",
		TestAudience: "test-audience",
		JWKSURL:      jwks.URL,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.Header() != "Cf-Access-Jwt-Assertion" {
		t.Errorf("Header = %q, want Cf-Access-Jwt-Assertion", p.Header())
	}

	now := time.Now()
	claims := map[string]any{
		"sub":   "test-subject",
		"iss":   "https://test.example.com",
		"aud":   "test-audience",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"email": "test@example.com",
		"name":  "Test User",
		"roles": []string{"admin"},
	}
	token := signTestToken(t, key, "test-key", claims)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cf-Access-Jwt-Assertion", token)
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
	if len(principal.Roles) != 1 || principal.Roles[0] != "admin" {
		t.Errorf("Roles = %v, want [admin]", principal.Roles)
	}
}

func TestNewProviderTestMissingSettings(t *testing.T) {
	cases := []struct {
		name     string
		settings Settings
	}{
		{
			name:     "missing issuer",
			settings: Settings{TestAudience: "aud", JWKSURL: "http://localhost/jwks"},
		},
		{
			name:     "missing audience",
			settings: Settings{TestIssuer: "iss", JWKSURL: "http://localhost/jwks"},
		},
		{
			name:     "missing JWKS URL",
			settings: Settings{TestIssuer: "iss", TestAudience: "aud"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewProvider("test", tc.settings)
			if err == nil {
				t.Fatal("NewProvider succeeded, want error")
			}
		})
	}
}

func TestNewProviderTestCustomHeaderAndAlgorithm(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(t, rsaJWK("test-key", &key.PublicKey))

	p, err := NewProvider("test", Settings{
		TestIssuer:    "https://test.example.com",
		TestAudience:  "test-audience",
		JWKSURL:       jwks.URL,
		TestHeader:    "X-Test-Auth",
		TestAlgorithm: AlgRS256,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.Header() != "X-Test-Auth" {
		t.Errorf("Header = %q, want X-Test-Auth", p.Header())
	}
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": AlgRS256, "typ": "JWT", "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshaling header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

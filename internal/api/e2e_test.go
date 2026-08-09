package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sandrorichi/webapp-template/internal/auth"
	"github.com/sandrorichi/webapp-template/internal/config"
	"github.com/sandrorichi/webapp-template/internal/ui"
)

// signE2E builds an RS256 JWT for the end-to-end test.
func signE2E(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
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

// TestEndToEnd boots the real server on 127.0.0.1:0 with a test provider
// backed by an in-test JWKS and walks the main request paths.
func TestEndToEnd(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "e2e-key",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}}
		if err := json.NewEncoder(w).Encode(doc); err != nil {
			t.Errorf("encoding JWKS: %v", err)
		}
	}))
	t.Cleanup(jwks.Close)

	const issuer = "https://e2e.example.com"
	provider, err := auth.NewJWTProvider(auth.JWTConfig{
		Header:    "Cf-Access-Jwt-Assertion",
		Issuer:    issuer,
		Audience:  "e2e-audience",
		Algorithm: auth.AlgRS256,
		JWKSURL:   jwks.URL,
		MapClaims: func(c auth.Claims) (auth.Principal, error) {
			email, _ := c.Custom["email"].(string)
			name, _ := c.Custom["name"].(string)
			roles := []string{}
			if raw, ok := c.Custom["roles"].([]any); ok {
				for _, r := range raw {
					if s, ok := r.(string); ok {
						roles = append(roles, s)
					}
				}
			}
			return auth.Principal{Subject: c.Subject, Email: email, DisplayName: name, Roles: roles}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewJWTProvider: %v", err)
	}

	st := openStore(t)
	cfg := config.Config{HTTPAddr: "127.0.0.1:0"}
	routes, err := Routes(st, provider, ui.StaticHandler(), ui.NewPageModel(st), false, testLogger())
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	server := NewServer(ServerConfig{
		Addr: cfg.HTTPAddr,
	}, routes)

	listener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("closing server: %v", err)
		}
	})
	baseURL := fmt.Sprintf("http://%s", listener.Addr().String())

	tokenFor := func(roles []string) string {
		return signE2E(t, key, "e2e-key", map[string]any{
			"sub":   "e2e-subject",
			"iss":   issuer,
			"aud":   "e2e-audience",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"email": "e2e@example.com",
			"name":  "E2E User",
			"roles": roles,
		})
	}

	t.Run("healthz answers unauthenticated", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Errorf("closing healthz response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("me rejected without token", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/me")
		if err != nil {
			t.Fatalf("GET /api/me: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("Content-Type = %q, want application/problem+json", ct)
		}
		body, _ := io.ReadAll(resp.Body)
		var problem map[string]any
		if err := json.Unmarshal(body, &problem); err != nil {
			t.Fatalf("decoding problem: %v", err)
		}
		if _, ok := problem["detail"]; ok {
			t.Errorf("auth failure must be vague, got detail: %v", problem["detail"])
		}
	})

	t.Run("me returns principal with valid token", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/me", nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Header.Set("Cf-Access-Jwt-Assertion", tokenFor([]string{}))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /api/me: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var principal map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&principal); err != nil {
			t.Fatalf("decoding principal: %v", err)
		}
		if principal["subject"] != "e2e-subject" || principal["display_name"] != "E2E User" {
			t.Errorf("unexpected principal: %v", principal)
		}
	})

	putConfig := func(t *testing.T, roles []string, csrf bool) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPut, baseURL+"/api/config/site_name",
			strings.NewReader(`{"value":"E2E Site"}`))
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cf-Access-Jwt-Assertion", tokenFor(roles))
		if csrf {
			req.Header.Set("X-Requested-With", "fetch")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT /api/config/site_name: %v", err)
		}
		return resp
	}

	t.Run("config mutation forbidden for non-admin", func(t *testing.T) {
		resp := putConfig(t, []string{}, true)
		if err := resp.Body.Close(); err != nil {
			t.Errorf("closing config response: %v", err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("config mutation succeeds for admin", func(t *testing.T) {
		resp := putConfig(t, []string{"admin"}, true)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var entry map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
			t.Fatalf("decoding entry: %v", err)
		}
		if entry["key"] != "site_name" || entry["value"] != "E2E Site" {
			t.Errorf("unexpected entry: %v", entry)
		}
	})

	t.Run("config mutation without CSRF headers rejected", func(t *testing.T) {
		resp := putConfig(t, []string{"admin"}, false)
		if err := resp.Body.Close(); err != nil {
			t.Errorf("closing CSRF response: %v", err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("metrics answers unauthenticated", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/metrics")
		if err != nil {
			t.Fatalf("GET /metrics: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("Content-Type = %q, want Prometheus text format", ct)
		}
		body, _ := io.ReadAll(resp.Body)
		for _, want := range []string{"http_requests_total", "http_request_duration_seconds_bucket", "go_goroutines"} {
			if !strings.Contains(string(body), want) {
				t.Errorf("metrics body missing %q", want)
			}
		}
	})
}

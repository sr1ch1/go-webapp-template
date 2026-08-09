package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestIsValidTeamDomain(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"simple", "example", true},
		{"subdomain", "team.example", true},
		{"with suffix", "example.cloudflareaccess.com", true},
		{"empty", "", false},
		{"leading dot", ".example", false},
		{"trailing dot", "example.", false},
		{"leading hyphen", "-example", false},
		{"trailing hyphen", "example-", false},
		{"double dot", "example..com", false},
		{"slash", "example/foo", false},
		{"at sign", "example@evil", false},
		{"colon", "example:443", false},
		{"space", "example com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidTeamDomain(tc.in); got != tc.want {
				t.Errorf("isValidTeamDomain(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNewCloudflare(t *testing.T) {
	cases := []struct {
		name       string
		teamDomain string
		audience   string
		wantErr    bool
	}{
		{"valid", "test", testAudience, false},
		{"valid with full suffix", "test.cloudflareaccess.com", testAudience, false},
		{"missing team domain", "", testAudience, true},
		{"missing audience", "test", "", true},
		{"missing both", "", "", true},
		{"invalid team domain", "test/evil", testAudience, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewCloudflare(tc.teamDomain, tc.audience, nil, nil, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatal("NewCloudflare succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewCloudflare: %v", err)
			}
			if p.Header() != "Cf-Access-Jwt-Assertion" {
				t.Errorf("header = %q, want Cf-Access-Jwt-Assertion", p.Header())
			}
			if p.Name() != "jwt:https://test.cloudflareaccess.com" {
				t.Errorf("name = %q, want jwt:https://test.cloudflareaccess.com", p.Name())
			}
		})
	}
}

// TestNewCloudflareMapsClaims runs a token end to end through a provider built
// by NewCloudflare. The JWKS URL is derived from the team domain, so a
// transport rewrite points the fetch at the test JWKS server.
func TestNewCloudflareMapsClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(t, rsaJWK("key-1", &key.PublicKey))
	jwksURL, err := url.Parse(jwks.URL)
	if err != nil {
		t.Fatalf("parsing JWKS URL: %v", err)
	}

	p, err := NewCloudflare("test", testAudience, nil,
		&http.Client{Transport: rewriteTransport{target: jwksURL}}, nil)
	if err != nil {
		t.Fatalf("NewCloudflare: %v", err)
	}

	principal, err := authenticate(t, p, signRS256(t, key, "key-1", validClaims()))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.Subject != "subject-1" || principal.Email != "ada@example.com" || principal.DisplayName != "Ada Lovelace" {
		t.Errorf("unexpected principal: %+v", principal)
	}
	if want := []string{"admin"}; fmt.Sprint(principal.Roles) != fmt.Sprint(want) {
		t.Errorf("roles = %v, want %v", principal.Roles, want)
	}
}

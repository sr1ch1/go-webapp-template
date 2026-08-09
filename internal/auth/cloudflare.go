package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func init() {
	register("cloudflare-access", func(s Settings) (Provider, error) {
		return NewCloudflare(s.TeamDomain, s.Audience, nil, s.HTTPClient, s.Now)
	})
}

// NewCloudflare builds the Cloudflare Access provider. The JWT arrives in the
// Cf-Access-Jwt-Assertion header, is issued by
// https://<team>.cloudflareaccess.com, and is pinned to RS256. mapRoles
// normalizes role naming; nil selects the identity mapping. httpClient and now
// override the defaults for JWKS fetching and expiry checks; nil selects a
// bounded stdlib client and time.Now.
// isValidTeamDomain reports whether s is a safe DNS-like domain for the
// Cloudflare Access team name. It rejects characters that could escape the
// intended hostname or inject path/query/fragment components.
func isValidTeamDomain(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") ||
		strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func NewCloudflare(teamDomain, audience string, mapRoles RoleMapper, httpClient *http.Client, now func() time.Time) (Provider, error) {
	if teamDomain == "" || audience == "" {
		return nil, fmt.Errorf("cloudflare-access: team domain and audience are required")
	}
	if !isValidTeamDomain(teamDomain) {
		return nil, fmt.Errorf("cloudflare-access: invalid team domain %q", teamDomain)
	}
	if mapRoles == nil {
		mapRoles = IdentityRoleMapper
	}
	teamDomain = strings.TrimSuffix(teamDomain, ".cloudflareaccess.com")
	issuer := "https://" + teamDomain + ".cloudflareaccess.com"

	return NewJWTProvider(JWTConfig{
		Header:     "Cf-Access-Jwt-Assertion",
		Issuer:     issuer,
		Audience:   audience,
		Algorithm:  AlgRS256,
		JWKSURL:    issuer + "/cdn-cgi/access/certs",
		MapClaims:  func(c Claims) (Principal, error) { return mapCloudflareClaims(c, mapRoles), nil },
		HTTPClient: httpClient,
		Now:        now,
	})
}

// mapCloudflareClaims maps verified Cloudflare Access claims (sub, email,
// name, and the custom "roles" array of strings) to a Principal, normalizing
// role names through mapRoles.
func mapCloudflareClaims(c Claims, mapRoles RoleMapper) Principal {
	email, _ := c.Custom["email"].(string)
	name, _ := c.Custom["name"].(string)

	var roles []string
	if raw, ok := c.Custom["roles"].([]any); ok {
		for _, r := range raw {
			if s, ok := r.(string); ok && s != "" {
				roles = append(roles, mapRoles(s))
			}
		}
	}

	return Principal{
		Subject:     c.Subject,
		Email:       email,
		DisplayName: name,
		Roles:       roles,
	}
}

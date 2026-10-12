package auth

import (
	"fmt"
	"strings"
)

func init() {
	register("pomerium", newPomeriumProvider)
}

// newPomeriumProvider builds a provider for apps behind Pomerium
// (pomerium.com), an identity-aware proxy that fronts an upstream OIDC
// Identity Provider such as Keycloak or Entra ID. Pomerium consumes the OIDC
// flow with the upstream IdP and reissues its own short-lived JWT for the
// upstream application; the original IdP token never reaches the app.
//
// Required environment variables:
//   - APP_AUTH_POMERIUM_JWKS_URL (e.g.
//     https://app.example.com/.well-known/pomerium/jwks.json)
//   - APP_AUTH_POMERIUM_ISSUER (the route's "from" host, e.g. app.example.com)
//   - APP_AUTH_POMERIUM_AUDIENCE (same as the issuer; Pomerium sets both
//     claims to the route host)
//
// Optional:
//   - APP_AUTH_POMERIUM_HEADER (default: X-Pomerium-Jwt-Assertion)
//   - APP_AUTH_POMERIUM_ALGORITHM (default: ES256, Pomerium's signing key
//     algorithm; RS256 is also supported)
//   - APP_AUTH_POMERIUM_ROLE_PREFIX (default: no prefix stripping)
//
// Pomerium asserts the upstream IdP's group memberships in the "groups"
// claim (an array of strings). mapPomeriumClaims feeds each group through
// RoleMapper so deployments can normalize, for example, Keycloak group paths
// ("/admins" -> "admin") or Entra ID object IDs into the app's canonical
// role names before RequireRole checks.
func newPomeriumProvider(s Settings) (Provider, error) {
	if s.PomeriumJWKSURL == "" || s.PomeriumIssuer == "" || s.PomeriumAudience == "" {
		return nil, fmt.Errorf("pomerium provider: APP_AUTH_POMERIUM_JWKS_URL, APP_AUTH_POMERIUM_ISSUER, and APP_AUTH_POMERIUM_AUDIENCE are required")
	}

	header := "X-Pomerium-Jwt-Assertion"
	if s.PomeriumHeader != "" {
		header = s.PomeriumHeader
	}

	alg := AlgES256
	if s.PomeriumAlgorithm != "" {
		alg = s.PomeriumAlgorithm
	}

	return NewJWTProvider(JWTConfig{
		Header:     header,
		Issuer:     s.PomeriumIssuer,
		Audience:   s.PomeriumAudience,
		Algorithm:  alg,
		JWKSURL:    s.PomeriumJWKSURL,
		HTTPClient: s.HTTPClient,
		Now:        s.Now,
		MapClaims: func(c Claims) (Principal, error) {
			return mapPomeriumClaims(c, trimRolePrefix(s.PomeriumRolePrefix)), nil
		},
	})
}

// mapPomeriumClaims maps the verified Pomerium JWT claims to a Principal.
// Roles come from the "groups" claim (asserted by the upstream Identity
// Provider and forwarded by Pomerium), normalized through mapRoles.
func mapPomeriumClaims(c Claims, mapRoles RoleMapper) Principal {
	email, _ := c.Custom["email"].(string)
	name, _ := c.Custom["name"].(string)

	var roles []string
	if raw, ok := c.Custom["groups"].([]any); ok {
		for _, g := range raw {
			if s, ok := g.(string); ok && s != "" {
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

// trimRolePrefix returns a RoleMapper that strips the given prefix from role
// strings, leaving other roles unchanged. An empty prefix selects the
// identity mapping. Useful when the Identity Provider asserts groups as
// paths (e.g. Keycloak "/admins") but the app expects bare role names
// ("admin").
func trimRolePrefix(prefix string) RoleMapper {
	if prefix == "" {
		return IdentityRoleMapper
	}
	return func(role string) string {
		return strings.TrimPrefix(role, prefix)
	}
}

package auth

import "fmt"

func init() {
	register("test", newTestJWTProvider)
}

// newTestJWTProvider builds a test-only Identity Provider backed by the same
// JWT verifier used in production. It is selected with APP_AUTH_PROVIDER=test
// and is intended for browser-based end-to-end tests that need to authenticate
// without a real Cloudflare Access tunnel.
//
// Required environment variables:
//   - APP_AUTH_TEST_ISSUER
//   - APP_AUTH_TEST_AUDIENCE
//   - APP_AUTH_TEST_JWKS_URL
//
// Optional:
//   - APP_AUTH_TEST_HEADER (default: Cf-Access-Jwt-Assertion)
//   - APP_AUTH_TEST_ALGORITHM (default: RS256)
func newTestJWTProvider(s Settings) (Provider, error) {
	issuer := s.TestIssuer
	audience := s.TestAudience
	if issuer == "" || audience == "" {
		return nil, fmt.Errorf("test provider: APP_AUTH_TEST_ISSUER and APP_AUTH_TEST_AUDIENCE are required")
	}

	header := "Cf-Access-Jwt-Assertion"
	if s.TestHeader != "" {
		header = s.TestHeader
	}

	alg := AlgRS256
	if s.TestAlgorithm != "" {
		alg = s.TestAlgorithm
	}

	jwksURL := s.JWKSURL
	if jwksURL == "" {
		return nil, fmt.Errorf("test provider: APP_AUTH_TEST_JWKS_URL is required")
	}

	return NewJWTProvider(JWTConfig{
		Header:     header,
		Issuer:     issuer,
		Audience:   audience,
		Algorithm:  alg,
		JWKSURL:    jwksURL,
		HTTPClient: s.HTTPClient,
		Now:        s.Now,
		MapClaims:  mapTestClaims,
	})
}

// mapTestClaims maps the verified JWT claims to a Principal using the same
// shape as the Cloudflare Access provider so that browser tests exercise the
// UI realistically.
func mapTestClaims(c Claims) (Principal, error) {
	email, _ := c.Custom["email"].(string)
	name, _ := c.Custom["name"].(string)

	var roles []string
	if raw, ok := c.Custom["roles"].([]any); ok {
		for _, r := range raw {
			if s, ok := r.(string); ok && s != "" {
				roles = append(roles, s)
			}
		}
	}

	return Principal{
		Subject:     c.Subject,
		Email:       email,
		DisplayName: name,
		Roles:       roles,
	}, nil
}

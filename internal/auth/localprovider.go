package auth

import "fmt"

func init() {
	register("local", newLocalJWTProvider)
}

// newLocalJWTProvider builds a local Identity Provider backed by the same
// JWT verifier used in production. It is selected with APP_AUTH_PROVIDER=local
// and is intended for local development and browser-based end-to-end tests
// that need to authenticate without a real Identity Provider.
//
// Required environment variables:
//   - APP_AUTH_LOCAL_ISSUER
//   - APP_AUTH_LOCAL_AUDIENCE
//   - APP_AUTH_LOCAL_JWKS_URL
//
// Optional:
//   - APP_AUTH_LOCAL_HEADER (default: Cf-Access-Jwt-Assertion)
//   - APP_AUTH_LOCAL_ALGORITHM (default: RS256)
func newLocalJWTProvider(s Settings) (Provider, error) {
	issuer := s.LocalIssuer
	audience := s.LocalAudience
	if issuer == "" || audience == "" {
		return nil, fmt.Errorf("local provider: APP_AUTH_LOCAL_ISSUER and APP_AUTH_LOCAL_AUDIENCE are required")
	}

	header := "Cf-Access-Jwt-Assertion"
	if s.LocalHeader != "" {
		header = s.LocalHeader
	}

	alg := AlgRS256
	if s.LocalAlgorithm != "" {
		alg = s.LocalAlgorithm
	}

	jwksURL := s.JWKSURL
	if jwksURL == "" {
		return nil, fmt.Errorf("local provider: APP_AUTH_LOCAL_JWKS_URL is required")
	}

	return NewJWTProvider(JWTConfig{
		Header:     header,
		Issuer:     issuer,
		Audience:   audience,
		Algorithm:  alg,
		JWKSURL:    jwksURL,
		HTTPClient: s.HTTPClient,
		Now:        s.Now,
		MapClaims:  mapLocalClaims,
	})
}

// mapLocalClaims maps the verified JWT claims to a Principal using the same
// shape as the Cloudflare Access provider so that browser tests exercise the
// UI realistically.
func mapLocalClaims(c Claims) (Principal, error) {
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

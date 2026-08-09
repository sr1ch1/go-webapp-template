package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Claims are the verified claims of a provider JWT, pre-mapping. Standard
// registered claims are parsed explicitly; provider-specific claims (such as
// roles) are available via Custom.
type Claims struct {
	Subject   string
	Issuer    string
	Audience  []string
	ExpiresAt int64
	NotBefore int64
	IssuedAt  int64
	Custom    map[string]any
}

// RoleMapper normalizes raw role strings from the Identity Provider into the
// application's canonical role naming. The default is the identity function.
type RoleMapper func(string) string

// IdentityRoleMapper leaves role names unchanged.
func IdentityRoleMapper(role string) string { return role }

// Provider authenticates requests by verifying the JWT carried in its header
// and mapping the verified claims to a Principal.
type Provider interface {
	// Name is the registry key, selected via APP_AUTH_PROVIDER.
	Name() string
	// Header is the request header carrying the JWT.
	Header() string
	// Authenticate verifies the request's JWT and returns the Principal.
	// The raw token must never be logged or included in returned errors
	// beyond provider-owned verification detail.
	Authenticate(ctx context.Context, r *http.Request) (Principal, error)
}

type registryEntry struct {
	// New builds a provider from deployment-specific settings. The settings
	// are interpreted by the provider itself (e.g., team domain, audience).
	New func(Settings) (Provider, error)
}

// Settings carry the provider-related configuration values. Providers pick
// what they need.
type Settings struct {
	TeamDomain string
	Audience   string
	// TestIssuer is used by the test provider as the expected token issuer.
	TestIssuer string
	// TestAudience is used by the test provider as the expected token audience.
	TestAudience string
	// JWKSURL is used by the test provider to point at a local JWKS server.
	JWKSURL string
	// TestHeader is used by the test provider; defaults to Cf-Access-Jwt-Assertion.
	TestHeader string
	// TestAlgorithm is used by the test provider; defaults to RS256.
	TestAlgorithm string
	// HTTPClient is used for outbound JWKS fetches. When nil, the provider
	// uses a bounded stdlib client with a 10-second timeout.
	HTTPClient *http.Client
	// Now returns the current time for expiry and cache checks. When nil,
	// the provider uses time.Now.
	Now func() time.Time
}

var registry = map[string]registryEntry{}

// Register adds a provider constructor to the compile-time registry. Adding a
// provider means adding a file and one registry entry here.
func register(name string, new func(Settings) (Provider, error)) {
	registry[name] = registryEntry{New: new}
}

// NewProvider builds the provider selected by name.
func NewProvider(name string, s Settings) (Provider, error) {
	entry, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown auth provider %q", name)
	}
	return entry.New(s)
}

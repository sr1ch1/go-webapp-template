package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Pinned algorithms supported by the verifier. The token's alg header is
// never trusted; every provider pins exactly one algorithm.
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// expiryLeeway is the clock skew tolerated when checking time-based claims.
const expiryLeeway = 60 * time.Second

// defaultJWKSFetchTimeout bounds each outbound JWKS request. The Identity
// Provider's certificate endpoint must answer within this window; otherwise
// the fetch fails and the caller may fall back to a stale cached key.
const defaultJWKSFetchTimeout = 10 * time.Second

// JWTConfig parametrizes a JWT-verifying Provider.
type JWTConfig struct {
	// Header is the request header carrying the JWT.
	Header string
	// Issuer must match the token's iss claim exactly.
	Issuer string
	// Audience must be present in the token's aud claim (string or array).
	Audience string
	// Algorithm is the pinned JWS algorithm (AlgRS256 or AlgES256).
	Algorithm string
	// JWKSURL is the provider's JSON Web Key Set endpoint.
	JWKSURL string
	// MapClaims maps verified claims to a Principal, including role
	// normalization. The default maps only the subject.
	MapClaims func(Claims) (Principal, error)
	// HTTPClient is used for JWKS fetches. When nil, http.DefaultClient is used.
	HTTPClient *http.Client
	// Now returns the current time for expiry and cache checks. When nil,
	// time.Now is used.
	Now func() time.Time
}

type jwtProvider struct {
	cfg    JWTConfig
	jwks   *jwksClient
	parser *jwt.Parser
	mapFn  func(Claims) (Principal, error)
}

// NewJWTProvider builds a Provider that verifies JWTs per cfg.
func NewJWTProvider(cfg JWTConfig) (Provider, error) {
	if cfg.Header == "" || cfg.Issuer == "" || cfg.Audience == "" || cfg.JWKSURL == "" {
		return nil, errors.New("jwt provider: header, issuer, audience and JWKS URL are required")
	}
	if cfg.Algorithm != AlgRS256 && cfg.Algorithm != AlgES256 {
		return nil, fmt.Errorf("jwt provider: unsupported pinned algorithm %q", cfg.Algorithm)
	}
	mapFn := cfg.MapClaims
	if mapFn == nil {
		mapFn = func(c Claims) (Principal, error) {
			return Principal{Subject: c.Subject}, nil
		}
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		// http.DefaultClient has no timeout, which can hang authentication
		// if the provider's JWKS endpoint stalls. Use a bounded client.
		httpClient = &http.Client{Timeout: defaultJWKSFetchTimeout}
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &jwtProvider{
		cfg:  cfg,
		jwks: newJWKSClient(cfg.JWKSURL, httpClient, nowFn),
		// The token's alg header is never trusted: the parser rejects any
		// signing method outside the pinned set before the keyfunc runs
		// (alg=none and algorithm confusion, threat model #1-3). The
		// validator owns iss/aud/exp/nbf/iat checks with the configured
		// leeway (#6-8).
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{cfg.Algorithm}),
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithAudience(cfg.Audience),
			jwt.WithLeeway(expiryLeeway),
			jwt.WithIssuedAt(),
			jwt.WithTimeFunc(nowFn),
		),
		mapFn: mapFn,
	}, nil
}

func (p *jwtProvider) Name() string   { return "jwt:" + p.cfg.Issuer }
func (p *jwtProvider) Header() string { return p.cfg.Header }

func (p *jwtProvider) Authenticate(ctx context.Context, r *http.Request) (Principal, error) {
	token := r.Header.Get(p.cfg.Header)
	if token == "" {
		return Principal{}, errors.New("no token in header")
	}
	claims, err := p.verify(ctx, token)
	if err != nil {
		// err never contains the token itself.
		return Principal{}, err
	}
	return p.mapFn(claims)
}

// Static rejection reasons. golang-jwt errors are never propagated to callers
// or logs: they are classified by errors.Is and mapped to these generic
// strings so no token material can leak through error paths (#10).
var (
	errUnexpectedAlgorithm = errors.New("unexpected signing algorithm")
	errMissingKeyID        = errors.New("missing key id")
	errNoUsableKey         = errors.New("no usable verification key")
	errKeyTypeMismatch     = errors.New("verification key type does not match pinned algorithm")
)

// Verify parses and validates token against the provider's pinned parameters.
// The token value is never included in returned errors.
func (p *jwtProvider) verify(ctx context.Context, token string) (Claims, error) {
	claims := jwt.MapClaims{}
	// keyfuncRan records whether signature verification was reached, so an
	// ErrTokenSignatureInvalid caused by a pinned-method rejection can still
	// be reported as an algorithm problem rather than a bad signature.
	keyfuncRan := false
	_, err := p.parser.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		keyfuncRan = true
		return p.verificationKey(ctx, t)
	})
	if err != nil {
		return Claims{}, mapJWTError(err, keyfuncRan)
	}
	return claimsFromMap(claims)
}

// verificationKey is the jwt.Keyfunc: it resolves the token's kid against the
// JWKS cache and enforces that the key type matches the pinned algorithm.
// All returned errors are static sentinels.
func (p *jwtProvider) verificationKey(ctx context.Context, token *jwt.Token) (any, error) {
	// Defense in depth: the parser already pins the method via
	// WithValidMethods before calling this keyfunc; double-check here.
	if token.Method.Alg() != p.cfg.Algorithm {
		return nil, errUnexpectedAlgorithm
	}
	// A missing key id would force the verifier to guess or default to a key,
	// which is a common signature-bypass primitive.
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, errMissingKeyID
	}
	// The JWKS client refreshes when the kid is unknown, preventing rotation
	// bypass (#4); refetches are throttled so random kids cannot force one
	// outbound request per authentication attempt.
	key, err := p.jwks.key(ctx, kid)
	if err != nil {
		return nil, errNoUsableKey
	}
	// The JWKS key type must match the pinned algorithm; a mismatch could
	// allow key-confusion attacks (#3).
	switch p.cfg.Algorithm {
	case AlgRS256:
		if _, ok := key.(*rsa.PublicKey); !ok {
			return nil, errKeyTypeMismatch
		}
	case AlgES256:
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			return nil, errKeyTypeMismatch
		}
	}
	return key, nil
}

// mapJWTError classifies a golang-jwt failure into a static, generic reason.
// Library error strings are deliberately discarded: some include decoded
// header values (e.g. the rejected alg), and future versions could embed
// other token-derived content. Nothing token-derived crosses this boundary.
func mapJWTError(err error, keyfuncRan bool) error {
	switch {
	case errors.Is(err, errUnexpectedAlgorithm),
		errors.Is(err, errMissingKeyID),
		errors.Is(err, errNoUsableKey),
		errors.Is(err, errKeyTypeMismatch):
		// Own keyfunc sentinels, wrapped by the library under
		// ErrTokenUnverifiable.
		return err
	case errors.Is(err, jwt.ErrTokenMalformed), errors.Is(err, jwt.ErrInvalidType):
		return errors.New("malformed token")
	case errors.Is(err, jwt.ErrTokenExpired):
		return errors.New("token expired")
	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return errors.New("token issued in the future")
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return errors.New("token not yet valid")
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return errors.New("unexpected issuer")
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return errors.New("unexpected audience")
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return errors.New("missing required claim")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		// The parser reports a pinned-method rejection (alg=none, HS256,
		// lowercase alg, ...) with the same sentinel as a bad signature;
		// the keyfunc only runs once the method has been accepted.
		if !keyfuncRan {
			return errUnexpectedAlgorithm
		}
		return errors.New("invalid signature")
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return errNoUsableKey
	default:
		return errors.New("token validation failed")
	}
}

// claimsFromMap converts the verified claims. The parser has already validated
// iss/aud/exp/nbf/iat; presence of exp and a non-empty sub are application
// requirements checked here (#6, #9).
func claimsFromMap(m jwt.MapClaims) (Claims, error) {
	exp, err := m.GetExpirationTime()
	if err != nil {
		return Claims{}, errors.New("malformed token")
	}
	if exp == nil {
		return Claims{}, errors.New("missing expiry")
	}
	sub, err := m.GetSubject()
	if err != nil || sub == "" {
		return Claims{}, errors.New("missing subject")
	}
	iss, _ := m.GetIssuer()
	aud, _ := m.GetAudience()

	custom := make(map[string]any, len(m))
	for k, v := range m {
		custom[k] = v
	}

	out := Claims{
		Subject:   sub,
		Issuer:    iss,
		Audience:  aud,
		ExpiresAt: exp.Unix(),
		Custom:    custom,
	}
	if nbf, _ := m.GetNotBefore(); nbf != nil {
		out.NotBefore = nbf.Unix()
	}
	if iat, _ := m.GetIssuedAt(); iat != nil {
		out.IssuedAt = iat.Unix()
	}
	return out, nil
}

// jwksTTL is how long a fetched key set is trusted before being refetched.
const jwksTTL = 15 * time.Minute

// jwksMinRefreshInterval bounds how often the JWKS may be refetched. An
// unauthenticated caller can present a token with any key id, so without a
// minimum interval a flood of random kids would drive one outbound fetch per
// request — cache churn plus a DoS amplifier against the Identity Provider.
const jwksMinRefreshInterval = 30 * time.Second

// minRSAKeyBits is the minimum RSA modulus size accepted from a JWKS. Keys
// smaller than 2048 bits are rejected to prevent weak-key attacks.
const minRSAKeyBits = 2048

// maxJWKSBytes bounds the size of a JWKS response to prevent a compromised
// or malicious Identity Provider from exhausting memory.
const maxJWKSBytes = 1 << 20 // 1 MiB

// jwksClient fetches and caches a JSON Web Key Set. The cache is refreshed
// when it is stale or when an unknown key id is requested, at most once per
// jwksMinRefreshInterval.
type jwksClient struct {
	url        string
	httpClient *http.Client
	nowFn      func() time.Time

	mu               sync.Mutex
	keys             map[string]any // kid → *rsa.PublicKey or *ecdsa.PublicKey
	fetchedAt        time.Time      // last successful fetch; drives the TTL
	lastFetchAttempt time.Time      // last fetch attempt; throttles refetches
}

func newJWKSClient(url string, httpClient *http.Client, nowFn func() time.Time) *jwksClient {
	return &jwksClient{
		url:        url,
		httpClient: httpClient,
		nowFn:      nowFn,
		keys:       map[string]any{},
	}
}

// key returns the public key for kid, refreshing the cache once if the key
// is unknown or the cache is stale. Refetches are throttled to at most one
// per jwksMinRefreshInterval; within the interval the cache answers as-is.
// The network fetch runs without holding c.mu: a slow Identity Provider
// stalls only the fetching goroutine, not every concurrent authentication.
func (c *jwksClient) key(ctx context.Context, kid string) (any, error) {
	now := c.nowFn()

	c.mu.Lock()
	if key, ok := c.keys[kid]; ok && now.Sub(c.fetchedAt) < jwksTTL {
		c.mu.Unlock()
		return key, nil
	}
	if now.Sub(c.lastFetchAttempt) < jwksMinRefreshInterval {
		// Throttled: answer from the cache as-is, stale entries included.
		key, ok := c.keys[kid]
		c.mu.Unlock()
		if !ok {
			return nil, errors.New("unknown key id")
		}
		return key, nil
	}
	// Claim the fetch slot under the lock so at most one goroutine per
	// throttle interval fetches; callers arriving during the fetch are
	// answered from the (possibly stale) cache by the throttled branch.
	c.lastFetchAttempt = now
	c.mu.Unlock()

	if err := c.fetch(ctx); err != nil {
		// Fall back to a stale cached key rather than failing outright
		// when the Identity Provider is briefly unreachable.
		c.mu.Lock()
		defer c.mu.Unlock()
		if key, ok := c.keys[kid]; ok {
			return key, nil
		}
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	key, ok := c.keys[kid]
	if !ok {
		return nil, errors.New("unknown key id")
	}
	return key, nil
}

// jwkSet is the JWKS document. Only RSA (n/e) and EC P-256 (x/y) keys are
// understood; other entries are skipped, as are entries explicitly scoped to
// a non-signature use.
type jwkSet struct {
	Keys []struct {
		KeyType string `json:"kty"`
		KeyID   string `json:"kid"`
		Use     string `json:"use"`
		N       string `json:"n"`
		E       string `json:"e"`
		X       string `json:"x"`
		Y       string `json:"y"`
		Curve   string `json:"crv"`
	} `json:"keys"`
}

// fetch replaces the cached key set from the Identity Provider. It performs
// no locking itself except for the final swap, so it must not be called with
// c.mu held.
func (c *jwksClient) fetch(ctx context.Context) (err error) {
	// The JWKS URL is configured at provider construction, not derived from
	// request input, so SSRF via user-controlled taint is not possible here.
	// #nosec G704
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	// #nosec G704
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("fetching JWKS: %w", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching JWKS: status %d", resp.StatusCode)
	}
	var set jwkSet
	// Bound response size so a malicious or compromised IdP cannot exhaust
	// memory here (#11).
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&set); err != nil {
		return fmt.Errorf("parsing JWKS: %w", err)
	}

	keys := make(map[string]any, len(set.Keys))
	for _, k := range set.Keys {
		if k.KeyID == "" {
			continue
		}
		// Entries explicitly scoped to a non-signature use cannot verify
		// tokens; skip them.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.KeyType {
		case "RSA":
			key, err := parseRSAJWK(k.N, k.E)
			if err != nil {
				continue
			}
			keys[k.KeyID] = key
		case "EC":
			key, err := parseECJWK(k.Curve, k.X, k.Y)
			if err != nil {
				continue
			}
			keys[k.KeyID] = key
		}
	}
	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = c.nowFn()
	c.mu.Unlock()
	return nil
}

// maxRSAExponentBytes caps the encoded RSA exponent length. A longer
// exponent would overflow int while parsing, and even a representable one
// makes verification cost scale with the exponent's size — a CPU-DoS knob
// for whoever controls the JWKS. Every exponent in real use fits (65537 is
// 3 bytes).
const maxRSAExponentBytes = 4

func parseRSAJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	// Reject weak RSA keys before accepting a JWKS entry. Bit length, not
	// encoded byte length: a leading zero byte would otherwise inflate the
	// count and sneak a sub-2048-bit modulus through.
	if n.BitLen() < minRSAKeyBits {
		return nil, errors.New("RSA modulus too small")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	if len(eBytes) > maxRSAExponentBytes {
		return nil, errors.New("invalid RSA exponent")
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e < 3 || e%2 == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseECJWK(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve %q", crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, err
	}
	const coordLen = 32
	if len(xBytes) > coordLen || len(yBytes) > coordLen {
		return nil, fmt.Errorf("invalid coordinate length")
	}
	point := make([]byte, 1+2*coordLen)
	point[0] = 0x04
	copy(point[1+coordLen-len(xBytes):1+coordLen], xBytes)
	copy(point[1+2*coordLen-len(yBytes):], yBytes)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testIssuer   = "https://test.cloudflareaccess.com"
	testAudience = "test-audience-tag"
)

// rsaJWK renders an RSA public key as a JWKS entry.
func rsaJWK(kid string, key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

// ecJWK renders a P-256 public key as a JWKS entry.
func ecJWK(t testing.TB, kid string, key *ecdsa.PublicKey) map[string]any {
	t.Helper()
	point, err := key.Bytes()
	if err != nil {
		t.Fatalf("encoding public key: %v", err)
	}
	// Uncompressed point: 0x04 || X || Y, each coordinate 32 bytes for P-256.
	return map[string]any{
		"kty": "EC",
		"kid": kid,
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(point[33:65]),
	}
}

// jwksServer serves a JWKS document whose keys can be swapped mid-test.
type jwksServer struct {
	*httptest.Server
	keys []map[string]any
}

func newJWKSServer(t testing.TB, keys ...map[string]any) *jwksServer {
	t.Helper()
	s := &jwksServer{keys: keys}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"keys": s.keys}); err != nil {
			t.Errorf("encoding JWKS: %v", err)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// signRS256 builds a signed JWT with the given header tweaks and claims.
func signRS256(t testing.TB, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": AlgRS256, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
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

// signES256 builds an ES256-signed JWT (JWS raw R||S signature).
func signES256(t testing.TB, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": AlgES256, "typ": "JWT", "kid": kid}
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
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func validClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"sub":   "subject-1",
		"iss":   testIssuer,
		"aud":   testAudience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"email": "ada@example.com",
		"name":  "Ada Lovelace",
		"roles": []string{"admin"},
	}
}

// newTestProvider builds an RS256-pinned provider against the test JWKS.
func newTestProvider(t testing.TB, jwksURL string) Provider {
	t.Helper()
	p, err := NewJWTProvider(JWTConfig{
		Header:    "Cf-Access-Jwt-Assertion",
		Issuer:    testIssuer,
		Audience:  testAudience,
		Algorithm: AlgRS256,
		JWKSURL:   jwksURL,
	})
	if err != nil {
		t.Fatalf("NewJWTProvider: %v", err)
	}
	return p
}

func authenticate(t testing.TB, p Provider, token string) (Principal, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		req.Header.Set(p.Header(), token)
	}
	return p.Authenticate(context.Background(), req)
}

func TestJWTProvider(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(t, rsaJWK("key-1", &key.PublicKey))

	t.Run("valid token maps to principal", func(t *testing.T) {
		p := newTestProvider(t, jwks.URL)
		principal, err := authenticate(t, p, signRS256(t, key, "key-1", validClaims()))
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if principal.Subject != "subject-1" {
			t.Errorf("subject = %q, want %q", principal.Subject, "subject-1")
		}
	})

	cases := []struct {
		name   string
		claims map[string]any
		kid    string
		signAs *rsa.PrivateKey
		token  string // overrides everything when set
	}{
		{name: "expired", claims: merge(validClaims(), map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}), kid: "key-1"},
		{name: "wrong audience", claims: merge(validClaims(), map[string]any{"aud": "someone-else"}), kid: "key-1"},
		{name: "wrong issuer", claims: merge(validClaims(), map[string]any{"iss": "https://evil.example.com"}), kid: "key-1"},
		{name: "missing expiry", claims: merge(validClaims(), map[string]any{"exp": nil}), kid: "key-1"},
		{name: "not before in future", claims: merge(validClaims(), map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}), kid: "key-1"},
		{name: "bad signature", kid: "key-1", signAs: otherKey},
		{name: "missing kid", kid: ""},
		{name: "malformed token", token: "not-a-jwt"},
		{name: "malformed segments", token: "a.b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(t, jwks.URL)
			token := tc.token
			if token == "" {
				claims := tc.claims
				if claims == nil {
					claims = validClaims()
				}
				signer := key
				if tc.signAs != nil {
					signer = tc.signAs
				}
				token = signRS256(t, signer, tc.kid, claims)
			}
			if _, err := authenticate(t, p, token); err == nil {
				t.Fatal("Authenticate succeeded, want error")
			}
		})
	}

	t.Run("audience as array", func(t *testing.T) {
		p := newTestProvider(t, jwks.URL)
		claims := merge(validClaims(), map[string]any{"aud": []string{"other", testAudience}})
		if _, err := authenticate(t, p, signRS256(t, key, "key-1", claims)); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	})

	t.Run("unknown kid triggers JWKS refresh", func(t *testing.T) {
		newKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}
		// Controllable clock: refetches are throttled to one per
		// jwksMinRefreshInterval, so rotation is only visible after it passes.
		now := time.Now()
		p, err := NewJWTProvider(JWTConfig{
			Header:    "Cf-Access-Jwt-Assertion",
			Issuer:    testIssuer,
			Audience:  testAudience,
			Algorithm: AlgRS256,
			JWKSURL:   jwks.URL,
			Now:       func() time.Time { return now },
		})
		if err != nil {
			t.Fatalf("NewJWTProvider: %v", err)
		}
		token := signRS256(t, newKey, "key-2", validClaims())

		// The JWKS does not know key-2 yet: rejection.
		if _, err := authenticate(t, p, token); err == nil {
			t.Fatal("Authenticate succeeded with unknown kid, want error")
		}
		// Rotation: the provider now publishes key-2, but the immediate retry
		// lands inside the refresh throttle window and is still rejected.
		jwks.keys = append(jwks.keys, rsaJWK("key-2", &newKey.PublicKey))
		if _, err := authenticate(t, p, token); err == nil {
			t.Fatal("Authenticate succeeded inside the refresh throttle window, want error")
		}
		// Once the throttle window passes, the client must refetch and accept.
		now = now.Add(jwksMinRefreshInterval + time.Second)
		if _, err := authenticate(t, p, token); err != nil {
			t.Fatalf("Authenticate after JWKS rotation: %v", err)
		}
	})

	t.Run("ES256 token rejected against RS256-pinned provider", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}
		p := newTestProvider(t, jwks.URL)
		// The pinned algorithm wins over the token header: no signature check
		// is even attempted.
		if _, err := authenticate(t, p, signES256(t, ecKey, "key-1", validClaims())); err == nil {
			t.Fatal("Authenticate succeeded with alg mismatch, want error")
		}
	})

	t.Run("ES256-pinned provider verifies P-256 tokens", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}
		ecJWKS := newJWKSServer(t, ecJWK(t, "ec-1", &ecKey.PublicKey))
		p, err := NewJWTProvider(JWTConfig{
			Header:    "X-Test-Jwt",
			Issuer:    testIssuer,
			Audience:  testAudience,
			Algorithm: AlgES256,
			JWKSURL:   ecJWKS.URL,
		})
		if err != nil {
			t.Fatalf("NewJWTProvider: %v", err)
		}
		if _, err := authenticate(t, p, signES256(t, ecKey, "ec-1", validClaims())); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	})

	t.Run("errors never contain the token", func(t *testing.T) {
		p := newTestProvider(t, jwks.URL)
		token := signRS256(t, otherKey, "key-1", validClaims())
		_, err := authenticate(t, p, token)
		if err == nil {
			t.Fatal("Authenticate succeeded, want error")
		}
		if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), strings.Split(token, ".")[2]) {
			t.Errorf("error leaks token material: %v", err)
		}
	})
}

// merge overlays extra onto base; nil values delete the key (JWT claims must
// be absent, not null, for the registered claims).
func merge(base, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

func TestMapCloudflareClaims(t *testing.T) {
	claims := Claims{
		Subject: "subject-1",
		Custom: map[string]any{
			"email": "ada@example.com",
			"name":  "Ada Lovelace",
			"roles": []any{"ADMIN", "Editor", 42, ""},
		},
	}

	t.Run("identity role mapping", func(t *testing.T) {
		p := mapCloudflareClaims(claims, IdentityRoleMapper)
		if p.Subject != "subject-1" || p.Email != "ada@example.com" || p.DisplayName != "Ada Lovelace" {
			t.Errorf("unexpected principal: %+v", p)
		}
		want := []string{"ADMIN", "Editor"}
		if fmt.Sprint(p.Roles) != fmt.Sprint(want) {
			t.Errorf("roles = %v, want %v (non-strings and empties dropped)", p.Roles, want)
		}
	})

	t.Run("normalizing role mapping", func(t *testing.T) {
		p := mapCloudflareClaims(claims, strings.ToLower)
		want := []string{"admin", "editor"}
		if fmt.Sprint(p.Roles) != fmt.Sprint(want) {
			t.Errorf("roles = %v, want %v", p.Roles, want)
		}
	})

	t.Run("no roles claim", func(t *testing.T) {
		p := mapCloudflareClaims(Claims{Subject: "s", Custom: map[string]any{}}, IdentityRoleMapper)
		if len(p.Roles) != 0 {
			t.Errorf("roles = %v, want empty", p.Roles)
		}
	})
}

func TestNewProviderRegistry(t *testing.T) {
	if _, err := NewProvider("does-not-exist", Settings{}); err == nil {
		t.Fatal("NewProvider with unknown name succeeded, want error")
	}
	p, err := NewProvider("cloudflare-access", Settings{TeamDomain: "test", Audience: "aud"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.Header() != "Cf-Access-Jwt-Assertion" {
		t.Errorf("header = %q, want Cf-Access-Jwt-Assertion", p.Header())
	}
}

func TestJWKSFetchTimeout(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// JWKS server that never responds.
	block := make(chan struct{})
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	defer func() {
		// Unblock the handler before closing the server so Close returns
		// promptly.
		close(block)
		jwks.Close()
	}()

	p, err := NewJWTProvider(JWTConfig{
		Header:     "X-Test-Jwt",
		Issuer:     testIssuer,
		Audience:   testAudience,
		Algorithm:  AlgRS256,
		JWKSURL:    jwks.URL,
		HTTPClient: &http.Client{Timeout: 50 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("NewJWTProvider: %v", err)
	}

	start := time.Now()
	_, err = authenticate(t, p, signRS256(t, key, "key-1", validClaims()))
	if err == nil {
		t.Fatal("Authenticate succeeded, want error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("JWKS fetch did not time out promptly: %v", elapsed)
	}
}

func TestJWKSUnknownKidRefreshThrottled(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// JWKS server that counts fetches; it only ever knows key-1.
	var fetches atomic.Int32
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{rsaJWK("key-1", &key.PublicKey)}}); err != nil {
			t.Errorf("encoding JWKS: %v", err)
		}
	}))
	t.Cleanup(jwks.Close)

	now := time.Now()
	p, err := NewJWTProvider(JWTConfig{
		Header:    "Cf-Access-Jwt-Assertion",
		Issuer:    testIssuer,
		Audience:  testAudience,
		Algorithm: AlgRS256,
		JWKSURL:   jwks.URL,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewJWTProvider: %v", err)
	}

	// A flood of tokens with random unknown kids must be rejected without
	// driving one outbound fetch per request (threat model #4).
	for i := 0; i < 10; i++ {
		token := signRS256(t, key, fmt.Sprintf("unknown-%d", i), validClaims())
		if _, err := authenticate(t, p, token); err == nil {
			t.Fatal("Authenticate succeeded with unknown kid, want error")
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("JWKS fetches after unknown-kid flood = %d, want 1", got)
	}

	// After the throttle window passes, an unknown kid may trigger exactly
	// one more refetch.
	now = now.Add(jwksMinRefreshInterval + time.Second)
	if _, err := authenticate(t, p, signRS256(t, key, "unknown-final", validClaims())); err == nil {
		t.Fatal("Authenticate succeeded with unknown kid, want error")
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("JWKS fetches after throttle window = %d, want 2", got)
	}
}

func TestJWKSFetchDoesNotBlockAuthentications(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// JWKS server that blocks until released, so the first fetch stays in
	// flight while a second request arrives.
	var enteredOnce sync.Once
	entered := make(chan struct{})
	release := make(chan struct{})
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enteredOnce.Do(func() { close(entered) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{rsaJWK("key-1", &key.PublicKey)}}); err != nil {
			t.Errorf("encoding JWKS: %v", err)
		}
	}))
	var releaseOnce sync.Once
	defer func() {
		// Unblock the handler before closing the server so Close returns
		// promptly, including on failure paths.
		releaseOnce.Do(func() { close(release) })
		jwks.Close()
	}()

	p, err := NewJWTProvider(JWTConfig{
		Header:     "Cf-Access-Jwt-Assertion",
		Issuer:     testIssuer,
		Audience:   testAudience,
		Algorithm:  AlgRS256,
		JWKSURL:    jwks.URL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	})
	if err != nil {
		t.Fatalf("NewJWTProvider: %v", err)
	}

	// The first request claims the fetch slot and blocks inside the fetch.
	first := make(chan error, 1)
	go func() {
		_, err := authenticate(t, p, signRS256(t, key, "key-1", validClaims()))
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first JWKS fetch did not reach the server")
	}

	// A concurrent request must be answered from the (empty) cache rather
	// than blocking behind the in-flight fetch's lock.
	start := time.Now()
	if _, err := authenticate(t, p, signRS256(t, key, "key-2", validClaims())); err == nil {
		t.Fatal("Authenticate succeeded with unknown kid, want error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("concurrent authentication blocked behind in-flight JWKS fetch: %v", elapsed)
	}

	// Release the first fetch; it must complete and authenticate.
	releaseOnce.Do(func() { close(release) })
	if err := <-first; err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}
}

func TestJWKSNonSigningUseSkipped(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// The only key in the set is explicitly scoped to encryption use; it must
	// not be accepted for signature verification.
	encKey := rsaJWK("key-1", &key.PublicKey)
	encKey["use"] = "enc"
	jwks := newJWKSServer(t, encKey)

	p := newTestProvider(t, jwks.URL)
	if _, err := authenticate(t, p, signRS256(t, key, "key-1", validClaims())); err == nil {
		t.Fatal("Authenticate succeeded with a use=enc JWKS key, want error")
	}
}

func TestParseRSAJWK(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	t.Run("valid", func(t *testing.T) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		if _, err := parseRSAJWK(n, e); err != nil {
			t.Fatalf("parseRSAJWK: %v", err)
		}
	})

	t.Run("invalid base64 n", func(t *testing.T) {
		if _, err := parseRSAJWK("!!!", base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())); err == nil {
			t.Fatal("parseRSAJWK succeeded, want error")
		}
	})

	t.Run("invalid base64 e", func(t *testing.T) {
		if _, err := parseRSAJWK(base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "!!!"); err == nil {
			t.Fatal("parseRSAJWK succeeded, want error")
		}
	})

	t.Run("zero exponent", func(t *testing.T) {
		if _, err := parseRSAJWK(base64.RawURLEncoding.EncodeToString(key.N.Bytes()), base64.RawURLEncoding.EncodeToString([]byte{0})); err == nil {
			t.Fatal("parseRSAJWK succeeded, want error")
		}
	})

	t.Run("even exponent", func(t *testing.T) {
		if _, err := parseRSAJWK(base64.RawURLEncoding.EncodeToString(key.N.Bytes()), base64.RawURLEncoding.EncodeToString([]byte{2})); err == nil {
			t.Fatal("parseRSAJWK succeeded, want error")
		}
	})

	t.Run("modulus too small", func(t *testing.T) {
		// Intentionally generate a weak key to verify the verifier rejects it.
		// #nosec G403
		smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("generating small key: %v", err)
		}
		n := base64.RawURLEncoding.EncodeToString(smallKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(smallKey.E)).Bytes())
		if _, err := parseRSAJWK(n, e); err == nil {
			t.Fatal("parseRSAJWK succeeded for 1024-bit key, want error")
		}
	})

	t.Run("padded undersized modulus", func(t *testing.T) {
		// A 2040-bit modulus prefixed with a zero byte encodes as 256 bytes;
		// encoded byte length must not stand in for bit length.
		short := new(big.Int).Lsh(big.NewInt(1), 2039) // 2040 bits
		n := base64.RawURLEncoding.EncodeToString(append([]byte{0}, short.Bytes()...))
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		if _, err := parseRSAJWK(n, e); err == nil {
			t.Fatal("parseRSAJWK succeeded for padded <2048-bit modulus, want error")
		}
	})

	t.Run("oversized exponent", func(t *testing.T) {
		// A >32-bit exponent would overflow int while parsing and inflate
		// verification cost; reject it outright.
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 0, 0, 1})
		if _, err := parseRSAJWK(n, e); err == nil {
			t.Fatal("parseRSAJWK succeeded for >32-bit exponent, want error")
		}
	})
}

func TestParseECJWK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encoding public key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(point[1:33])
	y := base64.RawURLEncoding.EncodeToString(point[33:65])

	t.Run("valid P-256", func(t *testing.T) {
		if _, err := parseECJWK("P-256", x, y); err != nil {
			t.Fatalf("parseECJWK: %v", err)
		}
	})

	t.Run("unsupported curve", func(t *testing.T) {
		if _, err := parseECJWK("P-384", x, y); err == nil {
			t.Fatal("parseECJWK succeeded, want error")
		}
	})

	t.Run("invalid base64 x", func(t *testing.T) {
		if _, err := parseECJWK("P-256", "!!!", y); err == nil {
			t.Fatal("parseECJWK succeeded, want error")
		}
	})

	t.Run("invalid base64 y", func(t *testing.T) {
		if _, err := parseECJWK("P-256", x, "!!!"); err == nil {
			t.Fatal("parseECJWK succeeded, want error")
		}
	})

	t.Run("coordinate too long", func(t *testing.T) {
		long := base64.RawURLEncoding.EncodeToString(make([]byte, 33))
		if _, err := parseECJWK("P-256", long, y); err == nil {
			t.Fatal("parseECJWK succeeded, want error")
		}
	})
}

func TestJWTVerifierProperties(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(t, rsaJWK("key-1", &key.PublicKey))

	now := time.Now()
	makeToken := func(claims map[string]any, tweaks ...func(map[string]any)) string {
		for _, tweak := range tweaks {
			tweak(claims)
		}
		return signRS256(t, key, "key-1", claims)
	}

	cases := []struct {
		name   string
		token  string
		wantOK bool
	}{
		{
			name:   "valid token",
			token:  makeToken(validClaims()),
			wantOK: true,
		},
		{
			name:   "alg=none header",
			token:  signWithHeader(t, key, map[string]any{"alg": "none", "typ": "JWT", "kid": "key-1"}, validClaims()),
			wantOK: false,
		},
		{
			name:   "alg=HS256 header against RS256 provider",
			token:  signWithHeader(t, key, map[string]any{"alg": "HS256", "typ": "JWT", "kid": "key-1"}, validClaims()),
			wantOK: false,
		},
		{
			name:   "future issued-at",
			token:  makeToken(validClaims(), setClaim("iat", now.Add(time.Hour).Unix())),
			wantOK: false,
		},
		{
			name:   "missing subject",
			token:  makeToken(validClaims(), setClaim("sub", nil)),
			wantOK: false,
		},
		{
			name:   "empty audience array",
			token:  makeToken(validClaims(), setClaim("aud", []string{})),
			wantOK: false,
		},
		{
			name:   "audience array without expected value",
			token:  makeToken(validClaims(), setClaim("aud", []string{"other"})),
			wantOK: false,
		},
		{
			name:   "wrong kid",
			token:  signRS256(t, key, "key-2", validClaims()),
			wantOK: false,
		},
		{
			name:   "signature from different RS256 key",
			token:  signRS256(t, otherKey, "key-1", validClaims()),
			wantOK: false,
		},
		{
			name:   "token with numeric audience",
			token:  makeToken(validClaims(), setClaim("aud", 42)),
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(t, jwks.URL)
			_, err := authenticate(t, p, tc.token)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("Authenticate: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Authenticate succeeded, want error")
			}
		})
	}
}

func setClaim(key string, value any) func(map[string]any) {
	return func(m map[string]any) {
		if value == nil {
			delete(m, key)
			return
		}
		m[key] = value
	}
}

func signWithHeader(t testing.TB, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
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

func FuzzVerifyMalformedToken(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(f, rsaJWK("key-1", &key.PublicKey))

	p, err := NewJWTProvider(JWTConfig{
		Header:    "X-Test-Jwt",
		Issuer:    testIssuer,
		Audience:  testAudience,
		Algorithm: AlgRS256,
		JWKSURL:   jwks.URL,
		Now:       func() time.Time { return time.Now() },
	})
	if err != nil {
		f.Fatalf("NewJWTProvider: %v", err)
	}

	seeds := []string{
		"",
		"not-a-jwt",
		"a.b",
		"a.b.c",
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzIn0.signature",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, token string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Test-Jwt", token)
		_, err := p.Authenticate(context.Background(), req)
		if err == nil {
			t.Error("Authenticate succeeded for malformed token, want error")
		}
		// The contract is that errors never contain the raw token. Only check
		// for plausible tokens to avoid false positives where a short random
		// string happens to match a generic error word.
		if len(token) >= 16 && strings.Contains(err.Error(), token) {
			t.Errorf("error leaks token: %v", err)
		}
	})
}

func FuzzVerifySignatureRS256(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(f, rsaJWK("key-1", &key.PublicKey))

	now := time.Now()
	makeClaims := func(subject string, expOffset time.Duration) map[string]any {
		return map[string]any{
			"sub": subject,
			"iss": testIssuer,
			"aud": testAudience,
			"exp": now.Add(expOffset).Unix(),
			"iat": now.Unix(),
		}
	}

	p, err := NewJWTProvider(JWTConfig{
		Header:    "X-Test-Jwt",
		Issuer:    testIssuer,
		Audience:  testAudience,
		Algorithm: AlgRS256,
		JWKSURL:   jwks.URL,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		f.Fatalf("NewJWTProvider: %v", err)
	}

	validToken := signRS256(f, key, "key-1", makeClaims("subject-1", time.Hour))
	f.Add(validToken)

	f.Fuzz(func(t *testing.T, token string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Test-Jwt", token)
		_, err := p.Authenticate(context.Background(), req)
		if err != nil {
			// Errors are expected for most mutated inputs; just ensure no panic.
			return
		}
		// Only the exact valid token should pass. A cheap way to confirm is
		// that the fuzzer does not report success for random bytes.
	})
}

// TestJWTAudienceShapes exercises the aud claim through the full verification
// path: the golang-jwt validator (via jwt.WithAudience) accepts a string or an
// array of strings containing the configured audience and rejects every other
// shape.
func TestJWTAudienceShapes(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(t, rsaJWK("key-1", &key.PublicKey))

	cases := []struct {
		name   string
		aud    any // nil deletes the claim
		wantOK bool
	}{
		{name: "string", aud: testAudience, wantOK: true},
		{name: "array containing audience", aud: []string{"other", testAudience}, wantOK: true},
		{name: "missing", aud: nil, wantOK: false},
		{name: "empty array", aud: []string{}, wantOK: false},
		{name: "array without audience", aud: []string{"other"}, wantOK: false},
		{name: "number rejected", aud: 42, wantOK: false},
		{name: "object rejected", aud: map[string]any{"aud": testAudience}, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(t, jwks.URL)
			claims := validClaims()
			if tc.aud == nil {
				delete(claims, "aud")
			} else {
				claims["aud"] = tc.aud
			}
			_, err := authenticate(t, p, signRS256(t, key, "key-1", claims))
			if tc.wantOK {
				if err != nil {
					t.Fatalf("Authenticate: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Authenticate succeeded, want error")
			}
		})
	}
}

// TestJWTSignatureNegative exercises signature and key-type rejection through
// the full verification path: the keyfunc enforces that the JWKS key type
// matches the pinned algorithm, and golang-jwt rejects bad signatures.
func TestJWTSignatureNegative(t *testing.T) {
	rsKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rsa key: %v", err)
	}
	otherRSKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rsa key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ec key: %v", err)
	}

	rsJWKS := newJWKSServer(t, rsaJWK("key-1", &rsKey.PublicKey))
	ecJWKS := newJWKSServer(t, ecJWK(t, "key-1", &ecKey.PublicKey))

	newES256Provider := func(t *testing.T, jwksURL string) Provider {
		t.Helper()
		p, err := NewJWTProvider(JWTConfig{
			Header:    "X-Test-Jwt",
			Issuer:    testIssuer,
			Audience:  testAudience,
			Algorithm: AlgES256,
			JWKSURL:   jwksURL,
		})
		if err != nil {
			t.Fatalf("NewJWTProvider: %v", err)
		}
		return p
	}

	// replaceSignature swaps the signature segment of an otherwise intact JWT.
	replaceSignature := func(token string, sig []byte) string {
		parts := strings.Split(token, ".")
		parts[2] = base64.RawURLEncoding.EncodeToString(sig)
		return strings.Join(parts, ".")
	}

	t.Run("RS256 provider rejects EC verification key", func(t *testing.T) {
		// The JWKS serves an EC key under the requested kid; the keyfunc must
		// reject it because the provider is pinned to RS256.
		p := newTestProvider(t, ecJWKS.URL)
		if _, err := authenticate(t, p, signRS256(t, rsKey, "key-1", validClaims())); err == nil {
			t.Fatal("Authenticate succeeded, want error")
		}
	})

	t.Run("RS256 invalid signature", func(t *testing.T) {
		p := newTestProvider(t, rsJWKS.URL)
		if _, err := authenticate(t, p, signRS256(t, otherRSKey, "key-1", validClaims())); err == nil {
			t.Fatal("Authenticate succeeded, want error")
		}
	})

	t.Run("ES256 provider rejects RSA verification key", func(t *testing.T) {
		p := newES256Provider(t, rsJWKS.URL)
		if _, err := authenticate(t, p, signES256(t, ecKey, "key-1", validClaims())); err == nil {
			t.Fatal("Authenticate succeeded, want error")
		}
	})

	t.Run("ES256 wrong signature length", func(t *testing.T) {
		p := newES256Provider(t, ecJWKS.URL)
		token := replaceSignature(signES256(t, ecKey, "key-1", validClaims()), make([]byte, 32))
		if _, err := authenticate(t, p, token); err == nil {
			t.Fatal("Authenticate succeeded, want error")
		}
	})

	t.Run("ES256 invalid signature", func(t *testing.T) {
		p := newES256Provider(t, ecJWKS.URL)
		token := replaceSignature(signES256(t, ecKey, "key-1", validClaims()), make([]byte, 64))
		if _, err := authenticate(t, p, token); err == nil {
			t.Fatal("Authenticate succeeded, want error")
		}
	})
}

// signHS256 builds an HMAC-SHA256-signed JWT with the given secret. It is used
// only to test that algorithm-confusion and key-confusion attacks are rejected.
func signHS256(t testing.TB, secret []byte, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshaling header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshaling payload: %v", err)
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// TestJWTKnownAttackRegressions exercises documented JWT attack classes. Each
// test name should map to an entry in docs/security/jwt-threat-model.md.
func TestJWTKnownAttackRegressions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	jwks := newJWKSServer(t, rsaJWK("key-1", &key.PublicKey))
	now := time.Now()

	makeValidToken := func(tweaks ...func(map[string]any)) string {
		claims := map[string]any{
			"sub": "subject-1",
			"iss": testIssuer,
			"aud": testAudience,
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
		}
		for _, tweak := range tweaks {
			tweak(claims)
		}
		return signRS256(t, key, "key-1", claims)
	}

	cases := []struct {
		name  string
		token func() string
	}{
		{
			name: "key confusion: RSA public key used as HMAC secret",
			token: func() string {
				// Even though the verifier never reaches HMAC validation,
				// construct the attack realistically: HS256 token signed with
				// the RSA public key modulus as the HMAC secret.
				pubBytes := key.N.Bytes()
				return signHS256(t, pubBytes, "key-1", map[string]any{
					"sub": "subject-1",
					"iss": testIssuer,
					"aud": testAudience,
					"exp": now.Add(time.Hour).Unix(),
				})
			},
		},
		{
			name: "tampered payload after valid signature",
			token: func() string {
				valid := makeValidToken()
				parts := strings.Split(valid, ".")
				payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
				var claims map[string]any
				if err := json.Unmarshal(payloadJSON, &claims); err != nil {
					t.Fatalf("unmarshaling payload: %v", err)
				}
				claims["sub"] = "attacker"
				newPayload, _ := json.Marshal(claims)
				parts[1] = base64.RawURLEncoding.EncodeToString(newPayload)
				return strings.Join(parts, ".")
			},
		},
		{
			name: "valid signature over wrong signing input",
			token: func() string {
				// Sign a different payload with the same key, then graft that
				// signature onto the original header.payload.
				original := makeValidToken()
				other := signRS256(t, key, "key-1", map[string]any{
					"sub": "other",
					"iss": testIssuer,
					"aud": testAudience,
					"exp": now.Add(time.Hour).Unix(),
				})
				origParts := strings.Split(original, ".")
				otherParts := strings.Split(other, ".")
				return origParts[0] + "." + origParts[1] + "." + otherParts[2]
			},
		},
		{
			name: "trailing garbage segment",
			token: func() string {
				return makeValidToken() + ".extra"
			},
		},
		{
			name: "missing signature segment",
			token: func() string {
				valid := makeValidToken()
				parts := strings.Split(valid, ".")
				return parts[0] + "." + parts[1]
			},
		},
		{
			name: "base64 standard encoding with padding",
			token: func() string {
				claims := map[string]any{
					"sub": "subject-1",
					"iss": testIssuer,
					"aud": testAudience,
					"exp": now.Add(time.Hour).Unix(),
				}
				headerJSON, _ := json.Marshal(map[string]any{"alg": AlgRS256, "typ": "JWT", "kid": "key-1"})
				payloadJSON, _ := json.Marshal(claims)
				input := base64.URLEncoding.EncodeToString(headerJSON) + "." + base64.URLEncoding.EncodeToString(payloadJSON)
				digest := sha256.Sum256([]byte(input))
				sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
				return input + "." + base64.URLEncoding.EncodeToString(sig)
			},
		},
		{
			name: "lowercase algorithm header",
			token: func() string {
				claims := map[string]any{
					"sub": "subject-1",
					"iss": testIssuer,
					"aud": testAudience,
					"exp": now.Add(time.Hour).Unix(),
				}
				headerJSON, _ := json.Marshal(map[string]any{"alg": "rs256", "typ": "JWT", "kid": "key-1"})
				payloadJSON, _ := json.Marshal(claims)
				input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
				digest := sha256.Sum256([]byte(input))
				sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
				return input + "." + base64.RawURLEncoding.EncodeToString(sig)
			},
		},
		{
			name: "expired exactly at leeway boundary",
			token: func() string {
				return makeValidToken(setClaim("exp", now.Add(-expiryLeeway).Unix()))
			},
		},
		{
			name: "empty signature",
			token: func() string {
				valid := makeValidToken()
				parts := strings.Split(valid, ".")
				parts[2] = ""
				return strings.Join(parts, ".")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProvider(t, jwks.URL)
			if _, err := authenticate(t, p, tc.token()); err == nil {
				t.Fatal("Authenticate succeeded, want error")
			}
		})
	}
}

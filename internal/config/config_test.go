package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", "example")
	t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", "aud")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.AuthProvider != "cloudflare-access" {
		t.Errorf("AuthProvider = %q, want cloudflare-access", cfg.AuthProvider)
	}
	if cfg.DatabasePath != "app.db" {
		t.Errorf("DatabasePath = %q, want app.db", cfg.DatabasePath)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 5s", cfg.ReadHeaderTimeout)
	}
	if cfg.ReadTimeout != 10*time.Second {
		t.Errorf("ReadTimeout = %v, want 10s", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s", cfg.WriteTimeout)
	}
	if cfg.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout = %v, want 60s", cfg.IdleTimeout)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 15s", cfg.ShutdownTimeout)
	}
}

func TestLoadCustomValues(t *testing.T) {
	t.Setenv("APP_HTTP_ADDR", ":9090")
	t.Setenv("APP_AUTH_PROVIDER", "cloudflare-access")
	t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", "myteam")
	t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", "my-aud")
	t.Setenv("APP_DATABASE_PATH", "/tmp/app.db")
	t.Setenv("APP_LOG_LEVEL", "debug")
	t.Setenv("APP_HTTP_READ_HEADER_TIMEOUT", "1s")
	t.Setenv("APP_HTTP_READ_TIMEOUT", "2s")
	t.Setenv("APP_HTTP_WRITE_TIMEOUT", "3s")
	t.Setenv("APP_HTTP_IDLE_TIMEOUT", "4s")
	t.Setenv("APP_HTTP_SHUTDOWN_TIMEOUT", "5s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q, want :9090", cfg.HTTPAddr)
	}
	if cfg.CloudflareTeam != "myteam" {
		t.Errorf("CloudflareTeam = %q, want myteam", cfg.CloudflareTeam)
	}
	if cfg.CloudflareAudience != "my-aud" {
		t.Errorf("CloudflareAudience = %q, want my-aud", cfg.CloudflareAudience)
	}
	if cfg.DatabasePath != "/tmp/app.db" {
		t.Errorf("DatabasePath = %q, want /tmp/app.db", cfg.DatabasePath)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}
	if cfg.ReadHeaderTimeout != 1*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 1s", cfg.ReadHeaderTimeout)
	}
	if cfg.ReadTimeout != 2*time.Second {
		t.Errorf("ReadTimeout = %v, want 2s", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 3*time.Second {
		t.Errorf("WriteTimeout = %v, want 3s", cfg.WriteTimeout)
	}
	if cfg.IdleTimeout != 4*time.Second {
		t.Errorf("IdleTimeout = %v, want 4s", cfg.IdleTimeout)
	}
	if cfg.ShutdownTimeout != 5*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 5s", cfg.ShutdownTimeout)
	}
}

func TestLoadMissingCloudflareSettings(t *testing.T) {
	for _, tc := range []struct {
		name        string
		team        string
		audience    string
		wantMissing string
	}{
		{
			name:        "missing team domain",
			audience:    "aud",
			wantMissing: "APP_AUTH_CLOUDFLARE_TEAM_DOMAIN",
		},
		{
			name:        "missing audience",
			team:        "example",
			wantMissing: "APP_AUTH_CLOUDFLARE_AUDIENCE",
		},
		{
			name:        "missing both",
			wantMissing: "APP_AUTH_CLOUDFLARE_TEAM_DOMAIN",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Clear any inherited values.
			t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", "")
			t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", "")
			if tc.team != "" {
				t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", tc.team)
			}
			if tc.audience != "" {
				t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", tc.audience)
			}

			_, err := Load()
			if err == nil {
				t.Fatal("Load succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.wantMissing) {
				t.Errorf("error = %q, want mention of %q", err.Error(), tc.wantMissing)
			}
		})
	}
}

func TestLoadTestProvider(t *testing.T) {
	t.Setenv("APP_AUTH_PROVIDER", "test")
	t.Setenv("APP_AUTH_TEST_ISSUER", "https://test.example.com")
	t.Setenv("APP_AUTH_TEST_AUDIENCE", "test-aud")
	t.Setenv("APP_AUTH_TEST_JWKS_URL", "http://localhost:9999/jwks")
	t.Setenv("APP_AUTH_TEST_HEADER", "X-Test-Auth")
	t.Setenv("APP_AUTH_TEST_ALGORITHM", "ES256")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AuthProvider != "test" {
		t.Errorf("AuthProvider = %q, want test", cfg.AuthProvider)
	}
	if cfg.TestIssuer != "https://test.example.com" {
		t.Errorf("TestIssuer = %q, want https://test.example.com", cfg.TestIssuer)
	}
	if cfg.TestAudience != "test-aud" {
		t.Errorf("TestAudience = %q, want test-aud", cfg.TestAudience)
	}
	if cfg.TestJWKSURL != "http://localhost:9999/jwks" {
		t.Errorf("TestJWKSURL = %q, want http://localhost:9999/jwks", cfg.TestJWKSURL)
	}
	if cfg.TestHeader != "X-Test-Auth" {
		t.Errorf("TestHeader = %q, want X-Test-Auth", cfg.TestHeader)
	}
	if cfg.TestAlgorithm != "ES256" {
		t.Errorf("TestAlgorithm = %q, want ES256", cfg.TestAlgorithm)
	}
}

func TestLoadTestProviderDefaults(t *testing.T) {
	t.Setenv("APP_AUTH_PROVIDER", "test")
	t.Setenv("APP_AUTH_TEST_ISSUER", "https://test.example.com")
	t.Setenv("APP_AUTH_TEST_AUDIENCE", "test-aud")
	t.Setenv("APP_AUTH_TEST_JWKS_URL", "http://localhost:9999/jwks")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TestHeader != "Cf-Access-Jwt-Assertion" {
		t.Errorf("TestHeader default = %q, want Cf-Access-Jwt-Assertion", cfg.TestHeader)
	}
	if cfg.TestAlgorithm != "RS256" {
		t.Errorf("TestAlgorithm default = %q, want RS256", cfg.TestAlgorithm)
	}
}

func TestLoadTestProviderMissingSettings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		issuer   string
		audience string
		jwksURL  string
		want     string
	}{
		{
			name:     "missing issuer",
			audience: "aud",
			jwksURL:  "http://localhost/jwks",
			want:     "APP_AUTH_TEST_ISSUER",
		},
		{
			name:    "missing audience",
			issuer:  "https://test.example.com",
			jwksURL: "http://localhost/jwks",
			want:    "APP_AUTH_TEST_AUDIENCE",
		},
		{
			name:     "missing JWKS URL",
			issuer:   "https://test.example.com",
			audience: "aud",
			want:     "APP_AUTH_TEST_JWKS_URL",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APP_AUTH_PROVIDER", "test")
			t.Setenv("APP_AUTH_TEST_ISSUER", "")
			t.Setenv("APP_AUTH_TEST_AUDIENCE", "")
			t.Setenv("APP_AUTH_TEST_JWKS_URL", "")
			if tc.issuer != "" {
				t.Setenv("APP_AUTH_TEST_ISSUER", tc.issuer)
			}
			if tc.audience != "" {
				t.Setenv("APP_AUTH_TEST_AUDIENCE", tc.audience)
			}
			if tc.jwksURL != "" {
				t.Setenv("APP_AUTH_TEST_JWKS_URL", tc.jwksURL)
			}

			_, err := Load()
			if err == nil {
				t.Fatal("Load succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want mention of %q", err.Error(), tc.want)
			}
		})
	}
}

func TestLoadInvalidDuration(t *testing.T) {
	t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", "example")
	t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", "aud")
	t.Setenv("APP_HTTP_READ_TIMEOUT", "not-a-duration")

	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded, want error")
	}
	if !strings.Contains(err.Error(), "APP_HTTP_READ_TIMEOUT") {
		t.Errorf("error = %q, want mention of APP_HTTP_READ_TIMEOUT", err.Error())
	}
}

func TestEnvString(t *testing.T) {
	key := "___CONFIG_TEST_ENV_STRING___"
	t.Setenv(key, "")

	if got := envString(key, "fallback"); got != "fallback" {
		t.Errorf("envString unset = %q, want fallback", got)
	}

	t.Setenv(key, "set")
	if got := envString(key, "fallback"); got != "set" {
		t.Errorf("envString set = %q, want set", got)
	}
}

func TestLoadInvalidHTTPAddr(t *testing.T) {
	t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", "example")
	t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", "aud")
	t.Setenv("APP_HTTP_ADDR", "not-an-address")

	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded, want error")
	}
	if !strings.Contains(err.Error(), "APP_HTTP_ADDR") {
		t.Errorf("error = %q, want mention of APP_HTTP_ADDR", err.Error())
	}
}

func TestLoadInvalidDatabasePath(t *testing.T) {
	t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", "example")
	t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", "aud")
	t.Setenv("APP_DATABASE_PATH", "../app.db")

	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded, want error")
	}
	if !strings.Contains(err.Error(), "APP_DATABASE_PATH") {
		t.Errorf("error = %q, want mention of APP_DATABASE_PATH", err.Error())
	}
}

func TestEnvDuration(t *testing.T) {
	key := "___CONFIG_TEST_ENV_DURATION___"
	t.Setenv(key, "")

	d, err := envDuration(key, 5*time.Second)
	if err != nil {
		t.Fatalf("envDuration: %v", err)
	}
	if d != 5*time.Second {
		t.Errorf("envDuration unset = %v, want 5s", d)
	}

	t.Setenv(key, "750ms")
	d, err = envDuration(key, 5*time.Second)
	if err != nil {
		t.Fatalf("envDuration: %v", err)
	}
	if d != 750*time.Millisecond {
		t.Errorf("envDuration set = %v, want 750ms", d)
	}

	t.Setenv(key, "bad")
	_, err = envDuration(key, 5*time.Second)
	if err == nil {
		t.Fatal("envDuration succeeded with bad value, want error")
	}
}

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

func TestLoadAllDurationsInvalid(t *testing.T) {
	t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", "example")
	t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", "aud")
	for _, key := range []string{
		"APP_HTTP_READ_HEADER_TIMEOUT",
		"APP_HTTP_READ_TIMEOUT",
		"APP_HTTP_WRITE_TIMEOUT",
		"APP_HTTP_IDLE_TIMEOUT",
		"APP_HTTP_SHUTDOWN_TIMEOUT",
	} {
		t.Setenv(key, "not-a-duration")
	}

	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded, want error")
	}
	for _, want := range []string{
		"APP_HTTP_READ_HEADER_TIMEOUT",
		"APP_HTTP_READ_TIMEOUT",
		"APP_HTTP_WRITE_TIMEOUT",
		"APP_HTTP_IDLE_TIMEOUT",
		"APP_HTTP_SHUTDOWN_TIMEOUT",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want mention of %q", err.Error(), want)
		}
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

func TestEnvBool(t *testing.T) {
	key := "___CONFIG_TEST_ENV_BOOL___"
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "unset", value: "", want: false},
		{name: "1", value: "1", want: true},
		{name: "true", value: "true", want: true},
		{name: "TRUE uppercase", value: "TRUE", want: true},
		{name: "yes", value: "yes", want: true},
		{name: "Yes mixed case", value: "Yes", want: true},
		{name: "0", value: "0", want: false},
		{name: "no", value: "no", want: false},
		{name: "false", value: "false", want: false},
		{name: "invalid value", value: "enabled", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(key, tc.value)
			if got := envBool(key); got != tc.want {
				t.Errorf("envBool(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestValidateHTTPAddr(t *testing.T) {
	for _, tc := range []struct {
		name    string
		addr    string
		wantErr string
	}{
		{name: "empty", addr: "", wantErr: "cannot be empty"},
		{name: "bare port", addr: ":8080"},
		{name: "host and port", addr: "127.0.0.1:8080"},
		{name: "hostname and port", addr: "localhost:9090"},
		{name: "missing port", addr: "127.0.0.1:", wantErr: "missing port"},
		{name: "no port separator", addr: "localhost", wantErr: "invalid address"},
		{name: "too many colons", addr: "a:b:c", wantErr: "invalid address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHTTPAddr(tc.addr)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("validateHTTPAddr(%q) = %v, want nil", tc.addr, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateHTTPAddr(%q) succeeded, want error", tc.addr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want mention of %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateDatabasePath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		wantErr string
	}{
		{name: "empty", path: "", wantErr: "cannot be empty"},
		{name: "relative file", path: "app.db"},
		{name: "absolute path", path: "/tmp/app.db"},
		{name: "nested relative path", path: "data/app.db"},
		{name: "dotdot prefix", path: "../app.db", wantErr: "cannot contain '..'"},
		{name: "dotdot inside", path: "data/../app.db", wantErr: "cannot contain '..'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDatabasePath(tc.path)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("validateDatabasePath(%q) = %v, want nil", tc.path, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateDatabasePath(%q) succeeded, want error", tc.path)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want mention of %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestLoadDisableHSTS(t *testing.T) {
	t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", "example")
	t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", "aud")
	t.Setenv("APP_HTTP_DISABLE_HSTS", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DisableHSTS {
		t.Error("DisableHSTS = false, want true")
	}
}

func TestLoadMultipleProblems(t *testing.T) {
	t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", "")
	t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", "")
	t.Setenv("APP_HTTP_IDLE_TIMEOUT", "not-a-duration")
	t.Setenv("APP_HTTP_ADDR", "not-an-address")
	t.Setenv("APP_DATABASE_PATH", "../app.db")

	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded, want error")
	}
	for _, want := range []string{
		"APP_AUTH_CLOUDFLARE_TEAM_DOMAIN",
		"APP_AUTH_CLOUDFLARE_AUDIENCE",
		"APP_HTTP_IDLE_TIMEOUT",
		"APP_HTTP_ADDR",
		"APP_DATABASE_PATH",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want mention of %q", err.Error(), want)
		}
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

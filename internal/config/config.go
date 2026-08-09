// Package config loads environment-only configuration for the application.
// All variables carry the APP_ prefix; missing required values fail fast at
// startup with clear messages.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Config holds the application's runtime settings, sourced exclusively from
// environment variables.
type Config struct {
	HTTPAddr           string
	ReadHeaderTimeout  time.Duration
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration
	ShutdownTimeout    time.Duration
	DisableHSTS        bool
	AuthProvider       string
	CloudflareTeam     string // team domain, e.g. "example" in example.cloudflareaccess.com
	CloudflareAudience string
	TestIssuer         string
	TestAudience       string
	TestJWKSURL        string
	TestHeader         string
	TestAlgorithm      string
	DatabasePath       string
	LogLevel           string
}

// Load reads configuration from the environment, applying defaults and
// validating required values. It returns an error listing every problem found.
func Load() (Config, error) {
	var problems []string

	cfg := Config{
		HTTPAddr:           envString("APP_HTTP_ADDR", ":8080"),
		DisableHSTS:        envBool("APP_HTTP_DISABLE_HSTS"),
		AuthProvider:       envString("APP_AUTH_PROVIDER", "cloudflare-access"),
		CloudflareTeam:     os.Getenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN"),
		CloudflareAudience: os.Getenv("APP_AUTH_CLOUDFLARE_AUDIENCE"),
		TestIssuer:         os.Getenv("APP_AUTH_TEST_ISSUER"),
		TestAudience:       os.Getenv("APP_AUTH_TEST_AUDIENCE"),
		TestJWKSURL:        os.Getenv("APP_AUTH_TEST_JWKS_URL"),
		TestHeader:         envString("APP_AUTH_TEST_HEADER", "Cf-Access-Jwt-Assertion"),
		TestAlgorithm:      envString("APP_AUTH_TEST_ALGORITHM", "RS256"),
		DatabasePath:       envString("APP_DATABASE_PATH", "app.db"),
		LogLevel:           envString("APP_LOG_LEVEL", "info"),
	}

	var err error
	if cfg.ReadHeaderTimeout, err = envDuration("APP_HTTP_READ_HEADER_TIMEOUT", 5*time.Second); err != nil {
		problems = append(problems, err.Error())
	}
	if cfg.ReadTimeout, err = envDuration("APP_HTTP_READ_TIMEOUT", 10*time.Second); err != nil {
		problems = append(problems, err.Error())
	}
	if cfg.WriteTimeout, err = envDuration("APP_HTTP_WRITE_TIMEOUT", 30*time.Second); err != nil {
		problems = append(problems, err.Error())
	}
	if cfg.IdleTimeout, err = envDuration("APP_HTTP_IDLE_TIMEOUT", 60*time.Second); err != nil {
		problems = append(problems, err.Error())
	}
	if cfg.ShutdownTimeout, err = envDuration("APP_HTTP_SHUTDOWN_TIMEOUT", 15*time.Second); err != nil {
		problems = append(problems, err.Error())
	}

	if err := validateHTTPAddr(cfg.HTTPAddr); err != nil {
		problems = append(problems, err.Error())
	}
	if err := validateDatabasePath(cfg.DatabasePath); err != nil {
		problems = append(problems, err.Error())
	}

	if cfg.AuthProvider == "cloudflare-access" {
		if cfg.CloudflareTeam == "" {
			problems = append(problems, "APP_AUTH_CLOUDFLARE_TEAM_DOMAIN is required when APP_AUTH_PROVIDER=cloudflare-access")
		}
		if cfg.CloudflareAudience == "" {
			problems = append(problems, "APP_AUTH_CLOUDFLARE_AUDIENCE is required when APP_AUTH_PROVIDER=cloudflare-access")
		}
	}

	if cfg.AuthProvider == "test" {
		if cfg.TestIssuer == "" {
			problems = append(problems, "APP_AUTH_TEST_ISSUER is required when APP_AUTH_PROVIDER=test")
		}
		if cfg.TestAudience == "" {
			problems = append(problems, "APP_AUTH_TEST_AUDIENCE is required when APP_AUTH_PROVIDER=test")
		}
		if cfg.TestJWKSURL == "" {
			problems = append(problems, "APP_AUTH_TEST_JWKS_URL is required when APP_AUTH_PROVIDER=test")
		}
	}

	if len(problems) > 0 {
		return Config{}, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return cfg, nil
}

func envString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	v := os.Getenv(key)
	if v == "" {
		return false
	}
	v = strings.ToLower(v)
	return v == "1" || v == "true" || v == "yes"
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid duration %q: %w", key, v, err)
	}
	return d, nil
}

func validateHTTPAddr(addr string) error {
	if addr == "" {
		return errors.New("APP_HTTP_ADDR cannot be empty")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		// net.SplitHostPort rejects bare ":port"; retry with a dummy host.
		_, port, err = net.SplitHostPort("0.0.0.0" + addr)
		if err != nil {
			return fmt.Errorf("APP_HTTP_ADDR: invalid address %q", addr)
		}
	}
	if port == "" {
		return fmt.Errorf("APP_HTTP_ADDR: missing port in %q", addr)
	}
	return nil
}

func validateDatabasePath(dbPath string) error {
	if dbPath == "" {
		return errors.New("APP_DATABASE_PATH cannot be empty")
	}
	if strings.Contains(dbPath, "..") {
		return errors.New("APP_DATABASE_PATH cannot contain '..'")
	}
	return nil
}

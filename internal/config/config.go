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
	HTTPAddr          string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	DisableHSTS       bool
	Auth              AuthConfig
	DatabasePath      string
	LogLevel          string
}

// AuthConfig selects the Identity Provider and groups each provider's
// settings under its own name.
type AuthConfig struct {
	Provider   string
	Cloudflare CloudflareConfig
	Local      LocalConfig
}

// CloudflareConfig holds the settings for the cloudflare-access provider.
type CloudflareConfig struct {
	TeamDomain string // team domain, e.g. "example" in example.cloudflareaccess.com
	Audience   string
}

// LocalConfig holds the settings for the local provider (local development
// and end-to-end tests against a local JWKS server).
type LocalConfig struct {
	Issuer    string
	Audience  string
	JWKSURL   string
	Header    string
	Algorithm string
}

// Load reads configuration from the environment, applying defaults and
// validating required values. It returns an error listing every problem found.
func Load() (Config, error) {
	var problems []string

	cfg := Config{
		HTTPAddr:    envString("APP_HTTP_ADDR", ":8080"),
		DisableHSTS: envBool("APP_HTTP_DISABLE_HSTS"),
		Auth: AuthConfig{
			Provider: envString("APP_AUTH_PROVIDER", "cloudflare-access"),
			Cloudflare: CloudflareConfig{
				TeamDomain: os.Getenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN"),
				Audience:   os.Getenv("APP_AUTH_CLOUDFLARE_AUDIENCE"),
			},
			Local: LocalConfig{
				Issuer:    os.Getenv("APP_AUTH_LOCAL_ISSUER"),
				Audience:  os.Getenv("APP_AUTH_LOCAL_AUDIENCE"),
				JWKSURL:   os.Getenv("APP_AUTH_LOCAL_JWKS_URL"),
				Header:    envString("APP_AUTH_LOCAL_HEADER", "Cf-Access-Jwt-Assertion"),
				Algorithm: envString("APP_AUTH_LOCAL_ALGORITHM", "RS256"),
			},
		},
		DatabasePath: envString("APP_DATABASE_PATH", "app.db"),
		LogLevel:     envString("APP_LOG_LEVEL", "info"),
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

	if cfg.Auth.Provider == "cloudflare-access" {
		if cfg.Auth.Cloudflare.TeamDomain == "" {
			problems = append(problems, "APP_AUTH_CLOUDFLARE_TEAM_DOMAIN is required when APP_AUTH_PROVIDER=cloudflare-access")
		}
		if cfg.Auth.Cloudflare.Audience == "" {
			problems = append(problems, "APP_AUTH_CLOUDFLARE_AUDIENCE is required when APP_AUTH_PROVIDER=cloudflare-access")
		}
	}

	if cfg.Auth.Provider == "local" {
		if cfg.Auth.Local.Issuer == "" {
			problems = append(problems, "APP_AUTH_LOCAL_ISSUER is required when APP_AUTH_PROVIDER=local")
		}
		if cfg.Auth.Local.Audience == "" {
			problems = append(problems, "APP_AUTH_LOCAL_AUDIENCE is required when APP_AUTH_PROVIDER=local")
		}
		if cfg.Auth.Local.JWKSURL == "" {
			problems = append(problems, "APP_AUTH_LOCAL_JWKS_URL is required when APP_AUTH_PROVIDER=local")
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

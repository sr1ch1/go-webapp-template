package main

import (
	"log/slog"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunMissingRequiredConfig(t *testing.T) {
	// t.Setenv forbids t.Parallel; pin the provider and clear the
	// Cloudflare settings so config.Load fails fast.
	t.Setenv("APP_AUTH_PROVIDER", "cloudflare-access")
	t.Setenv("APP_AUTH_CLOUDFLARE_TEAM_DOMAIN", "")
	t.Setenv("APP_AUTH_CLOUDFLARE_AUDIENCE", "")

	if err := run(); err == nil {
		t.Fatal("run succeeded with missing Cloudflare settings, want error")
	}
}

func TestRunStartsAndShutsDown(t *testing.T) {
	// Skip before starting the server: a late skip would leak the run()
	// goroutine, and Windows refuses to delete the still-open database file
	// during TempDir cleanup.
	if runtime.GOOS == "windows" {
		t.Skip("cannot send SIGTERM to own process on Windows")
	}

	// run() replaces the global default logger; restore it afterwards.
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	t.Setenv("APP_AUTH_PROVIDER", "test")
	t.Setenv("APP_AUTH_TEST_ISSUER", "https://test.example.com")
	t.Setenv("APP_AUTH_TEST_AUDIENCE", "test-aud")
	t.Setenv("APP_AUTH_TEST_JWKS_URL", "http://localhost:9999/jwks")
	t.Setenv("APP_HTTP_ADDR", "127.0.0.1:0")
	t.Setenv("APP_DATABASE_PATH", filepath.Join(t.TempDir(), "app.db"))
	t.Setenv("APP_HTTP_DISABLE_HSTS", "1")

	errCh := make(chan error, 1)
	go func() {
		errCh <- run()
	}()

	// Give the server a moment to bind before signalling shutdown.
	time.Sleep(200 * time.Millisecond)
	signalShutdown(t)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return within 5s after SIGTERM")
	}
}

// setValidTestEnv configures the environment for the test auth provider with
// a throwaway database, so config.Load succeeds and run() can proceed past
// the step under test.
func setValidTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("APP_AUTH_PROVIDER", "test")
	t.Setenv("APP_AUTH_TEST_ISSUER", "https://test.example.com")
	t.Setenv("APP_AUTH_TEST_AUDIENCE", "test-aud")
	t.Setenv("APP_AUTH_TEST_JWKS_URL", "http://localhost:9999/jwks")
	t.Setenv("APP_HTTP_ADDR", "127.0.0.1:0")
	t.Setenv("APP_DATABASE_PATH", filepath.Join(t.TempDir(), "app.db"))
	t.Setenv("APP_HTTP_DISABLE_HSTS", "1")
}

// restoreDefaultLogger preserves the global default logger across a run()
// call that replaces it.
func restoreDefaultLogger(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
}

func TestRunInvalidLogLevel(t *testing.T) {
	setValidTestEnv(t)
	t.Setenv("APP_LOG_LEVEL", "bogus")

	err := run()
	if err == nil {
		t.Fatal("run succeeded with an invalid APP_LOG_LEVEL, want error")
	}
	if !strings.Contains(err.Error(), "APP_LOG_LEVEL") {
		t.Errorf("error = %v, want mention of APP_LOG_LEVEL", err)
	}
}

func TestRunStoreOpenFailure(t *testing.T) {
	restoreDefaultLogger(t)
	setValidTestEnv(t)
	// SQLite cannot create a database inside a nonexistent directory.
	t.Setenv("APP_DATABASE_PATH", filepath.Join(t.TempDir(), "missing", "dir", "app.db"))

	if err := run(); err == nil {
		t.Fatal("run succeeded with an unwritable database path, want error")
	}
}

func TestRunUnknownAuthProvider(t *testing.T) {
	restoreDefaultLogger(t)
	setValidTestEnv(t)
	// config.Load accepts unknown provider names; auth.NewProvider rejects them.
	t.Setenv("APP_AUTH_PROVIDER", "bogus")

	err := run()
	if err == nil {
		t.Fatal("run succeeded with an unknown auth provider, want error")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error = %v, want mention of the provider name", err)
	}
}

func TestRunListenFailure(t *testing.T) {
	restoreDefaultLogger(t)
	setValidTestEnv(t)

	// Occupy a port so the server fails to bind and run() returns the
	// ListenAndServe error instead of blocking.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	t.Setenv("APP_HTTP_ADDR", ln.Addr().String())

	if err := run(); err == nil {
		t.Fatal("run succeeded on an occupied address, want error")
	}
}

// Command app wires configuration, store, auth provider, UI, and API into a
// running server. All logic lives in the internal packages.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sr1ch1/webapp-template/internal/api"
	"github.com/sr1ch1/webapp-template/internal/auth"
	"github.com/sr1ch1/webapp-template/internal/config"
	"github.com/sr1ch1/webapp-template/internal/logger"
	"github.com/sr1ch1/webapp-template/internal/store"
	"github.com/sr1ch1/webapp-template/internal/ui"
	"github.com/sr1ch1/webapp-template/internal/version"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		info := version.Info()
		fmt.Printf("%s %s (%s)\n", info["version"], info["commit"], info["build_time"])
		return
	}
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() (err error) {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log, err := logger.New(cfg.LogLevel)
	if err != nil {
		return err
	}
	slog.SetDefault(log)

	ctx := context.Background()
	st, err := store.Open(ctx, cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := st.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	settings := auth.Settings{
		TeamDomain:    cfg.CloudflareTeam,
		Audience:      cfg.CloudflareAudience,
		TestIssuer:    cfg.TestIssuer,
		TestAudience:  cfg.TestAudience,
		JWKSURL:       cfg.TestJWKSURL,
		TestHeader:    cfg.TestHeader,
		TestAlgorithm: cfg.TestAlgorithm,
	}
	provider, err := auth.NewProvider(cfg.AuthProvider, settings)
	if err != nil {
		return err
	}
	if cfg.AuthProvider == "test" {
		log.Warn("test auth provider is enabled; do not use in production")
	}

	routes, err := api.Routes(st, provider, ui.StaticHandler(), ui.NewPageModel(st), cfg.DisableHSTS, log)
	if err != nil {
		return fmt.Errorf("building routes: %w", err)
	}
	server := api.NewServer(api.ServerConfig{
		Addr:              cfg.HTTPAddr,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}, routes)

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		log.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return <-errCh
	}
}

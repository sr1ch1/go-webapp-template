package api

import (
	"net/http"
	"time"
)

// ServerConfig holds only the knobs the server factory needs. It is a small
// slice of the full application config, so callers do not have to pass unused
// fields to NewServer.
type ServerConfig struct {
	Addr              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// NewServer builds an http.Server from the given configuration and root
// handler. Routes handle route composition; this function is a thin
// adapter from handler to server.
func NewServer(cfg ServerConfig, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
}

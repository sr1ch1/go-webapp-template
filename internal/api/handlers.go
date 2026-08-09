// Package api wires the HTTP surface: middleware chain, health/readiness
// probes, the JSON API, and the server-rendered UI routes.
package api

import (
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"

	"github.com/sr1ch1/webapp-template/internal/auth"
	"github.com/sr1ch1/webapp-template/internal/httputil"
	"github.com/sr1ch1/webapp-template/internal/store"
	"github.com/sr1ch1/webapp-template/internal/version"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writing JSON response", "error", err)
	}
}

// healthz is the liveness probe: 200 with no dependency checks.
func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz is the readiness probe: 200 when the database answers, otherwise an
// information-free 503. The specific failure is logged server-side only.
func readyz(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := st.Ping(r.Context()); err != nil {
			slog.Error("readiness check failed", "error", err, "request_id", httputil.RequestIDFromContext(r.Context()))
			httputil.WriteProblem(w, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable), "")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// me returns the caller's curated Principal.
func me(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		httputil.WriteProblem(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "")
		return
	}
	writeJSON(w, http.StatusOK, principal)
}

// versionHandler returns the binary's build metadata.
func versionHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, version.Info())
}

// listConfig returns all Runtime Configuration entries.
func listConfig(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := st.ListConfig(r.Context())
		if err != nil {
			slog.Error("listing config", "error", err, "request_id", httputil.RequestIDFromContext(r.Context()))
			httputil.WriteProblem(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
			return
		}
		writeJSON(w, http.StatusOK, entries)
	}
}

// setConfigBody is the request body for PUT /api/config/{key}.
type setConfigBody struct {
	Value string `json:"value"`
}

// putConfig upserts one Runtime Configuration entry (admin role only; the
// guard is applied at the route).
func putConfig(st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key")
		if !store.ValidConfigKey(key) {
			httputil.WriteProblem(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "invalid key")
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			httputil.WriteProblem(w, http.StatusUnsupportedMediaType, http.StatusText(http.StatusUnsupportedMediaType), "")
			return
		}
		var body setConfigBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			status := http.StatusBadRequest
			detail := "invalid request body"
			if httputil.IsRequestEntityTooLarge(err) {
				status = http.StatusRequestEntityTooLarge
				detail = "request body too large"
			}
			slog.Error("setting config", "error", err, "request_id", httputil.RequestIDFromContext(r.Context()))
			httputil.WriteProblem(w, status, http.StatusText(status), detail)
			return
		}
		if err := st.SetConfig(r.Context(), key, body.Value); err != nil {
			slog.Error("setting config", "error", err, "request_id", httputil.RequestIDFromContext(r.Context()))
			httputil.WriteProblem(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
			return
		}
		principal, _ := auth.PrincipalFromContext(r.Context())
		slog.Info("config changed", "subject", principal.Subject, "key", key, "request_id", httputil.RequestIDFromContext(r.Context()))
		writeJSON(w, http.StatusOK, store.ConfigEntry{Key: key, Value: body.Value})
	}
}

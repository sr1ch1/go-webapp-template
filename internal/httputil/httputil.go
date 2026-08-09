// Package httputil holds HTTP conventions shared across the application:
// request-ID context helpers and RFC 9457 problem-detail responses.
// It is deliberately not tied to authentication, so UI and API handlers
// can share response formatting without importing the auth package.
package httputil

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

type requestIDKey struct{}

// WithRequestID stores the request ID in the request context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext retrieves the request ID, or "" if none was set.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// IsRequestEntityTooLarge reports whether err is the result of reading a
// request body larger than http.MaxBytesReader allows.
func IsRequestEntityTooLarge(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

// WriteProblem writes an RFC 9457 problem details response. detail must be
// safe for the caller; auth failures pass an empty detail.
func WriteProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	problem := map[string]any{
		"type":   "about:blank",
		"title":  title,
		"status": status,
	}
	if detail != "" {
		problem["detail"] = detail
	}
	if err := json.NewEncoder(w).Encode(problem); err != nil {
		slog.Error("writing problem response", "error", err)
	}
}

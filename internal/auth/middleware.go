package auth

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/sandrorichi/webapp-template/internal/httputil"
)

type contextKey struct{}

// WithPrincipal stores the Principal in the request context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

// PrincipalFromContext retrieves the Principal stored by Middleware.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(contextKey{}).(Principal)
	return p, ok
}

// Middleware authenticates every request with the given Provider and stores
// the resulting Principal in the request context. Failures are answered with
// a vague 401-problem response; the cause is logged server-side only. The
// token value is never logged.
func Middleware(p Provider, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, err := p.Authenticate(r.Context(), r)
			if err != nil {
				log.Info("authentication failed", "error", err, "request_id", httputil.RequestIDFromContext(r.Context()))
				httputil.WriteProblem(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "")
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
		})
	}
}

// RequireRole guards a route behind a role. Principals lacking the role get a
// vague 403-problem response.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFromContext(r.Context())
			if !ok || !principal.HasRole(role) {
				httputil.WriteProblem(w, http.StatusForbidden, http.StatusText(http.StatusForbidden), "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

package api

import (
	"log/slog"
	"net/http"

	"github.com/sandrorichi/webapp-template/internal/auth"
	"github.com/sandrorichi/webapp-template/internal/store"
	"github.com/sandrorichi/webapp-template/internal/ui"
)

// Routes compose the full application request tree: health/readiness probes,
// metrics, and static assets bypass authentication; everything else runs
// through CSRF, auth, and rate-limiting middleware. The returned handler is
// ready to be mounted into an http.Server by NewServer.
func Routes(st *store.Store, provider auth.Provider, staticHandler http.Handler, model ui.PageModel, disableHSTS bool, log *slog.Logger) (http.Handler, error) {
	// Admin mutations share one rate limiter across API and UI routes.
	rl := newRateLimiter(rateLimitRate, rateLimitBurst)

	uiHandler, err := ui.Handler(model, log, rl.adminMiddleware)
	if err != nil {
		return nil, err
	}

	m := newHTTPMetrics()

	// Authenticated subtree: metrics, CSRF, auth, and rate limiting on admin
	// mutations. Registered on the root mux under the catch-all "/" pattern.
	authed := http.NewServeMux()
	authed.HandleFunc("GET /api/me", me)
	authed.HandleFunc("GET /api/version", versionHandler)
	authed.HandleFunc("GET /api/config", listConfig(st))
	authed.Handle("PUT /api/config/{key}", rl.adminMiddleware(auth.RequireRole("admin")(putConfig(st))))
	authed.Handle("/", uiHandler)

	authedChain := m.middleware(maxBody(csrf(auth.Middleware(provider, log)(authed))))

	// Root mux: explicit unauthenticated routes first, then the authenticated
	// catch-all. Using one mux means there is no manual pattern matching or
	// double dispatch: ServeMux picks the most specific registered pattern.
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", healthz)
	root.HandleFunc("GET /readyz", readyz(st))
	// Metrics sit with the unauthenticated probes so a Prometheus scraper
	// does not need an Identity Provider token. The series carry no caller
	// data: only methods, route patterns, and status codes.
	root.Handle("GET /metrics", m.registry.Handler())
	root.Handle("/static/", staticHandler)
	root.Handle("/", authedChain)

	return requestID(logging(log, securityHeaders(disableHSTS, root))), nil
}

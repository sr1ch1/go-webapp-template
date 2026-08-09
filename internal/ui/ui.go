// Package ui serves the server-rendered pages. Full pages are rendered for
// plain requests; htmx requests (HX-Request header) get the matching
// fragment. All UI routes are authenticated; mutations are admin-only.
package ui

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/sandrorichi/webapp-template/internal/auth"
	"github.com/sandrorichi/webapp-template/internal/httputil"
	"github.com/sandrorichi/webapp-template/internal/store"
	"github.com/sandrorichi/webapp-template/web"
)

// pageData feeds the home template and its fragments.
type pageData struct {
	SiteName  string
	Principal auth.Principal
	Entries   []store.ConfigEntry
	IsAdmin   bool
}

// PageModel is the seam between the UI and the data layer. The handler
// depends only on this interface, so rendering can be tested with an in-memory
// model instead of a real database.
type PageModel interface {
	LoadPageData(ctx context.Context, principal auth.Principal) (pageData, error)
	SetConfig(ctx context.Context, key, value string) error
}

// storePageModel is the production PageModel adapter backed by the store.
type storePageModel struct {
	st *store.Store
}

func (m *storePageModel) LoadPageData(ctx context.Context, principal auth.Principal) (pageData, error) {
	entries, err := m.st.ListConfig(ctx)
	if err != nil {
		return pageData{}, err
	}
	siteName := "Web App"
	for _, e := range entries {
		if e.Key == "site_name" {
			siteName = e.Value
		}
	}
	return pageData{
		SiteName:  siteName,
		Principal: principal,
		Entries:   entries,
		IsAdmin:   principal.HasRole("admin"),
	}, nil
}

func (m *storePageModel) SetConfig(ctx context.Context, key, value string) error {
	return m.st.SetConfig(ctx, key, value)
}

// NewPageModel builds the production PageModel backed by st.
func NewPageModel(st *store.Store) PageModel {
	return &storePageModel{st: st}
}

// StaticHandler serves the embedded vendored frontend assets under /static/.
func StaticHandler() http.Handler {
	sub, err := fs.Sub(web.FS, "static")
	if err != nil {
		// "static" is embedded at compile time; this cannot fail at runtime.
		panic(err)
	}
	return http.StripPrefix("/static/", http.FileServerFS(sub))
}

// Handler serves the UI routes: GET / (home page) and the admin-only
// PUT /ui/config/{key} fragment update. adminMiddleware is applied to the
// admin mutation route; it is typically a rate limiter installed after auth.
func Handler(model PageModel, log *slog.Logger, adminMiddleware func(http.Handler) http.Handler) (http.Handler, error) {
	tmpl, err := template.ParseFS(web.FS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	h := &handler{tmpl: tmpl, model: model, log: log}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", h.home)
	mux.Handle("PUT /ui/config/{key}", adminMiddleware(auth.RequireRole("admin")(http.HandlerFunc(h.putConfig))))
	return mux, nil
}

type handler struct {
	tmpl  *template.Template
	model PageModel
	log   *slog.Logger
}

// data assembles the view model for the current request.
func (h *handler) data(r *http.Request) (pageData, error) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		return pageData{}, fmt.Errorf("missing principal in request context")
	}
	return h.model.LoadPageData(r.Context(), principal)
}

// isFragment reports whether the request came from htmx and expects only the
// updated fragment back.
func isFragment(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

func (h *handler) render(w http.ResponseWriter, r *http.Request, fullPage string) {
	d, err := h.data(r)
	if err != nil {
		h.log.Error("loading page data", "error", err, "request_id", httputil.RequestIDFromContext(r.Context()))
		httputil.WriteProblem(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}
	name := "config-section"
	if !isFragment(r) {
		name = fullPage
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, name, d); err != nil {
		h.log.Error("rendering template", "error", err, "request_id", httputil.RequestIDFromContext(r.Context()))
	}
}

// home renders the home page (full page or, for htmx, the config fragment).
func (h *handler) home(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "home")
}

// putConfig upserts a Runtime Configuration entry and answers with the
// updated config-section fragment (200, not Post/Redirect/Get).
func (h *handler) putConfig(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteProblem(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "invalid form body")
		return
	}
	key := r.PathValue("key")
	if !store.ValidConfigKey(key) {
		httputil.WriteProblem(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "invalid key")
		return
	}
	value := r.PostFormValue("value")
	if err := h.model.SetConfig(r.Context(), key, value); err != nil {
		h.log.Error("setting config", "error", err, "request_id", httputil.RequestIDFromContext(r.Context()))
		httputil.WriteProblem(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	h.log.Info("config changed", "subject", principal.Subject, "key", key, "request_id", httputil.RequestIDFromContext(r.Context()))
	h.render(w, r, "home")
}

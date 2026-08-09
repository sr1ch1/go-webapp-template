package ui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sr1ch1/webapp-template/internal/auth"
	"github.com/sr1ch1/webapp-template/internal/store"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

type fakePageModel struct {
	data     pageData
	dataErr  error
	setErr   error
	setCalls []struct{ Key, Value string }
}

func (m *fakePageModel) LoadPageData(_ context.Context, principal auth.Principal) (pageData, error) {
	if m.dataErr != nil {
		return pageData{}, m.dataErr
	}
	m.data.Principal = principal
	m.data.IsAdmin = principal.HasRole("admin")
	return m.data, nil
}

func (m *fakePageModel) SetConfig(_ context.Context, key, value string) error {
	m.setCalls = append(m.setCalls, struct{ Key, Value string }{key, value})
	return m.setErr
}

func withPrincipal(r *http.Request, p auth.Principal) *http.Request {
	return r.WithContext(auth.WithPrincipal(r.Context(), p))
}

func adminPrincipal() auth.Principal {
	return auth.Principal{
		Subject:     "s1",
		Email:       "admin@example.com",
		DisplayName: "Admin User",
		Roles:       []string{"admin"},
	}
}

func viewerPrincipal() auth.Principal {
	return auth.Principal{
		Subject:     "s2",
		Email:       "viewer@example.com",
		DisplayName: "Viewer User",
		Roles:       []string{},
	}
}

func TestStaticHandlerServesEmbeddedAsset(t *testing.T) {
	h := StaticHandler()
	req := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/css; charset=utf-8", ct)
	}
	if rec.Body.Len() == 0 {
		t.Error("body is empty")
	}
}

func TestHomeFullPage(t *testing.T) {
	model := &fakePageModel{data: pageData{
		SiteName: "Test Site",
		Entries:  []store.ConfigEntry{{Key: "site_name", Value: "Test Site"}},
		IsAdmin:  false,
	}}
	h, err := Handler(model, testLogger(), passthroughMiddleware)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := withPrincipal(httptest.NewRequest(http.MethodGet, "/", nil), viewerPrincipal())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Test Site") {
		t.Errorf("body missing site name: %q", body)
	}
	if !strings.Contains(body, "Viewer User") {
		t.Errorf("body missing display name: %q", body)
	}
	if !strings.Contains(body, "<html") {
		t.Errorf("body missing html tag; expected full page render")
	}
}

func TestHomeFragment(t *testing.T) {
	model := &fakePageModel{data: pageData{
		SiteName: "Test Site",
		Entries:  []store.ConfigEntry{{Key: "site_name", Value: "Test Site"}},
		IsAdmin:  false,
	}}
	h, err := Handler(model, testLogger(), passthroughMiddleware)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := withPrincipal(httptest.NewRequest(http.MethodGet, "/", nil), viewerPrincipal())
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<html") {
		t.Errorf("htmx fragment should not contain full html page")
	}
	if !strings.Contains(body, "config-section") {
		t.Errorf("fragment missing config-section: %q", body)
	}
}

func TestHomeMissingPrincipal(t *testing.T) {
	model := &fakePageModel{data: pageData{}}
	h, err := Handler(model, testLogger(), passthroughMiddleware)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestHomeModelError(t *testing.T) {
	model := &fakePageModel{dataErr: errors.New("boom")}
	h, err := Handler(model, testLogger(), passthroughMiddleware)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := withPrincipal(httptest.NewRequest(http.MethodGet, "/", nil), viewerPrincipal())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestPutConfigAdmin(t *testing.T) {
	model := &fakePageModel{data: pageData{
		SiteName: "Test Site",
		Entries:  []store.ConfigEntry{{Key: "site_name", Value: "New Name"}},
		IsAdmin:  true,
	}}
	h, err := Handler(model, testLogger(), auth.RequireRole("admin"))
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := withPrincipal(httptest.NewRequest(http.MethodPut, "/ui/config/site_name", strings.NewReader("value=New+Name")), adminPrincipal())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(model.setCalls) != 1 || model.setCalls[0].Key != "site_name" || model.setCalls[0].Value != "New Name" {
		t.Errorf("setCalls = %v, want [{site_name New Name}]", model.setCalls)
	}
}

func TestPutConfigInvalidKey(t *testing.T) {
	model := &fakePageModel{}
	h, err := Handler(model, testLogger(), auth.RequireRole("admin"))
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := withPrincipal(httptest.NewRequest(http.MethodPut, "/ui/config/bad.key", strings.NewReader("value=x")), adminPrincipal())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if len(model.setCalls) != 0 {
		t.Errorf("setCalls = %v, want none", model.setCalls)
	}
}

func TestPutConfigForbiddenForNonAdmin(t *testing.T) {
	model := &fakePageModel{}
	h, err := Handler(model, testLogger(), auth.RequireRole("admin"))
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := withPrincipal(httptest.NewRequest(http.MethodPut, "/ui/config/site_name", strings.NewReader("value=x")), viewerPrincipal())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestPutConfigModelError(t *testing.T) {
	model := &fakePageModel{setErr: errors.New("db down")}
	h, err := Handler(model, testLogger(), auth.RequireRole("admin"))
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := withPrincipal(httptest.NewRequest(http.MethodPut, "/ui/config/site_name", strings.NewReader("value=x")), adminPrincipal())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

func TestIsAdminDerivedFromPrincipal(t *testing.T) {
	model := &fakePageModel{data: pageData{
		Entries: []store.ConfigEntry{{Key: "site_name", Value: "V"}},
	}}
	h, err := Handler(model, testLogger(), passthroughMiddleware)
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := withPrincipal(httptest.NewRequest(http.MethodGet, "/", nil), adminPrincipal())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if model.data.IsAdmin != true {
		t.Errorf("IsAdmin = %v, want true", model.data.IsAdmin)
	}
}

func passthroughMiddleware(next http.Handler) http.Handler {
	return next
}

func TestStaticHandlerServesJavaScript(t *testing.T) {
	h := StaticHandler()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/javascript; charset=utf-8", ct)
	}
}

func TestStaticHandlerMissingFile(t *testing.T) {
	h := StaticHandler()
	req := httptest.NewRequest(http.MethodGet, "/static/does-not-exist.css", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestStaticHandlerRejectsTraversal ensures a path containing ".." is not
// served: the file server redirects it away instead of leaking files outside
// the embedded static directory.
func TestStaticHandlerRejectsTraversal(t *testing.T) {
	h := StaticHandler()
	req := httptest.NewRequest(http.MethodGet, "/static/../templates/home.html", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("status = 200 for traversal path, want redirect or error")
	}
	if strings.Contains(rec.Body.String(), "config-section") {
		t.Errorf("traversal path leaked template content: %q", rec.Body.String())
	}
}

// TestPutConfigInvalidFormBody ensures a malformed form body is rejected
// before the model is touched.
func TestPutConfigInvalidFormBody(t *testing.T) {
	model := &fakePageModel{}
	h, err := Handler(model, testLogger(), auth.RequireRole("admin"))
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := withPrincipal(httptest.NewRequest(http.MethodPut, "/ui/config/site_name", strings.NewReader("value=%zz")), adminPrincipal())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if len(model.setCalls) != 0 {
		t.Errorf("setCalls = %v, want none", model.setCalls)
	}
}

// TestNewPageModel ensures the production adapter delegates to the store.
// It uses a real in-memory store to confirm integration without a fake.
func TestNewPageModel(t *testing.T) {
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})

	if err := st.SetConfig(context.Background(), "site_name", "Real Site"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	model := NewPageModel(st)
	p := adminPrincipal()
	data, err := model.LoadPageData(context.Background(), p)
	if err != nil {
		t.Fatalf("LoadPageData: %v", err)
	}
	if data.SiteName != "Real Site" {
		t.Errorf("SiteName = %q, want Real Site", data.SiteName)
	}
	if data.Principal.Subject != p.Subject {
		t.Errorf("Principal.Subject = %q, want %q", data.Principal.Subject, p.Subject)
	}
	if !data.IsAdmin {
		t.Error("IsAdmin = false, want true")
	}
	if len(data.Entries) != 2 {
		t.Errorf("len(Entries) = %d, want 2 (seeded rows)", len(data.Entries))
	}
}

// TestPrincipalJSONTags ensures the struct serialized to the UI matches the
// template field names (snake_case).
func TestPrincipalJSONTags(t *testing.T) {
	p := auth.Principal{
		Subject:     "s1",
		Email:       "a@example.com",
		DisplayName: "Ada",
		Roles:       []string{"admin"},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := m["display_name"]; !ok {
		t.Errorf("missing display_name in %v", m)
	}
	if _, ok := m["DisplayName"]; ok {
		t.Errorf("unexpected DisplayName (camelCase) in %v", m)
	}
}

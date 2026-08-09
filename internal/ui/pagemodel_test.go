package ui

import (
	"context"
	"errors"
	"testing"

	"github.com/sr1ch1/webapp-template/internal/store"
)

// TestStorePageModelSetConfig ensures the production PageModel delegates
// SetConfig to the store. Key validation happens in the handler (see
// TestPutConfigInvalidKey); the model itself accepts any key.
func TestStorePageModelSetConfig(t *testing.T) {
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})

	model := NewPageModel(st)
	ctx := context.Background()

	if err := model.SetConfig(ctx, "site_name", "Model Site"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	entries, err := st.ListConfig(ctx)
	if err != nil {
		t.Fatalf("ListConfig: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Key == "site_name" && e.Value == "Model Site" {
			found = true
		}
	}
	if !found {
		t.Errorf("site_name = Model Site not persisted: %v", entries)
	}

	// Upsert overwrites the value.
	if err := model.SetConfig(ctx, "site_name", "Renamed"); err != nil {
		t.Fatalf("SetConfig upsert: %v", err)
	}
	data, err := model.LoadPageData(ctx, adminPrincipal())
	if err != nil {
		t.Fatalf("LoadPageData: %v", err)
	}
	if data.SiteName != "Renamed" {
		t.Errorf("SiteName = %q, want Renamed", data.SiteName)
	}
}

// TestStorePageModelSetConfigError ensures store errors propagate to the
// caller instead of being swallowed.
func TestStorePageModelSetConfigError(t *testing.T) {
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}

	model := NewPageModel(st)
	err = model.SetConfig(context.Background(), "site_name", "x")
	if err == nil {
		t.Fatal("SetConfig on closed store succeeded, want error")
	}
	if errors.Is(err, context.Canceled) {
		t.Errorf("SetConfig error = %v, unexpected context error", err)
	}
}

// TestStorePageModelLoadPageDataError ensures store errors from ListConfig
// propagate to the caller instead of being swallowed.
func TestStorePageModelLoadPageDataError(t *testing.T) {
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}

	model := NewPageModel(st)
	_, err = model.LoadPageData(context.Background(), adminPrincipal())
	if err == nil {
		t.Fatal("LoadPageData on closed store succeeded, want error")
	}
	if errors.Is(err, context.Canceled) {
		t.Errorf("LoadPageData error = %v, unexpected context error", err)
	}
}

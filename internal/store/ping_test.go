package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestPingOpenStore(t *testing.T) {
	st := open(t, filepath.Join(t.TempDir(), "app.db"))

	if err := st.Ping(context.Background()); err != nil {
		t.Errorf("Ping on open store: %v", err)
	}
}

func TestPingAfterClose(t *testing.T) {
	// Not using the open helper: it would Close again in cleanup and flag an error.
	st, err := Open(context.Background(), filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = st.Ping(context.Background())
	if err == nil {
		t.Fatal("Ping after Close succeeded, want error")
	}
	// database/sql does not export its closed-handle sentinel; match the text.
	if !strings.Contains(err.Error(), "database is closed") {
		t.Errorf("Ping after Close = %v, want a \"database is closed\" error", err)
	}
}

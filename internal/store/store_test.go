package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func open(t *testing.T, path string) *Store {
	t.Helper()
	st, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})
	return st
}

func TestOpenAppliesMigrations(t *testing.T) {
	st := open(t, filepath.Join(t.TempDir(), "app.db"))

	// Seed rows from 0001 exist.
	entries, err := st.ListConfig(context.Background())
	if err != nil {
		t.Fatalf("ListConfig: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("seed entries = %v, want at least site_name and motd", entries)
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")

	st := open(t, path)
	if err := st.SetConfig(context.Background(), "custom", "1"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Errorf("store.Close: %v", err)
	}

	// Reopening applies nothing new and keeps data.
	st = open(t, path)
	entries, err := st.ListConfig(context.Background())
	if err != nil {
		t.Fatalf("ListConfig: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Key == "custom" && e.Value == "1" {
			found = true
		}
	}
	if !found {
		t.Errorf("custom entry lost across reopen: %v", entries)
	}
}

func TestDowngradeProtection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")

	st := open(t, path)
	if err := st.Close(); err != nil {
		t.Errorf("store.Close: %v", err)
	}

	// Simulate a database migrated by a newer binary.
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec("INSERT INTO schema_migrations (version) VALUES ('9999_future')"); err != nil {
		t.Fatalf("seeding future migration: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("db.Close: %v", err)
	}

	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("Open succeeded against a newer database, want downgrade protection error")
	}
}

func TestConfigCRUD(t *testing.T) {
	st := open(t, filepath.Join(t.TempDir(), "app.db"))
	ctx := context.Background()

	if err := st.SetConfig(ctx, "greeting", "hello"); err != nil {
		t.Fatalf("SetConfig insert: %v", err)
	}
	if err := st.SetConfig(ctx, "greeting", "hi"); err != nil {
		t.Fatalf("SetConfig upsert: %v", err)
	}

	entries, err := st.ListConfig(ctx)
	if err != nil {
		t.Fatalf("ListConfig: %v", err)
	}
	var values []string
	for _, e := range entries {
		if e.Key == "greeting" {
			values = append(values, e.Value)
		}
	}
	if len(values) != 1 || values[0] != "hi" {
		t.Errorf("greeting values = %v, want exactly [hi]", values)
	}

	// Keys come back ordered.
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Key > entries[i].Key {
			t.Errorf("entries not ordered by key: %v", entries)
			break
		}
	}
}

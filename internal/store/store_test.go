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

func TestOpenUnwritablePath(t *testing.T) {
	// The parent directory does not exist, so SQLite cannot create the file
	// and Open fails while enabling WAL.
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "nonexistent", "app.db")); err == nil {
		t.Fatal("Open succeeded with a nonexistent parent directory, want error")
	}
}

func TestOpenMigrationFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")

	// Pre-create a conflicting config table; 0001_config.up.sql uses a plain
	// CREATE TABLE, so applying it must fail and roll back.
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE config (other TEXT)"); err != nil {
		t.Fatalf("creating conflicting table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("db.Close: %v", err)
	}

	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("Open succeeded despite a failing migration, want error")
	}
}

func TestApplyMigration(t *testing.T) {
	ctx := context.Background()

	newDB := func(t *testing.T) *sql.DB {
		t.Helper()
		db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "app.db"))
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		t.Cleanup(func() {
			if err := db.Close(); err != nil {
				t.Errorf("db.Close: %v", err)
			}
		})
		if _, err := db.ExecContext(ctx, `CREATE TABLE schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		)`); err != nil {
			t.Fatalf("creating schema_migrations: %v", err)
		}
		return db
	}

	t.Run("invalid SQL rolls back", func(t *testing.T) {
		db := newDB(t)
		if err := applyMigration(ctx, db, "0001_broken", "THIS IS NOT SQL"); err == nil {
			t.Fatal("applyMigration succeeded with invalid SQL, want error")
		}
		// The rollback leaves no row behind.
		var n int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = '0001_broken'").Scan(&n); err != nil {
			t.Fatalf("counting versions: %v", err)
		}
		if n != 0 {
			t.Errorf("failed migration recorded in schema_migrations")
		}
	})

	t.Run("duplicate version rejected", func(t *testing.T) {
		db := newDB(t)
		if err := applyMigration(ctx, db, "0001_noop", "SELECT 1"); err != nil {
			t.Fatalf("applyMigration: %v", err)
		}
		if err := applyMigration(ctx, db, "0001_noop", "SELECT 1"); err == nil {
			t.Fatal("applyMigration recorded the same version twice, want error")
		}
	})

	t.Run("closed database fails at BeginTx", func(t *testing.T) {
		db := newDB(t)
		if err := db.Close(); err != nil {
			t.Fatalf("db.Close: %v", err)
		}
		if err := applyMigration(ctx, db, "0001_closed", "SELECT 1"); err == nil {
			t.Fatal("applyMigration succeeded on a closed database, want error")
		}
	})
}

func TestListConfigScanError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	st := open(t, path)

	// SQLite is dynamically typed and TEXT PRIMARY KEY allows NULL here; a
	// NULL key fails to scan into a string field.
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("db.Close: %v", err)
		}
	}()
	if _, err := db.Exec("INSERT INTO config (key, value) VALUES (NULL, 'v')"); err != nil {
		t.Fatalf("inserting NULL key: %v", err)
	}

	if _, err := st.ListConfig(context.Background()); err == nil {
		t.Fatal("ListConfig succeeded with an unscannable row, want error")
	}
}

func TestMigrateScanError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")

	st, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A NULL version cannot scan into a string on the next Open.
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec("INSERT INTO schema_migrations (version) VALUES (NULL)"); err != nil {
		t.Fatalf("inserting NULL version: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("db.Close: %v", err)
	}

	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("Open succeeded with an unscannable schema_migrations row, want error")
	}
}

func TestConfigClosedStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	st, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ctx := context.Background()
	if _, err := st.ListConfig(ctx); err == nil {
		t.Error("ListConfig on closed store succeeded, want error")
	}
	if err := st.SetConfig(ctx, "k", "v"); err == nil {
		t.Error("SetConfig on closed store succeeded, want error")
	}
}

func TestMigrateUnknownVersionQueryError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")

	// A schema_migrations table without a version column: CREATE TABLE IF NOT
	// EXISTS is a no-op, then SELECT version fails.
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec("CREATE TABLE schema_migrations (bogus TEXT)"); err != nil {
		t.Fatalf("creating schema_migrations without version column: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("db.Close: %v", err)
	}

	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("Open succeeded with a malformed schema_migrations table, want error")
	}
}

func TestListConfigRows(t *testing.T) {
	tests := []struct {
		name string
		rows map[string]string
		want []ConfigEntry
	}{
		{
			name: "empty",
			rows: nil,
			want: []ConfigEntry{},
		},
		{
			name: "single row",
			rows: map[string]string{"a": "1"},
			want: []ConfigEntry{{Key: "a", Value: "1"}},
		},
		{
			name: "multiple rows ordered by key",
			rows: map[string]string{"c": "3", "a": "1", "b": "2"},
			want: []ConfigEntry{
				{Key: "a", Value: "1"},
				{Key: "b", Value: "2"},
				{Key: "c", Value: "3"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "app.db")
			st := open(t, path)

			// Remove the 0001 seed rows so want is the exact result.
			db, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatalf("sql.Open: %v", err)
			}
			if _, err := db.Exec("DELETE FROM config"); err != nil {
				t.Fatalf("clearing config: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Errorf("db.Close: %v", err)
			}

			for k, v := range tt.rows {
				if err := st.SetConfig(ctx, k, v); err != nil {
					t.Fatalf("SetConfig(%q, %q): %v", k, v, err)
				}
			}

			got, err := st.ListConfig(ctx)
			if err != nil {
				t.Fatalf("ListConfig: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ListConfig = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("ListConfig[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// Package store owns the SQLite database: connection setup, embedded up-only
// migrations, and queries. Migrations are applied in lexicographic order at
// startup, recorded in schema_migrations; the runner refuses to start when
// the database is newer than the binary (downgrade protection, ADR-0003).
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.up.sql
var migrationsFS embed.FS

// ConfigEntry is one Runtime Configuration key/value pair.
type ConfigEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Store wraps the application's database handle.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at the given path, enables WAL,
// verifies connectivity, and applies pending migrations.
func Open(ctx context.Context, path string) (_ *Store, err error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	defer func() {
		if err != nil {
			if closeErr := db.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("closing database: %w", closeErr))
			}
		}
	}()

	// SQLite is single-writer; one connection avoids SQLITE_BUSY surprises.
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("enabling WAL: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// ValidConfigKey reports whether key is a safe runtime-configuration key.
// Keys are restricted to alphanumeric characters, hyphens, and underscores to
// avoid path-breaking characters in URLs and HTML attributes.
func ValidConfigKey(key string) bool {
	if key == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// Ping verifies database connectivity (used by /readyz).
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// migrate applies all pending embedded migrations in lexicographic order,
// each in its own transaction.
func migrate(ctx context.Context, db *sql.DB) (err error) {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	)`); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	names, err := fs.Glob(migrationsFS, "migrations/*.up.sql")
	if err != nil {
		return fmt.Errorf("listing migrations: %w", err)
	}
	sort.Strings(names)

	known := make(map[string]bool, len(names))
	for _, n := range names {
		known[versionOf(n)] = true
	}

	// Downgrade protection: refuse to start if the database records a
	// migration this binary does not know.
	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("reading schema_migrations: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("reading schema_migrations: %w", closeErr)
		}
	}()

	var applied []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return fmt.Errorf("reading schema_migrations: %w", err)
		}
		applied = append(applied, v)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading schema_migrations: %w", err)
	}
	for _, v := range applied {
		if !known[v] {
			return fmt.Errorf("database is newer than this binary: unknown migration %q", v)
		}
	}

	appliedSet := make(map[string]bool, len(applied))
	for _, v := range applied {
		appliedSet[v] = true
	}

	for _, name := range names {
		version := versionOf(name)
		if appliedSet[version] {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", version, err)
		}
		if err := applyMigration(ctx, db, version, string(body)); err != nil {
			return err
		}
	}
	return nil
}

// versionOf extracts the version from a migration file name, e.g.
// "migrations/0001_config.up.sql" → "0001_config".
func versionOf(name string) string {
	base := name[strings.LastIndex(name, "/")+1:]
	return strings.TrimSuffix(base, ".up.sql")
}

func applyMigration(ctx context.Context, db *sql.DB, version, body string) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration %s: %w", version, err)
	}
	defer func() {
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) && err == nil {
			err = fmt.Errorf("migration %s: rollback: %w", version, rerr)
		}
	}()

	if _, err := tx.ExecContext(ctx, body); err != nil {
		return fmt.Errorf("migration %s: %w", version, err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES (?)", version); err != nil {
		return fmt.Errorf("migration %s: %w", version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %s: %w", version, err)
	}
	return nil
}

// ListConfig returns all Runtime Configuration entries ordered by key.
func (s *Store) ListConfig(ctx context.Context) (entries []ConfigEntry, err error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM config ORDER BY key")
	if err != nil {
		return nil, fmt.Errorf("listing config: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("listing config: %w", closeErr)
		}
	}()

	entries = []ConfigEntry{}
	for rows.Next() {
		var e ConfigEntry
		if err := rows.Scan(&e.Key, &e.Value); err != nil {
			return nil, fmt.Errorf("listing config: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing config: %w", err)
	}
	return entries, nil
}

// SetConfig upserts one Runtime Configuration entry.
func (s *Store) SetConfig(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value)
	if err != nil {
		return fmt.Errorf("setting config: %w", err)
	}
	return nil
}

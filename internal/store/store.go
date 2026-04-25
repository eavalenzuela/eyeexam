// Package store wraps the SQLite datastore: connection management, embedded
// migrations, and typed DAO functions for runs / executions / detections /
// audit rows. The DB file is opened with WAL + foreign_keys ON.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/jmoiron/sqlx"
	"github.com/pressly/goose/v3"

	_ "modernc.org/sqlite" // registers "sqlite" driver
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store is the long-lived datastore handle.
type Store struct {
	DB   *sqlx.DB
	path string
}

// Open opens (or creates) the SQLite db at path, applies pending migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("store: mkdir parent: %w", err)
	}
	dsn := buildDSN(path)
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if err := raw.PingContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	db := sqlx.NewDb(raw, "sqlite")

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: goose dialect: %w", err)
	}
	goose.SetLogger(goose.NopLogger())
	if err := goose.UpContext(ctx, db.DB, "migrations"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{DB: db, path: path}, nil
}

func (s *Store) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
}

func (s *Store) Path() string { return s.path }

func buildDSN(path string) string {
	q := url.Values{}
	q.Set("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "busy_timeout(5000)")
	return "file:" + path + "?" + q.Encode()
}

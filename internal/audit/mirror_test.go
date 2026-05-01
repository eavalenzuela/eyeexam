package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

// minimal subset of internal/store/migrations/0001_init.sql — only the
// audit_log table, so the audit package's tests can exercise the
// mirror without a circular dep on store.
const auditLogSchema = `
CREATE TABLE audit_log (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,
  ts              TEXT NOT NULL,
  actor_json      TEXT NOT NULL,
  engagement_id   TEXT,
  run_id          TEXT,
  event           TEXT NOT NULL,
  payload_json    TEXT NOT NULL,
  prev_hash       TEXT NOT NULL,
  hash            TEXT NOT NULL,
  signature       TEXT NOT NULL
);
`

func newTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db := sqlx.NewDb(raw, "sqlite")
	if _, err := db.Exec(auditLogSchema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mirrorRowCount(t *testing.T, db *sqlx.DB) int {
	t.Helper()
	var n int
	if err := db.Get(&n, `SELECT COUNT(*) FROM audit_log`); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAppendMirrorsToDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	db := newTestDB(t)
	pub, priv := newKey(t)

	l, err := Open(path, priv, db)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(context.Background(), Record{
			Actor:   Actor{OSUser: "alice", OSUID: 1000},
			Event:   "test",
			Payload: json.RawMessage(`{"i":` + itoa(i) + `}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := mirrorRowCount(t, db); got != 3 {
		t.Fatalf("audit_log rows = %d, want 3", got)
	}

	res, err := VerifyWithMirror(path, pub, db)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("verify failed: %+v", res)
	}
}

func TestBackfillFromFileOnOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	pub, priv := newKey(t)

	// Write file-only (legacy deployment: no DB mirror configured).
	l, err := Open(path, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := l.Append(context.Background(), Record{
			Actor:   Actor{OSUser: "alice", OSUID: 1000},
			Event:   "legacy",
			Payload: json.RawMessage(`{"i":` + itoa(i) + `}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Now reopen with a mirror DB; backfill should populate it from the file.
	db := newTestDB(t)
	l2, err := Open(path, priv, db)
	if err != nil {
		t.Fatalf("reopen with mirror: %v", err)
	}
	if got := mirrorRowCount(t, db); got != 4 {
		t.Fatalf("after backfill: rows=%d, want 4", got)
	}

	// One more append after backfill must extend both stores correctly.
	if _, err := l2.Append(context.Background(), Record{
		Actor: Actor{OSUser: "alice", OSUID: 1000},
		Event: "post-backfill",
	}); err != nil {
		t.Fatal(err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	if got := mirrorRowCount(t, db); got != 5 {
		t.Fatalf("after post-backfill append: rows=%d, want 5", got)
	}

	res, err := VerifyWithMirror(path, pub, db)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("verify after backfill+append: %+v", res)
	}
}

func TestVerifyWithMirrorDetectsDBDivergence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	db := newTestDB(t)
	pub, priv := newKey(t)

	l, err := Open(path, priv, db)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(context.Background(), Record{
			Actor: Actor{OSUser: "alice", OSUID: 1000},
			Event: "test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()

	// Tamper: change the hash on row 2 in the DB only.
	if _, err := db.Exec(`UPDATE audit_log SET hash = ? WHERE seq = 2`,
		"deadbeef"+"00000000000000000000000000000000000000000000000000000000"); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyWithMirror(path, pub, db)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("expected divergence to be reported, got OK: %+v", res)
	}
	if res.FirstBadSeq != 2 {
		t.Errorf("FirstBadSeq=%d, want 2", res.FirstBadSeq)
	}
}

func TestOpenRefusesDBAheadOfFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	db := newTestDB(t)
	_, priv := newKey(t)

	// File exists but is empty; DB has a row from a prior life.
	if _, err := db.Exec(`INSERT INTO audit_log
		(seq, ts, actor_json, event, payload_json, prev_hash, hash, signature)
		VALUES (1, '2026-01-01T00:00:00Z', '{}', 'orphan', 'null', '', '', '')`); err != nil {
		t.Fatal(err)
	}

	_, err := Open(path, priv, db)
	if err == nil {
		t.Fatal("expected Open to refuse when DB has rows beyond file")
	}
}

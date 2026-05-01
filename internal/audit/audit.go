// Package audit implements eyeexam's append-only signed audit log.
//
// Each Record carries a sha256 chain hash over the previous record plus its
// own canonical-JSON form, and an ed25519 signature over that hash. The log
// is written to a file on disk; tampering with any line breaks the chain at
// that point onwards. Verify reports the first divergent sequence number.
package audit

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
)

const genesisHashHex = "0000000000000000000000000000000000000000000000000000000000000000"

type Record struct {
	Seq        int64           `json:"seq"`
	TS         time.Time       `json:"ts"`
	Actor      Actor           `json:"actor"`
	Engagement string          `json:"engagement,omitempty"`
	RunID      string          `json:"run_id,omitempty"`
	Event      string          `json:"event"`
	Payload    json.RawMessage `json:"payload"`
	PrevHash   string          `json:"prev_hash"` // hex
	Hash       string          `json:"hash"`      // hex
	Signature  string          `json:"sig"`       // base64
}

// Logger is an append-only signed log writer. Safe for concurrent use.
//
// The file at path is the authoritative, signed source of truth. When db
// is non-nil, each Append also writes the record into the audit_log
// SQLite table as a queryable mirror. The file is written and fsync'd
// first; the DB INSERT is best-effort and logged on failure. On Open,
// any seq present in the file but missing from db is backfilled.
type Logger struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	priv     ed25519.PrivateKey
	db       *sqlx.DB
	lastSeq  int64
	lastHash string
}

// Open opens (or creates) the log at path with the given private key. It
// scans the existing file to recover the last seq + hash so subsequent
// Append calls chain correctly. When db is non-nil, audit_log is also
// reconciled against the file (missing seqs are backfilled).
func Open(path string, priv ed25519.PrivateKey, db *sqlx.DB) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	l := &Logger{path: path, file: f, priv: priv, db: db, lastHash: genesisHashHex}

	// Recover state by streaming existing records, simultaneously
	// backfilling any DB rows missing for seqs we observe in the file.
	var dbMaxSeq int64
	if db != nil {
		if err := db.Get(&dbMaxSeq, `SELECT COALESCE(MAX(seq), 0) FROM audit_log`); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: read db max seq: %w", err)
		}
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: seek: %w", err)
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<24)
	for scanner.Scan() {
		var r Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: parse existing log seq>%d: %w", l.lastSeq, err)
		}
		if db != nil && r.Seq > dbMaxSeq {
			if err := insertMirrorRow(db, r); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("audit: backfill seq %d: %w", r.Seq, err)
			}
		}
		l.lastSeq = r.Seq
		l.lastHash = r.Hash
	}
	if err := scanner.Err(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: scanning log: %w", err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: seek end: %w", err)
	}

	// Sanity check: DB must not have rows beyond what's in the file.
	// That would indicate the file was truncated/replaced or DB tampering.
	if db != nil {
		var postDBMax int64
		if err := db.Get(&postDBMax, `SELECT COALESCE(MAX(seq), 0) FROM audit_log`); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("audit: re-check db max seq: %w", err)
		}
		if postDBMax > l.lastSeq {
			_ = f.Close()
			return nil, fmt.Errorf("audit: db has seq %d but file ends at %d — file truncated or db tampered",
				postDBMax, l.lastSeq)
		}
	}
	return l, nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// Append writes a record. On return, r.Seq, r.PrevHash, r.Hash, r.Signature
// are populated. The file is fsync'd before the call returns.
func (l *Logger) Append(_ context.Context, r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return Record{}, errors.New("audit: logger closed")
	}

	r.Seq = l.lastSeq + 1
	if r.TS.IsZero() {
		r.TS = time.Now().UTC()
	} else {
		r.TS = r.TS.UTC()
	}
	r.PrevHash = l.lastHash
	if len(r.Payload) == 0 {
		r.Payload = json.RawMessage("null")
	}

	hash, err := computeHash(r)
	if err != nil {
		return Record{}, err
	}
	r.Hash = hash

	if l.priv != nil {
		hb, err := hex.DecodeString(r.Hash)
		if err != nil {
			return Record{}, fmt.Errorf("audit: decode hash: %w", err)
		}
		sig := ed25519.Sign(l.priv, hb)
		r.Signature = base64.StdEncoding.EncodeToString(sig)
	}

	line, err := json.Marshal(r)
	if err != nil {
		return Record{}, fmt.Errorf("audit: marshal record: %w", err)
	}
	line = append(line, '\n')
	if _, err := l.file.Write(line); err != nil {
		return Record{}, fmt.Errorf("audit: write: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return Record{}, fmt.Errorf("audit: fsync: %w", err)
	}
	l.lastSeq = r.Seq
	l.lastHash = r.Hash

	// Mirror to SQLite when configured. Best-effort: a DB failure here
	// leaves the file authoritative; the row will be backfilled at next
	// Open. We log loudly so the operator can investigate.
	if l.db != nil {
		if err := insertMirrorRow(l.db, r); err != nil {
			slog.Warn("audit: db mirror insert failed; will backfill on next Open",
				"seq", r.Seq, "event", r.Event, "err", err.Error())
		}
	}
	return r, nil
}

// insertMirrorRow writes one Record into the audit_log table.
// Idempotent on the seq primary key — re-inserts return a UNIQUE
// constraint error which the caller treats as benign at backfill time.
func insertMirrorRow(db *sqlx.DB, r Record) error {
	actorJSON, err := json.Marshal(r.Actor)
	if err != nil {
		return fmt.Errorf("marshal actor: %w", err)
	}
	payload := r.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("null")
	}
	_, err = db.Exec(`
		INSERT INTO audit_log (
		  seq, ts, actor_json, engagement_id, run_id,
		  event, payload_json, prev_hash, hash, signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		r.Seq, r.TS.UTC().Format(time.RFC3339Nano), string(actorJSON),
		nullStringIfEmpty(r.Engagement), nullStringIfEmpty(r.RunID),
		r.Event, string(payload), r.PrevHash, r.Hash, r.Signature)
	return err
}

func nullStringIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// computeHash returns sha256(prev_hash_bytes || canonical_json_without_hash_sig).
func computeHash(r Record) (string, error) {
	canon := canonicalForHash(r)
	b, err := json.Marshal(canon)
	if err != nil {
		return "", fmt.Errorf("audit: canonical marshal: %w", err)
	}
	prev, err := hex.DecodeString(r.PrevHash)
	if err != nil {
		return "", fmt.Errorf("audit: decode prev_hash: %w", err)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// canonicalForHash strips Hash + Signature and returns a stable struct for
// hashing. The field order in this anonymous struct defines canonical order.
func canonicalForHash(r Record) any {
	return struct {
		Seq        int64           `json:"seq"`
		TS         string          `json:"ts"`
		Actor      Actor           `json:"actor"`
		Engagement string          `json:"engagement,omitempty"`
		RunID      string          `json:"run_id,omitempty"`
		Event      string          `json:"event"`
		Payload    json.RawMessage `json:"payload"`
		PrevHash   string          `json:"prev_hash"`
	}{
		Seq:        r.Seq,
		TS:         r.TS.UTC().Format(time.RFC3339Nano),
		Actor:      r.Actor,
		Engagement: r.Engagement,
		RunID:      r.RunID,
		Event:      r.Event,
		Payload:    r.Payload,
		PrevHash:   r.PrevHash,
	}
}

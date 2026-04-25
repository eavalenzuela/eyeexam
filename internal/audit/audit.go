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
	"os"
	"sync"
	"time"
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
type Logger struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	priv     ed25519.PrivateKey
	lastSeq  int64
	lastHash string
}

// Open opens (or creates) the log at path with the given private key. It
// scans the existing file to recover the last seq + hash so subsequent
// Append calls chain correctly.
func Open(path string, priv ed25519.PrivateKey) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	l := &Logger{path: path, file: f, priv: priv, lastHash: genesisHashHex}

	// Recover state by streaming existing records.
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
	return r, nil
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

package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jmoiron/sqlx"
)

// VerifyResult captures the outcome of a full-log verification.
type VerifyResult struct {
	OK             bool
	RecordsChecked int64
	FirstBadSeq    int64 // 0 when OK
	Reason         string
}

// VerifyWithMirror cross-checks the file at path against the audit_log
// table. The file is authoritative on conflict; any divergence is
// reported as a verification failure pointing at the first divergent
// seq.
func VerifyWithMirror(path string, pub ed25519.PublicKey, db *sqlx.DB) (VerifyResult, error) {
	res, err := Verify(path, pub)
	if err != nil || !res.OK || db == nil {
		return res, err
	}

	type mirrorRow struct {
		Seq  int64  `db:"seq"`
		Hash string `db:"hash"`
	}
	var rows []mirrorRow
	if err := db.Select(&rows, `SELECT seq, hash FROM audit_log ORDER BY seq`); err != nil {
		return VerifyResult{}, fmt.Errorf("audit verify: read mirror: %w", err)
	}

	if int64(len(rows)) != res.RecordsChecked {
		return VerifyResult{
			RecordsChecked: res.RecordsChecked,
			FirstBadSeq:    int64(len(rows)) + 1,
			Reason: fmt.Sprintf("file has %d records but db has %d",
				res.RecordsChecked, len(rows)),
		}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit verify: reopen %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<24)
	idx := 0
	for scanner.Scan() {
		var r Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return VerifyResult{FirstBadSeq: int64(idx + 1), Reason: "unparseable line"}, nil
		}
		row := rows[idx]
		if row.Seq != r.Seq {
			return VerifyResult{
				RecordsChecked: int64(idx),
				FirstBadSeq:    r.Seq,
				Reason:         fmt.Sprintf("db seq %d != file seq %d", row.Seq, r.Seq),
			}, nil
		}
		if row.Hash != r.Hash {
			return VerifyResult{
				RecordsChecked: int64(idx),
				FirstBadSeq:    r.Seq,
				Reason:         "db hash diverges from file hash (db tampered or file truncated)",
			}, nil
		}
		idx++
	}
	if err := scanner.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("audit verify: scan: %w", err)
	}
	return res, nil
}

// Verify walks path top-to-bottom, checking the chain hash and (if pub is
// non-nil) the ed25519 signature on each record. Stops at the first failure.
// Does not consult the SQLite mirror — use VerifyWithMirror for that.
func Verify(path string, pub ed25519.PublicKey) (VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit verify: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	prev := genesisHashHex
	var seq int64
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<24)
	for scanner.Scan() {
		var r Record
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return VerifyResult{FirstBadSeq: seq + 1, Reason: "unparseable line"}, nil
		}
		if r.Seq != seq+1 {
			return VerifyResult{FirstBadSeq: r.Seq, Reason: "non-monotonic seq"}, nil
		}
		if r.PrevHash != prev {
			return VerifyResult{FirstBadSeq: r.Seq, Reason: "prev_hash mismatch"}, nil
		}
		want, err := computeHash(r)
		if err != nil {
			return VerifyResult{FirstBadSeq: r.Seq, Reason: err.Error()}, nil
		}
		if want != r.Hash {
			return VerifyResult{FirstBadSeq: r.Seq, Reason: "hash mismatch"}, nil
		}
		if pub != nil {
			hb, err := hex.DecodeString(r.Hash)
			if err != nil {
				return VerifyResult{FirstBadSeq: r.Seq, Reason: "decode hash"}, nil
			}
			sig, err := base64.StdEncoding.DecodeString(r.Signature)
			if err != nil {
				return VerifyResult{FirstBadSeq: r.Seq, Reason: "decode signature"}, nil
			}
			if !ed25519.Verify(pub, hb, sig) {
				return VerifyResult{FirstBadSeq: r.Seq, Reason: "bad signature"}, nil
			}
		}
		prev = r.Hash
		seq = r.Seq
	}
	if err := scanner.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("audit verify: scan: %w", err)
	}
	return VerifyResult{OK: true, RecordsChecked: seq}, nil
}

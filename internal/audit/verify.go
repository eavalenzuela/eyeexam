package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// VerifyResult captures the outcome of a full-log verification.
type VerifyResult struct {
	OK             bool
	RecordsChecked int64
	FirstBadSeq    int64 // 0 when OK
	Reason         string
}

// Verify walks path top-to-bottom, checking the chain hash and (if pub is
// non-nil) the ed25519 signature on each record. Stops at the first failure.
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

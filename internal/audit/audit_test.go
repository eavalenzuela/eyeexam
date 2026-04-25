package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestAppendAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	pub, priv := newKey(t)

	l, err := Open(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{OSUser: "alice", OSUID: 1000}

	for i := 0; i < 5; i++ {
		_, err := l.Append(context.Background(), Record{
			Actor:   actor,
			Event:   "test_event",
			Payload: json.RawMessage(`{"i":` + itoa(i) + `}`),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	_ = l.Close()

	res, err := Verify(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("verify failed: bad seq=%d reason=%s", res.FirstBadSeq, res.Reason)
	}
	if res.RecordsChecked != 5 {
		t.Fatalf("expected 5 records, got %d", res.RecordsChecked)
	}
}

func TestTamperDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	pub, priv := newKey(t)
	l, err := Open(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{OSUser: "alice", OSUID: 1000}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(context.Background(), Record{
			Actor: actor, Event: "ev", Payload: json.RawMessage(`{}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()

	// Corrupt a byte in the middle of the file.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// flip a payload character on line 2
	idx := -1
	lines := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			lines++
			if lines == 1 {
				idx = i + 20
				break
			}
		}
	}
	if idx < 0 || idx >= len(b) {
		t.Fatal("could not find tamper point")
	}
	b[idx] ^= 0x20
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("expected verify to fail after tamper")
	}
}

func TestResumeChainsCorrectly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	pub, priv := newKey(t)

	l, err := Open(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(context.Background(), Record{
		Actor: Actor{OSUser: "u", OSUID: 1}, Event: "a", Payload: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	l2, err := Open(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := l2.Append(context.Background(), Record{
		Actor: Actor{OSUser: "u", OSUID: 1}, Event: "b", Payload: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Close()
	if r.Seq != 2 {
		t.Fatalf("expected seq=2 after resume, got %d", r.Seq)
	}
	res, err := Verify(path, pub)
	if err != nil || !res.OK {
		t.Fatalf("verify after resume failed: %+v err=%v", res, err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

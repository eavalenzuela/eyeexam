package signature

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

// build returns a signed pack fsys backed by the given file map plus a
// trusted public key. The map's keys are pack-relative paths; values
// are the file bytes. MANIFEST and MANIFEST.sig are computed and added
// to the returned fsys.
func build(t *testing.T, files map[string]string, packName string) (fstest.MapFS, ed25519.PublicKey) {
	t.Helper()
	fsys := fstest.MapFS{}
	for p, b := range files {
		fsys[p] = &fstest.MapFile{Data: []byte(b)}
	}
	m, err := BuildManifest(fsys, packName)
	if err != nil {
		t.Fatal(err)
	}
	manifest := m.Canonical()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, manifest)
	fsys[ManifestFile] = &fstest.MapFile{Data: manifest}
	fsys[ManifestSigFile] = &fstest.MapFile{Data: sig}
	return fsys, pub
}

func TestVerifyPackHappyPath(t *testing.T) {
	fsys, pub := build(t, map[string]string{
		"eye-001.yaml":              "id: eye-001\n",
		"eye-002.yaml":              "id: eye-002\n",
		"expectations/eye-001.yaml": "sigma_id: rule-1\n",
	}, "test-pack")
	if err := VerifyPack(fsys, []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyPackRejectsTamperedFile(t *testing.T) {
	fsys, pub := build(t, map[string]string{
		"eye-001.yaml": "id: eye-001\n",
	}, "test-pack")
	// Tamper a covered file; manifest sha256 won't match.
	fsys["eye-001.yaml"] = &fstest.MapFile{Data: []byte("id: eye-001-EVIL\n")}
	err := VerifyPack(fsys, []ed25519.PublicKey{pub})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch, got %v", err)
	}
}

func TestVerifyPackRejectsSmuggledFile(t *testing.T) {
	fsys, pub := build(t, map[string]string{
		"eye-001.yaml": "id: eye-001\n",
	}, "test-pack")
	// Add a yaml file after signing — it isn't in the manifest.
	fsys["eye-002.yaml"] = &fstest.MapFile{Data: []byte("id: eye-002\n")}
	err := VerifyPack(fsys, []ed25519.PublicKey{pub})
	if err == nil || !strings.Contains(err.Error(), "undeclared file") {
		t.Fatalf("expected undeclared file rejection, got %v", err)
	}
}

func TestVerifyPackRejectsMissingFile(t *testing.T) {
	fsys, pub := build(t, map[string]string{
		"eye-001.yaml": "id: eye-001\n",
		"eye-002.yaml": "id: eye-002\n",
	}, "test-pack")
	delete(fsys, "eye-002.yaml")
	err := VerifyPack(fsys, []ed25519.PublicKey{pub})
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected missing-file rejection, got %v", err)
	}
}

func TestVerifyPackRejectsBadSignature(t *testing.T) {
	fsys, _ := build(t, map[string]string{
		"eye-001.yaml": "id: eye-001\n",
	}, "test-pack")
	// Use a different key than the one that signed.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	err := VerifyPack(fsys, []ed25519.PublicKey{otherPub})
	if !errors.Is(err, ErrNoTrustedKey) {
		t.Fatalf("expected ErrNoTrustedKey, got %v", err)
	}
}

func TestVerifyPackTriesAllTrustedKeys(t *testing.T) {
	fsys, pub := build(t, map[string]string{
		"eye-001.yaml": "id: eye-001\n",
	}, "test-pack")
	// pub is the real signer; put it second among trusted keys to
	// ensure the loop tries multiple before giving up.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyPack(fsys, []ed25519.PublicKey{otherPub, pub}); err != nil {
		t.Fatalf("verify with multi-key: %v", err)
	}
}

func TestVerifyPackEmptyTrustedKeys(t *testing.T) {
	fsys, _ := build(t, map[string]string{
		"eye-001.yaml": "id: eye-001\n",
	}, "test-pack")
	err := VerifyPack(fsys, nil)
	if err == nil || !strings.Contains(err.Error(), "no trusted keys") {
		t.Fatalf("expected empty-trust rejection, got %v", err)
	}
}

func TestParseManifestRoundTrip(t *testing.T) {
	original, _ := build(t, map[string]string{
		"a.yaml": "x", "b.yaml": "y", "expectations/c.yaml": "z",
	}, "rt-pack")
	mb, _ := original.ReadFile(ManifestFile)
	parsed, err := ParseManifest(mb)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Pack != "rt-pack" {
		t.Errorf("pack=%q", parsed.Pack)
	}
	if len(parsed.Files) != 3 {
		t.Errorf("files=%d, want 3", len(parsed.Files))
	}
	// Canonical should round-trip byte-for-byte.
	if string(parsed.Canonical()) != string(mb) {
		t.Errorf("Canonical didn't round-trip:\norig:\n%s\nrt:\n%s", mb, parsed.Canonical())
	}
}

func TestParseManifestRejectsOutOfOrder(t *testing.T) {
	bad := []byte(`version: 1
pack: x
created: 2026-01-01T00:00:00Z
files:
  b.yaml  sha256:` + strings.Repeat("0", 64) + `
  a.yaml  sha256:` + strings.Repeat("0", 64) + `
`)
	_, err := ParseManifest(bad)
	if err == nil || !strings.Contains(err.Error(), "out of order") {
		t.Fatalf("expected out-of-order rejection, got %v", err)
	}
}

func TestParseManifestRejectsBadVersion(t *testing.T) {
	bad := []byte("version: 99\npack: x\ncreated: 2026-01-01T00:00:00Z\nfiles:\n")
	_, err := ParseManifest(bad)
	if err == nil || !strings.Contains(err.Error(), "unsupported version") {
		t.Fatalf("expected version rejection, got %v", err)
	}
}

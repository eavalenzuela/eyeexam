package pack

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/eavalenzuela/eyeexam/internal/pack/signature"
)

// signPack writes a MANIFEST + MANIFEST.sig into dir for the given
// pack name, signed with priv. Round-trips through BuildManifest +
// Canonical so the on-disk artifacts match what the verifier reads.
func signPack(t *testing.T, dir, name string, priv ed25519.PrivateKey) {
	t.Helper()
	m, err := signature.BuildManifest(os.DirFS(dir), name)
	if err != nil {
		t.Fatal(err)
	}
	manifest := m.Canonical()
	sig := ed25519.Sign(priv, manifest)
	if err := os.WriteFile(filepath.Join(dir, signature.ManifestFile), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, signature.ManifestSigFile), sig, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAddNativeSignedAcceptsValidSignature(t *testing.T) {
	dir := writePack(t, map[string]string{"a.yaml": validNative})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signPack(t, dir, "p", priv)

	r := NewRegistry(nil)
	if err := r.AddNativeSigned("p", dir, []ed25519.PublicKey{pub}); err != nil {
		t.Fatalf("signed add: %v", err)
	}
	if len(r.All()) != 1 {
		t.Errorf("expected 1 test loaded, got %d", len(r.All()))
	}
}

func TestAddNativeSignedRejectsTamperPostSign(t *testing.T) {
	dir := writePack(t, map[string]string{"a.yaml": validNative})
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signPack(t, dir, "p", priv)

	// Tamper the YAML after signing.
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(validNative+"\n# evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := NewRegistry(nil)
	err := r.AddNativeSigned("p", dir, []ed25519.PublicKey{pub})
	if err == nil {
		t.Fatal("expected post-sign tamper to be rejected")
	}
}

func TestAddNativeSignedRejectsUnknownKey(t *testing.T) {
	dir := writePack(t, map[string]string{"a.yaml": validNative})
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signPack(t, dir, "p", priv)

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	r := NewRegistry(nil)
	err := r.AddNativeSigned("p", dir, []ed25519.PublicKey{otherPub})
	if !errors.Is(err, signature.ErrNoTrustedKey) {
		t.Fatalf("expected ErrNoTrustedKey, got %v", err)
	}
}

func TestAddNativeSignedRejectsMissingManifest(t *testing.T) {
	dir := writePack(t, map[string]string{"a.yaml": validNative})
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Don't sign — no MANIFEST exists.
	r := NewRegistry(nil)
	if err := r.AddNativeSigned("p", dir, []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("expected unsigned pack to be rejected")
	}
}

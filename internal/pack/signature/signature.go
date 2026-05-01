// Package signature implements eyeexam's pack-signing wire format.
//
// A signed pack ships two files alongside its YAML tests:
//
//   - MANIFEST  — a deterministic text record of every pack file
//     with its sha256, signable as plain bytes.
//   - MANIFEST.sig — an ed25519 signature over MANIFEST bytes.
//
// Verification (VerifyPack) checks three things, in order:
//
//  1. The signature in MANIFEST.sig is valid for the bytes of
//     MANIFEST under at least one trusted public key.
//  2. Every file path listed in MANIFEST exists in the pack
//     filesystem with a matching sha256.
//  3. No *.yaml file exists in the pack filesystem that isn't
//     listed in MANIFEST (no smuggled tests).
//
// MANIFEST and MANIFEST.sig themselves are excluded from both
// directions of the comparison. The embedded builtin pack does
// not pass through this code path — its trust boundary is the
// binary, not a disk file.
package signature

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	ManifestFile    = "MANIFEST"
	ManifestSigFile = "MANIFEST.sig"
	ManifestVersion = 1
)

// FileEntry is one row in a manifest: relative slash-separated path
// inside the pack, with the sha256 of the file's bytes (hex-encoded).
type FileEntry struct {
	Path   string
	SHA256 string
}

// Manifest is the parsed form of a MANIFEST file.
type Manifest struct {
	Version int
	Pack    string
	Created time.Time
	Signer  string // optional human-readable label, e.g. "eyeexam-attackpacks-2026-key1"
	Files   []FileEntry
}

// ErrNoTrustedKey is returned when MANIFEST.sig didn't verify against
// any of the supplied public keys. Callers may surface this distinctly
// from "manifest invalid" / "file content drift".
var ErrNoTrustedKey = errors.New("signature: MANIFEST.sig did not verify against any trusted key")

// BuildManifest walks fsys for *.yaml files and produces a Manifest
// covering them. MANIFEST and MANIFEST.sig themselves are skipped if
// already present (so a pack author can re-sign in place).
func BuildManifest(fsys fs.FS, packName string) (*Manifest, error) {
	var files []FileEntry
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if p == ManifestFile || p == ManifestSigFile {
			return nil
		}
		ext := strings.ToLower(path.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}
		sum := sha256.Sum256(b)
		files = append(files, FileEntry{Path: p, SHA256: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return &Manifest{
		Version: ManifestVersion,
		Pack:    packName,
		Created: time.Now().UTC(),
		Files:   files,
	}, nil
}

// Canonical returns the bytes of the manifest in a stable text form
// suitable for both human inspection (cat MANIFEST) and signing.
//
//	version: 1
//	pack: <name>
//	created: <RFC3339Nano UTC>
//	signer: <label>          # optional, omitted when empty
//	files:
//	  <path>  sha256:<hex>
//	  <path>  sha256:<hex>
//
// The trailing newline after the last file row is included so signers
// using `openssl pkeyutl -sign -in MANIFEST` produce the same bytes
// the verifier hashes.
func (m *Manifest) Canonical() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "version: %d\n", m.Version)
	fmt.Fprintf(&b, "pack: %s\n", m.Pack)
	fmt.Fprintf(&b, "created: %s\n", m.Created.UTC().Format(time.RFC3339Nano))
	if m.Signer != "" {
		fmt.Fprintf(&b, "signer: %s\n", m.Signer)
	}
	b.WriteString("files:\n")
	for _, f := range m.Files {
		fmt.Fprintf(&b, "  %s  sha256:%s\n", f.Path, f.SHA256)
	}
	return b.Bytes()
}

// ParseManifest reads a MANIFEST text blob into a Manifest. Strict —
// rejects unknown lines and out-of-order files (so signers can't
// produce two manifests with identical signatures but different
// rendered content).
func ParseManifest(b []byte) (*Manifest, error) {
	m := &Manifest{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	inFiles := false
	for sc.Scan() {
		line := sc.Text()
		if inFiles {
			if !strings.HasPrefix(line, "  ") {
				return nil, fmt.Errorf("manifest: file row missing two-space indent: %q", line)
			}
			row := strings.TrimPrefix(line, "  ")
			parts := strings.SplitN(row, "  sha256:", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("manifest: malformed file row: %q", line)
			}
			f := FileEntry{Path: parts[0], SHA256: parts[1]}
			if len(f.SHA256) != 64 {
				return nil, fmt.Errorf("manifest: bad sha256 length on %q", f.Path)
			}
			if len(m.Files) > 0 && m.Files[len(m.Files)-1].Path >= f.Path {
				return nil, fmt.Errorf("manifest: files out of order at %q", f.Path)
			}
			m.Files = append(m.Files, f)
			continue
		}
		switch {
		case strings.HasPrefix(line, "version: "):
			n, err := parseInt(strings.TrimPrefix(line, "version: "))
			if err != nil {
				return nil, fmt.Errorf("manifest: version: %w", err)
			}
			m.Version = n
		case strings.HasPrefix(line, "pack: "):
			m.Pack = strings.TrimPrefix(line, "pack: ")
		case strings.HasPrefix(line, "created: "):
			t, err := time.Parse(time.RFC3339Nano, strings.TrimPrefix(line, "created: "))
			if err != nil {
				return nil, fmt.Errorf("manifest: created: %w", err)
			}
			m.Created = t
		case strings.HasPrefix(line, "signer: "):
			m.Signer = strings.TrimPrefix(line, "signer: ")
		case line == "files:":
			inFiles = true
		default:
			return nil, fmt.Errorf("manifest: unrecognized line: %q", line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("manifest: scan: %w", err)
	}
	if m.Version != ManifestVersion {
		return nil, fmt.Errorf("manifest: unsupported version %d (want %d)", m.Version, ManifestVersion)
	}
	if m.Pack == "" {
		return nil, errors.New("manifest: missing pack name")
	}
	return m, nil
}

// VerifyPack runs the full three-step check against fsys.
//
// fsys should be rooted at the pack root and include MANIFEST,
// MANIFEST.sig, and every test YAML. Sig is verified against any
// element of pubs; if none match, ErrNoTrustedKey is returned.
func VerifyPack(fsys fs.FS, pubs []ed25519.PublicKey) error {
	if len(pubs) == 0 {
		return errors.New("signature: no trusted keys provided")
	}
	manifestBytes, err := fs.ReadFile(fsys, ManifestFile)
	if err != nil {
		return fmt.Errorf("read MANIFEST: %w", err)
	}
	sigBytes, err := fs.ReadFile(fsys, ManifestSigFile)
	if err != nil {
		return fmt.Errorf("read MANIFEST.sig: %w", err)
	}

	verified := false
	for _, pub := range pubs {
		if ed25519.Verify(pub, manifestBytes, sigBytes) {
			verified = true
			break
		}
	}
	if !verified {
		return ErrNoTrustedKey
	}

	m, err := ParseManifest(manifestBytes)
	if err != nil {
		return err
	}

	// Step 2: every manifest entry exists with matching sha256.
	declared := make(map[string]string, len(m.Files))
	for _, f := range m.Files {
		b, err := fs.ReadFile(fsys, f.Path)
		if err != nil {
			return fmt.Errorf("declared file %q missing: %w", f.Path, err)
		}
		sum := sha256.Sum256(b)
		got := hex.EncodeToString(sum[:])
		if got != f.SHA256 {
			return fmt.Errorf("declared file %q sha256 mismatch (have %s, want %s)",
				f.Path, got, f.SHA256)
		}
		declared[f.Path] = f.SHA256
	}

	// Step 3: no smuggled *.yaml files.
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if p == ManifestFile || p == ManifestSigFile {
			return nil
		}
		ext := strings.ToLower(path.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if _, ok := declared[p]; !ok {
			return fmt.Errorf("undeclared file %q (smuggled or signer missed it)", p)
		}
		return nil
	})
	return err
}

func parseInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("bad int %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

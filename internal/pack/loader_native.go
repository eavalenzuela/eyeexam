package pack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadNativeDir walks dir for *.yaml files, parses each as a native Test,
// and returns the list. Validation errors are reported with the file path.
func LoadNativeDir(dir string) ([]Test, error) {
	return LoadNativeFS(os.DirFS(dir))
}

// LoadNativeFS is the fs.FS-backed variant of LoadNativeDir, used for
// the embedded builtin pack. The walk semantics are identical: *.yaml
// files at any depth except under expectations/.
func LoadNativeFS(fsys fs.FS) ([]Test, error) {
	var out []Test
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if strings.HasPrefix(path, "expectations/") {
			return nil
		}
		b, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("pack: read %s: %w", path, err)
		}
		t, err := parseNativeBytes(b, path)
		if err != nil {
			return fmt.Errorf("pack: load %s: %w", path, err)
		}
		out = append(out, t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func loadNativeFile(path string) (Test, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Test{}, err
	}
	return parseNativeBytes(b, path)
}

func parseNativeBytes(b []byte, source string) (Test, error) {
	var t Test
	if err := yaml.Unmarshal(b, &t); err != nil {
		return Test{}, fmt.Errorf("yaml parse %s: %w", source, err)
	}
	t.Source = SourceNative
	sum := sha256.Sum256(b)
	t.YAMLSHA256 = hex.EncodeToString(sum[:])
	if err := ValidateNative(t); err != nil {
		return Test{}, err
	}
	if t.WaitSeconds == 0 {
		t.WaitSeconds = 60
	}
	return t, nil
}

// ValidateNative enforces the eyeexam-native required fields. verify_cleanup
// is REQUIRED on native tests (per IMPLEMENTATION.md §4.6).
func ValidateNative(t Test) error {
	if t.ID == "" {
		return fmt.Errorf("%w: missing id", ErrInvalidTest)
	}
	if t.Name == "" {
		return fmt.Errorf("%w: %s missing name", ErrInvalidTest, t.ID)
	}
	switch t.Destructiveness {
	case DestLow, DestMedium, DestHigh:
	default:
		return fmt.Errorf("%w: %s destructiveness must be low|medium|high (got %q)",
			ErrInvalidTest, t.ID, t.Destructiveness)
	}
	if len(t.Platforms) == 0 {
		return fmt.Errorf("%w: %s missing platforms", ErrInvalidTest, t.ID)
	}
	if len(t.Execute) == 0 {
		return fmt.Errorf("%w: %s missing execute steps", ErrInvalidTest, t.ID)
	}
	for i, s := range t.Execute {
		if s.Shell == "" || s.Command == "" {
			return fmt.Errorf("%w: %s execute[%d] missing shell or command",
				ErrInvalidTest, t.ID, i)
		}
	}
	if len(t.Cleanup) > 0 && len(t.VerifyCleanup) == 0 {
		return fmt.Errorf("%w: %s defines cleanup but no verify_cleanup",
			ErrInvalidTest, t.ID)
	}
	for i, s := range t.VerifyCleanup {
		if s.Shell == "" || s.Command == "" {
			return fmt.Errorf("%w: %s verify_cleanup[%d] missing shell or command",
				ErrInvalidTest, t.ID, i)
		}
	}
	return nil
}

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

// LoadAtomicDir walks an Atomic Red Team clone — typically the
// `atomics/<technique>/<technique>.yaml` layout — and returns one
// pack.Test per atomic_test, normalized to the eyeexam internal model.
//
// Skipped tests (platform mismatch, PowerShell-only on Linux, missing
// executor) are returned as the second slice with reason strings, so the
// CLI plan view can show them without polluting the executable set.
//
// Per IMPLEMENTATION.md: eyeexam never vendors Atomic Red Team into its
// own tree. The operator clones redcanaryco/atomic-red-team somewhere
// they manage and points eyeexam at it via `eyeexam pack add atomic <path>
// --source atomic`.
func LoadAtomicDir(dir string) (tests []Test, skipped []SkippedTest, err error) {
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		// Atomic conventionally lives in atomics/<technique>/<technique>.yaml.
		// We accept any *.yaml under dir but filter the well-known
		// expectations sidecar directory.
		rel, _ := filepath.Rel(dir, path)
		if strings.HasPrefix(rel, "expectations"+string(filepath.Separator)) ||
			strings.HasPrefix(rel, "expectations/") {
			return nil
		}
		ts, sk, perr := loadAtomicFile(dir, path)
		if perr != nil {
			return fmt.Errorf("pack atomic: load %s: %w", path, perr)
		}
		tests = append(tests, ts...)
		skipped = append(skipped, sk...)
		return nil
	})
	if walkErr != nil {
		return nil, nil, walkErr
	}
	return tests, skipped, nil
}

// SkippedTest reports a single Atomic test that the loader chose not to
// expose. ID is the eyeexam-internal id we would have assigned.
type SkippedTest struct {
	ID     string
	Reason string
}

// atomicFile is the on-disk shape of one Atomic Red Team YAML file.
type atomicFile struct {
	AttackTechnique string       `yaml:"attack_technique"`
	DisplayName     string       `yaml:"display_name"`
	AtomicTests     []atomicTest `yaml:"atomic_tests"`
}

type atomicTest struct {
	Name           string                         `yaml:"name"`
	GUID           string                         `yaml:"auto_generated_guid"`
	Description    string                         `yaml:"description"`
	SupportedPlats []string                       `yaml:"supported_platforms"`
	InputArguments map[string]atomicInputArgument `yaml:"input_arguments"`
	Executor       atomicExecutor                 `yaml:"executor"`
}

type atomicInputArgument struct {
	Description string `yaml:"description"`
	Type        string `yaml:"type"`
	Default     any    `yaml:"default"`
}

type atomicExecutor struct {
	Name              string `yaml:"name"`
	Command           string `yaml:"command"`
	CleanupCommand    string `yaml:"cleanup_command"`
	ElevationRequired bool   `yaml:"elevation_required"`
}

func loadAtomicFile(packRoot, path string) ([]Test, []SkippedTest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f atomicFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, nil, fmt.Errorf("yaml parse: %w", err)
	}
	if f.AttackTechnique == "" || len(f.AtomicTests) == 0 {
		// Not an Atomic file (could be a stray YAML in the clone) — skip
		// silently. Loader's job is to tolerate the live repo layout.
		return nil, nil, nil
	}
	sum := sha256.Sum256(b)
	yamlHash := hex.EncodeToString(sum[:])

	var tests []Test
	var skipped []SkippedTest
	for i, at := range f.AtomicTests {
		id := atomicTestID(f.AttackTechnique, i+1)

		shell, ok := executorShellFor(at.Executor.Name)
		if !ok {
			skipped = append(skipped, SkippedTest{
				ID:     id,
				Reason: fmt.Sprintf("executor %q not supported on this platform", at.Executor.Name),
			})
			continue
		}
		platforms := normalizePlatforms(at.SupportedPlats)

		t := Test{
			ID:              id,
			Source:          SourceAtomic,
			YAMLSHA256:      yamlHash,
			Name:            at.Name,
			Description:     at.Description,
			Attack:          AttackRef{Technique: f.AttackTechnique},
			Destructiveness: DestMedium, // sane Atomic default; sidecar can override
			Platforms:       platforms,
			Inputs:          inputsFromAtomic(at.InputArguments),
			Execute: []Step{{
				Shell:   shell,
				Command: at.Executor.Command,
			}},
		}
		if at.Executor.CleanupCommand != "" {
			t.Cleanup = []Step{{Shell: shell, Command: at.Executor.CleanupCommand}}
			// Atomic format does not carry verify_cleanup; runlife marks
			// the verify state as warned_atomic per PLAN.md §"Cleanup
			// verification".
		}

		// Apply sidecar (expectations + optional destructiveness override).
		if sc, err := LoadSidecar(packRoot, id); err != nil {
			return nil, nil, err
		} else if sc != nil {
			if len(sc.Expectations) > 0 {
				t.Expectations = sc.Expectations
			}
			if sc.WaitSeconds > 0 {
				t.WaitSeconds = sc.WaitSeconds
			}
			if sc.Destructiveness != "" {
				t.Destructiveness = sc.Destructiveness
			}
		}
		if t.WaitSeconds == 0 {
			t.WaitSeconds = 60
		}

		tests = append(tests, t)
	}
	return tests, skipped, nil
}

// atomicTestID returns the eyeexam-internal id for the i-th atomic_test
// (1-indexed) of a given technique. We deliberately use a stable scheme
// so sidecar files can be authored against a known path.
func atomicTestID(technique string, index int) string {
	return fmt.Sprintf("atomic-%s-%d", technique, index)
}

// executorShellFor returns the eyeexam shell name for an Atomic executor,
// and whether it is supported on the runner host. PowerShell is supported
// only when `pwsh` is on PATH; Linux runs without `pwsh` skip the test.
func executorShellFor(executor string) (string, bool) {
	switch strings.ToLower(executor) {
	case "bash":
		return "bash", true
	case "sh":
		return "sh", true
	case "command_prompt":
		return "", false // windows-only; M4 stays linux-first per PLAN.md "Still open"
	case "powershell":
		// PowerShell on Linux works via `pwsh` but is an extra runtime
		// dependency. Skip with a clear marker — IMPLEMENTATION.md §8.2.
		return "", false
	case "manual":
		return "", false
	default:
		return "", false
	}
}

func normalizePlatforms(in []string) []string {
	if len(in) == 0 {
		return []string{"linux"}
	}
	out := make([]string, 0, len(in))
	for _, p := range in {
		switch strings.ToLower(p) {
		case "linux":
			out = append(out, "linux")
		case "macos":
			out = append(out, "darwin")
		case "windows":
			out = append(out, "windows")
		default:
			// preserve unknowns so the planner can still skip cleanly
			out = append(out, strings.ToLower(p))
		}
	}
	return out
}

func inputsFromAtomic(in map[string]atomicInputArgument) map[string]InputSpec {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]InputSpec, len(in))
	for k, v := range in {
		def := ""
		switch d := v.Default.(type) {
		case string:
			def = d
		case nil:
			def = ""
		default:
			def = fmt.Sprintf("%v", d)
		}
		out[k] = InputSpec{Type: v.Type, Default: def}
	}
	return out
}

package pack

import (
	"os"
	"path/filepath"
	"testing"
)

const validNative = `id: eye-test-001
name: Touch a tmp file
description: Smoke test
attack:
  technique: T1059.004
  tactic: TA0002
destructiveness: low
platforms: [linux]
execute:
  - shell: bash
    command: |
      touch /tmp/eyeexam-test
cleanup:
  - shell: bash
    command: |
      rm -f /tmp/eyeexam-test
verify_cleanup:
  - shell: bash
    command: |
      test ! -f /tmp/eyeexam-test
`

func writePack(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadNativeValid(t *testing.T) {
	dir := writePack(t, map[string]string{"a.yaml": validNative})
	tests, err := LoadNativeDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) != 1 || tests[0].ID != "eye-test-001" {
		t.Fatalf("got %+v", tests)
	}
	if tests[0].YAMLSHA256 == "" {
		t.Fatal("expected sha256 set")
	}
	if tests[0].WaitSeconds != 60 {
		t.Fatalf("expected default wait_seconds=60, got %d", tests[0].WaitSeconds)
	}
}

func TestLoadNativeRejectsMissingVerify(t *testing.T) {
	bad := `id: bad
name: bad
attack: {technique: T0, tactic: T0}
destructiveness: low
platforms: [linux]
execute:
  - shell: bash
    command: "echo hi"
cleanup:
  - shell: bash
    command: "echo cleanup"
`
	dir := writePack(t, map[string]string{"b.yaml": bad})
	_, err := LoadNativeDir(dir)
	if err == nil {
		t.Fatal("expected error for missing verify_cleanup")
	}
}

func TestRegistryDuplicateRejected(t *testing.T) {
	dir1 := writePack(t, map[string]string{"a.yaml": validNative})
	dir2 := writePack(t, map[string]string{"b.yaml": validNative})
	r := NewRegistry(nil)
	if err := r.AddNative("p1", dir1); err != nil {
		t.Fatal(err)
	}
	if err := r.AddNative("p2", dir2); err == nil {
		t.Fatal("expected duplicate-id rejection")
	}
}

func TestDestRanking(t *testing.T) {
	if !DestLow.AtMost(DestHigh) {
		t.Fatal("low <= high")
	}
	if DestHigh.AtMost(DestLow) {
		t.Fatal("high should not be <= low")
	}
}

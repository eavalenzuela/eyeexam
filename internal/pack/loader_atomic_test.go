package pack

import (
	"path/filepath"
	"testing"
)

func atomicFixturePath(t *testing.T) string {
	t.Helper()
	// resolve repo root from test cwd (internal/pack/)
	wd, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for d := wd; d != "/"; d = filepath.Dir(d) {
		probe := filepath.Join(d, "tests", "fixtures", "packs", "atomic")
		if isDir(probe) {
			return probe
		}
	}
	t.Fatal("atomic fixture dir not found from cwd")
	return ""
}

func isDir(p string) bool {
	if p == "" {
		return false
	}
	// avoid extra import; rely on os via a tiny helper
	return statIsDir(p)
}

func TestLoadAtomicHappyPath(t *testing.T) {
	root := atomicFixturePath(t)
	tests, skipped, err := LoadAtomicDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) != 1 {
		t.Fatalf("expected 1 loadable test, got %d (%+v)", len(tests), tests)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected 1 skipped test, got %d (%+v)", len(skipped), skipped)
	}
	tt := tests[0]
	if tt.ID != "atomic-T1059.004-1" {
		t.Fatalf("id=%s", tt.ID)
	}
	if tt.Source != SourceAtomic {
		t.Fatalf("source=%s", tt.Source)
	}
	// Sidecar override applied
	if tt.Destructiveness != DestLow {
		t.Fatalf("dest=%s, expected sidecar-applied low", tt.Destructiveness)
	}
	if tt.WaitSeconds != 5 {
		t.Fatalf("wait=%d, expected sidecar 5", tt.WaitSeconds)
	}
	if len(tt.Expectations) != 2 {
		t.Fatalf("expectations=%d, expected 2 from sidecar", len(tt.Expectations))
	}
	if tt.Attack.Technique != "T1059.004" {
		t.Fatalf("technique=%s", tt.Attack.Technique)
	}
	if len(tt.Cleanup) == 0 {
		t.Fatal("expected cleanup populated from atomic cleanup_command")
	}
}

func TestAtomicSkipsPowershell(t *testing.T) {
	root := atomicFixturePath(t)
	_, skipped, err := LoadAtomicDir(root)
	if err != nil {
		t.Fatal(err)
	}
	want := "atomic-T1059.004-2"
	found := false
	for _, s := range skipped {
		if s.ID == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected powershell-only test %s in skipped list, got %+v", want, skipped)
	}
}

func TestRefuserBlocksAtomicID(t *testing.T) {
	r := NewRefuser(nil)
	if !r.Refused("atomic-T1556.001-1") {
		t.Fatal("Skeleton Key atomic should be on the refuse list")
	}
	if !r.Refused("atomic-T1562.001-1") {
		t.Fatal("EDR-disable atomic should be on the refuse list")
	}
	if r.Refused("atomic-T1059.004-1") {
		t.Fatal("benign atomic should not be refused")
	}
}

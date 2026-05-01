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
	// Both the bash test and the powershell test load; pwsh availability
	// is checked at execute time (host-level skip), not at load time.
	if len(tests) != 2 {
		t.Fatalf("expected 2 loadable tests, got %d (%+v)", len(tests), tests)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected 0 skipped tests, got %d (%+v)", len(skipped), skipped)
	}
	var tt Test
	for _, c := range tests {
		if c.ID == "atomic-T1059.004-1" {
			tt = c
			break
		}
	}
	if tt.ID != "atomic-T1059.004-1" {
		t.Fatalf("missing atomic-T1059.004-1 in loaded tests")
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

func TestAtomicLoadsPowershellTest(t *testing.T) {
	// Previously: PS-only tests were skipped at load time. Now: they
	// load with shell="powershell" and the runtime check decides per
	// host. This guards against re-introducing the load-time skip.
	root := atomicFixturePath(t)
	tests, _, err := LoadAtomicDir(root)
	if err != nil {
		t.Fatal(err)
	}
	want := "atomic-T1059.004-2"
	for _, c := range tests {
		if c.ID == want {
			if len(c.Execute) == 0 || c.Execute[0].Shell != "powershell" {
				t.Fatalf("PS test %s loaded but Execute[0].Shell=%q (want \"powershell\")",
					want, c.Execute[0].Shell)
			}
			return
		}
	}
	t.Fatalf("expected PS-only test %s to be loaded, but not found", want)
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

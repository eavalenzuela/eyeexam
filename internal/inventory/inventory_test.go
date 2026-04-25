package inventory

import (
	"testing"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

func sample() *Inventory {
	return &Inventory{
		Hosts: []Host{
			{Name: "web-01", Transport: "ssh", Tags: []string{"linux", "web", "prod"}},
			{Name: "build-01", Transport: "ssh", Tags: []string{"linux", "build"}},
			{Name: "win-01", Transport: "ssh", Tags: []string{"windows", "build"}},
		},
		Tags: map[string]TagPolicy{
			"prod": {MaxDestructiveness: pack.DestLow},
		},
	}
}

func TestSelectByTag(t *testing.T) {
	inv := sample()
	got, warns, err := inv.Apply(Selector{Tags: []string{"linux"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 linux hosts, got %d", len(got))
	}
}

func TestSelectByNotTag(t *testing.T) {
	inv := sample()
	got, _, _ := inv.Apply(Selector{Tags: []string{"linux"}, NotTags: []string{"prod"}})
	if len(got) != 1 || got[0].Name != "build-01" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestUnknownHostWarns(t *testing.T) {
	inv := sample()
	_, warns, _ := inv.Apply(Selector{Hosts: []string{"ghost-01"}})
	if len(warns) == 0 {
		t.Fatal("expected warning for unknown host")
	}
}

func TestCapForHostUsesLowest(t *testing.T) {
	inv := sample()
	prodHost := inv.Hosts[0]
	cap := inv.CapForHost(prodHost)
	if cap != pack.DestLow {
		t.Fatalf("expected low cap from prod tag, got %s", cap)
	}
}

func TestTestIDGlob(t *testing.T) {
	s := Selector{Tests: []string{"eye-*"}, NotTests: []string{"eye-003-*"}}
	if !s.MatchTestID("eye-001-tmp-touch") {
		t.Fatal("eye-001 should match")
	}
	if s.MatchTestID("eye-003-curl") {
		t.Fatal("eye-003-* should be excluded")
	}
	if s.MatchTestID("atomic-T1059") {
		t.Fatal("non-eye- should not match")
	}
}

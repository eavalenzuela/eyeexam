package attack

import "testing"

func TestEmbeddedFallbackIndexed(t *testing.T) {
	b := EmbeddedFallback()
	if got, ok := b.Index("T1070.003"); !ok || got.Name != "Clear Command History" {
		t.Fatalf("index miss: %+v ok=%v", got, ok)
	}
	if got, ok := b.Index("T1070"); !ok || got.ParentID != "" {
		t.Fatalf("parent miss: %+v ok=%v", got, ok)
	}
	if _, ok := b.Index("T9999"); ok {
		t.Fatal("unknown id should miss")
	}
}

func TestSubtechniques(t *testing.T) {
	b := EmbeddedFallback()
	subs := b.SubtechniquesOf("T1562")
	if len(subs) < 3 {
		t.Fatalf("expected ≥3 T1562 subs, got %d", len(subs))
	}
}

func TestTechniquesForTactic(t *testing.T) {
	b := EmbeddedFallback()
	got := b.TechniquesForTactic("TA0005")
	if len(got) == 0 {
		t.Fatal("expected at least one Defense Evasion technique")
	}
	for _, x := range got {
		if x.ParentID != "" {
			t.Fatalf("expected only parent techniques, got %s (parent=%s)", x.ID, x.ParentID)
		}
	}
}

func TestParentOf(t *testing.T) {
	if ParentOf("T1059.004") != "T1059" {
		t.Fatal("parent of subtechnique")
	}
	if ParentOf("T1059") != "T1059" {
		t.Fatal("parent of parent should be self")
	}
}

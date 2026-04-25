package matrix

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/attack"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// seedExecution inserts an engagement, run, host, and one execution.
func seedExecution(t *testing.T, st *store.Store, runID, hostName, technique, state string, when time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := st.UpsertEngagement(ctx, store.Engagement{ID: "ENG", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertHost(ctx, store.Host{ID: "h-" + hostName, Name: hostName, InventoryJSON: "{}"}); err != nil {
		t.Fatal(err)
	}
	r, err := st.GetRun(ctx, runID)
	if err != nil || r.ID == "" {
		_ = st.InsertRun(ctx, store.Run{
			ID: runID, EngagementID: "ENG", Seed: 0, MaxDest: "low",
			SelectorJSON: "{}", PlanJSON: "{}", Phase: "reported", AuthorizedBy: "tester",
		})
	}
	ex := store.Execution{
		ID:                 "x-" + runID + "-" + technique,
		RunID:              runID,
		HostID:             "h-" + hostName,
		TestID:             "fixture-" + technique,
		TestSource:         "native",
		TestYAMLSHA256:     "deadbeef",
		Destructiveness:    "low",
		Runner:             "local",
		StartedAt:          when.UTC().Format(time.RFC3339Nano),
		CleanupState:       "succeeded",
		CleanupVerifyState: "succeeded",
		DetectionState:     state,
	}
	ex.AttackTechnique.String = technique
	ex.AttackTechnique.Valid = true
	if err := st.InsertExecution(ctx, ex); err != nil {
		t.Fatal(err)
	}
}

func TestBuildMatrixCellStates(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	now := time.Now().UTC()
	since := now.Add(-7 * 24 * time.Hour)

	seedExecution(t, st, "r-1", "h1", "T1059.004", "caught", now.Add(-1*time.Hour))
	seedExecution(t, st, "r-2", "h1", "T1070.003", "missed", now.Add(-2*time.Hour))
	seedExecution(t, st, "r-3", "h1", "T1105", "uncertain", now.Add(-3*time.Hour))

	m, err := Build(context.Background(), st, attack.EmbeddedFallback(), since)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]CellState{}
	for _, col := range m.Tactics {
		for _, c := range col.Cells {
			got[c.TechniqueID] = c.State
		}
	}
	cases := []struct {
		id   string
		want CellState
	}{
		{"T1059", StateGreen}, // T1059.004 caught rolls up to T1059
		{"T1070", StateRed},
		{"T1105", StateYellow},
		{"T1003", StateGrey}, // no exec
	}
	for _, c := range cases {
		if got[c.id] != c.want {
			t.Errorf("%s: got %s want %s", c.id, got[c.id], c.want)
		}
	}
}

func TestDriftDetected(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	now := time.Now().UTC()
	priorTime := now.Add(-30 * 24 * time.Hour)
	since := now.Add(-7 * 24 * time.Hour)

	// Old run: T1070.003 was caught.
	seedExecution(t, st, "r-old", "h1", "T1070.003", "caught", priorTime)
	// New run inside the window: T1070.003 missed.
	seedExecution(t, st, "r-new", "h1", "T1070.003", "missed", now.Add(-1*time.Hour))

	m, err := Build(context.Background(), st, attack.EmbeddedFallback(), since)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Drift) == 0 {
		t.Fatal("expected at least one drift entry")
	}
	if m.Drift[0].TechniqueID != "T1070" || m.Drift[0].From != StateGreen || m.Drift[0].To != StateRed {
		t.Fatalf("drift entry %+v", m.Drift[0])
	}
}

func TestRenderHTMLContainsCells(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	seedExecution(t, st, "r-1", "h1", "T1059.004", "caught", time.Now().UTC())
	m, err := Build(context.Background(), st, attack.EmbeddedFallback(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := m.RenderHTML(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ATT&amp;CK coverage matrix") {
		t.Fatal("html missing title")
	}
	if !strings.Contains(buf.String(), "T1059") {
		t.Fatal("html missing T1059 cell")
	}
}

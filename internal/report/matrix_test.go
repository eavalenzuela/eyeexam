package report

import (
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

// seedMatrixExec inserts an engagement + run + host + execution. Used
// by the matrix tests as a compact fixture builder.
func seedMatrixExec(t *testing.T, st *store.Store, runID, hostName, technique, state string, when time.Time) {
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

	seedMatrixExec(t, st, "r-1", "h1", "T1059.004", "caught", now.Add(-1*time.Hour))
	seedMatrixExec(t, st, "r-2", "h1", "T1070.003", "missed", now.Add(-2*time.Hour))
	seedMatrixExec(t, st, "r-3", "h1", "T1105", "uncertain", now.Add(-3*time.Hour))

	m, err := BuildMatrix(context.Background(), st, attack.EmbeddedFallback(), MatrixRequest{Since: since})
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
		{"T1059", StateGreen},
		{"T1070", StateRed},
		{"T1105", StateYellow},
		{"T1003", StateGrey},
	}
	for _, c := range cases {
		if got[c.id] != c.want {
			t.Errorf("%s: got %s want %s", c.id, got[c.id], c.want)
		}
	}
}

func TestMatrixDriftDetected(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	now := time.Now().UTC()
	priorTime := now.Add(-30 * 24 * time.Hour)
	since := now.Add(-7 * 24 * time.Hour)

	seedMatrixExec(t, st, "r-old", "h1", "T1070.003", "caught", priorTime)
	seedMatrixExec(t, st, "r-new", "h1", "T1070.003", "missed", now.Add(-1*time.Hour))

	m, err := BuildMatrix(context.Background(), st, attack.EmbeddedFallback(), MatrixRequest{Since: since})
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

func TestMatrixEngagementFilter(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	ctx := context.Background()

	if err := st.UpsertEngagement(ctx, store.Engagement{ID: "ENG-A", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertEngagement(ctx, store.Engagement{ID: "ENG-B", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertHost(ctx, store.Host{ID: "h-1", Name: "h1", InventoryJSON: "{}"}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	insertRunWithEng := func(runID, eng string) {
		_ = st.InsertRun(ctx, store.Run{
			ID: runID, EngagementID: eng, Seed: 0, MaxDest: "low",
			SelectorJSON: "{}", PlanJSON: "{}", Phase: "reported", AuthorizedBy: "tester",
		})
	}
	insertRunWithEng("r-A", "ENG-A")
	insertRunWithEng("r-B", "ENG-B")

	mkExec := func(runID, technique, state string) {
		ex := store.Execution{
			ID: "x-" + runID, RunID: runID, HostID: "h-1",
			TestID: "t", TestSource: "native", TestYAMLSHA256: "x",
			Destructiveness: "low", Runner: "local",
			StartedAt:      now.Add(-1 * time.Hour).Format(time.RFC3339Nano),
			DetectionState: state, CleanupState: "succeeded", CleanupVerifyState: "succeeded",
		}
		ex.AttackTechnique.String = technique
		ex.AttackTechnique.Valid = true
		if err := st.InsertExecution(ctx, ex); err != nil {
			t.Fatal(err)
		}
	}
	mkExec("r-A", "T1070.003", "caught")
	mkExec("r-B", "T1070.003", "missed")

	mA, err := BuildMatrix(ctx, st, attack.EmbeddedFallback(), MatrixRequest{
		Engagement: "ENG-A", Since: now.Add(-24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, col := range mA.Tactics {
		for _, c := range col.Cells {
			if c.TechniqueID == "T1070" && c.State != StateGreen {
				t.Errorf("ENG-A T1070 expected green (engagement isolates B's miss), got %s", c.State)
			}
		}
	}
}

func TestMatrixHTMLAndJSONRenderers(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()
	seedMatrixExec(t, st, "r-1", "h1", "T1059.004", "caught", time.Now().UTC())
	m, err := BuildMatrix(context.Background(), st, attack.EmbeddedFallback(), MatrixRequest{
		Since: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	html, err := RenderHTMLMatrix(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "ATT&amp;CK coverage") {
		t.Error("html missing title")
	}
	if !strings.Contains(string(html), "T1059") {
		t.Error("html missing T1059 cell")
	}
	if _, err := RenderJSONMatrix(m); err != nil {
		t.Fatal(err)
	}
}

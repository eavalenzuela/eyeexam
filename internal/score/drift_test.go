package score

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "drift.db"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func seed(t *testing.T, st *store.Store, runID, technique, state string, when time.Time) {
	t.Helper()
	ctx := context.Background()
	_ = st.UpsertEngagement(ctx, store.Engagement{ID: "ENG", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	_ = st.UpsertHost(ctx, store.Host{ID: "h-1", Name: "h-1", InventoryJSON: "{}"})
	_, err := st.GetRun(ctx, runID)
	if err != nil {
		_ = st.InsertRun(ctx, store.Run{
			ID: runID, EngagementID: "ENG", Seed: 0, MaxDest: "low",
			SelectorJSON: "{}", PlanJSON: "{}", Phase: "reported", AuthorizedBy: "tester",
		})
	}
	ex := store.Execution{
		ID:                 "x-" + runID + "-" + technique,
		RunID:              runID,
		HostID:             "h-1",
		TestID:             "t-" + technique,
		TestSource:         "native",
		TestYAMLSHA256:     "x",
		Destructiveness:    "low",
		Runner:             "local",
		StartedAt:          when.UTC().Format(time.RFC3339Nano),
		CleanupState:       "succeeded",
		CleanupVerifyState: "succeeded",
		DetectionState:     state,
	}
	ex.AttackTechnique = sql.NullString{String: technique, Valid: true}
	if err := st.InsertExecution(ctx, ex); err != nil {
		t.Fatal(err)
	}
}

func TestCompareRunsDetectsRegressions(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	now := time.Now().UTC()
	seed(t, st, "r-prior", "T1070.003", "caught", now.Add(-2*time.Hour))
	seed(t, st, "r-prior", "T1059.004", "missed", now.Add(-2*time.Hour))
	seed(t, st, "r-curr", "T1070.003", "missed", now)
	seed(t, st, "r-curr", "T1059.004", "missed", now)
	seed(t, st, "r-curr", "T1105", "caught", now)

	regs, err := CompareRuns(context.Background(), st, "r-prior", "r-curr")
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 1 {
		t.Fatalf("expected 1 regression, got %d (%+v)", len(regs), regs)
	}
	if regs[0].Technique != "T1070.003" || regs[0].From != StateCaught || regs[0].To != StateMissed {
		t.Fatalf("unexpected regression: %+v", regs[0])
	}
}

func TestCompareRunsNoPrior(t *testing.T) {
	st := openStore(t)
	defer st.Close()
	seed(t, st, "r-1", "T1070.003", "missed", time.Now().UTC())
	regs, err := CompareRuns(context.Background(), st, "", "r-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 0 {
		t.Fatalf("expected no regressions without prior, got %d", len(regs))
	}
}

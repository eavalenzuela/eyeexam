package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// TestRunsResumeAfterInterrupt drives Plan → cancelled-Execute → Resume
// against the builtin pack and asserts the run reaches `reported` and
// every execution finishes exactly once. The cancellation is delivered
// before the first test runs, so resume has the full execute phase to
// re-enter.
func TestRunsResumeAfterInterrupt(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e in short mode")
	}
	ctx := context.Background()
	tmp := t.TempDir()

	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	builtin := filepath.Join(root, "packs", "builtin")

	st, err := store.Open(ctx, filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.Open(filepath.Join(tmp, "audit.log"), priv)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	reg := pack.NewRegistry(nil)
	if err := reg.AddNative("builtin", builtin); err != nil {
		t.Fatal(err)
	}

	eng, err := runlife.New(runlife.Options{
		Store: st, Audit: al, Registry: reg, Inventory: inventory.DefaultLocalhost(),
		Runners:       map[string]runner.Runner{"local": runner.NewLocal()},
		GlobalRateTPS: 100,
		PerHostConcur: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	actor := audit.Actor{OSUser: "tester", OSUID: 1000}
	runID, _, err := eng.Plan(ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG",
		Authorized:   true,
		MaxDest:      pack.DestLow,
		PackName:     "builtin",
		Actor:        actor,
	})
	if err != nil {
		t.Fatal(err)
	}

	r, err := st.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Phase != "planned" {
		t.Fatalf("after Plan: phase=%s, want planned", r.Phase)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	_ = eng.Execute(cancelCtx, runID, actor)

	r, err = st.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Phase == "reported" {
		t.Fatalf("expected run not yet reported after cancelled Execute, got %s", r.Phase)
	}

	if err := eng.Resume(ctx, runID, actor); err != nil {
		t.Fatalf("resume: %v", err)
	}

	r, err = st.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Phase != "reported" {
		t.Fatalf("after Resume: phase=%s, want reported", r.Phase)
	}

	execs, err := st.ListExecutionsForRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 3 {
		t.Fatalf("expected 3 executions after resume, got %d (executed-twice would yield > 3)", len(execs))
	}
	for _, ex := range execs {
		if ex.CleanupVerifyState != "succeeded" {
			t.Errorf("%s verify=%s", ex.TestID, ex.CleanupVerifyState)
		}
	}
}

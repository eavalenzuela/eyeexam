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

// TestLocalSmokeFullLifecycle drives plan → execute → cleanup → report
// against the bundled builtin pack on the local machine. It asserts that
// every execution produced cleanup_state=succeeded, cleanup_verify=succeeded,
// and detection_state=no_expectation (the M1 stub).
func TestLocalSmokeFullLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e in short mode")
	}
	ctx := context.Background()
	tmp := t.TempDir()

	// Resolve the builtin pack directory relative to repo root.
	repoRoot, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	builtin := filepath.Join(repoRoot, "packs", "builtin")

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

	inv := inventory.DefaultLocalhost()

	eng, err := runlife.New(runlife.Options{
		Store: st, Audit: al, Registry: reg, Inventory: inv,
		Runners:       map[string]runner.Runner{"local": runner.NewLocal()},
		GlobalRateTPS: 100, // unblock for tests
		PerHostConcur: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	actor := audit.Actor{OSUser: "tester", OSUID: 1000}
	runID, plan, err := eng.Plan(ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG",
		Authorized:   true,
		MaxDest:      pack.DestLow,
		PackName:     "builtin",
		Actor:        actor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tests) != 3 {
		t.Fatalf("expected 3 tests in plan, got %d", len(plan.Tests))
	}

	if err := eng.Execute(ctx, runID, actor); err != nil {
		t.Fatal(err)
	}

	r, err := st.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Phase != "reported" {
		t.Fatalf("expected reported, got %s", r.Phase)
	}

	execs, err := st.ListExecutionsForRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 3 {
		t.Fatalf("expected 3 executions, got %d", len(execs))
	}
	for _, ex := range execs {
		if ex.ExitCode.Int64 != 0 {
			t.Errorf("%s exit_code=%d", ex.TestID, ex.ExitCode.Int64)
		}
		if ex.CleanupState != "succeeded" {
			t.Errorf("%s cleanup_state=%s", ex.TestID, ex.CleanupState)
		}
		if ex.CleanupVerifyState != "succeeded" {
			t.Errorf("%s verify=%s", ex.TestID, ex.CleanupVerifyState)
		}
		if ex.DetectionState != "no_expectation" {
			t.Errorf("%s detect=%s", ex.TestID, ex.DetectionState)
		}
	}

	res, err := audit.Verify(filepath.Join(tmp, "audit.log"), nil)
	if err != nil || !res.OK {
		t.Fatalf("audit verify failed: %+v err=%v", res, err)
	}
}

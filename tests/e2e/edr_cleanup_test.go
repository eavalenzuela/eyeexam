package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/pack/embedded"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// edrHarness bundles the shared setup for the EDR-hardening e2e tests.
type edrHarness struct {
	ctx   context.Context
	st    *store.Store
	al    *audit.Logger
	actor audit.Actor
}

func newEDRHarness(t *testing.T) *edrHarness {
	t.Helper()
	ctx := context.Background()
	tmp := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.Open(filepath.Join(tmp, "audit.log"), priv, st.DB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = al.Close() })
	return &edrHarness{ctx: ctx, st: st, al: al, actor: audit.Actor{OSUser: "tester", OSUID: 1000}}
}

func builtinRegistry(t *testing.T) *pack.Registry {
	t.Helper()
	reg := pack.NewRegistry(nil)
	if err := reg.AddEmbedded("builtin", embedded.BuiltinFS()); err != nil {
		t.Fatal(err)
	}
	return reg
}

// writeOrderingPack writes a two-test pack (ids sorted a<b) that shares a work
// dir. Test-a drops a marker and reverts it in cleanup; test-b's execute FAILS
// (exit 3) if a's marker is still present. In eager mode a's cleanup runs
// before b executes, so b sees no marker and exits 0; in deferred mode a's
// cleanup is deferred to the end, so b would see the marker and exit 3. That
// difference is what makes this test eager-specific.
func writeOrderingPack(t *testing.T, workDir string) string {
	t.Helper()
	packDir := filepath.Join(t.TempDir(), "pack")
	if err := osMkdirAll(packDir); err != nil {
		t.Fatal(err)
	}
	a := fmt.Sprintf(`id: e2e-order-a
name: ordering a
attack: {technique: T1059.004, tactic: TA0002}
destructiveness: low
platforms: [linux]
execute:
  - shell: bash
    command: |
      mkdir -p %q
      touch %q/a-ran
      echo a-executed
cleanup:
  - shell: bash
    command: |
      rm -f %q/a-ran
verify_cleanup:
  - shell: bash
    command: |
      test ! -e %q/a-ran
`, workDir, workDir, workDir, workDir)
	b := fmt.Sprintf(`id: e2e-order-b
name: ordering b
attack: {technique: T1059.004, tactic: TA0002}
destructiveness: low
platforms: [linux]
execute:
  - shell: bash
    command: |
      mkdir -p %q
      if [ -e %q/a-ran ]; then echo "a not yet cleaned" >&2; exit 3; fi
      echo b-executed
cleanup:
  - shell: bash
    command: |
      rm -rf %q
verify_cleanup:
  - shell: bash
    command: |
      test ! -e %q
`, workDir, workDir, workDir, workDir)
	if err := osWriteFile(filepath.Join(packDir, "e2e-order-a.yaml"), []byte(a)); err != nil {
		t.Fatal(err)
	}
	if err := osWriteFile(filepath.Join(packDir, "e2e-order-b.yaml"), []byte(b)); err != nil {
		t.Fatal(err)
	}
	return packDir
}

// TestEagerCleanupRunsBetweenTests proves eager mode reverts each test BEFORE
// the next runs — not merely that the run reaches the same terminal state as
// deferred. See writeOrderingPack: test-b exits 0 iff test-a was already
// cleaned up when b executes, which only holds under eager cleanup.
func TestEagerCleanupRunsBetweenTests(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e in short mode")
	}
	run := func(t *testing.T, mode string) map[string]int64 {
		h := newEDRHarness(t)
		workDir := filepath.Join(t.TempDir(), "work")
		reg := pack.NewRegistry(nil)
		if err := reg.AddNative("order", writeOrderingPack(t, workDir)); err != nil {
			t.Fatal(err)
		}
		eng, err := runlife.New(runlife.Options{
			Store: h.st, Audit: h.al, Registry: reg, Inventory: inventory.DefaultLocalhost(),
			Runners:       map[string]runner.Runner{"local": runner.NewLocal()},
			GlobalRateTPS: 100,
			PerHostConcur: 1,
			CleanupMode:   mode,
		})
		if err != nil {
			t.Fatal(err)
		}
		runID, _, err := eng.Plan(h.ctx, runlife.PlanRequest{
			EngagementID: "TEST-ENG", Authorized: true, MaxDest: pack.DestLow,
			PackName: "order", Actor: h.actor,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := eng.Execute(h.ctx, runID, h.actor); err != nil {
			t.Fatal(err)
		}
		if r, err := h.st.GetRun(h.ctx, runID); err != nil {
			t.Fatal(err)
		} else if r.Phase != "reported" {
			t.Fatalf("mode=%s phase=%s, want reported", mode, r.Phase)
		}
		execs, err := h.st.ListExecutionsForRun(h.ctx, runID)
		if err != nil {
			t.Fatal(err)
		}
		exits := map[string]int64{}
		for _, ex := range execs {
			exits[ex.TestID] = ex.ExitCode.Int64
			// Both modes must finalise every test's cleanup by run end.
			if ex.CleanupState != "succeeded" || ex.CleanupVerifyState != "succeeded" {
				t.Errorf("mode=%s %s cleanup=%s verify=%s", mode, ex.TestID, ex.CleanupState, ex.CleanupVerifyState)
			}
		}
		if pend, _ := h.st.ListRunsWithPendingCleanup(h.ctx); len(pend) != 0 {
			t.Errorf("mode=%s left %d run(s) pending cleanup", mode, len(pend))
		}
		return exits
	}

	// Eager: a is cleaned before b runs, so b sees no marker → exit 0.
	eager := run(t, runlife.CleanupEager)
	if eager["e2e-order-b"] != 0 {
		t.Fatalf("eager: test-b exit=%d, want 0 (a should have been cleaned before b ran)", eager["e2e-order-b"])
	}

	// Control: deferred leaves a's marker in place when b runs → b exits 3.
	// This asserts the fixture genuinely detects the difference (guards the
	// test from silently passing if eager degraded to deferred).
	deferred := run(t, runlife.CleanupDeferred)
	if deferred["e2e-order-b"] != 3 {
		t.Fatalf("deferred control: test-b exit=%d, want 3 (fixture should see a's uncleaned marker)", deferred["e2e-order-b"])
	}
}

// writeFixturePack writes a single-test native pack that touches a marker file
// under markerDir, declares an expectation (so the wait phase actually blocks),
// and reverts the marker in cleanup. Returns the pack dir.
func writeFixturePack(t *testing.T, markerDir string, waitSeconds int) string {
	t.Helper()
	packDir := filepath.Join(t.TempDir(), "pack")
	if err := osMkdirAll(packDir); err != nil {
		t.Fatal(err)
	}
	y := fmt.Sprintf(`id: e2e-drain-1
name: drain fixture
attack:
  technique: T1059.004
  tactic: TA0002
destructiveness: low
platforms: [linux]
wait_seconds: %d
execute:
  - shell: bash
    command: |
      mkdir -p %q
      touch %q/marker
      echo created
cleanup:
  - shell: bash
    command: |
      rm -rf %q
verify_cleanup:
  - shell: bash
    command: |
      test ! -e %q
expected_detections:
  - sigma_id: e2e-0001
    backend: fake
    description: never-caught
`, waitSeconds, markerDir, markerDir, markerDir, markerDir)
	if err := osWriteFile(filepath.Join(packDir, "e2e-drain-1.yaml"), []byte(y)); err != nil {
		t.Fatal(err)
	}
	return packDir
}

// TestDrainRecoversAfterInterrupt simulates an EDR (or Ctrl-C) killing a run
// after the file-modifying test executed but before cleanup: the run is
// cancelled during the wait phase, leaving the marker on disk and cleanup
// pending. It then proves the recovery path (ListRunsWithPendingCleanup +
// CleanupAllPending) reverts the change on a fresh context.
func TestDrainRecoversAfterInterrupt(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e in short mode")
	}
	h := newEDRHarness(t)
	markerDir := filepath.Join(t.TempDir(), "marker")
	packDir := writeFixturePack(t, markerDir, 30) // long wait so cancel lands in phaseWait

	reg := pack.NewRegistry(nil)
	if err := reg.AddNative("drain", packDir); err != nil {
		t.Fatal(err)
	}
	eng, err := runlife.New(runlife.Options{
		Store: h.st, Audit: h.al, Registry: reg, Inventory: inventory.DefaultLocalhost(),
		Runners:       map[string]runner.Runner{"local": runner.NewLocal()},
		GlobalRateTPS: 100,
		PerHostConcur: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	runID, _, err := eng.Plan(h.ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG", Authorized: true, MaxDest: pack.DestLow,
		PackName: "drain", Actor: h.actor,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Interrupt deterministically: run Execute in a goroutine, wait until the
	// test's execution row is FINISHED (execute done, marker written, now in
	// the 30s wait phase), then cancel. This synchronises on observed state
	// rather than a fixed sleep, so it can't race execution setup under load.
	runCtx, cancel := context.WithCancel(h.ctx)
	execErr := make(chan error, 1)
	go func() { execErr <- eng.Execute(runCtx, runID, h.actor) }()

	deadline := time.Now().Add(20 * time.Second)
	for {
		execs, _ := h.st.ListExecutionsForRun(h.ctx, runID)
		if len(execs) == 1 && execs[0].FinishedAt.Valid {
			break // execute completed; run is now blocked in phaseWait
		}
		if time.Now().After(deadline) {
			cancel()
			<-execErr
			t.Fatal("execution never reached finished state before deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-execErr; err == nil {
		t.Fatal("expected Execute to fail on cancellation")
	}

	// The marker was created and cleanup never ran.
	if _, err := os.Stat(filepath.Join(markerDir, "marker")); err != nil {
		t.Fatalf("marker should exist after interrupted run: %v", err)
	}
	r, err := h.st.GetRun(h.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	// An aborted run must be recorded terminal (failed), not left stuck in a
	// non-terminal phase — even though the abort cancelled the run context.
	if r.Phase != "failed" {
		t.Fatalf("interrupted run phase=%s, want failed", r.Phase)
	}
	before, err := h.st.CountPendingCleanupForRun(h.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if before == 0 {
		t.Fatal("expected pending cleanup after interrupt")
	}
	pend, err := h.st.ListRunsWithPendingCleanup(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(pend, runID) {
		t.Fatalf("ListRunsWithPendingCleanup=%v missing %s", pend, runID)
	}

	// Recover: drain all pending cleanups (the `runs cleanup --all-pending`
	// path) on a fresh context, as the CLI does after a signal abort.
	ids, err := eng.CleanupAllPending(h.ctx, h.actor)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(ids, runID) {
		t.Fatalf("CleanupAllPending returned %v, missing %s", ids, runID)
	}

	// Marker reverted, states finalised, nothing left pending.
	if _, err := os.Stat(filepath.Join(markerDir, "marker")); !os.IsNotExist(err) {
		t.Fatalf("marker should be gone after drain (err=%v)", err)
	}
	execs, err := h.st.ListExecutionsForRun(h.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	for _, ex := range execs {
		if ex.CleanupState != "succeeded" || ex.CleanupVerifyState != "succeeded" {
			t.Errorf("after drain %s cleanup=%s verify=%s", ex.TestID, ex.CleanupState, ex.CleanupVerifyState)
		}
	}
	after, err := h.st.CountPendingCleanupForRun(h.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if after != 0 {
		t.Fatalf("expected 0 pending after drain, got %d", after)
	}

	// Idempotent: a second drain finds nothing.
	ids2, err := eng.CleanupAllPending(h.ctx, h.actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids2) != 0 {
		t.Fatalf("second drain should be a no-op, got %v", ids2)
	}
}

// TestDrainRetriesFailedCleanup proves a cleanup that FAILED (as it would if a
// live EDR blocked/killed the cleanup undo command, hitting the per-step
// timeout while the run context stays alive) remains recoverable: `runs
// cleanup` re-attempts it and reverts the residue, rather than treating
// 'failed' as terminal and stranding the host modification.
func TestDrainRetriesFailedCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e in short mode")
	}
	h := newEDRHarness(t)
	workDir := filepath.Join(t.TempDir(), "work")
	gate := filepath.Join(t.TempDir(), "gate") // cleanup only succeeds once this exists
	packDir := filepath.Join(t.TempDir(), "pack")
	if err := osMkdirAll(packDir); err != nil {
		t.Fatal(err)
	}
	// cleanup succeeds (removes the sandbox) ONLY if the gate file exists;
	// otherwise `test -e gate` fails and the cleanup step exits non-zero →
	// cleanup_state=failed with the sandbox left in place.
	y := fmt.Sprintf(`id: e2e-retry-1
name: retry fixture
attack:
  technique: T1059.004
  tactic: TA0002
destructiveness: low
platforms: [linux]
execute:
  - shell: bash
    command: |
      mkdir -p %q
      touch %q/marker
      echo created
cleanup:
  - shell: bash
    command: |
      test -e %q && rm -rf %q
verify_cleanup:
  - shell: bash
    command: |
      test ! -e %q
`, workDir, workDir, gate, workDir, workDir)
	if err := osWriteFile(filepath.Join(packDir, "e2e-retry-1.yaml"), []byte(y)); err != nil {
		t.Fatal(err)
	}
	reg := pack.NewRegistry(nil)
	if err := reg.AddNative("retry", packDir); err != nil {
		t.Fatal(err)
	}
	eng, err := runlife.New(runlife.Options{
		Store: h.st, Audit: h.al, Registry: reg, Inventory: inventory.DefaultLocalhost(),
		Runners:       map[string]runner.Runner{"local": runner.NewLocal()},
		GlobalRateTPS: 100,
		PerHostConcur: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	runID, _, err := eng.Plan(h.ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG", Authorized: true, MaxDest: pack.DestLow,
		PackName: "retry", Actor: h.actor,
	})
	if err != nil {
		t.Fatal(err)
	}
	// First run: gate absent → cleanup fails, sandbox residue remains.
	if err := eng.Execute(h.ctx, runID, h.actor); err != nil {
		t.Fatal(err)
	}
	execs, err := h.st.ListExecutionsForRun(h.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 1 || execs[0].CleanupState != "failed" {
		t.Fatalf("expected cleanup_state=failed, got %+v", execs)
	}
	if _, err := os.Stat(filepath.Join(workDir, "marker")); err != nil {
		t.Fatalf("residue should remain after failed cleanup: %v", err)
	}
	// A failed cleanup must be recoverable, not stranded.
	if n, _ := h.st.CountPendingCleanupForRun(h.ctx, runID); n != 1 {
		t.Fatalf("failed cleanup should count as recoverable, got %d", n)
	}

	// Open the gate, then drain: the retry now succeeds and reverts residue.
	if err := osWriteFile(gate, []byte("go")); err != nil {
		t.Fatal(err)
	}
	ids, err := eng.CleanupAllPending(h.ctx, h.actor)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(ids, runID) {
		t.Fatalf("drain skipped the failed-cleanup run %s (got %v)", runID, ids)
	}
	if _, err := os.Stat(filepath.Join(workDir, "marker")); !os.IsNotExist(err) {
		t.Fatalf("residue should be reverted after retry (err=%v)", err)
	}
	execs, _ = h.st.ListExecutionsForRun(h.ctx, runID)
	if execs[0].CleanupState != "succeeded" || execs[0].CleanupVerifyState != "succeeded" {
		t.Fatalf("after retry cleanup=%s verify=%s", execs[0].CleanupState, execs[0].CleanupVerifyState)
	}
}

// TestInterTestPaceDelaysExecutions asserts pace inserts a delay between the
// N executions of a run (N-1 gaps), so activity is spread out rather than
// bursty. The builtin pack has 3 low-dest tests.
func TestInterTestPaceDelaysExecutions(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e in short mode")
	}
	h := newEDRHarness(t)
	const pace = 250 * time.Millisecond
	eng, err := runlife.New(runlife.Options{
		Store: h.st, Audit: h.al, Registry: builtinRegistry(t), Inventory: inventory.DefaultLocalhost(),
		Runners:       map[string]runner.Runner{"local": runner.NewLocal()},
		GlobalRateTPS: 1000, // don't let the rate limiter dominate timing
		PerHostConcur: 1,
		InterTestPace: pace,
	})
	if err != nil {
		t.Fatal(err)
	}
	runID, _, err := eng.Plan(h.ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG", Authorized: true, MaxDest: pack.DestLow,
		PackName: "builtin", Actor: h.actor,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := eng.Execute(h.ctx, runID, h.actor); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	// 3 tests → 2 pace gaps. Allow slack but require the pacing is real.
	if min := 2 * pace; elapsed < min {
		t.Fatalf("elapsed %s < expected pacing floor %s (pace not applied)", elapsed, min)
	}
}

// TestStepTimeoutBoundsSlowStep proves a per-step timeout kills a step that an
// EDR (or a wedged session) would otherwise let hang, recording exit -1 rather
// than blocking the run for the command's full duration.
func TestStepTimeoutBoundsSlowStep(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e in short mode")
	}
	h := newEDRHarness(t)
	packDir := filepath.Join(t.TempDir(), "pack")
	if err := osMkdirAll(packDir); err != nil {
		t.Fatal(err)
	}
	y := `id: e2e-slow-1
name: slow step fixture
attack:
  technique: T1059.004
  tactic: TA0002
destructiveness: low
platforms: [linux]
execute:
  - shell: bash
    command: |
      sleep 30
      echo done
cleanup:
  - shell: bash
    command: |
      true
verify_cleanup:
  - shell: bash
    command: |
      true
`
	if err := osWriteFile(filepath.Join(packDir, "e2e-slow-1.yaml"), []byte(y)); err != nil {
		t.Fatal(err)
	}
	reg := pack.NewRegistry(nil)
	if err := reg.AddNative("slow", packDir); err != nil {
		t.Fatal(err)
	}
	eng, err := runlife.New(runlife.Options{
		Store: h.st, Audit: h.al, Registry: reg, Inventory: inventory.DefaultLocalhost(),
		Runners:       map[string]runner.Runner{"local": runner.NewLocal()},
		GlobalRateTPS: 1000,
		PerHostConcur: 1,
		StepTimeout:   500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	runID, _, err := eng.Plan(h.ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG", Authorized: true, MaxDest: pack.DestLow,
		PackName: "slow", Actor: h.actor,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := eng.Execute(h.ctx, runID, h.actor); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > 10*time.Second {
		t.Fatalf("step-timeout did not bound the 30s sleep; elapsed %s", elapsed)
	}
	execs, err := h.st.ListExecutionsForRun(h.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(execs))
	}
	if execs[0].ExitCode.Int64 != -1 {
		t.Fatalf("expected exit -1 from timed-out step, got %d", execs[0].ExitCode.Int64)
	}
}

func containsStr(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

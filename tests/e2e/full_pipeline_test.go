package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/detector"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// TestFullPipelineFakeDetector wires plan → execute → wait → query → score
// → cleanup-verify against a scripted fake detector. Three tests with one
// expectation each are configured to deliberately produce one caught, one
// missed, and one uncertain outcome. We assert exact distribution.
func TestFullPipelineFakeDetector(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	ctx := context.Background()
	tmp := t.TempDir()

	packRoot := filepath.Join(tmp, "pack")
	mustWritePipelineTests(t, packRoot)

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
	if err := reg.AddNative("pipeline", packRoot); err != nil {
		t.Fatal(err)
	}

	// Detectors:
	// - "fake" supports everything.
	// - For sigma rule "rule-caught", returns 1 hit → caught.
	// - For sigma rule "rule-missed", returns 0 hits → missed.
	// - For sigma rule "rule-uncertain", returns an error → uncertain.
	fake := detector.NewFake("fake")
	fake.On("rule-caught", detector.FakeScript{
		Hits: []detector.Hit{detector.MakeHit("h1", time.Now(), "localhost", map[string]string{"rule": "rule-caught"})},
	})
	fake.On("rule-uncertain", detector.FakeScript{
		Err: errExpected("simulated detector failure"),
	})

	dreg := detector.NewRegistry(fake)

	inv := inventory.DefaultLocalhost()
	eng, err := runlife.New(runlife.Options{
		Store: st, Audit: al, Registry: reg, Inventory: inv,
		Runners:       map[string]runner.Runner{"local": runner.NewLocal()},
		Detectors:     dreg,
		QueryGrace:    100 * time.Millisecond,
		GlobalRateTPS: 100,
		PerHostConcur: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	actor := audit.Actor{OSUser: "tester", OSUID: 1000}
	runID, plan, err := eng.Plan(ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG", Authorized: true,
		MaxDest: pack.DestLow, PackName: "pipeline", Actor: actor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tests) != 3 {
		t.Fatalf("expected 3 tests, got %d", len(plan.Tests))
	}

	if err := eng.Execute(ctx, runID, actor); err != nil {
		t.Fatal(err)
	}
	r, err := st.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Phase != "reported" {
		t.Fatalf("phase=%s", r.Phase)
	}
	execs, err := st.ListExecutionsForRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"pipe-caught":    "caught",
		"pipe-missed":    "missed",
		"pipe-uncertain": "uncertain",
	}
	got := map[string]string{}
	for _, ex := range execs {
		got[ex.TestID] = ex.DetectionState
		if ex.CleanupState != "succeeded" {
			t.Errorf("%s cleanup_state=%s", ex.TestID, ex.CleanupState)
		}
		if ex.CleanupVerifyState != "succeeded" {
			t.Errorf("%s verify=%s", ex.TestID, ex.CleanupVerifyState)
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got detection_state=%s want=%s", k, got[k], v)
		}
	}

	// Per-expectation rows persisted with state + reason where applicable.
	for _, ex := range execs {
		exps, err := st.ListExpectedDetectionsForExecution(ctx, ex.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(exps) != 1 {
			t.Errorf("%s expected_detections=%d want 1", ex.TestID, len(exps))
		}
		for _, e := range exps {
			if e.State == "" {
				t.Errorf("%s expectation has empty state", ex.TestID)
			}
		}
	}

	if vr, err := audit.Verify(filepath.Join(tmp, "audit.log"), nil); err != nil || !vr.OK {
		t.Fatalf("audit verify: %+v err=%v", vr, err)
	}
}

func mustWritePipelineTests(t *testing.T, root string) {
	t.Helper()
	if err := osMkdirAll(root); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id, sigma string
	}{
		{"pipe-caught", "rule-caught"},
		{"pipe-missed", "rule-missed"},
		{"pipe-uncertain", "rule-uncertain"},
	}
	for _, c := range cases {
		body := `id: ` + c.id + `
name: pipeline test ` + c.id + `
description: pipeline scoring assertion
attack: {technique: T0, tactic: T0}
destructiveness: low
platforms: [linux]
execute:
  - shell: bash
    command: |
      true
cleanup:
  - shell: bash
    command: |
      true
verify_cleanup:
  - shell: bash
    command: |
      true
expected_detections:
  - sigma_id: ` + c.sigma + `
wait_seconds: 1
`
		if err := osWriteFile(filepath.Join(root, c.id+".yaml"), []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
}

func errExpected(msg string) error { return errMsg(msg) }

type errMsg string

func (e errMsg) Error() string { return string(e) }

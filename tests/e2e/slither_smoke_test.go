package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// TestSlitherRunnerEndToEnd starts an in-process slither shim, points
// the engine at it via transport=slither, and asserts:
//
//   - Plan/execute/score/cleanup completes against the shim.
//   - The audit log records `slither_control_id` (cross-reference with
//     slither's own audit) and `slither_agent_id` in the test_executed
//     payload.
//   - Cleanup runs through the same shim with verify_cleanup succeeding.
func TestSlitherRunnerEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	ctx := context.Background()
	tmp := t.TempDir()

	// In-process slither shim.
	type basReq struct {
		ControlID    string `json:"control_id"`
		OperatorID   string `json:"operator_id"`
		EngagementID string `json:"engagement_id"`
		AgentID      string `json:"agent_id"`
		Shell        string `json:"shell"`
		Command      string `json:"command"`
	}
	type basResp struct {
		ControlID string `json:"control_id"`
		ExitCode  int    `json:"exit_code"`
		StdoutB64 string `json:"stdout_b64"`
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/bas/health", func(w http.ResponseWriter, _ *http.Request) {})
	mux.HandleFunc("/api/v1/bas/execute", func(w http.ResponseWriter, r *http.Request) {
		var req basReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		// Echo the engagement back via stdout so test can assert the
		// plumbing.
		stdout := "ran on " + req.AgentID + " for " + req.EngagementID
		_ = json.NewEncoder(w).Encode(basResp{
			ControlID: req.ControlID + "-slither",
			ExitCode:  0,
			StdoutB64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Pack: a single bash test with no expectation (so M3 detection
	// scoring marks it no_expectation; we're testing the runner here).
	packRoot := filepath.Join(tmp, "pack")
	if err := osMkdirAll(packRoot); err != nil {
		t.Fatal(err)
	}
	body := `id: sl-smoke-1
name: slither smoke
description: dispatch via slither shim
attack: {technique: T0, tactic: T0}
destructiveness: low
platforms: [linux]
execute:
  - shell: bash
    command: |
      echo hi-from-eyeexam
cleanup:
  - shell: bash
    command: |
      true
verify_cleanup:
  - shell: bash
    command: |
      true
`
	if err := osWriteFile(filepath.Join(packRoot, "sl.yaml"), []byte(body)); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(ctx, filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	al, err := audit.Open(filepath.Join(tmp, "audit.log"), priv)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	reg := pack.NewRegistry(nil)
	if err := reg.AddNative("p", packRoot); err != nil {
		t.Fatal(err)
	}

	inv := &inventory.Inventory{
		Hosts: []inventory.Host{{
			Name: "agent-host", Transport: "slither", AgentID: "uuid-1",
			Tags: []string{"linux"},
		}},
	}

	slR, err := runner.NewSlitherRunner(runner.SlitherRunnerConfig{
		Server: srv.URL, OperatorID: "tester(uid=1000)", EngagementID: "TEST-ENG",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer slR.Close()

	eng, err := runlife.New(runlife.Options{
		Store: st, Audit: al, Registry: reg, Inventory: inv,
		Runners: map[string]runner.Runner{
			"local":   runner.NewLocal(),
			"slither": slR,
		},
		GlobalRateTPS: 100,
		PerHostConcur: 1,
		QueryGrace:    10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	actor := audit.Actor{OSUser: "tester", OSUID: 1000}
	runID, plan, err := eng.Plan(ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG", Authorized: true,
		MaxDest: pack.DestLow, PackName: "p", Actor: actor,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tests) != 1 {
		t.Fatalf("plan size=%d", len(plan.Tests))
	}
	if err := eng.Execute(ctx, runID, actor); err != nil {
		t.Fatal(err)
	}

	execs, err := st.ListExecutionsForRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 1 {
		t.Fatalf("expected 1 exec, got %d", len(execs))
	}
	ex := execs[0]
	if ex.Runner != "slither" {
		t.Errorf("runner=%s", ex.Runner)
	}
	if ex.ExitCode.Int64 != 0 {
		t.Errorf("exit=%d stderr=%s", ex.ExitCode.Int64, ex.StderrInline.String)
	}
	if !strings.Contains(ex.StdoutInline.String, "ran on uuid-1 for TEST-ENG") {
		t.Errorf("stdout missing slither plumbing markers: %q", ex.StdoutInline.String)
	}
	if ex.CleanupVerifyState != "succeeded" {
		t.Errorf("verify=%s", ex.CleanupVerifyState)
	}

	// Audit must contain a test_executed record with the cross-reference.
	auditBytes, err := readFile(t, filepath.Join(tmp, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(auditBytes), `"slither_control_id":"`+ex.ID+`-slither"`) {
		t.Errorf("audit log missing slither_control_id cross-ref; have:\n%s", auditBytes)
	}
	if !strings.Contains(string(auditBytes), `"slither_agent_id":"uuid-1"`) {
		t.Errorf("audit log missing slither_agent_id; have:\n%s", auditBytes)
	}

	if vr, err := audit.Verify(filepath.Join(tmp, "audit.log"), nil); err != nil || !vr.OK {
		t.Fatalf("audit verify: %+v err=%v", vr, err)
	}
}

func readFile(t *testing.T, p string) ([]byte, error) {
	t.Helper()
	return osReadFile(p)
}

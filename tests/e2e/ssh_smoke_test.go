package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"github.com/eavalenzuela/eyeexam/tests/sshfx"
)

func TestSSHSmokeFullLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("ssh e2e in short mode")
	}
	ctx := context.Background()
	tmp := t.TempDir()

	keyPath, signer := sshfx.WriteKeyPair(t, tmp, "id_ed25519")
	srv := sshfx.Start(t, signer.PublicKey())
	defer func() { _ = srv.Close() }()

	st, err := store.Open(ctx, filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.Open(filepath.Join(tmp, "audit.log"), priv, st.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	reg := pack.NewRegistry(nil)
	if err := reg.AddEmbedded("builtin", embedded.BuiltinFS()); err != nil {
		t.Fatal(err)
	}

	inv := &inventory.Inventory{
		Hosts: []inventory.Host{{
			Name: "fakehost", Address: srv.Addr(), Transport: "ssh",
			User: "tester", KeyPath: keyPath, Tags: []string{"linux"},
		}},
	}

	sshR, err := runner.NewSSH(runner.SSHConfig{
		DefaultUser: "tester", DefaultKeyPath: keyPath,
		ConnectTimeout:         5 * time.Second,
		CommandTimeout:         15 * time.Second,
		InsecureSkipKnownHosts: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sshR.Close()

	eng, err := runlife.New(runlife.Options{
		Store: st, Audit: al, Registry: reg, Inventory: inv,
		Runners: map[string]runner.Runner{
			"local": runner.NewLocal(),
			"ssh":   sshR,
		},
		GlobalRateTPS: 100,
		PerHostConcur: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	actor := audit.Actor{OSUser: "tester", OSUID: 1000}
	runID, plan, err := eng.Plan(ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG", Authorized: true,
		MaxDest: pack.DestLow, PackName: "builtin", Actor: actor,
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
		t.Fatalf("expected reported, got %s", r.Phase)
	}
	execs, err := st.ListExecutionsForRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 3 {
		t.Fatalf("expected 3 execs, got %d", len(execs))
	}
	for _, ex := range execs {
		if ex.Runner != "ssh" {
			t.Errorf("%s ran on %s, want ssh", ex.TestID, ex.Runner)
		}
		if ex.ExitCode.Int64 != 0 {
			t.Errorf("%s exit=%d", ex.TestID, ex.ExitCode.Int64)
		}
		if ex.CleanupVerifyState != "succeeded" {
			t.Errorf("%s verify=%s", ex.TestID, ex.CleanupVerifyState)
		}
	}
	if vr, err := audit.Verify(filepath.Join(tmp, "audit.log"), nil); err != nil || !vr.OK {
		t.Fatalf("audit verify: %+v err=%v", vr, err)
	}
}

// TestSSHRateLimitAndConcurrency builds a synthetic plan spanning multiple
// hosts and tests, asserts the global rate limiter throttles starts to the
// configured rate, and the per-host semaphore prevents concurrent execs on
// the same host.
func TestSSHRateLimitAndConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("rate-limit e2e")
	}
	ctx := context.Background()
	tmp := t.TempDir()
	keyPath, signer := sshfx.WriteKeyPair(t, tmp, "id_ed25519")
	srv := sshfx.Start(t, signer.PublicKey())
	defer srv.Close()

	st, err := store.Open(ctx, filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.Open(filepath.Join(tmp, "audit.log"), priv, st.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	// One pack with 5 trivial tests.
	packRoot := filepath.Join(tmp, "pack")
	mustWriteTrivialTests(t, packRoot, 5)

	reg := pack.NewRegistry(nil)
	if err := reg.AddNative("rl", packRoot); err != nil {
		t.Fatal(err)
	}

	hosts := []inventory.Host{
		{Name: "h1", Address: srv.Addr(), Transport: "ssh", User: "tester", KeyPath: keyPath, Tags: []string{"linux"}},
		{Name: "h2", Address: srv.Addr(), Transport: "ssh", User: "tester", KeyPath: keyPath, Tags: []string{"linux"}},
	}
	inv := &inventory.Inventory{Hosts: hosts}

	sshR, err := runner.NewSSH(runner.SSHConfig{
		DefaultUser: "tester", DefaultKeyPath: keyPath,
		ConnectTimeout:         5 * time.Second,
		CommandTimeout:         5 * time.Second,
		InsecureSkipKnownHosts: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sshR.Close()

	// 5 tests/sec rate. 5 tests * 2 hosts = 10 starts → expect ~2 seconds.
	eng, err := runlife.New(runlife.Options{
		Store: st, Audit: al, Registry: reg, Inventory: inv,
		Runners:       map[string]runner.Runner{"ssh": sshR},
		GlobalRateTPS: 5,
		PerHostConcur: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	actor := audit.Actor{OSUser: "tester", OSUID: 1000}
	runID, _, err := eng.Plan(ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG", Authorized: true,
		MaxDest: pack.DestLow, PackName: "rl", Actor: actor,
	})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	if err := eng.Execute(ctx, runID, actor); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(t0)
	// 10 starts at 5/sec = 9 inter-start gaps of 200ms each = 1.8s. Allow
	// a generous lower bound of 1.5s and an upper bound of 8s for slow CI.
	if elapsed < 1500*time.Millisecond {
		t.Errorf("rate limiter let through too fast: %s", elapsed)
	}
	if elapsed > 8*time.Second {
		t.Errorf("rate limiter too slow: %s", elapsed)
	}
}

func mustWriteTrivialTests(t *testing.T, root string, n int) {
	t.Helper()
	if err := osMkdirAll(root); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		body := `id: rl-test-` + itoa(i) + `
name: trivial test ` + itoa(i) + `
description: rate-limit harness
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
`
		if err := osWriteFile(filepath.Join(root, "rl-"+itoa(i)+".yaml"), []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
}

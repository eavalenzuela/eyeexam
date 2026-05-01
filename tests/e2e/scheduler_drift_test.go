package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/alert"
	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/detector"
	"github.com/eavalenzuela/eyeexam/internal/idgen"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/scheduler"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// TestSchedulerDriftAlert exercises the M8 acceptance: scripted fake
// detector toggles caught → missed; running the schedule twice produces
// a regression that is delivered to a webhook within one cycle.
func TestSchedulerDriftAlert(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	ctx := context.Background()
	tmp := t.TempDir()

	// Webhook captures regression bundles.
	got := make(chan alert.Bundle, 4)
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b alert.Bundle
		_ = json.NewDecoder(r.Body).Decode(&b)
		got <- b
	}))
	defer hookSrv.Close()

	// Pack: a single test with one expectation. Tag it with a real
	// technique so drift comparison has something to roll up.
	packRoot := filepath.Join(tmp, "pack")
	if err := osMkdirAll(packRoot); err != nil {
		t.Fatal(err)
	}
	body := `id: drift-1
name: regress-me
description: scheduler drift fixture
attack:
  technique: T1070.003
  tactic: TA0005
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
  - sigma_id: rule-drift-1
wait_seconds: 1
`
	if err := osWriteFile(filepath.Join(packRoot, "drift.yaml"), []byte(body)); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(ctx, filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	al, err := audit.Open(filepath.Join(tmp, "audit.log"), priv, st.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	reg := pack.NewRegistry(nil)
	if err := reg.AddNative("p", packRoot); err != nil {
		t.Fatal(err)
	}

	// Fake detector: first call returns a hit (caught); subsequent calls
	// return zero hits (missed).
	var calls int32
	fake := detector.NewFake("fake")
	// Pre-register the script so phase_query routes correctly. Then we
	// flip the registered script after the first run.
	fake.On("rule-drift-1", detector.FakeScript{
		Hits: []detector.Hit{detector.MakeHit("hit-1", time.Now(), "localhost", map[string]string{"rule": "rule-drift-1"})},
	})
	dreg := detector.NewRegistry(fake)

	inv := inventory.DefaultLocalhost()

	eng, err := runlife.New(runlife.Options{
		Store: st, Audit: al, Registry: reg, Inventory: inv,
		Runners:       map[string]runner.Runner{"local": runner.NewLocal()},
		Detectors:     dreg,
		QueryGrace:    50 * time.Millisecond,
		GlobalRateTPS: 100,
		PerHostConcur: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Engagement + schedule.
	if err := st.UpsertEngagement(ctx, store.Engagement{
		ID: "TEST-ENG", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	sinks := []alert.SinkConfig{{Name: "wh", Type: "webhook", URL: hookSrv.URL}}
	sinksJSON, _ := json.Marshal(sinks)
	sc := store.Schedule{
		ID: idgen.New("s"), Name: "drift-fixture",
		CronExpr:     "* * * * *", // every minute (we drive Tick manually)
		EngagementID: "TEST-ENG", PackName: "p", MaxDest: "low",
		SelectorJSON: "{}", AlertsJSON: string(sinksJSON),
		Enabled: 1, AuthorizedBy: "tester(uid=1000)",
	}
	if err := st.InsertSchedule(ctx, sc); err != nil {
		t.Fatal(err)
	}

	// Drive a manual tick — should fire the schedule once.
	now := time.Now().UTC()
	s, err := scheduler.New(scheduler.Options{
		Store: st, Audit: al, Engine: eng,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	nextFire := map[string]time.Time{
		// Force the first tick to fire by setting next-fire in the past.
		"drift-fixture": now.Add(-time.Second),
	}
	if err := s.Tick(ctx, nextFire); err != nil {
		t.Fatal(err)
	}
	// Allow the asynchronous fire goroutine to complete.
	waitForRunCount(t, st, 1, 2*time.Second)

	// Flip the detector script: rule-drift-1 now returns no hits → missed.
	fake.On("rule-drift-1", detector.FakeScript{Hits: nil})

	atomic.StoreInt32(&calls, 0)
	now = now.Add(2 * time.Minute)
	s2, err := scheduler.New(scheduler.Options{
		Store: st, Audit: al, Engine: eng,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	nextFire2 := map[string]time.Time{"drift-fixture": now.Add(-time.Second)}
	if err := s2.Tick(ctx, nextFire2); err != nil {
		t.Fatal(err)
	}
	waitForRunCount(t, st, 2, 2*time.Second)

	// Webhook should have received a Bundle with at least the T1070.003
	// regression (caught → missed).
	select {
	case bundle := <-got:
		if len(bundle.Regressions) == 0 {
			t.Fatalf("expected regressions in bundle, got %+v", bundle)
		}
		found := false
		for _, r := range bundle.Regressions {
			if r.TechniqueID == "T1070.003" && r.From == "caught" && r.To == "missed" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected T1070.003 caught→missed, got %+v", bundle.Regressions)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("webhook never received a bundle")
	}
}

func waitForRunCount(t *testing.T, st *store.Store, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rows, err := st.ListRuns(context.Background(), "TEST-ENG", 10)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, r := range rows {
			if r.Phase == "reported" {
				count++
			}
		}
		if count >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d reported runs", want)
}

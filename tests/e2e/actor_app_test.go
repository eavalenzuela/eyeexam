package e2e

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// TestActorAppThreading runs the full pipeline with PlanRequest.AppUser set
// and asserts both the runs row and the audit log records carry the value.
func TestActorAppThreading(t *testing.T) {
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
	logPath := filepath.Join(tmp, "audit.log")
	al, err := audit.Open(logPath, priv, st.DB)
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

	appUser := "alice@example.com"
	actor := audit.Actor{OSUser: "svc", OSUID: 1234, AppUser: &appUser}

	runID, _, err := eng.Plan(ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG",
		Authorized:   true,
		MaxDest:      pack.DestLow,
		PackName:     "builtin",
		Actor:        actor,
		AppUser:      &appUser,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Execute(ctx, runID, actor); err != nil {
		t.Fatal(err)
	}

	r, err := st.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if !r.AppUser.Valid || r.AppUser.String != appUser {
		t.Errorf("runs.app_user = %+v, want %q", r.AppUser, appUser)
	}

	// Walk audit.log; every record must have actor.app_user == appUser
	// since this Logger only saw records from this run.
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	count := 0
	for sc.Scan() {
		var rec audit.Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("parse audit line: %v", err)
		}
		if rec.Actor.AppUser == nil {
			t.Errorf("seq=%d event=%q: actor.app_user nil", rec.Seq, rec.Event)
			continue
		}
		if *rec.Actor.AppUser != appUser {
			t.Errorf("seq=%d event=%q: actor.app_user=%q want %q",
				rec.Seq, rec.Event, *rec.Actor.AppUser, appUser)
		}
		count++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("no audit records found")
	}

	// And: an unset AppUser on a fresh run must NOT carry it.
	runID2, _, err := eng.Plan(ctx, runlife.PlanRequest{
		EngagementID: "TEST-ENG",
		Authorized:   true,
		MaxDest:      pack.DestLow,
		PackName:     "builtin",
		Actor:        audit.Actor{OSUser: "svc", OSUID: 1234},
	})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := st.GetRun(ctx, runID2)
	if err != nil {
		t.Fatal(err)
	}
	if r2.AppUser.Valid {
		t.Errorf("runs.app_user should be NULL when unset, got %+v", r2.AppUser)
	}
}

package scheduler

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// TestVerifyAuditOnceCleanChain — happy path. Append rows, run the
// daemon's chain check, expect OK and no audit_chain_broken event.
func TestVerifyAuditOnceCleanChain(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "audit.log")

	st, err := store.Open(ctx, filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	al, err := audit.Open(logPath, priv, st.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	for i := 0; i < 3; i++ {
		_, err := al.Append(ctx, audit.Record{
			Actor: audit.Actor{OSUser: "tester", OSUID: 1000},
			Event: "test_event",
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	eng := minimalEngine(t, st, al)
	s, err := New(Options{
		Store: st, Audit: al, Engine: eng,
		AuditLogPath:        logPath,
		AuditVerifyInterval: 0, // unused; calling VerifyAuditOnce directly
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.VerifyAuditOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("expected OK on clean chain, got: %+v", res)
	}

	rows, _ := st.ListAudit(ctx, store.AuditFilter{Event: "audit_chain_broken"})
	if len(rows) != 0 {
		t.Errorf("expected no audit_chain_broken events on clean chain, got %d", len(rows))
	}
}

// TestVerifyAuditOnceTamperedMirror — tamper with a row in the SQLite
// mirror, run the check, expect failure + audit_chain_broken record.
func TestVerifyAuditOnceTamperedMirror(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "audit.log")

	st, err := store.Open(ctx, filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	al, err := audit.Open(logPath, priv, st.DB)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()

	for i := 0; i < 3; i++ {
		if _, err := al.Append(ctx, audit.Record{
			Actor: audit.Actor{OSUser: "tester", OSUID: 1000},
			Event: "test_event",
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Tamper: change the hash on row 2 in the DB only. File is unchanged
	// so VerifyWithMirror's cross-check phase catches it.
	if _, err := st.DB.Exec(`UPDATE audit_log SET hash = ? WHERE seq = 2`,
		"deadbeef"+"00000000000000000000000000000000000000000000000000000000"); err != nil {
		t.Fatal(err)
	}

	eng := minimalEngine(t, st, al)
	s, err := New(Options{
		Store: st, Audit: al, Engine: eng,
		AuditLogPath: logPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.VerifyAuditOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("expected divergence to be reported, got OK: %+v", res)
	}
	if res.FirstBadSeq != 2 {
		t.Errorf("FirstBadSeq=%d, want 2", res.FirstBadSeq)
	}

	// audit_chain_broken event must have been appended after the break.
	rows, err := st.ListAudit(ctx, store.AuditFilter{Event: "audit_chain_broken"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit_chain_broken record, got %d", len(rows))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(rows[0].PayloadJSON), &payload); err != nil {
		t.Fatal(err)
	}
	if int(payload["first_bad_seq"].(float64)) != 2 {
		t.Errorf("event payload first_bad_seq=%v, want 2", payload["first_bad_seq"])
	}
}

// minimalEngine builds a runlife engine with no runners, just enough
// to satisfy the scheduler.New constructor. The verify-loop tests
// don't actually fire schedules, so the engine is never asked to do
// anything beyond exist.
func minimalEngine(t *testing.T, st *store.Store, al *audit.Logger) *runlife.Engine {
	t.Helper()
	eng, err := runlife.New(runlife.Options{
		Store: st, Audit: al,
		Registry:      pack.NewRegistry(nil),
		Inventory:     inventory.DefaultLocalhost(),
		Runners:       map[string]runner.Runner{"local": runner.NewLocal()},
		GlobalRateTPS: 1, PerHostConcur: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

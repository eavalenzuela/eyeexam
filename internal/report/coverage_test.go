package report

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/attack"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// TestBuildCoverageHappyPath drives a small in-memory dataset and
// checks every report section: state counts, technique aggregation,
// regression detection, audit sections (destructive auths +
// unsigned packs).
func TestBuildCoverageHappyPath(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.UpsertEngagement(ctx, store.Engagement{
		ID: "ENG-1", CreatedAt: rfc("2026-04-01T00:00:00Z"),
	}); err != nil {
		t.Fatal(err)
	}

	host := store.Host{ID: "h-1", Name: "web-01", InventoryJSON: "{}"}
	if err := st.UpsertHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	// Run 1 (in window): 2 caught against T1070.003.
	mustInsertRun(t, st, "r-1", "ENG-1", "reported", "2026-04-10T10:00:00Z")
	mustInsertExec(t, st, "x-1-1", "r-1", host.ID, "tA", "T1070.003", "caught", "2026-04-10T10:01:00Z")
	mustInsertExec(t, st, "x-1-2", "r-1", host.ID, "tB", "T1070.003", "caught", "2026-04-10T10:02:00Z")

	// Run 2 (in window): 1 missed against T1070.003 — regression!
	mustInsertRun(t, st, "r-2", "ENG-1", "reported", "2026-04-20T10:00:00Z")
	mustInsertExec(t, st, "x-2-1", "r-2", host.ID, "tA", "T1070.003", "missed", "2026-04-20T10:01:00Z")

	// Run 3 (failed phase, in window): doesn't count toward state counts.
	mustInsertRun(t, st, "r-3", "ENG-1", "failed", "2026-04-22T10:00:00Z")

	// Audit: a destructive_run_authorized for r-2.
	insertAudit(t, st, 1, "destructive_run_authorized", "ENG-1", "r-2",
		`{"os_user":"alice","os_uid":1000}`,
		`{"max_dest":"medium"}`, "2026-04-20T09:59:00Z")
	// Audit: a pack_loaded_unsigned for r-2.
	insertAudit(t, st, 2, "pack_loaded_unsigned", "ENG-1", "r-2",
		`{"os_user":"alice","os_uid":1000}`,
		`{"pack":"atomic"}`, "2026-04-20T09:59:01Z")
	// An audit row outside the window — should be excluded.
	insertAudit(t, st, 3, "destructive_run_authorized", "ENG-1", "r-old",
		`{"os_user":"alice","os_uid":1000}`,
		`{"max_dest":"high"}`, "2026-01-01T00:00:00Z")

	now, _ := time.Parse(time.RFC3339, "2026-05-01T00:00:00Z")
	cov, err := Build(ctx, st, attack.EmbeddedFallback(), CoverageRequest{
		Engagement: "ENG-1",
		Since:      now.Add(-30 * 24 * time.Hour),
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	if cov.RunCount != 3 {
		t.Errorf("RunCount=%d, want 3", cov.RunCount)
	}
	if cov.ReportedCount != 2 {
		t.Errorf("ReportedCount=%d, want 2", cov.ReportedCount)
	}
	if cov.FailedCount != 1 {
		t.Errorf("FailedCount=%d, want 1", cov.FailedCount)
	}
	if cov.ExecCount != 3 {
		t.Errorf("ExecCount=%d, want 3", cov.ExecCount)
	}
	if cov.StateCounts.Caught != 2 {
		t.Errorf("Caught=%d, want 2", cov.StateCounts.Caught)
	}
	if cov.StateCounts.Missed != 1 {
		t.Errorf("Missed=%d, want 1", cov.StateCounts.Missed)
	}

	if len(cov.Techniques) != 1 || cov.Techniques[0].TechniqueID != "T1070.003" {
		t.Errorf("Techniques=%+v", cov.Techniques)
	}

	if len(cov.Regressions) != 1 {
		t.Fatalf("Regressions=%d, want 1", len(cov.Regressions))
	}
	r := cov.Regressions[0]
	if r.TechniqueID != "T1070.003" || r.From != "caught" || r.To != "missed" {
		t.Errorf("regression: %+v", r)
	}

	if len(cov.DestructiveOps) != 1 {
		t.Errorf("DestructiveOps=%d, want 1 (out-of-window row excluded)", len(cov.DestructiveOps))
	}
	if len(cov.UnsignedPacks) != 1 {
		t.Errorf("UnsignedPacks=%d, want 1", len(cov.UnsignedPacks))
	}

	md := RenderMarkdown(cov)
	for _, want := range []string{
		"# Coverage report — ENG-1",
		"Runs: 3 (2 reported, 1 failed)",
		"T1070.003",
		"Regressions in window",
		"caught → missed",
		"Destructive-run authorizations",
		"alice(uid=1000)",
		"Unsigned pack loads",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n--- markdown ---\n%s", want, md)
		}
	}

	jsonBytes, err := RenderJSON(cov)
	if err != nil {
		t.Fatal(err)
	}
	var rt Coverage
	if err := json.Unmarshal(jsonBytes, &rt); err != nil {
		t.Fatal(err)
	}
	if rt.Engagement != "ENG-1" || rt.RunCount != 3 {
		t.Errorf("json round-trip: %+v", rt)
	}
}

func TestBuildRequiresEngagement(t *testing.T) {
	tmp := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(tmp, "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = Build(context.Background(), st, nil, CoverageRequest{})
	if err == nil || !strings.Contains(err.Error(), "engagement required") {
		t.Fatalf("expected engagement-required error, got %v", err)
	}
}

func TestIsWorseRanking(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		{"caught", "missed", true},
		{"caught", "uncertain", true},
		{"uncertain", "missed", true},
		{"missed", "caught", false},
		{"caught", "caught", false},
		{"", "missed", false}, // no prior state, no regression
		{"caught", "no_expectation", false},
	}
	for _, tc := range cases {
		got := isWorse(tc.from, tc.to)
		if got != tc.want {
			t.Errorf("isWorse(%q, %q) = %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

// helpers

func rfc(s string) string {
	t, _ := time.Parse(time.RFC3339, s)
	return t.Format(time.RFC3339Nano)
}

func mustInsertRun(t *testing.T, st *store.Store, id, eng, phase, startedAt string) {
	t.Helper()
	r := store.Run{
		ID: id, EngagementID: eng, Seed: 1, MaxDest: "low",
		SelectorJSON: "{}", PlanJSON: `{"refused":[]}`, Phase: phase,
		AuthorizedBy: "tester(uid=1000)",
		StartedAt:    sql.NullString{Valid: true, String: rfc(startedAt)},
	}
	if err := st.InsertRun(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

func mustInsertExec(t *testing.T, st *store.Store, id, runID, hostID, testID, technique, detect, finishedAt string) {
	t.Helper()
	e := store.Execution{
		ID: id, RunID: runID, HostID: hostID, TestID: testID,
		TestSource: "native", TestYAMLSHA256: "0",
		Destructiveness: "low", Runner: "local",
		StartedAt: rfc(finishedAt), FinishedAt: sql.NullString{Valid: true, String: rfc(finishedAt)},
		ExitCode:           sql.NullInt64{Valid: true, Int64: 0},
		AttackTechnique:    sql.NullString{Valid: true, String: technique},
		CleanupState:       "succeeded",
		CleanupVerifyState: "succeeded",
		DetectionState:     detect,
	}
	if err := st.InsertExecution(context.Background(), e); err != nil {
		t.Fatal(err)
	}
}

func insertAudit(t *testing.T, st *store.Store, seq int, event, eng, runID, actorJSON, payloadJSON, ts string) {
	t.Helper()
	_, err := st.DB.Exec(`INSERT INTO audit_log
		(seq, ts, actor_json, engagement_id, run_id, event, payload_json, prev_hash, hash, signature)
		VALUES (?, ?, ?, ?, ?, ?, ?, '', '', '')`,
		seq, rfc(ts), actorJSON, eng, runID, event, payloadJSON)
	if err != nil {
		t.Fatal(err)
	}
}

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenAppliesMigrations(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var n int
	row := s.DB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='runs'`)
	if err := row.Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected runs table, got count=%d", n)
	}
}

func TestRunInsertAndPhaseUpdate(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertEngagement(ctx, Engagement{
		ID: "ENG-1", Description: "test", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	r := Run{
		ID: "r-1", EngagementID: "ENG-1", Seed: 1, MaxDest: "low",
		SelectorJSON: "{}", PlanJSON: "{}", Phase: "planned",
		AuthorizedBy: "tester(uid=1000)",
	}
	if err := s.InsertRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateRunPhase(ctx, "r-1", "executing"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRun(ctx, "r-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Phase != "executing" {
		t.Fatalf("phase=%s", got.Phase)
	}
}

func TestListAuditFilters(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Insert a few canned rows directly. The audit package owns the real
	// write path; here we just need data to exercise the filter SQL.
	insert := func(seq int, ts, event, runID, actor string) {
		t.Helper()
		_, err := s.DB.Exec(`INSERT INTO audit_log
			(seq, ts, actor_json, engagement_id, run_id, event, payload_json, prev_hash, hash, signature)
			VALUES (?, ?, ?, ?, ?, ?, 'null', '', '', '')`,
			seq, ts, actor, "ENG-1", runID, event)
		if err != nil {
			t.Fatal(err)
		}
	}
	insert(1, "2026-04-01T00:00:00Z", "run_planned", "r-1", `{"os_user":"alice","os_uid":1000}`)
	insert(2, "2026-04-01T00:00:01Z", "test_executed", "r-1", `{"os_user":"alice","os_uid":1000}`)
	insert(3, "2026-04-02T00:00:00Z", "run_planned", "r-2", `{"os_user":"bob","os_uid":1001,"app_user":"bob@example.com"}`)
	insert(4, "2026-04-03T00:00:00Z", "destructive_run_authorized", "r-2", `{"os_user":"bob","os_uid":1001,"app_user":"bob@example.com"}`)

	// run filter
	rows, err := s.ListAudit(ctx, AuditFilter{RunID: "r-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Errorf("run=r-1: got %d rows, want 2", len(rows))
	}

	// event filter
	rows, _ = s.ListAudit(ctx, AuditFilter{Event: "run_planned"})
	if len(rows) != 2 {
		t.Errorf("event=run_planned: got %d, want 2", len(rows))
	}

	// actor substring
	rows, _ = s.ListAudit(ctx, AuditFilter{Actor: "bob@example.com"})
	if len(rows) != 2 {
		t.Errorf("actor=bob@example.com: got %d, want 2", len(rows))
	}

	// since filter
	rows, _ = s.ListAudit(ctx, AuditFilter{SinceTS: "2026-04-02T00:00:00Z"})
	if len(rows) != 2 {
		t.Errorf("since=Apr2: got %d, want 2", len(rows))
	}

	// combined
	rows, _ = s.ListAudit(ctx, AuditFilter{RunID: "r-2", Event: "destructive_run_authorized"})
	if len(rows) != 1 {
		t.Errorf("combined filters: got %d, want 1", len(rows))
	}
}

func TestPendingCleanupQueries(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertEngagement(ctx, Engagement{ID: "ENG-1", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertHost(ctx, Host{ID: "h-1", Name: "localhost", InventoryJSON: "{}"}); err != nil {
		t.Fatal(err)
	}
	mkRun := func(id string) {
		t.Helper()
		if err := s.InsertRun(ctx, Run{
			ID: id, EngagementID: "ENG-1", Seed: 0, MaxDest: "low",
			SelectorJSON: "{}", PlanJSON: "{}", Phase: "cleanup", AuthorizedBy: "tester",
		}); err != nil {
			t.Fatal(err)
		}
	}
	mkExec := func(id, runID, cleanup, verify string) {
		t.Helper()
		if err := s.InsertExecution(ctx, Execution{
			ID: id, RunID: runID, HostID: "h-1", TestID: "eye-001", TestSource: "native",
			TestYAMLSHA256: "x", Destructiveness: "low", Runner: "local",
			StartedAt:    time.Now().UTC().Format(time.RFC3339Nano),
			CleanupState: cleanup, CleanupVerifyState: verify, DetectionState: "pending",
		}); err != nil {
			t.Fatal(err)
		}
	}

	mkRun("r-1")
	mkExec("x-1a", "r-1", "pending", "pending") // fully pending
	mkExec("x-1b", "r-1", "succeeded", "succeeded")
	mkRun("r-2")
	mkExec("x-2a", "r-2", "succeeded", "pending") // verify still pending → counts
	mkRun("r-3")
	mkExec("x-3a", "r-3", "succeeded", "succeeded") // fully done → excluded
	mkExec("x-3b", "r-3", "no_cleanup_defined", "not_defined")
	mkRun("r-4")
	mkExec("x-4a", "r-4", "failed", "failed") // failed cleanup is RETRYABLE → counts

	runs, err := s.ListRunsWithPendingCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range runs {
		got[r] = true
	}
	if !got["r-1"] || !got["r-2"] || !got["r-4"] {
		t.Errorf("expected r-1, r-2, r-4 pending/retryable, got %v", runs)
	}
	if got["r-3"] {
		t.Errorf("r-3 has no pending cleanup but was returned: %v", runs)
	}

	for _, tc := range []struct {
		run  string
		want int
	}{{"r-1", 1}, {"r-2", 1}, {"r-3", 0}, {"r-4", 1}} {
		n, err := s.CountPendingCleanupForRun(ctx, tc.run)
		if err != nil {
			t.Fatal(err)
		}
		if n != tc.want {
			t.Errorf("CountPendingCleanupForRun(%s)=%d, want %d", tc.run, n, tc.want)
		}
	}
}

func TestScheduleAppUserRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertEngagement(ctx, Engagement{
		ID: "ENG-1", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	withApp := Schedule{
		ID: "s-1", Name: "with-app", CronExpr: "0 3 * * *",
		EngagementID: "ENG-1", PackName: "builtin", MaxDest: "low",
		Enabled: 1, AuthorizedBy: "svc(uid=0)",
	}
	withApp.AppUser.Valid = true
	withApp.AppUser.String = "alice@example.com"
	if err := s.InsertSchedule(ctx, withApp); err != nil {
		t.Fatal(err)
	}

	withoutApp := Schedule{
		ID: "s-2", Name: "no-app", CronExpr: "0 4 * * *",
		EngagementID: "ENG-1", PackName: "builtin", MaxDest: "low",
		Enabled: 1, AuthorizedBy: "svc(uid=0)",
	}
	if err := s.InsertSchedule(ctx, withoutApp); err != nil {
		t.Fatal(err)
	}

	got1, err := s.GetScheduleByName(ctx, "with-app")
	if err != nil {
		t.Fatal(err)
	}
	if !got1.AppUser.Valid || got1.AppUser.String != "alice@example.com" {
		t.Errorf("with-app: AppUser=%+v", got1.AppUser)
	}

	got2, err := s.GetScheduleByName(ctx, "no-app")
	if err != nil {
		t.Fatal(err)
	}
	if got2.AppUser.Valid {
		t.Errorf("no-app: AppUser should be NULL, got %+v", got2.AppUser)
	}
}

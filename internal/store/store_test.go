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

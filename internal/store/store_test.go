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

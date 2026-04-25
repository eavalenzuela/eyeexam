package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Run struct {
	ID           string         `db:"id"`
	EngagementID string         `db:"engagement_id"`
	Seed         int64          `db:"seed"`
	MaxDest      string         `db:"max_dest"`
	SelectorJSON string         `db:"selector_json"`
	PlanJSON     string         `db:"plan_json"`
	Phase        string         `db:"phase"`
	AuthorizedBy string         `db:"authorized_by"`
	AppUser      sql.NullString `db:"app_user"`
	StartedAt    sql.NullString `db:"started_at"`
	FinishedAt   sql.NullString `db:"finished_at"`
}

type Engagement struct {
	ID          string `db:"id"`
	Description string `db:"description"`
	CreatedAt   string `db:"created_at"`
}

func (s *Store) UpsertEngagement(ctx context.Context, e Engagement) error {
	if e.CreatedAt == "" {
		e.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, err := s.DB.NamedExecContext(ctx, `
		INSERT INTO engagements (id, description, created_at)
		VALUES (:id, :description, :created_at)
		ON CONFLICT(id) DO UPDATE SET description=excluded.description
	`, e)
	if err != nil {
		return fmt.Errorf("store: upsert engagement: %w", err)
	}
	return nil
}

func (s *Store) InsertRun(ctx context.Context, r Run) error {
	_, err := s.DB.NamedExecContext(ctx, `
		INSERT INTO runs (id, engagement_id, seed, max_dest, selector_json,
		  plan_json, phase, authorized_by, app_user, started_at, finished_at)
		VALUES (:id, :engagement_id, :seed, :max_dest, :selector_json,
		  :plan_json, :phase, :authorized_by, :app_user, :started_at, :finished_at)
	`, r)
	if err != nil {
		return fmt.Errorf("store: insert run: %w", err)
	}
	return nil
}

func (s *Store) UpdateRunPhase(ctx context.Context, runID, phase string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE runs SET phase = ? WHERE id = ?`, phase, runID)
	if err != nil {
		return fmt.Errorf("store: update run phase: %w", err)
	}
	return nil
}

func (s *Store) MarkRunStarted(ctx context.Context, runID string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE runs SET started_at = ? WHERE id = ? AND started_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), runID)
	return err
}

func (s *Store) MarkRunFinished(ctx context.Context, runID string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE runs SET finished_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), runID)
	return err
}

func (s *Store) GetRun(ctx context.Context, runID string) (Run, error) {
	var r Run
	err := s.DB.GetContext(ctx, &r, `SELECT * FROM runs WHERE id = ?`, runID)
	if err != nil {
		return Run{}, fmt.Errorf("store: get run %s: %w", runID, err)
	}
	return r, nil
}

func (s *Store) ListRuns(ctx context.Context, engagementID string, limit int) ([]Run, error) {
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT * FROM runs`
	args := []any{}
	if engagementID != "" {
		q += ` WHERE engagement_id = ?`
		args = append(args, engagementID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	var out []Run
	if err := s.DB.SelectContext(ctx, &out, q, args...); err != nil {
		return nil, fmt.Errorf("store: list runs: %w", err)
	}
	return out, nil
}

type Host struct {
	ID            string `db:"id"`
	Name          string `db:"name"`
	InventoryJSON string `db:"inventory_json"`
}

func (s *Store) UpsertHost(ctx context.Context, h Host) error {
	_, err := s.DB.NamedExecContext(ctx, `
		INSERT INTO hosts (id, name, inventory_json)
		VALUES (:id, :name, :inventory_json)
		ON CONFLICT(name) DO UPDATE SET
		  inventory_json = excluded.inventory_json
	`, h)
	if err != nil {
		return fmt.Errorf("store: upsert host: %w", err)
	}
	return nil
}

func (s *Store) GetHostByName(ctx context.Context, name string) (Host, error) {
	var h Host
	err := s.DB.GetContext(ctx, &h, `SELECT * FROM hosts WHERE name = ?`, name)
	if err != nil {
		return Host{}, fmt.Errorf("store: get host %s: %w", name, err)
	}
	return h, nil
}

func (s *Store) GetHostByID(ctx context.Context, id string) (Host, error) {
	var h Host
	err := s.DB.GetContext(ctx, &h, `SELECT * FROM hosts WHERE id = ?`, id)
	if err != nil {
		return Host{}, fmt.Errorf("store: get host id %s: %w", id, err)
	}
	return h, nil
}

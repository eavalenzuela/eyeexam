package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type Schedule struct {
	ID           string         `db:"id"`
	Name         string         `db:"name"`
	CronExpr     string         `db:"cron_expr"`
	EngagementID string         `db:"engagement_id"`
	PackName     string         `db:"pack_name"`
	MaxDest      string         `db:"max_dest"`
	SelectorJSON string         `db:"selector_json"`
	AlertsJSON   string         `db:"alerts_json"`
	Enabled      int64          `db:"enabled"`
	AuthorizedBy string         `db:"authorized_by"`
	LastRunAt    sql.NullString `db:"last_run_at"`
	LastRunID    sql.NullString `db:"last_run_id"`
	CreatedAt    string         `db:"created_at"`
}

func (s *Store) InsertSchedule(ctx context.Context, sc Schedule) error {
	if sc.CreatedAt == "" {
		sc.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if sc.SelectorJSON == "" {
		sc.SelectorJSON = "{}"
	}
	if sc.AlertsJSON == "" {
		sc.AlertsJSON = "[]"
	}
	_, err := s.DB.NamedExecContext(ctx, `
		INSERT INTO schedules (
		  id, name, cron_expr, engagement_id, pack_name, max_dest,
		  selector_json, alerts_json, enabled, authorized_by,
		  last_run_at, last_run_id, created_at
		) VALUES (
		  :id, :name, :cron_expr, :engagement_id, :pack_name, :max_dest,
		  :selector_json, :alerts_json, :enabled, :authorized_by,
		  :last_run_at, :last_run_id, :created_at
		)
	`, sc)
	if err != nil {
		return fmt.Errorf("store: insert schedule: %w", err)
	}
	return nil
}

func (s *Store) ListSchedules(ctx context.Context, enabledOnly bool) ([]Schedule, error) {
	q := `SELECT * FROM schedules`
	if enabledOnly {
		q += ` WHERE enabled = 1`
	}
	q += ` ORDER BY name`
	var out []Schedule
	if err := s.DB.SelectContext(ctx, &out, q); err != nil {
		return nil, fmt.Errorf("store: list schedules: %w", err)
	}
	return out, nil
}

func (s *Store) GetScheduleByName(ctx context.Context, name string) (Schedule, error) {
	var sc Schedule
	err := s.DB.GetContext(ctx, &sc, `SELECT * FROM schedules WHERE name = ?`, name)
	if err != nil {
		return Schedule{}, fmt.Errorf("store: get schedule %s: %w", name, err)
	}
	return sc, nil
}

func (s *Store) DeleteScheduleByName(ctx context.Context, name string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM schedules WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("store: delete schedule: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("schedule %q not found", name)
	}
	return nil
}

func (s *Store) MarkScheduleRan(ctx context.Context, scheduleID, runID string) error {
	_, err := s.DB.ExecContext(ctx, `
		UPDATE schedules SET last_run_at = ?, last_run_id = ? WHERE id = ?
	`, time.Now().UTC().Format(time.RFC3339Nano), runID, scheduleID)
	return err
}

// PriorRunForSchedule returns the most recent reported run for the same
// engagement before beforeRunID (or the latest reported run when
// beforeRunID is empty). v1 scopes by engagement only; per-schedule
// scoping arrives when run rows record their schedule_id.
func (s *Store) PriorRunForSchedule(ctx context.Context, sc Schedule, beforeRunID string) (string, error) {
	var startedAt sql.NullString
	if beforeRunID != "" {
		if r, err := s.GetRun(ctx, beforeRunID); err == nil {
			startedAt = r.StartedAt
		}
	}
	const q = `
		SELECT id FROM runs
		WHERE engagement_id = ?
		  AND id != ?
		  AND phase = 'reported'
		  AND (? = '' OR started_at < ?)
		ORDER BY started_at DESC LIMIT 1`
	var prior string
	err := s.DB.GetContext(ctx, &prior, q,
		sc.EngagementID, beforeRunID, startedAt.String, startedAt.String)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("store: prior run for schedule: %w", err)
	}
	return prior, nil
}

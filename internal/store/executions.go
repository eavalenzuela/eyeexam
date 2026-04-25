package store

import (
	"context"
	"database/sql"
	"fmt"
)

type Execution struct {
	ID                 string         `db:"id"`
	RunID              string         `db:"run_id"`
	HostID             string         `db:"host_id"`
	TestID             string         `db:"test_id"`
	TestSource         string         `db:"test_source"`
	TestYAMLSHA256     string         `db:"test_yaml_sha256"`
	AttackTechnique    sql.NullString `db:"attack_technique"`
	AttackTactic       sql.NullString `db:"attack_tactic"`
	Destructiveness    string         `db:"destructiveness"`
	Runner             string         `db:"runner"`
	StartedAt          string         `db:"started_at"`
	FinishedAt         sql.NullString `db:"finished_at"`
	ExitCode           sql.NullInt64  `db:"exit_code"`
	DurationMS         sql.NullInt64  `db:"duration_ms"`
	StdoutPath         sql.NullString `db:"stdout_path"`
	StdoutInline       sql.NullString `db:"stdout_inline"`
	StderrPath         sql.NullString `db:"stderr_path"`
	StderrInline       sql.NullString `db:"stderr_inline"`
	CleanupState       string         `db:"cleanup_state"`
	CleanupVerifyState string         `db:"cleanup_verify_state"`
	DetectionState     string         `db:"detection_state"`
}

func (s *Store) InsertExecution(ctx context.Context, e Execution) error {
	_, err := s.DB.NamedExecContext(ctx, `
		INSERT INTO executions (
		  id, run_id, host_id, test_id, test_source, test_yaml_sha256,
		  attack_technique, attack_tactic, destructiveness, runner,
		  started_at, finished_at, exit_code, duration_ms,
		  stdout_path, stdout_inline, stderr_path, stderr_inline,
		  cleanup_state, cleanup_verify_state, detection_state
		) VALUES (
		  :id, :run_id, :host_id, :test_id, :test_source, :test_yaml_sha256,
		  :attack_technique, :attack_tactic, :destructiveness, :runner,
		  :started_at, :finished_at, :exit_code, :duration_ms,
		  :stdout_path, :stdout_inline, :stderr_path, :stderr_inline,
		  :cleanup_state, :cleanup_verify_state, :detection_state
		)
	`, e)
	if err != nil {
		return fmt.Errorf("store: insert execution: %w", err)
	}
	return nil
}

func (s *Store) UpdateExecution(ctx context.Context, e Execution) error {
	_, err := s.DB.NamedExecContext(ctx, `
		UPDATE executions SET
		  finished_at = :finished_at,
		  exit_code = :exit_code,
		  duration_ms = :duration_ms,
		  stdout_path = :stdout_path,
		  stdout_inline = :stdout_inline,
		  stderr_path = :stderr_path,
		  stderr_inline = :stderr_inline,
		  cleanup_state = :cleanup_state,
		  cleanup_verify_state = :cleanup_verify_state,
		  detection_state = :detection_state
		WHERE id = :id
	`, e)
	if err != nil {
		return fmt.Errorf("store: update execution: %w", err)
	}
	return nil
}

func (s *Store) ListExecutionsForRun(ctx context.Context, runID string) ([]Execution, error) {
	var out []Execution
	if err := s.DB.SelectContext(ctx, &out, `
		SELECT * FROM executions WHERE run_id = ? ORDER BY started_at, id
	`, runID); err != nil {
		return nil, fmt.Errorf("store: list executions: %w", err)
	}
	return out, nil
}

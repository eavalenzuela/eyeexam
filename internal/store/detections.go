package store

import (
	"context"
	"database/sql"
	"fmt"
)

type ExpectedDetection struct {
	ID              string         `db:"id"`
	ExecutionID     string         `db:"execution_id"`
	ExpectationJSON string         `db:"expectation_json"`
	WaitSeconds     int            `db:"wait_seconds"`
	State           string         `db:"state"`
	DetectorName    sql.NullString `db:"detector_name"`
	Reason          sql.NullString `db:"reason"`
}

type DetectionHit struct {
	ID         string `db:"id"`
	ExpectedID string `db:"expected_id"`
	HitID      string `db:"hit_id"`
	HitAt      string `db:"hit_at"`
	RawJSON    string `db:"raw_json"`
}

func (s *Store) InsertExpectedDetection(ctx context.Context, e ExpectedDetection) error {
	_, err := s.DB.NamedExecContext(ctx, `
		INSERT INTO expected_detections (
		  id, execution_id, expectation_json, wait_seconds, state, detector_name, reason
		) VALUES (
		  :id, :execution_id, :expectation_json, :wait_seconds, :state, :detector_name, :reason
		)
	`, e)
	if err != nil {
		return fmt.Errorf("store: insert expected_detection: %w", err)
	}
	return nil
}

func (s *Store) UpdateExpectedDetection(ctx context.Context, e ExpectedDetection) error {
	_, err := s.DB.NamedExecContext(ctx, `
		UPDATE expected_detections SET
		  state = :state,
		  detector_name = :detector_name,
		  reason = :reason
		WHERE id = :id
	`, e)
	if err != nil {
		return fmt.Errorf("store: update expected_detection: %w", err)
	}
	return nil
}

func (s *Store) ListExpectedDetectionsForExecution(ctx context.Context, executionID string) ([]ExpectedDetection, error) {
	var out []ExpectedDetection
	err := s.DB.SelectContext(ctx, &out, `
		SELECT * FROM expected_detections WHERE execution_id = ? ORDER BY id
	`, executionID)
	if err != nil {
		return nil, fmt.Errorf("store: list expected_detections: %w", err)
	}
	return out, nil
}

func (s *Store) InsertDetectionHit(ctx context.Context, h DetectionHit) error {
	_, err := s.DB.NamedExecContext(ctx, `
		INSERT INTO detection_hits (id, expected_id, hit_id, hit_at, raw_json)
		VALUES (:id, :expected_id, :hit_id, :hit_at, :raw_json)
		ON CONFLICT(expected_id, hit_id) DO NOTHING
	`, h)
	if err != nil {
		return fmt.Errorf("store: insert detection_hit: %w", err)
	}
	return nil
}

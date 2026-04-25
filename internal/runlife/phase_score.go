package runlife

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/eavalenzuela/eyeexam/internal/detector"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/score"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// phaseScore computes per-expectation outcomes from query results and
// per-execution detection_state from the worst expectation. We re-query
// detectors here so the per-detector outcome (including errors) is
// authoritative for state. This is intentional: hit dedup happens at the
// store level; score correctness happens here.
func (e *Engine) phaseScore(ctx context.Context, runID string) error {
	execs, err := e.store.ListExecutionsForRun(ctx, runID)
	if err != nil {
		return err
	}
	for _, ex := range execs {
		t, err := e.testByID(ex.TestID)
		if err != nil {
			return err
		}
		expecteds, err := e.store.ListExpectedDetectionsForExecution(ctx, ex.ID)
		if err != nil {
			return err
		}
		if len(expecteds) == 0 {
			ex.DetectionState = "no_expectation"
			if err := e.store.UpdateExecution(ctx, ex); err != nil {
				return err
			}
			continue
		}
		outcomes := make([]score.ExpectationOutcome, 0, len(expecteds))
		for _, exp := range expecteds {
			outcome, err := e.scoreExpectation(ctx, exp, t)
			if err != nil {
				return err
			}
			outcomes = append(outcomes, outcome)
			// persist per-expectation state
			expRow := exp
			expRow.State = string(outcome.State)
			expRow.DetectorName = sql.NullString{String: outcome.DetectorName, Valid: outcome.DetectorName != ""}
			expRow.Reason = sql.NullString{String: outcome.Reason, Valid: outcome.Reason != ""}
			if err := e.store.UpdateExpectedDetection(ctx, expRow); err != nil {
				return err
			}
		}
		// Worst-state aggregation over per-expectation states.
		ex.DetectionState = string(score.WorstAcross(outcomes))
		if err := e.store.UpdateExecution(ctx, ex); err != nil {
			return err
		}
	}
	return nil
}

// scoreExpectation re-runs detector queries (same window) and aggregates
// per-detector outcomes. We rely on the (expected_id, hit_id) UNIQUE in
// detection_hits to keep this idempotent across re-scoring.
func (e *Engine) scoreExpectation(ctx context.Context, exp store.ExpectedDetection, t pack.Test) (score.ExpectationOutcome, error) {
	var expectation pack.Expectation
	if err := json.Unmarshal([]byte(exp.ExpectationJSON), &expectation); err != nil {
		return score.ExpectationOutcome{}, err
	}
	if e.detectors == nil {
		return score.ExpectationOutcome{
			State:  score.StateUncertain,
			Reason: "no detector registry configured",
		}, nil
	}
	matched := e.detectors.For(expectation)
	if len(matched) == 0 {
		return score.ExpectationOutcome{
			State:  score.StateUncertain,
			Reason: "no detector configured for backend=" + nonEmpty(expectation.Backend, "any"),
		}, nil
	}
	var per []score.PerDetectorOutcome
	// Use the same window as phase_query; we don't need exec timestamps
	// here because phase_query's hits are already in the store. We instead
	// use stored hits when available, and re-query only to surface errors
	// that occurred during phase_query (kept in memory if any).
	//
	// Simpler approach: re-run query against detectors. Hits dedup at the
	// store layer; for scoring we use the live detector responses.
	exec, err := e.execByID(ctx, exp.ExecutionID)
	if err != nil {
		return score.ExpectationOutcome{}, err
	}
	hostRow, err := e.store.GetHostByID(ctx, exec.HostID)
	if err != nil {
		return score.ExpectationOutcome{}, err
	}
	startedAt := exec.StartedAt
	finishedAt := exec.FinishedAt.String

	q := detector.ExpectationQuery{
		Expectation: expectation,
		HostID:      hostRow.ID,
		HostName:    hostRow.Name,
		ExecutionID: exec.ID,
		Window: detector.TimeWindow{
			Start: parseTimeOrZero(startedAt),
			End:   parseTimeOrZero(finishedAt).Add(durSecs(exp.WaitSeconds) + e.queryGrace),
		},
	}
	_ = t // unused but kept to clarify the scoring inputs
	for _, d := range matched {
		hits, err := d.Query(ctx, q)
		per = append(per, score.PerDetectorOutcome{
			DetectorName: d.Name(), Hits: hits, Err: err,
		})
	}
	return score.ScoreExpectation(per), nil
}

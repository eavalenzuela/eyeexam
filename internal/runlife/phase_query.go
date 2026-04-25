package runlife

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/detector"
	"github.com/eavalenzuela/eyeexam/internal/idgen"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// phaseQuery walks every execution's expected_detections rows and queries
// each detector that supports the expectation. Hits are deduped by the
// (expected_id, hit_id) unique constraint. Per-detector outcomes are
// stashed on the engine state for the score phase.
func (e *Engine) phaseQuery(ctx context.Context, runID string, actor audit.Actor) error {
	execs, err := e.store.ListExecutionsForRun(ctx, runID)
	if err != nil {
		return err
	}
	for _, ex := range execs {
		expecteds, err := e.store.ListExpectedDetectionsForExecution(ctx, ex.ID)
		if err != nil {
			return err
		}
		if len(expecteds) == 0 {
			continue
		}
		hostRow, err := e.store.GetHostByID(ctx, ex.HostID)
		if err != nil {
			return err
		}
		var h inventory.Host
		if err := json.Unmarshal([]byte(hostRow.InventoryJSON), &h); err != nil {
			return fmt.Errorf("runlife query: parse host: %w", err)
		}

		started, _ := time.Parse(time.RFC3339Nano, ex.StartedAt)
		finishedStr := ex.FinishedAt.String
		finished, _ := time.Parse(time.RFC3339Nano, finishedStr)

		for _, expRow := range expecteds {
			var expectation pack.Expectation
			if err := json.Unmarshal([]byte(expRow.ExpectationJSON), &expectation); err != nil {
				return fmt.Errorf("runlife query: parse expectation: %w", err)
			}
			window := detector.TimeWindow{
				Start: started,
				End:   finished.Add(time.Duration(expRow.WaitSeconds)*time.Second + e.queryGrace),
			}
			query := detector.ExpectationQuery{
				Expectation: expectation,
				HostID:      hostRow.ID,
				HostName:    hostRow.Name,
				HostAddress: h.Address,
				ExecutionID: ex.ID,
				Window:      window,
			}

			if err := e.queryOneExpectation(ctx, runID, actor, expRow, query); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Engine) queryOneExpectation(ctx context.Context, runID string, actor audit.Actor, expRow store.ExpectedDetection, query detector.ExpectationQuery) error {
	if e.detectors == nil {
		// No detectors configured at all → fast-path uncertain. The score
		// phase will pick this up.
		return nil
	}
	matched := e.detectors.For(query.Expectation)
	if len(matched) == 0 {
		if e.audit != nil {
			payload, _ := json.Marshal(map[string]any{
				"execution_id":   query.ExecutionID,
				"expectation_id": expRow.ID,
				"expectation":    query.Expectation,
				"reason":         "no detector configured for backend",
			})
			_, _ = e.audit.Append(ctx, audit.Record{
				Actor: actor, RunID: runID,
				Event: "expectation_skipped", Payload: payload,
			})
		}
		return nil
	}
	for _, d := range matched {
		hits, err := d.Query(ctx, query)
		if err != nil {
			e.log.Warn("detector query failed",
				"detector", d.Name(), "execution", query.ExecutionID, "err", err.Error())
			continue
		}
		for _, h := range hits {
			if err := e.store.InsertDetectionHit(ctx, store.DetectionHit{
				ID:         idgen.Hit(),
				ExpectedID: expRow.ID,
				HitID:      h.ID,
				HitAt:      h.At.UTC().Format(time.RFC3339Nano),
				RawJSON:    string(h.Raw),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

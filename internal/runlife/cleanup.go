package runlife

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func (e *Engine) phaseCleanup(ctx context.Context, runID string, actor audit.Actor) error {
	execs, err := e.store.ListExecutionsForRun(ctx, runID)
	if err != nil {
		return err
	}
	for _, ex := range execs {
		// Skip if already finalised on resume.
		if ex.CleanupState != "pending" && ex.CleanupVerifyState != "pending" {
			continue
		}
		if err := e.cleanupOne(ctx, runID, ex, actor); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) cleanupOne(ctx context.Context, runID string, ex store.Execution, actor audit.Actor) error {
	t, err := e.testByID(ex.TestID)
	if err != nil {
		return err
	}
	hostRow, err := e.store.GetHostByID(ctx, ex.HostID)
	if err != nil {
		return err
	}
	var h inventory.Host
	if err := json.Unmarshal([]byte(hostRow.InventoryJSON), &h); err != nil {
		return fmt.Errorf("runlife cleanup: parse host: %w", err)
	}
	rn, err := e.runnerFor(h)
	if err != nil {
		return err
	}

	if len(t.Cleanup) == 0 {
		ex.CleanupState = "no_cleanup_defined"
	} else {
		_, _, exit, _, runErr := runSteps(ctx, rn, h, t.Cleanup)
		if runErr != nil || exit != 0 {
			ex.CleanupState = "failed"
		} else {
			ex.CleanupState = "succeeded"
		}
	}

	if len(t.VerifyCleanup) == 0 {
		if t.Source == "atomic" {
			ex.CleanupVerifyState = "warned_atomic"
		} else {
			ex.CleanupVerifyState = "not_defined"
		}
	} else if ex.CleanupState == "failed" {
		ex.CleanupVerifyState = "failed"
	} else {
		_, _, exit, _, runErr := runSteps(ctx, rn, h, t.VerifyCleanup)
		if runErr != nil || exit != 0 {
			ex.CleanupVerifyState = "failed"
		} else {
			ex.CleanupVerifyState = "succeeded"
		}
	}

	if err := e.store.UpdateExecution(ctx, ex); err != nil {
		return err
	}

	if e.audit != nil && (ex.CleanupState == "failed" || ex.CleanupVerifyState == "failed") {
		payload, _ := json.Marshal(map[string]any{
			"execution_id":         ex.ID,
			"test_id":              ex.TestID,
			"cleanup_state":        ex.CleanupState,
			"cleanup_verify_state": ex.CleanupVerifyState,
		})
		_, _ = e.audit.Append(ctx, audit.Record{
			Actor: actor, RunID: runID,
			Event: "cleanup_failed", Payload: payload,
		})
	}
	return nil
}

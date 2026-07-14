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
		// Skip only if cleanup is in a terminal-ok state. A 'failed' cleanup is
		// retried here so a resume or `runs cleanup` can revert residue that a
		// prior interrupted/blocked attempt left behind.
		if !cleanupNeedsAttempt(ex) {
			continue
		}
		if err := e.cleanupOne(ctx, runID, ex, actor); err != nil {
			return err
		}
	}
	return nil
}

// cleanupNeedsAttempt reports whether an execution still needs a cleanup pass:
// its cleanup or its verify is pending (never run) or failed (a prior attempt
// did not complete). Failed is retryable — see hasPendingCleanup in the store.
func cleanupNeedsAttempt(ex store.Execution) bool {
	retryable := func(s string) bool { return s == "pending" || s == "failed" }
	return retryable(ex.CleanupState) || retryable(ex.CleanupVerifyState)
}

// DrainCleanup runs cleanup + cleanup-verify for every still-pending
// execution in runID, independent of the wait/query/score phases. It is the
// standalone recovery path behind `eyeexam runs cleanup <run-id>`: safe to
// invoke after a run was interrupted (EDR kill, Ctrl-C, power loss) so that
// file-modifying tests are reverted even though the run never reached its
// cleanup phase. Idempotent — already-finalised executions are skipped.
func (e *Engine) DrainCleanup(ctx context.Context, runID string, actor audit.Actor) error {
	return e.phaseCleanup(ctx, runID, actor)
}

// CleanupAllPending drains pending cleanups across every run that has any,
// returning the run ids it touched. Backs `eyeexam runs cleanup --all-pending`.
func (e *Engine) CleanupAllPending(ctx context.Context, actor audit.Actor) ([]string, error) {
	runIDs, err := e.store.ListRunsWithPendingCleanup(ctx)
	if err != nil {
		return nil, err
	}
	for _, id := range runIDs {
		if err := e.phaseCleanup(ctx, id, actor); err != nil {
			return runIDs, fmt.Errorf("runlife: drain cleanup for run %s: %w", id, err)
		}
	}
	return runIDs, nil
}

// cleanupExecByID runs cleanup for a single execution id if it is still
// pending. Used by eager cleanup mode right after a test executes.
func (e *Engine) cleanupExecByID(ctx context.Context, runID, exID string, actor audit.Actor) error {
	ex, err := e.execByID(ctx, exID)
	if err != nil {
		return err
	}
	if ex.CleanupState != "pending" && ex.CleanupVerifyState != "pending" {
		return nil
	}
	return e.cleanupOne(ctx, runID, ex, actor)
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
		_, _, exit, _, _, runErr := runSteps(ctx, rn, h, t.Cleanup, e.stepTimeout, map[string]string{
			"EYEEXAM_CONTROL_ID": ex.ID,
			"EYEEXAM_RUN_ID":     runID,
		})
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
		_, _, exit, _, _, runErr := runSteps(ctx, rn, h, t.VerifyCleanup, e.stepTimeout, map[string]string{
			"EYEEXAM_CONTROL_ID": ex.ID,
			"EYEEXAM_RUN_ID":     runID,
		})
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

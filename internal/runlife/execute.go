package runlife

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/idgen"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// Execute runs the full lifecycle for runID from its current phase forward.
// Idempotent at phase granularity.
func (e *Engine) Execute(ctx context.Context, runID string, actor audit.Actor) error {
	r, err := e.store.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	var plan Plan
	if err := json.Unmarshal([]byte(r.PlanJSON), &plan); err != nil {
		return fmt.Errorf("runlife: parse plan: %w", err)
	}

	if r.Phase == "planned" || r.Phase == "executing" {
		if err := e.store.MarkRunStarted(ctx, runID); err != nil {
			return err
		}
		if err := e.store.UpdateRunPhase(ctx, runID, "executing"); err != nil {
			return err
		}
		if err := e.phaseExecute(ctx, r, plan, actor); err != nil {
			return e.fail(ctx, runID, actor, err)
		}
	}

	// Phases waiting/querying/scoring stubbed in M1 — M3 will replace.
	if r.Phase != "reported" && r.Phase != "failed" {
		if err := e.store.UpdateRunPhase(ctx, runID, "waiting"); err != nil {
			return err
		}
		if err := e.store.UpdateRunPhase(ctx, runID, "querying"); err != nil {
			return err
		}
		if err := e.store.UpdateRunPhase(ctx, runID, "scoring"); err != nil {
			return err
		}
		if err := e.phaseFinaliseDetection(ctx, runID); err != nil {
			return e.fail(ctx, runID, actor, err)
		}
		if err := e.store.UpdateRunPhase(ctx, runID, "cleanup"); err != nil {
			return err
		}
		if err := e.phaseCleanup(ctx, runID, actor); err != nil {
			return e.fail(ctx, runID, actor, err)
		}
		if err := e.store.UpdateRunPhase(ctx, runID, "reported"); err != nil {
			return err
		}
		if err := e.store.MarkRunFinished(ctx, runID); err != nil {
			return err
		}
	}

	if e.audit != nil {
		_, _ = e.audit.Append(ctx, audit.Record{
			Actor: actor, Engagement: r.EngagementID, RunID: runID,
			Event: "run_finished", Payload: json.RawMessage(`{}`),
		})
	}
	return nil
}

// Resume re-enters the engine for a partially complete run.
func (e *Engine) Resume(ctx context.Context, runID string, actor audit.Actor) error {
	return e.Execute(ctx, runID, actor)
}

func (e *Engine) phaseExecute(ctx context.Context, r store.Run, plan Plan, actor audit.Actor) error {
	already, err := e.store.ListExecutionsForRun(ctx, r.ID)
	if err != nil {
		return err
	}
	done := map[string]bool{}
	for _, ex := range already {
		done[ex.HostID+"|"+ex.TestID] = true
	}

	for _, pt := range plan.Tests {
		if done[pt.HostID+"|"+pt.TestID] {
			continue
		}
		if err := e.limiter.Wait(ctx); err != nil {
			return err
		}
		if err := e.hostSem.Acquire(ctx, pt.HostID); err != nil {
			return err
		}
		err := e.executeOneTest(ctx, r, pt, actor)
		e.hostSem.Release(pt.HostID)
		if err != nil {
			// Abort the run on per-test infrastructure failures (runner
			// not found, store write failure). Test exit-code != 0 is
			// captured as exit_code on the row, not a Go error.
			return err
		}
	}
	return nil
}

func (e *Engine) executeOneTest(ctx context.Context, r store.Run, pt PlannedTest, actor audit.Actor) error {
	t, err := e.testByID(pt.TestID)
	if err != nil {
		return err
	}
	hostRow, err := e.store.GetHostByName(ctx, pt.HostName)
	if err != nil {
		return err
	}
	var h inventory.Host
	if err := json.Unmarshal([]byte(hostRow.InventoryJSON), &h); err != nil {
		return fmt.Errorf("runlife: parse host %s: %w", hostRow.Name, err)
	}
	rn, err := e.runnerFor(h)
	if err != nil {
		return err
	}

	exID := idgen.Execution()
	startedAt := time.Now().UTC().Format(time.RFC3339Nano)

	exec := store.Execution{
		ID:                 exID,
		RunID:              r.ID,
		HostID:             hostRow.ID,
		TestID:             t.ID,
		TestSource:         string(t.Source),
		TestYAMLSHA256:     t.YAMLSHA256,
		Destructiveness:    string(t.Destructiveness),
		Runner:             rn.Name(),
		StartedAt:          startedAt,
		CleanupState:       "pending",
		CleanupVerifyState: "pending",
		DetectionState:     "pending",
	}
	if t.Attack.Technique != "" {
		exec.AttackTechnique = sql.NullString{String: t.Attack.Technique, Valid: true}
	}
	if t.Attack.Tactic != "" {
		exec.AttackTactic = sql.NullString{String: t.Attack.Tactic, Valid: true}
	}
	if err := e.store.InsertExecution(ctx, exec); err != nil {
		return err
	}

	stdout, stderr, exitCode, dur, runErr := runSteps(ctx, rn, h, t.Execute)
	exec.FinishedAt = sql.NullString{String: time.Now().UTC().Format(time.RFC3339Nano), Valid: true}
	exec.ExitCode = sql.NullInt64{Int64: int64(exitCode), Valid: true}
	exec.DurationMS = sql.NullInt64{Int64: dur.Milliseconds(), Valid: true}
	exec.StdoutInline = inlineOrNull(stdout)
	exec.StderrInline = inlineOrNull(stderr)

	if e.audit != nil {
		payload, _ := json.Marshal(map[string]any{
			"execution_id": exID,
			"host":         h.Name,
			"test_id":      t.ID,
			"exit_code":    exitCode,
			"runner_err":   errString(runErr),
		})
		_, _ = e.audit.Append(ctx, audit.Record{
			Actor: actor, Engagement: r.EngagementID, RunID: r.ID,
			Event: "test_executed", Payload: payload,
		})
	}

	if err := e.store.UpdateExecution(ctx, exec); err != nil {
		return err
	}
	return nil
}

// runSteps executes a slice of pack steps in order, returning combined stdout
// and stderr plus the final exit code. Stops at the first non-zero exit.
func runSteps(ctx context.Context, rn runner.Runner, host inventory.Host, steps []pack.Step) (stdout, stderr []byte, exitCode int, total time.Duration, err error) {
	for _, s := range steps {
		res, runErr := rn.Execute(ctx, host, runner.ExecuteStep{
			Shell: s.Shell, Command: s.Command,
		})
		stdout = append(stdout, res.Stdout...)
		stderr = append(stderr, res.Stderr...)
		total += res.Duration()
		if runErr != nil {
			return stdout, stderr, -1, total, runErr
		}
		if res.ExitCode != 0 {
			return stdout, stderr, res.ExitCode, total, nil
		}
	}
	return stdout, stderr, 0, total, nil
}

func inlineOrNull(b []byte) sql.NullString {
	if len(b) == 0 {
		return sql.NullString{}
	}
	const maxInline = 64 * 1024
	if len(b) > maxInline {
		b = b[:maxInline]
	}
	return sql.NullString{String: string(b), Valid: true}
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// phaseFinaliseDetection sets detection_state to no_expectation for any
// execution whose test had no expectations defined. M3 replaces this with
// real wait/query/score logic.
func (e *Engine) phaseFinaliseDetection(ctx context.Context, runID string) error {
	execs, err := e.store.ListExecutionsForRun(ctx, runID)
	if err != nil {
		return err
	}
	for _, ex := range execs {
		t, err := e.testByID(ex.TestID)
		if err != nil {
			return err
		}
		if len(t.Expectations) == 0 {
			ex.DetectionState = "no_expectation"
		} else {
			// M1 has no detector; surface honestly as uncertain rather
			// than caught/missed.
			ex.DetectionState = "uncertain"
		}
		if err := e.store.UpdateExecution(ctx, ex); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) fail(ctx context.Context, runID string, actor audit.Actor, cause error) error {
	_ = e.store.UpdateRunPhase(ctx, runID, "failed")
	_ = e.store.MarkRunFinished(ctx, runID)
	if e.audit != nil {
		payload, _ := json.Marshal(map[string]string{"reason": cause.Error()})
		_, _ = e.audit.Append(ctx, audit.Record{
			Actor: actor, RunID: runID,
			Event: "run_failed", Payload: payload,
		})
	}
	return cause
}

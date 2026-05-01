package runlife

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

	if r.Phase != "reported" && r.Phase != "failed" {
		if err := e.store.UpdateRunPhase(ctx, runID, "waiting"); err != nil {
			return err
		}
		if err := e.phaseWait(ctx, runID); err != nil {
			return e.fail(ctx, runID, actor, err)
		}
		if err := e.store.UpdateRunPhase(ctx, runID, "querying"); err != nil {
			return err
		}
		if err := e.phaseQuery(ctx, runID, actor); err != nil {
			return e.fail(ctx, runID, actor, err)
		}
		if err := e.store.UpdateRunPhase(ctx, runID, "scoring"); err != nil {
			return err
		}
		if err := e.phaseScore(ctx, runID); err != nil {
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

	skippedHosts := map[string]bool{}
	for _, pt := range plan.Tests {
		if done[pt.HostID+"|"+pt.TestID] {
			continue
		}
		if skippedHosts[pt.HostID] {
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
			// If the failure is a per-host issue (runner missing,
			// dial failure, host_skipped), record host_skipped and
			// keep the run going for other hosts. Bail only on
			// store-level errors.
			if isHostLevelError(err) {
				skippedHosts[pt.HostID] = true
				if e.audit != nil {
					payload, _ := json.Marshal(map[string]any{
						"host_id": pt.HostID,
						"host":    pt.HostName,
						"reason":  err.Error(),
					})
					_, _ = e.audit.Append(ctx, audit.Record{
						Actor: actor, Engagement: r.EngagementID, RunID: r.ID,
						Event: "host_skipped", Payload: payload,
					})
				}
				e.log.Warn("host skipped",
					"host", pt.HostName, "run", r.ID, "reason", err.Error())
				continue
			}
			return err
		}
	}
	return nil
}

// isHostLevelError returns true for runner / dial / shell errors that scope
// to a single host. Store-level errors propagate as run-level failures.
func isHostLevelError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, runner.ErrUnsupportedShell) {
		return true
	}
	msg := err.Error()
	for _, sub := range []string{"ssh:", "runner local:", "no runner registered", "ssh exec"} {
		if containsCaseSensitive(msg, sub) {
			return true
		}
	}
	return false
}

func containsCaseSensitive(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
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

	stdout, stderr, exitCode, dur, extra, runErr := runSteps(ctx, rn, h, t.Execute, map[string]string{
		"EYEEXAM_CONTROL_ID": exID,
		"EYEEXAM_RUN_ID":     r.ID,
		"EYEEXAM_ENGAGEMENT": r.EngagementID,
	})
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
			"runner_extra": extra,
		})
		_, _ = e.audit.Append(ctx, audit.Record{
			Actor: actor, Engagement: r.EngagementID, RunID: r.ID,
			Event: "test_executed", Payload: payload,
		})
	}

	if err := e.store.UpdateExecution(ctx, exec); err != nil {
		return err
	}
	if err := e.persistExpectedDetections(ctx, exec, t); err != nil {
		return err
	}
	return nil
}

// runSteps executes a slice of pack steps in order, returning combined
// stdout / stderr / exit / duration plus an Extra map merged across all
// steps' Result.Extra. Stops at the first non-zero exit.
func runSteps(ctx context.Context, rn runner.Runner, host inventory.Host, steps []pack.Step, env map[string]string) (stdout, stderr []byte, exitCode int, total time.Duration, extra map[string]string, err error) {
	for _, s := range steps {
		res, runErr := rn.Execute(ctx, host, runner.ExecuteStep{
			Shell: s.Shell, Command: s.Command, Env: env,
		})
		stdout = append(stdout, res.Stdout...)
		stderr = append(stderr, res.Stderr...)
		total += res.Duration()
		if extra == nil && len(res.Extra) > 0 {
			extra = make(map[string]string, len(res.Extra))
		}
		for k, v := range res.Extra {
			extra[k] = v
		}
		if runErr != nil {
			return stdout, stderr, -1, total, extra, runErr
		}
		if res.ExitCode != 0 {
			return stdout, stderr, res.ExitCode, total, extra, nil
		}
	}
	return stdout, stderr, 0, total, extra, nil
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

// persistExpectedDetections writes one expected_detections row per
// expectation on the test, called once at execute-finalise time before the
// wait phase. We use a stable id derived from execution_id + index so the
// rows are idempotent across resume.
func (e *Engine) persistExpectedDetections(ctx context.Context, ex store.Execution, t pack.Test) error {
	existing, err := e.store.ListExpectedDetectionsForExecution(ctx, ex.ID)
	if err != nil {
		return err
	}
	if len(existing) == len(t.Expectations) {
		return nil // already persisted on a previous run
	}
	wait := t.WaitSeconds
	if wait == 0 {
		wait = 60
	}
	for i, exp := range t.Expectations {
		expJSON, _ := json.Marshal(exp)
		if err := e.store.InsertExpectedDetection(ctx, store.ExpectedDetection{
			ID:              ex.ID + "-e" + itoa(i),
			ExecutionID:     ex.ID,
			ExpectationJSON: string(expJSON),
			WaitSeconds:     wait,
			State:           "pending",
		}); err != nil {
			return err
		}
	}
	return nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
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

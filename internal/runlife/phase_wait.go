package runlife

import (
	"context"
	"fmt"
	"time"
)

// phaseWait sleeps until every execution has had its wait_seconds elapse
// since finished_at. The longest wait wins; we sleep once for the residual.
func (e *Engine) phaseWait(ctx context.Context, runID string) error {
	execs, err := e.store.ListExecutionsForRun(ctx, runID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var deadline time.Time
	for _, ex := range execs {
		t, err := e.testByID(ex.TestID)
		if err != nil {
			return err
		}
		// No expectations on this test → no need to wait for ingestion;
		// the score phase will mark detection_state=no_expectation.
		if len(t.Expectations) == 0 {
			continue
		}
		wait := t.WaitSeconds
		if wait == 0 {
			wait = 60
		}
		if !ex.FinishedAt.Valid {
			continue
		}
		fin, err := time.Parse(time.RFC3339Nano, ex.FinishedAt.String)
		if err != nil {
			return fmt.Errorf("runlife: parse finished_at %q: %w", ex.FinishedAt.String, err)
		}
		d := fin.Add(time.Duration(wait) * time.Second)
		if d.After(deadline) {
			deadline = d
		}
	}
	if deadline.IsZero() || !deadline.After(now) {
		return nil
	}
	wait := deadline.Sub(now)
	e.log.Info("waiting for detector ingestion", "run", runID, "wait", wait.String())

	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

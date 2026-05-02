package report

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/store"
)

// RunReport is the structured form of a single-run readout. It bundles
// the run row, its executions (with host names resolved), expected
// detections, and audit events filtered to that run.
type RunReport struct {
	Title        string            `json:"-"` // for HTML layout
	GeneratedAt  time.Time         `json:"generated_at"`
	Run          store.Run         `json:"run"`
	HostNames    map[string]string `json:"host_names"`
	Executions   []store.Execution `json:"executions"`
	Expectations []ExpectationRow  `json:"expectations"`
	AuditEvents  []AuditEntry      `json:"audit_events"`
}

// ExpectationRow is a per-execution expectation flattened with the
// owning execution id for table-friendly rendering.
type ExpectationRow struct {
	ExecutionID string `json:"execution_id"`
	store.ExpectedDetection
}

// BuildRun assembles the run-detail report. Returns an error if the
// run id doesn't exist.
func BuildRun(ctx context.Context, st *store.Store, runID string) (*RunReport, error) {
	if runID == "" {
		return nil, fmt.Errorf("report: run id required")
	}
	run, err := st.GetRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	execs, err := st.ListExecutionsForRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("list executions: %w", err)
	}
	hostNames := map[string]string{}
	for _, ex := range execs {
		if _, ok := hostNames[ex.HostID]; ok {
			continue
		}
		if h, err := st.GetHostByID(ctx, ex.HostID); err == nil {
			hostNames[ex.HostID] = h.Name
		}
	}
	var expectations []ExpectationRow
	for _, ex := range execs {
		eds, err := st.ListExpectedDetectionsForExecution(ctx, ex.ID)
		if err != nil {
			return nil, fmt.Errorf("list expectations: %w", err)
		}
		for _, ed := range eds {
			expectations = append(expectations, ExpectationRow{
				ExecutionID:       ex.ID,
				ExpectedDetection: ed,
			})
		}
	}
	auditRows, err := st.ListAudit(ctx, store.AuditFilter{RunID: runID, Limit: 1000})
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	auditEntries := make([]AuditEntry, 0, len(auditRows))
	for _, r := range auditRows {
		t, _ := time.Parse(time.RFC3339Nano, r.TS)
		auditEntries = append(auditEntries, AuditEntry{
			Seq:     r.Seq,
			TS:      t,
			Event:   r.Event,
			Actor:   summarizeActor(r.ActorJSON),
			RunID:   r.RunID.String,
			Payload: r.PayloadJSON,
		})
	}
	return &RunReport{
		Title:        "Run " + runID,
		GeneratedAt:  time.Now().UTC(),
		Run:          run,
		HostNames:    hostNames,
		Executions:   execs,
		Expectations: expectations,
		AuditEvents:  auditEntries,
	}, nil
}

// RenderHTMLRun renders the run report as a standalone HTML document.
func RenderHTMLRun(r *RunReport) ([]byte, error) {
	return renderHTML("run.html", r)
}

// RenderJSONRun returns the run report as indented JSON.
func RenderJSONRun(r *RunReport) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

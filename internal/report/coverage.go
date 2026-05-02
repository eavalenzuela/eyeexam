// Package report renders engagement-scoped summaries from the SQLite
// store. Reports are the operator-facing readout — quarterly reviews,
// audit handoffs, post-incident retrospectives — not real-time
// observability. eyeexam is a periodic-batch tool whose outputs are
// reports; metrics dashboards are an analogy that doesn't fit.
package report

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/attack"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// Coverage is the structured form of a coverage report. Renderers
// (HTML, JSON) consume this; CLI parses operator flags into a
// CoverageRequest, builds Coverage via Build, picks a renderer.
type Coverage struct {
	Title          string         `json:"-"` // for HTML layout
	Engagement     string         `json:"engagement"`
	GeneratedAt    time.Time      `json:"generated_at"`
	Window         Window         `json:"window"`
	RunCount       int            `json:"run_count"`
	ReportedCount  int            `json:"reported_count"`
	FailedCount    int            `json:"failed_count"`
	ExecCount      int            `json:"executions"`
	StateCounts    StateCounts    `json:"state_counts"`
	RefusedCount   int            `json:"refused_count"`
	Techniques     []TechniqueRow `json:"techniques"`
	Regressions    []Regression   `json:"regressions"`
	DestructiveOps []AuditEntry   `json:"destructive_authorizations"`
	UnsignedPacks  []AuditEntry   `json:"unsigned_pack_loads"`
}

type Window struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

type StateCounts struct {
	Caught        int `json:"caught"`
	Missed        int `json:"missed"`
	Uncertain     int `json:"uncertain"`
	NoExpectation int `json:"no_expectation"`
	Pending       int `json:"pending"`
}

type TechniqueRow struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name,omitempty"`
	Tactic        string `json:"tactic,omitempty"`
	Caught        int    `json:"caught"`
	Missed        int    `json:"missed"`
	Uncertain     int    `json:"uncertain"`
	Latest        string `json:"latest"` // most recent state, eg "caught"
}

type Regression struct {
	TechniqueID string    `json:"technique_id"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	At          time.Time `json:"at"`
	RunID       string    `json:"run_id"`
}

type AuditEntry struct {
	Seq     int64     `json:"seq"`
	TS      time.Time `json:"ts"`
	Event   string    `json:"event"`
	Actor   string    `json:"actor"`
	RunID   string    `json:"run_id"`
	Payload string    `json:"payload"`
}

// CoverageRequest is what the CLI hands to Build.
type CoverageRequest struct {
	Engagement string
	Since      time.Time        // zero → 30d before now
	Now        func() time.Time // injectable for tests
}

func Build(ctx context.Context, st *store.Store, _ *attack.Bundle, req CoverageRequest) (*Coverage, error) {
	if req.Engagement == "" {
		return nil, fmt.Errorf("report: engagement required")
	}
	if req.Now == nil {
		req.Now = func() time.Time { return time.Now().UTC() }
	}
	now := req.Now().UTC()
	since := req.Since
	if since.IsZero() {
		since = now.Add(-30 * 24 * time.Hour)
	}

	cov := &Coverage{
		Title:       "Coverage report — " + req.Engagement,
		Engagement:  req.Engagement,
		GeneratedAt: now,
		Window:      Window{Since: since, Until: now},
	}

	runs, err := st.ListRuns(ctx, req.Engagement, 10_000)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	runsInWindow := make([]store.Run, 0, len(runs))
	for _, r := range runs {
		if !r.StartedAt.Valid {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, r.StartedAt.String)
		if err != nil {
			continue
		}
		if t.Before(since) || t.After(now) {
			continue
		}
		runsInWindow = append(runsInWindow, r)
		switch r.Phase {
		case "reported":
			cov.ReportedCount++
		case "failed":
			cov.FailedCount++
		}
	}
	cov.RunCount = len(runsInWindow)

	type techEvent struct {
		state string
		at    time.Time
		runID string
	}
	type techAgg struct {
		caught, missed, uncertain int
		events                    []techEvent
	}
	techs := map[string]*techAgg{}

	for _, r := range runsInWindow {
		execs, err := st.ListExecutionsForRun(ctx, r.ID)
		if err != nil {
			return nil, fmt.Errorf("list execs %s: %w", r.ID, err)
		}
		cov.ExecCount += len(execs)
		for _, ex := range execs {
			switch ex.DetectionState {
			case "caught":
				cov.StateCounts.Caught++
			case "missed":
				cov.StateCounts.Missed++
			case "uncertain":
				cov.StateCounts.Uncertain++
			case "no_expectation":
				cov.StateCounts.NoExpectation++
			case "pending":
				cov.StateCounts.Pending++
			}
			tech := ex.AttackTechnique.String
			if tech == "" {
				continue
			}
			ag := techs[tech]
			if ag == nil {
				ag = &techAgg{}
				techs[tech] = ag
			}
			switch ex.DetectionState {
			case "caught":
				ag.caught++
			case "missed":
				ag.missed++
			case "uncertain":
				ag.uncertain++
			}
			if ex.FinishedAt.Valid {
				if t, err := time.Parse(time.RFC3339Nano, ex.FinishedAt.String); err == nil {
					ag.events = append(ag.events, techEvent{
						state: ex.DetectionState, at: t, runID: r.ID,
					})
				}
			}
		}
	}

	for techID, ag := range techs {
		// Sort events chronologically — runs come back DESC from
		// ListRuns, so we must order before computing latest +
		// prior-different state.
		sort.Slice(ag.events, func(i, j int) bool {
			return ag.events[i].at.Before(ag.events[j].at)
		})
		var latest, prior techEvent
		for _, e := range ag.events {
			if e.state != latest.state && latest.state != "" {
				prior = latest
			}
			latest = e
		}
		cov.Techniques = append(cov.Techniques, TechniqueRow{
			TechniqueID: techID,
			Caught:      ag.caught,
			Missed:      ag.missed,
			Uncertain:   ag.uncertain,
			Latest:      latest.state,
		})
		if isWorse(prior.state, latest.state) {
			cov.Regressions = append(cov.Regressions, Regression{
				TechniqueID: techID,
				From:        prior.state,
				To:          latest.state,
				At:          latest.at,
				RunID:       latest.runID,
			})
		}
	}
	sort.Slice(cov.Techniques, func(i, j int) bool {
		return cov.Techniques[i].TechniqueID < cov.Techniques[j].TechniqueID
	})
	sort.Slice(cov.Regressions, func(i, j int) bool {
		return cov.Regressions[i].At.After(cov.Regressions[j].At)
	})

	cov.DestructiveOps = collectAudit(ctx, st, store.AuditFilter{
		EngagementID: req.Engagement,
		Event:        "destructive_run_authorized",
		SinceTS:      since.Format(time.RFC3339Nano),
	})
	cov.UnsignedPacks = collectAudit(ctx, st, store.AuditFilter{
		EngagementID: req.Engagement,
		Event:        "pack_loaded_unsigned",
		SinceTS:      since.Format(time.RFC3339Nano),
	})

	for _, r := range runsInWindow {
		var p struct {
			Refused []string `json:"refused"`
		}
		_ = json.Unmarshal([]byte(r.PlanJSON), &p)
		cov.RefusedCount += len(p.Refused)
	}

	return cov, nil
}

func collectAudit(ctx context.Context, st *store.Store, f store.AuditFilter) []AuditEntry {
	rows, err := st.ListAudit(ctx, f)
	if err != nil {
		return nil
	}
	out := make([]AuditEntry, 0, len(rows))
	for _, r := range rows {
		t, _ := time.Parse(time.RFC3339Nano, r.TS)
		out = append(out, AuditEntry{
			Seq:     r.Seq,
			TS:      t,
			Event:   r.Event,
			Actor:   summarizeActor(r.ActorJSON),
			RunID:   r.RunID.String,
			Payload: r.PayloadJSON,
		})
	}
	return out
}

func summarizeActor(actorJSON string) string {
	var a struct {
		OSUser  string  `json:"os_user"`
		OSUID   int     `json:"os_uid"`
		AppUser *string `json:"app_user,omitempty"`
	}
	if err := json.Unmarshal([]byte(actorJSON), &a); err != nil {
		return actorJSON
	}
	if a.AppUser != nil {
		return fmt.Sprintf("%s/%s(uid=%d)", *a.AppUser, a.OSUser, a.OSUID)
	}
	return fmt.Sprintf("%s(uid=%d)", a.OSUser, a.OSUID)
}

// isWorse returns true if `to` is strictly worse than `from` in the
// detection-state ordering (caught < uncertain < missed). Empty `from`
// means there's no prior state to compare to, so no regression.
func isWorse(from, to string) bool {
	rank := func(s string) int {
		switch s {
		case "caught":
			return 0
		case "uncertain":
			return 1
		case "missed":
			return 2
		default:
			return -1
		}
	}
	rf, rt := rank(from), rank(to)
	if rf < 0 || rt < 0 {
		return false
	}
	return rt > rf
}

// RenderHTMLCoverage returns Coverage as a standalone HTML document.
func RenderHTMLCoverage(c *Coverage) ([]byte, error) {
	if c.Title == "" {
		c.Title = "Coverage report — " + c.Engagement
	}
	return renderHTML("coverage.html", c)
}

// RenderJSONCoverage returns Coverage as indented JSON.
func RenderJSONCoverage(c *Coverage) ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

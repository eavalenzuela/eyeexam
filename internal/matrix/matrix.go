// Package matrix builds the ATT&CK heatmap from store data and renders it
// as either standalone HTML (for `eyeexam matrix --out matrix.html`) or
// JSON (for embedding in other dashboards / drift comparisons).
package matrix

import (
	"context"
	"sort"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/attack"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// CellState mirrors PLAN.md §"ATT&CK matrix":
//
//	green  — most recent run for this technique was caught
//	yellow — most recent run is uncertain
//	red    — most recent run is missed
//	grey   — no test for this technique in the configured packs
type CellState string

const (
	StateGreen  CellState = "green"
	StateYellow CellState = "yellow"
	StateRed    CellState = "red"
	StateGrey   CellState = "grey"
)

// Cell is one parent-technique cell in the matrix.
type Cell struct {
	TechniqueID   string
	TechniqueName string
	State         CellState
	// Counts across the configured time window:
	Caught    int
	Missed    int
	Uncertain int
	// LastRunAt is the most recent execution.started_at for this technique.
	LastRunAt time.Time
}

// Matrix is the rendered grid: tactics as columns, parent techniques as
// rows under each tactic.
type Matrix struct {
	GeneratedAt time.Time
	Window      Window
	Tactics     []TacticColumn
	// Drift lists techniques that regressed from green→yellow/red within
	// the window, ordered most-recent-regression first.
	Drift []DriftEntry
}

type TacticColumn struct {
	ID    string
	Name  string
	Cells []Cell
}

type Window struct {
	Since time.Time
	Until time.Time
}

type DriftEntry struct {
	TechniqueID   string
	TechniqueName string
	From          CellState
	To            CellState
	At            time.Time
}

// Build queries the store for executions in the window and projects the
// per-technique latest state onto the bundle's tactic grid.
//
// Drift detection compares each technique's latest state inside the
// window with its previous state strictly before the window's first
// execution for that technique. It is best-effort: if the previous run is
// outside the store retention horizon, no drift entry is emitted.
func Build(ctx context.Context, st *store.Store, b *attack.Bundle, since time.Time) (*Matrix, error) {
	if since.IsZero() {
		since = time.Now().UTC().Add(-30 * 24 * time.Hour)
	}
	until := time.Now().UTC()

	// Pull all executions and their per-technique latest detection state.
	rows, err := loadByTechnique(ctx, st, since, until)
	if err != nil {
		return nil, err
	}
	priorState, err := loadPriorByTechnique(ctx, st, since)
	if err != nil {
		return nil, err
	}

	m := &Matrix{
		GeneratedAt: time.Now().UTC(),
		Window:      Window{Since: since, Until: until},
	}
	for _, ta := range b.SortedTactics() {
		col := TacticColumn{ID: ta.ID, Name: ta.Name}
		for _, t := range b.TechniquesForTactic(ta.ID) {
			cell := Cell{TechniqueID: t.ID, TechniqueName: t.Name, State: StateGrey}
			// roll up the parent + every subtechnique under it
			summary := mergeSummary(rows, t.ID, b)
			if summary != nil {
				cell.Caught = summary.caught
				cell.Missed = summary.missed
				cell.Uncertain = summary.uncertain
				cell.LastRunAt = summary.lastAt
				cell.State = stateFromLatest(summary.latestState)
			}
			col.Cells = append(col.Cells, cell)
		}
		sort.SliceStable(col.Cells, func(i, j int) bool {
			return col.Cells[i].TechniqueID < col.Cells[j].TechniqueID
		})
		m.Tactics = append(m.Tactics, col)
	}

	// Drift: any technique whose latest-in-window state is worse than its
	// prior-to-window state. Subtechnique prior states roll up to the
	// parent the same way current-window summaries do.
	for _, ta := range b.SortedTactics() {
		for _, t := range b.TechniquesForTactic(ta.ID) {
			summary := mergeSummary(rows, t.ID, b)
			if summary == nil {
				continue
			}
			prior := mergePriorState(priorState, t.ID, b)
			if prior == "" {
				continue
			}
			from := stateFromLatest(prior)
			to := stateFromLatest(summary.latestState)
			if rank(to) > rank(from) {
				m.Drift = append(m.Drift, DriftEntry{
					TechniqueID: t.ID, TechniqueName: t.Name,
					From: from, To: to, At: summary.lastAt,
				})
			}
		}
	}
	sort.SliceStable(m.Drift, func(i, j int) bool { return m.Drift[i].At.After(m.Drift[j].At) })

	return m, nil
}

func rank(s CellState) int {
	switch s {
	case StateGreen:
		return 0
	case StateYellow:
		return 1
	case StateRed:
		return 2
	default:
		return -1
	}
}

func stateFromLatest(detect string) CellState {
	switch detect {
	case "caught":
		return StateGreen
	case "uncertain":
		return StateYellow
	case "missed":
		return StateRed
	case "no_expectation":
		// We have a test but no expectation → operator wasn't measuring
		// detection; show as grey to avoid implying "not caught".
		return StateGrey
	default:
		return StateGrey
	}
}

type techSummary struct {
	caught      int
	missed      int
	uncertain   int
	latestState string
	lastAt      time.Time
}

func mergeSummary(rows map[string]*techSummary, parentID string, b *attack.Bundle) *techSummary {
	merged := &techSummary{}
	contributed := false

	collect := func(id string) {
		if s, ok := rows[id]; ok {
			contributed = true
			merged.caught += s.caught
			merged.missed += s.missed
			merged.uncertain += s.uncertain
			if s.lastAt.After(merged.lastAt) {
				merged.lastAt = s.lastAt
				merged.latestState = s.latestState
			}
		}
	}
	collect(parentID)
	for _, sub := range b.SubtechniquesOf(parentID) {
		collect(sub.ID)
	}
	if !contributed {
		return nil
	}
	return merged
}

// loadByTechnique groups executions in [since, until] by attack_technique
// and returns counts + the latest state per technique.
func loadByTechnique(ctx context.Context, st *store.Store, since, until time.Time) (map[string]*techSummary, error) {
	type row struct {
		Technique string `db:"attack_technique"`
		StartedAt string `db:"started_at"`
		Detection string `db:"detection_state"`
	}
	var rows []row
	err := st.DB.SelectContext(ctx, &rows, `
		SELECT
		  COALESCE(attack_technique, '') AS attack_technique,
		  started_at,
		  detection_state
		FROM executions
		WHERE started_at >= ? AND started_at <= ? AND attack_technique IS NOT NULL
	`, since.UTC().Format(time.RFC3339Nano), until.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	out := map[string]*techSummary{}
	for _, r := range rows {
		if r.Technique == "" {
			continue
		}
		s, ok := out[r.Technique]
		if !ok {
			s = &techSummary{}
			out[r.Technique] = s
		}
		switch r.Detection {
		case "caught":
			s.caught++
		case "missed":
			s.missed++
		case "uncertain":
			s.uncertain++
		}
		started, _ := time.Parse(time.RFC3339Nano, r.StartedAt)
		if started.After(s.lastAt) {
			s.lastAt = started
			s.latestState = r.Detection
		}
	}
	return out, nil
}

// mergePriorState rolls subtechnique prior states up to a parent, picking
// the one with the highest detection-state severity (worst-case prior so
// that drift is conservative — we don't claim a regression where one
// previously didn't exist on the parent technique).
func mergePriorState(prior map[string]string, parentID string, b *attack.Bundle) string {
	worst := ""
	consider := func(id string) {
		s, ok := prior[id]
		if !ok {
			return
		}
		if rank(stateFromLatest(s)) > rank(stateFromLatest(worst)) || worst == "" {
			worst = s
		}
	}
	consider(parentID)
	for _, sub := range b.SubtechniquesOf(parentID) {
		consider(sub.ID)
	}
	return worst
}

// loadPriorByTechnique returns the latest detection_state strictly before
// `before`, per technique. Used to compute drift entries.
func loadPriorByTechnique(ctx context.Context, st *store.Store, before time.Time) (map[string]string, error) {
	type row struct {
		Technique string `db:"attack_technique"`
		StartedAt string `db:"started_at"`
		Detection string `db:"detection_state"`
	}
	var rows []row
	err := st.DB.SelectContext(ctx, &rows, `
		SELECT
		  COALESCE(attack_technique, '') AS attack_technique,
		  started_at,
		  detection_state
		FROM executions
		WHERE started_at < ? AND attack_technique IS NOT NULL
		ORDER BY attack_technique, started_at DESC
	`, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		if r.Technique == "" {
			continue
		}
		if _, ok := out[r.Technique]; ok {
			continue // we ordered DESC, so first hit is latest
		}
		out[r.Technique] = r.Detection
	}
	return out, nil
}

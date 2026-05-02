package report

import (
	"context"
	"encoding/json"
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

// MatrixCell is one parent-technique cell in the matrix.
type MatrixCell struct {
	TechniqueID   string    `json:"technique_id"`
	TechniqueName string    `json:"technique_name"`
	State         CellState `json:"state"`
	Caught        int       `json:"caught"`
	Missed        int       `json:"missed"`
	Uncertain     int       `json:"uncertain"`
	LastRunAt     time.Time `json:"last_run_at,omitempty"`
}

// Matrix is the rendered grid: tactics as columns, parent techniques as
// rows under each tactic.
type Matrix struct {
	Title       string         `json:"-"` // for HTML layout
	Engagement  string         `json:"engagement,omitempty"`
	GeneratedAt time.Time      `json:"generated_at"`
	Window      Window         `json:"window"`
	Tactics     []TacticColumn `json:"tactics"`
	// Drift lists techniques that regressed within the window, ordered
	// most-recent-regression first.
	Drift []DriftEntry `json:"drift"`
}

type TacticColumn struct {
	ID    string       `json:"id"`
	Name  string       `json:"name"`
	Cells []MatrixCell `json:"cells"`
}

type DriftEntry struct {
	TechniqueID   string    `json:"technique_id"`
	TechniqueName string    `json:"technique_name"`
	From          CellState `json:"from"`
	To            CellState `json:"to"`
	At            time.Time `json:"at"`
}

// MatrixRequest narrows BuildMatrix.
type MatrixRequest struct {
	Engagement string    // empty → cross-engagement (legacy matrix behavior)
	Since      time.Time // zero → 30d before now
	Now        func() time.Time
}

// BuildMatrix queries the store for executions in the window and projects
// the per-technique latest state onto the bundle's tactic grid. When
// req.Engagement is set, only executions belonging to runs in that
// engagement count.
func BuildMatrix(ctx context.Context, st *store.Store, b *attack.Bundle, req MatrixRequest) (*Matrix, error) {
	if req.Now == nil {
		req.Now = func() time.Time { return time.Now().UTC() }
	}
	now := req.Now().UTC()
	since := req.Since
	if since.IsZero() {
		since = now.Add(-30 * 24 * time.Hour)
	}
	until := now

	rows, err := loadByTechnique(ctx, st, req.Engagement, since, until)
	if err != nil {
		return nil, err
	}
	priorState, err := loadPriorByTechnique(ctx, st, req.Engagement, since)
	if err != nil {
		return nil, err
	}

	title := "ATT&CK coverage"
	if req.Engagement != "" {
		title = "ATT&CK coverage — " + req.Engagement
	}
	m := &Matrix{
		Title:       title,
		Engagement:  req.Engagement,
		GeneratedAt: now,
		Window:      Window{Since: since, Until: until},
	}
	for _, ta := range b.SortedTactics() {
		col := TacticColumn{ID: ta.ID, Name: ta.Name}
		for _, t := range b.TechniquesForTactic(ta.ID) {
			cell := MatrixCell{TechniqueID: t.ID, TechniqueName: t.Name, State: StateGrey}
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

// RenderHTMLMatrix returns the matrix as a standalone HTML document.
func RenderHTMLMatrix(m *Matrix) ([]byte, error) {
	if m.Title == "" {
		m.Title = "ATT&CK coverage"
	}
	return renderHTML("matrix.html", m)
}

// RenderJSONMatrix returns the matrix as indented JSON.
func RenderJSONMatrix(m *Matrix) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
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

func loadByTechnique(ctx context.Context, st *store.Store, engagement string, since, until time.Time) (map[string]*techSummary, error) {
	type row struct {
		Technique string `db:"attack_technique"`
		StartedAt string `db:"started_at"`
		Detection string `db:"detection_state"`
	}
	q := `
		SELECT
		  COALESCE(e.attack_technique, '') AS attack_technique,
		  e.started_at,
		  e.detection_state
		FROM executions e
		` + maybeJoinRuns(engagement) + `
		WHERE e.started_at >= ? AND e.started_at <= ? AND e.attack_technique IS NOT NULL
	`
	args := []any{since.UTC().Format(time.RFC3339Nano), until.UTC().Format(time.RFC3339Nano)}
	if engagement != "" {
		q += ` AND r.engagement_id = ?`
		args = append(args, engagement)
	}
	var rows []row
	if err := st.DB.SelectContext(ctx, &rows, q, args...); err != nil {
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

func loadPriorByTechnique(ctx context.Context, st *store.Store, engagement string, before time.Time) (map[string]string, error) {
	type row struct {
		Technique string `db:"attack_technique"`
		StartedAt string `db:"started_at"`
		Detection string `db:"detection_state"`
	}
	q := `
		SELECT
		  COALESCE(e.attack_technique, '') AS attack_technique,
		  e.started_at,
		  e.detection_state
		FROM executions e
		` + maybeJoinRuns(engagement) + `
		WHERE e.started_at < ? AND e.attack_technique IS NOT NULL
	`
	args := []any{before.UTC().Format(time.RFC3339Nano)}
	if engagement != "" {
		q += ` AND r.engagement_id = ?`
		args = append(args, engagement)
	}
	q += ` ORDER BY e.attack_technique, e.started_at DESC`
	var rows []row
	if err := st.DB.SelectContext(ctx, &rows, q, args...); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		if r.Technique == "" {
			continue
		}
		if _, ok := out[r.Technique]; ok {
			continue
		}
		out[r.Technique] = r.Detection
	}
	return out, nil
}

func maybeJoinRuns(engagement string) string {
	if engagement == "" {
		return ""
	}
	return "JOIN runs r ON r.id = e.run_id"
}

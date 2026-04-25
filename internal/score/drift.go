package score

import (
	"context"
	"sort"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/store"
)

// Regression is one technique that got worse between two runs.
type Regression struct {
	Technique string
	From      State
	To        State
	At        time.Time
}

// CompareRuns returns techniques whose detection_state worsened from
// priorRunID to currentRunID. State ranking matches the score package
// convention: caught < uncertain < missed.
//
// Both runs are scoped by attack_technique. Multiple executions for the
// same technique within a single run roll up to the latest detection
// state by started_at.
func CompareRuns(ctx context.Context, st *store.Store, priorRunID, currentRunID string) ([]Regression, error) {
	prior, err := latestStateByTechnique(ctx, st, priorRunID)
	if err != nil {
		return nil, err
	}
	current, err := latestStateByTechnique(ctx, st, currentRunID)
	if err != nil {
		return nil, err
	}
	var out []Regression
	for tech, currStateAndTime := range current {
		from, ok := prior[tech]
		if !ok {
			continue
		}
		if rank(currStateAndTime.state) > rank(from.state) {
			out = append(out, Regression{
				Technique: tech,
				From:      from.state,
				To:        currStateAndTime.state,
				At:        currStateAndTime.at,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Technique < out[j].Technique })
	return out, nil
}

type stateAt struct {
	state State
	at    time.Time
}

func latestStateByTechnique(ctx context.Context, st *store.Store, runID string) (map[string]stateAt, error) {
	if runID == "" {
		return map[string]stateAt{}, nil
	}
	type row struct {
		Technique string `db:"attack_technique"`
		StartedAt string `db:"started_at"`
		Detection string `db:"detection_state"`
	}
	var rows []row
	err := st.DB.SelectContext(ctx, &rows, `
		SELECT COALESCE(attack_technique,'') AS attack_technique,
		       started_at, detection_state
		FROM executions
		WHERE run_id = ? AND attack_technique IS NOT NULL
		  AND attack_technique != ''
	`, runID)
	if err != nil {
		return nil, err
	}
	out := map[string]stateAt{}
	for _, r := range rows {
		t, _ := time.Parse(time.RFC3339Nano, r.StartedAt)
		s := stateFromDetect(r.Detection)
		if s == "" {
			continue
		}
		cur, ok := out[r.Technique]
		if !ok || t.After(cur.at) {
			out[r.Technique] = stateAt{state: s, at: t}
		}
	}
	return out, nil
}

func stateFromDetect(s string) State {
	switch s {
	case "caught":
		return StateCaught
	case "uncertain":
		return StateUncertain
	case "missed":
		return StateMissed
	}
	return ""
}

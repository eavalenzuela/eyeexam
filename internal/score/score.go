// Package score implements the caught/missed/uncertain scoring logic.
//
// Per IMPLEMENTATION.md §4.5: a hit from any detector that supports an
// expectation makes that expectation `caught`. Lack of hits across all
// claiming detectors is `missed`. Errors or no supporting detectors mean
// `uncertain`. Test-level state is the worst across all expectations:
// caught < uncertain < missed (worse later in the chain).
package score

import (
	"strings"

	"github.com/eavalenzuela/eyeexam/internal/detector"
)

type State string

const (
	StateCaught        State = "caught"
	StateMissed        State = "missed"
	StateUncertain     State = "uncertain"
	StateNoExpectation State = "no_expectation"
)

// rank: caught < uncertain < missed. WorstAcross picks the highest rank.
func rank(s State) int {
	switch s {
	case StateCaught:
		return 0
	case StateUncertain:
		return 1
	case StateMissed:
		return 2
	default:
		return -1 // StateNoExpectation sorts before caught
	}
}

// PerDetectorOutcome captures one detector's response for one expectation.
type PerDetectorOutcome struct {
	DetectorName string
	Hits         []detector.Hit
	Err          error
}

// ExpectationOutcome is the per-expectation aggregate across all detectors
// that supported it.
type ExpectationOutcome struct {
	State        State
	Reason       string
	Hits         []detector.Hit
	DetectorName string // detector that produced caught (first one to do so)
	PerDetector  []PerDetectorOutcome
}

// ScoreExpectation aggregates per-detector outcomes for one expectation.
//
//   - At least one hit anywhere → caught (DetectorName = first detector
//     that returned a hit).
//   - No detectors at all → uncertain ("no detector configured for backend").
//   - Detectors all returned zero hits and no errors → missed.
//   - Some detectors errored, no hits anywhere → uncertain (reason lists
//     failing detectors).
func ScoreExpectation(per []PerDetectorOutcome) ExpectationOutcome {
	if len(per) == 0 {
		return ExpectationOutcome{
			State:  StateUncertain,
			Reason: "no detector configured for this expectation",
		}
	}
	var allHits []detector.Hit
	var firstHitDet string
	var failingDets []string
	for _, p := range per {
		if p.Err != nil {
			failingDets = append(failingDets, p.DetectorName+": "+p.Err.Error())
			continue
		}
		if len(p.Hits) > 0 {
			if firstHitDet == "" {
				firstHitDet = p.DetectorName
			}
			allHits = append(allHits, p.Hits...)
		}
	}
	out := ExpectationOutcome{PerDetector: per, Hits: allHits, DetectorName: firstHitDet}
	if len(allHits) > 0 {
		out.State = StateCaught
		return out
	}
	if len(failingDets) > 0 {
		out.State = StateUncertain
		out.Reason = "detector errors: " + strings.Join(failingDets, "; ")
		return out
	}
	out.State = StateMissed
	out.Reason = "no detector returned hits"
	return out
}

// WorstAcross returns the worst state across the given outcomes. If all
// expectations are no_expectation (only possible when an execution had zero
// expectations defined), the result is no_expectation.
func WorstAcross(outcomes []ExpectationOutcome) State {
	if len(outcomes) == 0 {
		return StateNoExpectation
	}
	worst := StateCaught
	any := false
	for _, o := range outcomes {
		if o.State == StateNoExpectation {
			continue
		}
		any = true
		if rank(o.State) > rank(worst) {
			worst = o.State
		}
	}
	if !any {
		return StateNoExpectation
	}
	return worst
}

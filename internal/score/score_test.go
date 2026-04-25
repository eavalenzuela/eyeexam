package score

import (
	"errors"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/detector"
)

func hits(n int) []detector.Hit {
	out := make([]detector.Hit, n)
	for i := 0; i < n; i++ {
		out[i] = detector.Hit{ID: "h", At: time.Now()}
	}
	return out
}

func TestScoreExpectationCaught(t *testing.T) {
	out := ScoreExpectation([]PerDetectorOutcome{
		{DetectorName: "fake1", Hits: hits(1)},
		{DetectorName: "fake2"},
	})
	if out.State != StateCaught {
		t.Fatalf("state=%s", out.State)
	}
	if out.DetectorName != "fake1" {
		t.Fatalf("det=%s", out.DetectorName)
	}
}

func TestScoreExpectationMissed(t *testing.T) {
	out := ScoreExpectation([]PerDetectorOutcome{
		{DetectorName: "fake1"},
		{DetectorName: "fake2"},
	})
	if out.State != StateMissed {
		t.Fatalf("state=%s", out.State)
	}
}

func TestScoreExpectationUncertainOnError(t *testing.T) {
	out := ScoreExpectation([]PerDetectorOutcome{
		{DetectorName: "fake1", Err: errors.New("boom")},
		{DetectorName: "fake2"},
	})
	if out.State != StateUncertain {
		t.Fatalf("state=%s", out.State)
	}
}

func TestScoreExpectationUncertainOnEmpty(t *testing.T) {
	out := ScoreExpectation(nil)
	if out.State != StateUncertain {
		t.Fatalf("state=%s", out.State)
	}
}

func TestWorstAcross(t *testing.T) {
	cases := []struct {
		name string
		in   []State
		want State
	}{
		{"no expectation", nil, StateNoExpectation},
		{"all caught", []State{StateCaught, StateCaught}, StateCaught},
		{"caught + uncertain", []State{StateCaught, StateUncertain}, StateUncertain},
		{"caught + missed", []State{StateCaught, StateMissed}, StateMissed},
		{"missed wins over uncertain", []State{StateUncertain, StateMissed}, StateMissed},
		{"all no_expectation", []State{StateNoExpectation, StateNoExpectation}, StateNoExpectation},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			outs := make([]ExpectationOutcome, len(c.in))
			for i, s := range c.in {
				outs[i] = ExpectationOutcome{State: s}
			}
			if got := WorstAcross(outs); got != c.want {
				t.Fatalf("got %s want %s", got, c.want)
			}
		})
	}
}

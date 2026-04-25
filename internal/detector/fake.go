package detector

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

// Fake is an in-process detector used by tests. It returns scripted hits or
// errors keyed by either sigma_id, tag, or query string. Calls and supplied
// queries are recorded for assertion.
type Fake struct {
	mu       sync.Mutex
	name     string
	scripted map[string]FakeScript
	calls    []ExpectationQuery
}

type FakeScript struct {
	Hits []Hit
	Err  error // if set, Query returns this error
}

func NewFake(name string) *Fake {
	return &Fake{name: name, scripted: map[string]FakeScript{}}
}

func (f *Fake) Name() string                        { return f.name }
func (f *Fake) Supports(_ pack.Expectation) bool    { return true }
func (f *Fake) HealthCheck(_ context.Context) error { return nil }

// On registers a script for an expectation matched by the given key
// (sigma_id, tag, or query — first non-empty wins).
func (f *Fake) On(key string, s FakeScript) *Fake {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripted[key] = s
	return f
}

// Calls returns every ExpectationQuery this fake has received, in order.
func (f *Fake) Calls() []ExpectationQuery {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ExpectationQuery, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *Fake) Query(_ context.Context, q ExpectationQuery) ([]Hit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, q)
	key := keyFor(q.Expectation)
	if s, ok := f.scripted[key]; ok {
		return s.Hits, s.Err
	}
	return nil, nil
}

// MakeHit is a small helper for tests building scripted hits.
func MakeHit(id string, at time.Time, host string, raw any) Hit {
	b, _ := json.Marshal(raw)
	return Hit{ID: id, At: at, HostHint: host, Raw: b}
}

func keyFor(e pack.Expectation) string {
	switch {
	case e.SigmaID != "":
		return e.SigmaID
	case e.Tag != "":
		return e.Tag
	case e.Query != "":
		return e.Query
	default:
		return e.Description
	}
}

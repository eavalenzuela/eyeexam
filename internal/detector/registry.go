package detector

import (
	"context"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

// Registry holds configured detectors and dispatches expectations to those
// that Support them. It is safe to use from one goroutine — phase_query
// drives queries serially per execution.
type Registry struct {
	dets []Detector
}

func NewRegistry(dets ...Detector) *Registry {
	return &Registry{dets: dets}
}

// All returns every registered detector.
func (r *Registry) All() []Detector { return r.dets }

// For returns every detector that claims an expectation. Empty result means
// the expectation has no supporting backend; the caller should treat the
// outcome as `uncertain` with reason "no detector configured".
func (r *Registry) For(e pack.Expectation) []Detector {
	var out []Detector
	for _, d := range r.dets {
		if d.Supports(e) {
			out = append(out, d)
		}
	}
	return out
}

// HealthCheckAll runs HealthCheck against each detector. The returned slice
// holds one entry per detector (in registration order); err is the first
// failure encountered. Used by `eyeexam inventory check` (M2) and serve
// startup (M5).
type HealthResult struct {
	Name string
	Err  error
}

func (r *Registry) HealthCheckAll(ctx context.Context) []HealthResult {
	out := make([]HealthResult, 0, len(r.dets))
	for _, d := range r.dets {
		out = append(out, HealthResult{Name: d.Name(), Err: d.HealthCheck(ctx)})
	}
	return out
}

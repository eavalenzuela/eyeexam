// Package detector defines the SIEM/EDR query interface and the registry
// used to dispatch expectations to the right backends.
//
// Per IMPLEMENTATION.md §4.4: a hit from any detector that Supports an
// expectation makes that expectation `caught`. Lack of hits across all
// claiming detectors is `missed`. If any detector errored and others
// returned no hits, the result is `uncertain` with a reason listing the
// failing detectors.
package detector

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

// TimeWindow is the inclusive [Start, End] interval to search for hits.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// ExpectationQuery is one detection lookup. Detectors that Support the
// expectation receive this and return any matching hits.
type ExpectationQuery struct {
	Expectation pack.Expectation
	HostID      string
	HostName    string
	HostAddress string
	Window      TimeWindow
	ExecutionID string
}

// Hit is one detection record returned by a detector. ID is detector-native
// and used for deduplication within an (expected_id, hit_id) pair.
type Hit struct {
	ID       string
	At       time.Time
	HostHint string
	Raw      json.RawMessage
}

// Detector is implemented by every SIEM/EDR backend.
type Detector interface {
	Name() string
	Supports(e pack.Expectation) bool
	Query(ctx context.Context, q ExpectationQuery) ([]Hit, error)
	HealthCheck(ctx context.Context) error
}

// ErrNoSupportingDetector is surfaced by the Registry when an expectation
// has no detector that Supports it. The runlife layer translates this into
// an `uncertain` outcome with a clear reason.
var ErrNoSupportingDetector = errors.New("detector: no detector supports this expectation")

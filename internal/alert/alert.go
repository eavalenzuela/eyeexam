// Package alert delivers drift / regression notifications to operator-
// configured sinks (webhook, ntfy, discord). The Sink interface is
// intentionally narrow: one method, "send this regression event".
//
// Alerts are best-effort. Send failures are logged but do not fail the
// scheduler — a missed alert is preferable to wedging a scheduled run.
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Regression is the structured event sent to every Sink. It is JSON-
// serialisable so the webhook sink can pass it through directly.
type Regression struct {
	ScheduleName  string    `json:"schedule"`
	Engagement    string    `json:"engagement"`
	RunID         string    `json:"run_id"`
	PriorRunID    string    `json:"prior_run_id,omitempty"`
	TechniqueID   string    `json:"technique_id"`
	TechniqueName string    `json:"technique_name,omitempty"`
	From          string    `json:"from"` // caught|uncertain|missed
	To            string    `json:"to"`
	At            time.Time `json:"at"`
}

// Bundle is what gets handed to a Sink: zero or more regressions in a
// single delivery, plus context for the ScheduleName / RunID / etc.
type Bundle struct {
	ScheduleName string       `json:"schedule"`
	RunID        string       `json:"run_id"`
	PriorRunID   string       `json:"prior_run_id,omitempty"`
	Engagement   string       `json:"engagement"`
	GeneratedAt  time.Time    `json:"generated_at"`
	Regressions  []Regression `json:"regressions"`
}

// Sink is implemented by every alert backend (webhook, ntfy, discord).
type Sink interface {
	Name() string
	Send(ctx context.Context, b Bundle) error
}

// Send fans a bundle out to every sink. Errors per sink are logged via
// the supplied logger callback (so packages don't have to depend on a
// concrete logger) and do not abort siblings.
func Send(ctx context.Context, sinks []Sink, b Bundle, onErr func(name string, err error)) {
	for _, s := range sinks {
		if err := s.Send(ctx, b); err != nil && onErr != nil {
			onErr(s.Name(), err)
		}
	}
}

// SinkConfig is the on-disk shape of a single sink, as embedded in a
// Schedule's `alerts_json` column. Type selects the implementation.
type SinkConfig struct {
	Name string         `json:"name"`
	Type string         `json:"type"` // "webhook"|"ntfy"|"discord"
	URL  string         `json:"url"`
	Opts map[string]any `json:"opts,omitempty"`
}

// BuildSinks constructs Sink implementations from a list of configs.
// Unknown types return an error.
func BuildSinks(configs []SinkConfig) ([]Sink, error) {
	out := make([]Sink, 0, len(configs))
	for _, cfg := range configs {
		switch cfg.Type {
		case "webhook":
			out = append(out, NewWebhook(cfg.Name, cfg.URL))
		case "ntfy":
			topic, _ := cfg.Opts["topic"].(string)
			out = append(out, NewNtfy(cfg.Name, cfg.URL, topic))
		case "discord":
			out = append(out, NewDiscord(cfg.Name, cfg.URL))
		default:
			return nil, fmt.Errorf("alert: unsupported sink type %q", cfg.Type)
		}
	}
	return out, nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

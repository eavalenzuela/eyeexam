package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

// Slither queries the slither server's read API. As of M3 the slither
// project does not expose a stable read API yet (../slither/PROJECT.md is
// pre-implementation). This client targets a documented JSON-over-HTTP
// shim — POST /api/v1/query with {query, time_window, host_hint} → {hits[]}.
//
// When slither's real read API lands, swap this implementation behind the
// same Detector interface. See IMPLEMENTATION.md §8.1 / docs/slither-detector.md.
type Slither struct {
	name   string
	base   *url.URL
	apiKey string
	client *http.Client
}

type SlitherConfig struct {
	URL     string // e.g. https://slither.lab:7443
	APIKey  string // optional; sent as Authorization: Bearer
	Timeout time.Duration
}

func NewSlither(name string, cfg SlitherConfig) (*Slither, error) {
	if name == "" {
		name = "slither"
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("slither: parse url: %w", err)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Slither{
		name:   name,
		base:   u,
		apiKey: cfg.APIKey,
		client: &http.Client{Timeout: cfg.Timeout},
	}, nil
}

func (s *Slither) Name() string { return s.name }

func (s *Slither) Supports(e pack.Expectation) bool {
	if e.Backend != "" && e.Backend != "slither" {
		return false
	}
	// Slither speaks Sigma-id-by-rule, ATT&CK tag, and free query.
	return e.SigmaID != "" || e.Tag != "" || e.Query != ""
}

func (s *Slither) HealthCheck(ctx context.Context) error {
	u := *s.base
	u.Path = "/api/v1/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	s.applyAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slither health: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("slither health: status %d", resp.StatusCode)
	}
	return nil
}

type slitherQueryReq struct {
	Query      string    `json:"query,omitempty"`
	SigmaID    string    `json:"sigma_id,omitempty"`
	Tag        string    `json:"tag,omitempty"`
	Backend    string    `json:"backend,omitempty"`
	HostHint   string    `json:"host_hint,omitempty"`
	WindowFrom time.Time `json:"window_from"`
	WindowTo   time.Time `json:"window_to"`
}

type slitherHit struct {
	ID    string          `json:"id"`
	At    time.Time       `json:"at"`
	Host  string          `json:"host,omitempty"`
	Event json.RawMessage `json:"event"`
}

type slitherQueryResp struct {
	Hits []slitherHit `json:"hits"`
}

func (s *Slither) Query(ctx context.Context, q ExpectationQuery) ([]Hit, error) {
	body, err := json.Marshal(slitherQueryReq{
		Query: q.Expectation.Query, SigmaID: q.Expectation.SigmaID,
		Tag: q.Expectation.Tag, Backend: q.Expectation.Backend,
		HostHint:   q.HostName,
		WindowFrom: q.Window.Start,
		WindowTo:   q.Window.End,
	})
	if err != nil {
		return nil, err
	}
	u := *s.base
	u.Path = "/api/v1/query"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	s.applyAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("slither query: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("slither read: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("slither query: status %d body=%s", resp.StatusCode, respBody)
	}
	var parsed slitherQueryResp
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("slither parse: %w", err)
	}
	out := make([]Hit, 0, len(parsed.Hits))
	for _, h := range parsed.Hits {
		out = append(out, Hit{
			ID: h.ID, At: h.At, HostHint: h.Host, Raw: h.Event,
		})
	}
	return out, nil
}

func (s *Slither) applyAuth(req *http.Request) {
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
}

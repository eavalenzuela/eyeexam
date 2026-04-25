package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

// Loki queries a Grafana Loki instance over LogQL. It supports expectations
// where Backend is "loki" or empty (loki accepts any query-style expectation
// when no backend is specified).
type Loki struct {
	name   string
	base   *url.URL
	tenant string
	client *http.Client
}

type LokiConfig struct {
	URL     string        // e.g. http://loki.lab:3100
	Tenant  string        // X-Scope-OrgID header (optional)
	Timeout time.Duration // per-request timeout
}

func NewLoki(name string, cfg LokiConfig) (*Loki, error) {
	if name == "" {
		name = "loki"
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("loki: parse url: %w", err)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Loki{
		name:   name,
		base:   u,
		tenant: cfg.Tenant,
		client: &http.Client{Timeout: cfg.Timeout},
	}, nil
}

func (l *Loki) Name() string { return l.name }

func (l *Loki) Supports(e pack.Expectation) bool {
	if e.Backend != "" && e.Backend != "loki" {
		return false
	}
	return e.Query != ""
}

func (l *Loki) HealthCheck(ctx context.Context) error {
	u := *l.base
	u.Path = "/ready"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if l.tenant != "" {
		req.Header.Set("X-Scope-OrgID", l.tenant)
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("loki health: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("loki health: status %d", resp.StatusCode)
	}
	return nil
}

// Query runs a LogQL query_range against [Window.Start, Window.End].
func (l *Loki) Query(ctx context.Context, q ExpectationQuery) ([]Hit, error) {
	u := *l.base
	u.Path = "/loki/api/v1/query_range"
	v := url.Values{}
	v.Set("query", q.Expectation.Query)
	v.Set("start", strconv.FormatInt(q.Window.Start.UnixNano(), 10))
	v.Set("end", strconv.FormatInt(q.Window.End.UnixNano(), 10))
	v.Set("limit", "500")
	v.Set("direction", "forward")
	u.RawQuery = v.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if l.tenant != "" {
		req.Header.Set("X-Scope-OrgID", l.tenant)
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki query: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("loki read: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("loki query: status %d body=%s", resp.StatusCode, body)
	}
	return parseLokiResponse(body, q)
}

type lokiResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][2]string       `json:"values"` // [unix-ns, line]
		} `json:"result"`
	} `json:"data"`
}

func parseLokiResponse(body []byte, q ExpectationQuery) ([]Hit, error) {
	var resp lokiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("loki parse: %w", err)
	}
	var out []Hit
	for streamIdx, stream := range resp.Data.Result {
		hostHint := stream.Stream["host"]
		if hostHint == "" {
			hostHint = stream.Stream["hostname"]
		}
		// Caller-provided host hint helps correlate when log labels lack it.
		if hostHint == "" {
			hostHint = q.HostName
		}
		for vi, v := range stream.Values {
			ts, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				continue
			}
			rawObj := map[string]any{
				"stream": stream.Stream,
				"line":   v[1],
				"ts":     v[0],
			}
			rawBytes, _ := json.Marshal(rawObj)
			out = append(out, Hit{
				ID:       fmt.Sprintf("loki-%s-s%d-v%d", q.ExecutionID, streamIdx, vi),
				At:       time.Unix(0, ts),
				HostHint: hostHint,
				Raw:      rawBytes,
			})
		}
	}
	return out, nil
}

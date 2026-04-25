package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

// Splunk queries the Splunk search REST API. The flow is:
//
//  1. POST /services/search/v2/jobs with `search=<spl>&exec_mode=normal`
//     → returns `sid`.
//  2. GET /services/search/v2/jobs/<sid>?output_mode=json — poll until
//     dispatchState is DONE/FAILED.
//  3. GET /services/search/v2/jobs/<sid>/results?output_mode=json — read
//     hits.
//
// Auth defaults to Bearer token (Splunk Cloud / app tokens). Username +
// password is supported for on-prem dev clusters.
type Splunk struct {
	name         string
	base         *url.URL
	token        string
	user         string
	password     string
	app          string
	defaultIndex string
	hostField    string
	pollInterval time.Duration
	maxPolls     int
	client       *http.Client
}

type SplunkConfig struct {
	URL          string // e.g. https://splunk.lab:8089
	Token        string // Splunk app/HTTP-event-collector token (Bearer)
	Username     string // for dev clusters
	Password     string
	App          string        // search context, e.g. "search"
	DefaultIndex string        // prepended to query if non-empty: `index=<x> <user-query>`
	HostField    string        // host correlation field (default "host")
	PollInterval time.Duration // 1s default
	MaxPolls     int           // default 30 (~30s upper bound)
	InsecureTLS  bool
	Timeout      time.Duration
}

func NewSplunk(name string, cfg SplunkConfig) (*Splunk, error) {
	if name == "" {
		name = "splunk"
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("splunk: parse url: %w", err)
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 1 * time.Second
	}
	if cfg.MaxPolls == 0 {
		cfg.MaxPolls = 30
	}
	if cfg.HostField == "" {
		cfg.HostField = "host"
	}
	if cfg.App == "" {
		cfg.App = "search"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Splunk{
		name:         name,
		base:         u,
		token:        cfg.Token,
		user:         cfg.Username,
		password:     cfg.Password,
		app:          cfg.App,
		defaultIndex: cfg.DefaultIndex,
		hostField:    cfg.HostField,
		pollInterval: cfg.PollInterval,
		maxPolls:     cfg.MaxPolls,
		client:       buildHTTPClient(cfg.InsecureTLS, cfg.Timeout),
	}, nil
}

func (s *Splunk) Name() string { return s.name }

func (s *Splunk) Supports(e pack.Expectation) bool {
	if e.Backend != "" && e.Backend != "splunk" {
		return false
	}
	return e.Query != "" || e.SigmaID != "" || e.Tag != ""
}

func (s *Splunk) HealthCheck(ctx context.Context) error {
	u := s.endpoint("/services/server/info")
	q := u.Query()
	q.Set("output_mode", "json")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	s.applyAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunk health: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("splunk health: status %d body=%s", resp.StatusCode, body)
	}
	return nil
}

// Query runs an SPL search synchronously: create-job → poll → fetch.
func (s *Splunk) Query(ctx context.Context, q ExpectationQuery) ([]Hit, error) {
	spl := s.buildSPL(q.Expectation, q.HostName)
	if spl == "" {
		return nil, nil
	}
	sid, err := s.createSearch(ctx, spl, q.Window)
	if err != nil {
		return nil, err
	}
	if err := s.waitDone(ctx, sid); err != nil {
		return nil, err
	}
	return s.fetchResults(ctx, sid, q)
}

func (s *Splunk) buildSPL(e pack.Expectation, hostHint string) string {
	parts := []string{"search"}
	if s.defaultIndex != "" {
		parts = append(parts, "index="+s.defaultIndex)
	}
	if e.SigmaID != "" {
		parts = append(parts, fmt.Sprintf(`rule_id="%s"`, escapeSPL(e.SigmaID)))
	}
	if e.Tag != "" {
		parts = append(parts, fmt.Sprintf(`tag="%s"`, escapeSPL(e.Tag)))
	}
	if e.Query != "" {
		parts = append(parts, e.Query)
	}
	if hostHint != "" && s.hostField != "" {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, s.hostField, escapeSPL(hostHint)))
	}
	if len(parts) == 1 {
		// Nothing to search for.
		return ""
	}
	return strings.Join(parts, " ")
}

func (s *Splunk) createSearch(ctx context.Context, spl string, window TimeWindow) (string, error) {
	u := s.endpoint(fmt.Sprintf("/servicesNS/-/%s/search/v2/jobs", s.app))
	form := url.Values{}
	form.Set("search", spl)
	form.Set("exec_mode", "normal")
	form.Set("earliest_time", window.Start.UTC().Format(time.RFC3339))
	form.Set("latest_time", window.End.UTC().Format(time.RFC3339))
	form.Set("output_mode", "json")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.applyAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("splunk create: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("splunk create: status %d body=%s", resp.StatusCode, body)
	}
	var parsed struct {
		Sid string `json:"sid"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("splunk create parse: %w body=%s", err, body)
	}
	if parsed.Sid == "" {
		return "", fmt.Errorf("splunk create: empty sid (body=%s)", body)
	}
	return parsed.Sid, nil
}

func (s *Splunk) waitDone(ctx context.Context, sid string) error {
	for i := 0; i < s.maxPolls; i++ {
		state, err := s.jobState(ctx, sid)
		if err != nil {
			return err
		}
		switch state {
		case "DONE":
			return nil
		case "FAILED":
			return fmt.Errorf("splunk job %s failed", sid)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.pollInterval):
		}
	}
	return fmt.Errorf("splunk job %s did not complete after %d polls", sid, s.maxPolls)
}

func (s *Splunk) jobState(ctx context.Context, sid string) (string, error) {
	u := s.endpoint(fmt.Sprintf("/servicesNS/-/%s/search/v2/jobs/%s", s.app, sid))
	q := u.Query()
	q.Set("output_mode", "json")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	s.applyAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("splunk state: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("splunk state: status %d body=%s", resp.StatusCode, body)
	}
	var parsed struct {
		Entry []struct {
			Content struct {
				DispatchState string `json:"dispatchState"`
			} `json:"content"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("splunk state parse: %w", err)
	}
	if len(parsed.Entry) == 0 {
		return "", nil
	}
	return parsed.Entry[0].Content.DispatchState, nil
}

func (s *Splunk) fetchResults(ctx context.Context, sid string, q ExpectationQuery) ([]Hit, error) {
	u := s.endpoint(fmt.Sprintf("/servicesNS/-/%s/search/v2/jobs/%s/results", s.app, sid))
	qv := u.Query()
	qv.Set("output_mode", "json")
	qv.Set("count", "200")
	u.RawQuery = qv.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	s.applyAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("splunk results: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("splunk results: status %d body=%s", resp.StatusCode, body)
	}
	var parsed struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("splunk results parse: %w", err)
	}
	out := make([]Hit, 0, len(parsed.Results))
	for i, r := range parsed.Results {
		ts := time.Time{}
		if s, ok := r["_time"].(string); ok {
			t, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				t, _ = time.Parse(time.RFC3339, s)
			}
			ts = t
		}
		host := q.HostName
		if hv, ok := r[s.hostField].(string); ok && hv != "" {
			host = hv
		}
		raw, _ := json.Marshal(r)
		hitID := fmt.Sprintf("splunk-%s-%d", sid, i)
		if v, ok := r["_cd"].(string); ok && v != "" {
			hitID = "splunk-" + v
		} else if v, ok := r["_serial"].(string); ok && v != "" {
			hitID = "splunk-" + sid + "-" + v
		}
		out = append(out, Hit{ID: hitID, At: ts, HostHint: host, Raw: raw})
	}
	return out, nil
}

func (s *Splunk) endpoint(path string) url.URL {
	u := *s.base
	u.Path = path
	return u
}

func (s *Splunk) applyAuth(req *http.Request) {
	switch {
	case s.token != "":
		req.Header.Set("Authorization", "Bearer "+s.token)
	case s.user != "":
		req.SetBasicAuth(s.user, s.password)
	}
}

// escapeSPL escapes double quotes in user-supplied values that we wrap in
// "...". We do not attempt to be a full SPL escaper; SigmaIDs and tags
// don't carry embedded quotes in practice, but defense in depth is cheap.
func escapeSPL(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

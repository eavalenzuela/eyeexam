package detector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

// Wazuh queries the Wazuh indexer (OpenSearch). Wazuh's alerts default to
// the `wazuh-alerts-*` index pattern; rule.id and rule.mitre fields are
// the standard correlation surface. Auth defaults to basic (admin/pwd in
// dev clusters) but ApiKey is supported.
type Wazuh struct {
	name           string
	base           *url.URL
	indexPattern   string
	user           string
	password       string
	apiKey         string
	hostField      string
	ruleField      string
	tagField       string
	timestampField string
	insecureTLS    bool
	client         *http.Client
}

type WazuhConfig struct {
	URL            string // https://wazuh-indexer.lab:9200
	IndexPattern   string // wazuh-alerts-* (default)
	Username       string // basic auth user (optional)
	Password       string // basic auth password (optional)
	APIKey         string // OpenSearch API key (optional)
	HostField      string // default "agent.name"
	RuleField      string // default "rule.id"
	TagField       string // default "rule.mitre.tactic"
	TimestampField string // default "@timestamp"
	InsecureTLS    bool   // skip TLS verify (dev only)
	Timeout        time.Duration
}

func NewWazuh(name string, cfg WazuhConfig) (*Wazuh, error) {
	if name == "" {
		name = "wazuh"
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("wazuh: parse url: %w", err)
	}
	if cfg.IndexPattern == "" {
		cfg.IndexPattern = "wazuh-alerts-*"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Wazuh{
		name:           name,
		base:           u,
		indexPattern:   cfg.IndexPattern,
		user:           cfg.Username,
		password:       cfg.Password,
		apiKey:         cfg.APIKey,
		hostField:      cfg.HostField,
		ruleField:      cfg.RuleField,
		tagField:       cfg.TagField,
		timestampField: cfg.TimestampField,
		insecureTLS:    cfg.InsecureTLS,
		client:         buildHTTPClient(cfg.InsecureTLS, cfg.Timeout),
	}, nil
}

func (w *Wazuh) Name() string { return w.name }

func (w *Wazuh) Supports(e pack.Expectation) bool {
	if e.Backend != "" && e.Backend != "wazuh" {
		return false
	}
	return e.Query != "" || e.SigmaID != "" || e.Tag != ""
}

func (w *Wazuh) HealthCheck(ctx context.Context) error {
	u := *w.base
	u.Path = "/_cluster/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	w.applyAuth(req)
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("wazuh health: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("wazuh health: status %d body=%s", resp.StatusCode, body)
	}
	return nil
}

func (w *Wazuh) Query(ctx context.Context, q ExpectationQuery) ([]Hit, error) {
	body, err := buildESQuery(q.Expectation, q.HostName,
		w.hostField, w.ruleField, w.tagField, w.timestampField, q.Window, 200)
	if err != nil {
		return nil, err
	}
	u := *w.base
	u.Path = "/" + strings.TrimPrefix(w.indexPattern, "/") + "/_search"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	w.applyAuth(req)
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wazuh query: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("wazuh read: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("wazuh query: status %d body=%s", resp.StatusCode, respBody)
	}
	return extractESHits(respBody, q, w.timestampField)
}

func (w *Wazuh) applyAuth(req *http.Request) {
	switch {
	case w.apiKey != "":
		req.Header.Set("Authorization", "ApiKey "+w.apiKey)
	case w.user != "":
		req.SetBasicAuth(w.user, w.password)
	}
}

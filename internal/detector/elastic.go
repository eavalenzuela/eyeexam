package detector

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

// Elastic queries an Elasticsearch / Elastic Security cluster. ApiKey
// auth is the production path; Username/Password is supported for dev
// clusters. Index pattern defaults to filebeat-* but is configurable —
// SOCs running Elastic Security typically pin it to logs-* or
// .alerts-security.alerts-*.
type Elastic struct {
	name           string
	base           *url.URL
	indexPattern   string
	apiKey         string
	user           string
	password       string
	hostField      string
	ruleField      string
	tagField       string
	timestampField string
	client         *http.Client
}

type ElasticConfig struct {
	URL            string
	IndexPattern   string
	APIKey         string
	Username       string
	Password       string
	HostField      string
	RuleField      string
	TagField       string
	TimestampField string
	InsecureTLS    bool
	Timeout        time.Duration
}

func NewElastic(name string, cfg ElasticConfig) (*Elastic, error) {
	if name == "" {
		name = "elastic"
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("elastic: parse url: %w", err)
	}
	if cfg.IndexPattern == "" {
		cfg.IndexPattern = "filebeat-*"
	}
	if cfg.HostField == "" {
		cfg.HostField = "host.name"
	}
	if cfg.RuleField == "" {
		cfg.RuleField = "rule.uuid"
	}
	if cfg.TagField == "" {
		cfg.TagField = "tags"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Elastic{
		name:           name,
		base:           u,
		indexPattern:   cfg.IndexPattern,
		apiKey:         cfg.APIKey,
		user:           cfg.Username,
		password:       cfg.Password,
		hostField:      cfg.HostField,
		ruleField:      cfg.RuleField,
		tagField:       cfg.TagField,
		timestampField: cfg.TimestampField,
		client:         buildHTTPClient(cfg.InsecureTLS, cfg.Timeout),
	}, nil
}

func (e *Elastic) Name() string { return e.name }

func (e *Elastic) Supports(exp pack.Expectation) bool {
	if exp.Backend != "" && exp.Backend != "elastic" {
		return false
	}
	return exp.Query != "" || exp.SigmaID != "" || exp.Tag != ""
}

func (e *Elastic) HealthCheck(ctx context.Context) error {
	u := *e.base
	u.Path = "/_cluster/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	e.applyAuth(req)
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("elastic health: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("elastic health: status %d body=%s", resp.StatusCode, body)
	}
	return nil
}

func (e *Elastic) Query(ctx context.Context, q ExpectationQuery) ([]Hit, error) {
	body, err := buildESQuery(q.Expectation, q.HostName,
		e.hostField, e.ruleField, e.tagField, e.timestampField, q.Window, 200)
	if err != nil {
		return nil, err
	}
	u := *e.base
	u.Path = "/" + strings.TrimPrefix(e.indexPattern, "/") + "/_search"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	e.applyAuth(req)
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("elastic query: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("elastic read: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("elastic query: status %d body=%s", resp.StatusCode, respBody)
	}
	return extractESHits(respBody, q, e.timestampField)
}

func (e *Elastic) applyAuth(req *http.Request) {
	switch {
	case e.apiKey != "":
		req.Header.Set("Authorization", "ApiKey "+e.apiKey)
	case e.user != "":
		req.SetBasicAuth(e.user, e.password)
	}
}

// buildHTTPClient returns an http.Client honoring InsecureTLS for dev
// clusters that ship with self-signed certs.
func buildHTTPClient(insecureTLS bool, timeout time.Duration) *http.Client {
	c := &http.Client{Timeout: timeout}
	if insecureTLS {
		t, _ := http.DefaultTransport.(*http.Transport)
		clone := t.Clone()
		clone.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit operator opt-in
		c.Transport = clone
	}
	return c
}

package runner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
)

// SlitherRunner dispatches BAS commands through a slither server's read
// API. As of M7 the slither project (../slither/PROJECT.md) is pre-
// implementation, so this client targets a documented JSON-over-HTTP
// shim — POST /api/v1/bas/execute with {control_id, operator_id,
// engagement_id, agent_id, shell, command, timeout_seconds}, returning
// {control_id, exit_code, stdout_b64, stderr_b64, error}.
//
// When slither's real BAS RPC lands (BasExecuteRequest /
// BasExecuteResponse over the existing gRPC control plane —
// IMPLEMENTATION.md §M7 pre-work), swap this implementation behind the
// same Runner interface. Contract is documented in docs/slither-runner.md.
type SlitherRunner struct {
	cfg    SlitherRunnerConfig
	client *http.Client
}

type SlitherRunnerConfig struct {
	Server         string        // https://slither.lab:7443
	APIKey         string        // optional Authorization: Bearer
	OperatorID     string        // required; written into every dispatch
	EngagementID   string        // required; gates dispatch on slither side
	ConnectTimeout time.Duration // default 10s
	CommandTimeout time.Duration // default 5m
	InsecureTLS    bool          // dev clusters only
}

func NewSlitherRunner(cfg SlitherRunnerConfig) (*SlitherRunner, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("slither runner: server is required")
	}
	if cfg.OperatorID == "" {
		return nil, fmt.Errorf("slither runner: operator_id is required")
	}
	if cfg.EngagementID == "" {
		return nil, fmt.Errorf("slither runner: engagement_id is required")
	}
	if _, err := url.Parse(cfg.Server); err != nil {
		return nil, fmt.Errorf("slither runner: parse server: %w", err)
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.CommandTimeout == 0 {
		cfg.CommandTimeout = 5 * time.Minute
	}

	client := &http.Client{Timeout: cfg.ConnectTimeout + cfg.CommandTimeout}
	if cfg.InsecureTLS {
		t, _ := http.DefaultTransport.(*http.Transport)
		clone := t.Clone()
		clone.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		client.Transport = clone
	}
	return &SlitherRunner{cfg: cfg, client: client}, nil
}

func (s *SlitherRunner) Name() string           { return "slither" }
func (s *SlitherRunner) Capabilities() []string { return []string{"shell:bash", "shell:sh"} }
func (s *SlitherRunner) Close() error           { return nil }

// HealthCheck pings slither's BAS health endpoint.
func (s *SlitherRunner) HealthCheck(ctx context.Context) error {
	u := s.cfg.Server + "/api/v1/bas/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	s.applyAuth(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slither runner health: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slither runner health: status %d body=%s", resp.StatusCode, body)
	}
	return nil
}

// Execute dispatches the step through slither. host.AgentID identifies
// the target slither agent. control_id is set to the calling step's
// supplied id (defaults to a random per-call value if not provided).
func (s *SlitherRunner) Execute(ctx context.Context, host inventory.Host, step ExecuteStep) (Result, error) {
	if host.Transport != "slither" {
		return Result{}, fmt.Errorf("slither runner: host %q transport=%q", host.Name, host.Transport)
	}
	if host.AgentID == "" {
		return Result{}, fmt.Errorf("slither runner: host %q missing agent_id in inventory", host.Name)
	}
	switch step.Shell {
	case "bash", "sh", "":
	default:
		return Result{}, fmt.Errorf("%w: %q", ErrUnsupportedShell, step.Shell)
	}

	timeout := step.Timeout
	if timeout == 0 {
		timeout = s.cfg.CommandTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	controlID := step.Env["EYEEXAM_CONTROL_ID"]
	if controlID == "" {
		controlID = fmt.Sprintf("ee-%s-%d", host.Name, time.Now().UnixNano())
	}

	reqBody, _ := json.Marshal(slitherBasRequest{
		ControlID:      controlID,
		OperatorID:     s.cfg.OperatorID,
		EngagementID:   s.cfg.EngagementID,
		AgentID:        host.AgentID,
		Shell:          fallbackShell(step.Shell),
		Command:        step.Command,
		TimeoutSeconds: int(timeout.Seconds()),
	})

	u := s.cfg.Server + "/api/v1/bas/execute"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(reqBody))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	s.applyAuth(req)

	res := Result{Started: time.Now().UTC()}
	resp, err := s.client.Do(req)
	if err != nil {
		res.Finished = time.Now().UTC()
		res.ExitCode = -1
		return res, fmt.Errorf("slither runner: dispatch %s: %w", host.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	res.Finished = time.Now().UTC()
	if err != nil {
		res.ExitCode = -1
		return res, fmt.Errorf("slither runner: read response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		res.ExitCode = -1
		return res, fmt.Errorf("slither runner: status %d body=%s", resp.StatusCode, body)
	}

	var parsed slitherBasResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		res.ExitCode = -1
		return res, fmt.Errorf("slither runner: parse response: %w", err)
	}
	if parsed.Error != "" {
		res.ExitCode = -1
		res.Extra = map[string]string{
			"slither_control_id": nonEmptyStr(parsed.ControlID, controlID),
		}
		return res, fmt.Errorf("slither runner: agent error: %s", parsed.Error)
	}
	res.ExitCode = parsed.ExitCode
	res.Stdout, _ = base64.StdEncoding.DecodeString(parsed.StdoutB64)
	res.Stderr, _ = base64.StdEncoding.DecodeString(parsed.StderrB64)
	res.Extra = map[string]string{
		"slither_control_id": nonEmptyStr(parsed.ControlID, controlID),
		"slither_agent_id":   host.AgentID,
	}
	return res, nil
}

func (s *SlitherRunner) applyAuth(req *http.Request) {
	if s.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.APIKey)
	}
}

func fallbackShell(s string) string {
	if s == "" {
		return "bash"
	}
	return s
}

func nonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type slitherBasRequest struct {
	ControlID      string `json:"control_id"`
	OperatorID     string `json:"operator_id"`
	EngagementID   string `json:"engagement_id"`
	AgentID        string `json:"agent_id"`
	Shell          string `json:"shell"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type slitherBasResponse struct {
	ControlID string `json:"control_id"`
	ExitCode  int    `json:"exit_code"`
	StdoutB64 string `json:"stdout_b64"`
	StderrB64 string `json:"stderr_b64"`
	Error     string `json:"error,omitempty"`
}

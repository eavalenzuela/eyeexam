package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
)

func newSlitherShim(t *testing.T, h func(slitherBasRequest) slitherBasResponse) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/bas/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/bas/execute", func(w http.ResponseWriter, r *http.Request) {
		var req slitherBasRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := h(req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}

func TestSlitherRunnerDispatch(t *testing.T) {
	srv := newSlitherShim(t, func(req slitherBasRequest) slitherBasResponse {
		return slitherBasResponse{
			ControlID: req.ControlID + "-slither",
			ExitCode:  0,
			StdoutB64: base64.StdEncoding.EncodeToString([]byte("hi from agent")),
		}
	})
	defer srv.Close()

	r, err := NewSlitherRunner(SlitherRunnerConfig{
		Server: srv.URL, OperatorID: "ealey(uid=1000)", EngagementID: "TEST",
	})
	if err != nil {
		t.Fatal(err)
	}

	host := inventory.Host{
		Name: "slither-host", Transport: "slither", AgentID: "agent-uuid-1",
		Tags: []string{"linux"},
	}
	res, err := r.Execute(context.Background(), host, ExecuteStep{
		Shell: "bash", Command: "echo hi",
		Env: map[string]string{"EYEEXAM_CONTROL_ID": "x-1234"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "hi from agent") {
		t.Fatalf("stdout=%q", res.Stdout)
	}
	if got := res.Extra["slither_control_id"]; got != "x-1234-slither" {
		t.Fatalf("control_id cross-ref missing: %v", res.Extra)
	}
	if res.Extra["slither_agent_id"] != "agent-uuid-1" {
		t.Fatalf("agent_id cross-ref missing: %v", res.Extra)
	}
}

func TestSlitherRunnerHealth(t *testing.T) {
	srv := newSlitherShim(t, func(_ slitherBasRequest) slitherBasResponse { return slitherBasResponse{} })
	defer srv.Close()
	r, err := NewSlitherRunner(SlitherRunnerConfig{
		Server: srv.URL, OperatorID: "op", EngagementID: "TEST",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.HealthCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSlitherRunnerRefusesNonSlitherTransport(t *testing.T) {
	srv := newSlitherShim(t, func(_ slitherBasRequest) slitherBasResponse { return slitherBasResponse{} })
	defer srv.Close()
	r, _ := NewSlitherRunner(SlitherRunnerConfig{
		Server: srv.URL, OperatorID: "op", EngagementID: "TEST",
	})
	if _, err := r.Execute(context.Background(), inventory.Host{Transport: "ssh"}, ExecuteStep{Shell: "bash", Command: "true"}); err == nil {
		t.Fatal("expected refusal for transport=ssh")
	}
}

func TestSlitherRunnerAgentError(t *testing.T) {
	srv := newSlitherShim(t, func(req slitherBasRequest) slitherBasResponse {
		return slitherBasResponse{ControlID: req.ControlID, Error: "agent refused: BAS not enabled"}
	})
	defer srv.Close()
	r, _ := NewSlitherRunner(SlitherRunnerConfig{
		Server: srv.URL, OperatorID: "op", EngagementID: "TEST",
	})
	host := inventory.Host{Name: "h", Transport: "slither", AgentID: "a"}
	_, err := r.Execute(context.Background(), host, ExecuteStep{Shell: "bash", Command: "true"})
	if err == nil || !strings.Contains(err.Error(), "agent error") {
		t.Fatalf("err=%v", err)
	}
}

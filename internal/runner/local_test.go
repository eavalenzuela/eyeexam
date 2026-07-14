package runner

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
)

func TestLocalEcho(t *testing.T) {
	l := NewLocal()
	host := inventory.Host{Name: "localhost", Transport: "local"}
	res, err := l.Execute(context.Background(), host, ExecuteStep{
		Shell: "bash", Command: "echo hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "hello") {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestLocalExitCode(t *testing.T) {
	l := NewLocal()
	res, err := l.Execute(context.Background(), inventory.Host{}, ExecuteStep{
		Shell: "bash", Command: "exit 7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit=%d", res.ExitCode)
	}
}

// TestLocalBackgroundChildStillReportsZero guards against the WaitDelay
// misclassification: a step that exits 0 but backgrounds a child holding the
// stdout pipe (as C2/beacon BAS tests do) must be scored exit 0, not a runner
// error. WaitDelay bounds the wait; ProcessState carries the real exit status.
func TestLocalBackgroundChildStillReportsZero(t *testing.T) {
	if testing.Short() {
		t.Skip("takes ~killGrace to drain the backgrounded pipe")
	}
	l := NewLocal()
	start := time.Now()
	// The backgrounded sleep outlives killGrace and inherits stdout, so Wait
	// hits WaitDelay; the shell itself exited 0.
	res, err := l.Execute(context.Background(), inventory.Host{}, ExecuteStep{
		Shell: "bash", Command: "sleep 30 & echo started",
	})
	if err != nil {
		t.Fatalf("unexpected error for a clean background start: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d, want 0 (backgrounded child must not fail the step)", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "started") {
		t.Fatalf("stdout=%q", res.Stdout)
	}
	if elapsed := time.Since(start); elapsed > killGrace+5*time.Second {
		t.Fatalf("step took %s, WaitDelay did not bound the backgrounded pipe", elapsed)
	}
}

func TestLocalPowershellWhenInstalled(t *testing.T) {
	if _, err := exec.LookPath("pwsh"); err != nil {
		t.Skip("pwsh not on PATH; install powershell-core to exercise this path")
	}
	l := NewLocal()
	res, err := l.Execute(context.Background(), inventory.Host{}, ExecuteStep{
		Shell: "powershell", Command: `Write-Host "ps-from-eyeexam"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%s", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(string(res.Stdout), "ps-from-eyeexam") {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestLocalPowershellMissingReturnsUnsupported(t *testing.T) {
	if _, err := exec.LookPath("pwsh"); err == nil {
		t.Skip("pwsh is on PATH; this test exercises the missing-binary path")
	}
	l := NewLocal()
	_, err := l.Execute(context.Background(), inventory.Host{}, ExecuteStep{
		Shell: "powershell", Command: `Write-Host hi`,
	})
	if !errors.Is(err, ErrUnsupportedShell) {
		t.Fatalf("expected ErrUnsupportedShell, got %v", err)
	}
}

func TestLocalCapabilitiesAdvertisesPwshConditionally(t *testing.T) {
	caps := NewLocal().Capabilities()
	hasPS := false
	for _, c := range caps {
		if c == "shell:powershell" {
			hasPS = true
		}
	}
	_, pwshAvail := exec.LookPath("pwsh")
	want := pwshAvail == nil
	if hasPS != want {
		t.Errorf("Capabilities advertises shell:powershell=%v, but pwsh-on-PATH=%v", hasPS, want)
	}
}

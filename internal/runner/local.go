package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
)

// killGrace is how long we wait, after cancelling a step, for the process
// and its children to release the output pipes before Wait() forcibly
// returns. Without this a grandchild that outlives the shell (e.g. a
// command an EDR has blocked, or a backgrounded process) can keep Wait()
// blocked for the command's full runtime, defeating the step timeout.
const killGrace = 5 * time.Second

// Local executes commands on the same host eyeexam itself runs on. It is
// fully capable of destructive runs — destructiveness gating happens upstream
// in the runlife engine, not here.
type Local struct{}

func NewLocal() *Local { return &Local{} }

func (l *Local) Name() string { return "local" }
func (l *Local) Capabilities() []string {
	caps := []string{"shell:bash", "shell:sh"}
	if _, err := exec.LookPath("pwsh"); err == nil {
		caps = append(caps, "shell:powershell")
	}
	return caps
}
func (l *Local) Close() error { return nil }

func (l *Local) Execute(ctx context.Context, host inventory.Host, step ExecuteStep) (Result, error) {
	shell, err := resolveLocalShell(step.Shell)
	if err != nil {
		return Result{}, err
	}

	if step.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, step.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, shell, "-c", step.Command)
	cmd.Stdin = step.Stdin

	// Run the step in its own process group and, on timeout/cancel, kill the
	// whole group so children die with the shell rather than being reparented
	// and left running (and holding the stdout/stderr pipes open). WaitDelay
	// is a backstop for anything that escapes the group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			// Negative pid → the process group led by the child.
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = killGrace

	if len(step.Env) > 0 {
		env := os.Environ()
		for k, v := range step.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = env
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	res := Result{Started: time.Now().UTC()}
	err = cmd.Run()
	res.Finished = time.Now().UTC()
	res.Stdout = stdout.Bytes()
	res.Stderr = stderr.Bytes()

	if err != nil {
		var ee *exec.ExitError
		if exitErrAs(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		// WaitDelay expired: the shell itself exited (ProcessState is set) but
		// a lingering child kept the output pipes open — common for a step that
		// backgrounds a process (`foo &`, a beacon/listener). Trust the shell's
		// real exit status instead of reporting a spurious runner error; a
		// clean background start (exit 0) must not be scored as a failure.
		if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil {
			res.ExitCode = cmd.ProcessState.ExitCode()
			return res, nil
		}
		// non-exit failure (couldn't start, context cancelled, etc.)
		res.ExitCode = -1
		return res, fmt.Errorf("runner local: %w", err)
	}
	res.ExitCode = 0
	return res, nil
}

func exitErrAs(err error, target **exec.ExitError) bool {
	for e := err; e != nil; {
		if ee, ok := e.(*exec.ExitError); ok {
			*target = ee
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

func resolveLocalShell(shell string) (string, error) {
	switch shell {
	case "bash":
		if p, err := exec.LookPath("bash"); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("%w: bash not on PATH", ErrUnsupportedShell)
	case "sh", "":
		if p, err := exec.LookPath("sh"); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("%w: sh not on PATH", ErrUnsupportedShell)
	case "powershell", "pwsh":
		// PowerShell on Linux works via the `pwsh` binary
		// (Microsoft's package, ships .deb/.rpm). Atomic tests with
		// `executor: powershell` use this path; without `pwsh` on
		// PATH the test is skipped at the host level (see runlife
		// isHostLevelError).
		if p, err := exec.LookPath("pwsh"); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("%w: pwsh not on PATH (install powershell-core)", ErrUnsupportedShell)
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedShell, shell)
	}
}

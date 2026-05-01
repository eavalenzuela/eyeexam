// Package runner abstracts how a command runs against a host. The runner is
// dumb on purpose — it doesn't know about pack semantics, expectations, or
// scoring. The runlife layer composes runners into the test lifecycle.
package runner

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
)

type ExecuteStep struct {
	Shell   string            // "bash"|"sh"|"powershell"
	Command string            // already-substituted final command
	Stdin   io.Reader         // usually nil
	Env     map[string]string // additional env
	Timeout time.Duration     // 0 = no timeout
}

type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	Started  time.Time
	Finished time.Time
	// Extra is runner-specific metadata that runlife threads into the
	// test_executed audit record. Currently unused; reserved for future
	// runners that need to thread cross-reference identifiers (session
	// ids, container ids, etc.) into the audit log.
	Extra map[string]string
}

func (r Result) Duration() time.Duration { return r.Finished.Sub(r.Started) }

// ErrUnsupportedShell is returned when a runner doesn't implement the
// requested shell.
var ErrUnsupportedShell = errors.New("runner: unsupported shell")

type Runner interface {
	Name() string
	Capabilities() []string
	Execute(ctx context.Context, host inventory.Host, step ExecuteStep) (Result, error)
	Close() error
}

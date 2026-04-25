// Package runlife is the run-lifecycle engine. It owns sequencing across
// phases (planned → executing → waiting → querying → scoring → cleanup →
// reported), persists state at every transition, and routes work to the
// runner + detector layers. M1 implements the executing/cleanup/reported
// phases; waiting/querying/scoring land in M3.
package runlife

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/rate"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

type Engine struct {
	store   *store.Store
	audit   *audit.Logger
	reg     *pack.Registry
	inv     *inventory.Inventory
	runners map[string]runner.Runner
	limiter *rate.Limiter
	hostSem *rate.HostSemaphore
	log     *slog.Logger
}

type Options struct {
	Store         *store.Store
	Audit         *audit.Logger
	Registry      *pack.Registry
	Inventory     *inventory.Inventory
	Runners       map[string]runner.Runner
	GlobalRateTPS float64
	PerHostConcur int
	Logger        *slog.Logger
}

func New(opts Options) (*Engine, error) {
	if opts.Store == nil {
		return nil, errors.New("runlife: store required")
	}
	if opts.Registry == nil {
		return nil, errors.New("runlife: registry required")
	}
	if opts.Inventory == nil {
		return nil, errors.New("runlife: inventory required")
	}
	if len(opts.Runners) == 0 {
		return nil, errors.New("runlife: at least one runner required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Engine{
		store:   opts.Store,
		audit:   opts.Audit,
		reg:     opts.Registry,
		inv:     opts.Inventory,
		runners: opts.Runners,
		limiter: rate.NewLimiter(opts.GlobalRateTPS),
		hostSem: rate.NewHostSemaphore(opts.PerHostConcur),
		log:     opts.Logger,
	}, nil
}

// runnerFor returns the runner that handles a host's transport.
func (e *Engine) runnerFor(h inventory.Host) (runner.Runner, error) {
	r, ok := e.runners[h.Transport]
	if !ok {
		return nil, fmt.Errorf("runlife: no runner registered for transport %q", h.Transport)
	}
	return r, nil
}

// testByID is a helper used by phase code.
func (e *Engine) testByID(id string) (pack.Test, error) {
	for _, t := range e.reg.All() {
		if t.ID == id {
			return t, nil
		}
	}
	return pack.Test{}, fmt.Errorf("runlife: test %q not in registry", id)
}

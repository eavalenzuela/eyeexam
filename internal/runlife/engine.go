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
	"math/rand"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/detector"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/rate"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// Cleanup modes control when a test's cleanup + cleanup-verify runs.
//
//   - deferred (default): every test executes, then wait → query → score,
//     then all cleanups run in the cleanup phase. Keeps the detection query
//     window free of cleanup-generated events, at the cost of leaving every
//     executed test's file modifications in place until the run finishes.
//   - eager: each test's cleanup + verify runs immediately after that test
//     executes, before the next test starts. Shrinks the window in which a
//     file modification (authorized_keys, crontab, .bashrc, …) is left on a
//     live-EDR host to a single test's duration — so an EDR killing a *later*
//     test cannot strand an *earlier* test's change. Recommended when running
//     against hosts with an active EDR.
const (
	CleanupDeferred = "deferred"
	CleanupEager    = "eager"
)

type Engine struct {
	store     *store.Store
	audit     *audit.Logger
	reg       *pack.Registry
	inv       *inventory.Inventory
	runners   map[string]runner.Runner
	detectors *detector.Registry
	limiter   *rate.Limiter
	hostSem   *rate.HostSemaphore
	log       *slog.Logger

	// queryGrace is added to the wait window when querying detectors,
	// covering minor clock drift between target hosts and the SIEM.
	queryGrace time.Duration

	// cleanupMode is "deferred" or "eager"; see the Cleanup* constants.
	cleanupMode string
	// interTestPace is a minimum delay inserted between consecutive test
	// executions; interTestJitter adds a uniform random [0,jitter) on top.
	// Together they spread activity out so EDR burst/velocity heuristics do
	// not trip on a tight cluster of look-alike-malicious commands.
	interTestPace   time.Duration
	interTestJitter time.Duration
	// stepTimeout bounds every individual execute/cleanup/verify step so a
	// command an EDR silently blocks (or a wedged SSH session) cannot stall
	// the whole run. 0 leaves the runner's own default in force.
	stepTimeout time.Duration
	jitterRand  *rand.Rand
}

type Options struct {
	Store         *store.Store
	Audit         *audit.Logger
	Registry      *pack.Registry
	Inventory     *inventory.Inventory
	Runners       map[string]runner.Runner
	Detectors     *detector.Registry // optional; nil means no detection scoring
	QueryGrace    time.Duration      // default 10s
	GlobalRateTPS float64
	PerHostConcur int
	Logger        *slog.Logger

	// EDR-friendliness knobs (all optional; zero values preserve the
	// original behaviour). See the Engine fields of the same name.
	CleanupMode     string
	InterTestPace   time.Duration
	InterTestJitter time.Duration
	StepTimeout     time.Duration
	// JitterSeed seeds the pacing jitter RNG. 0 uses a fixed seed so runs
	// are reproducible; set it (e.g. to the plan seed) for varied timing.
	JitterSeed int64
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
	if opts.QueryGrace == 0 {
		opts.QueryGrace = 10 * time.Second
	}
	if opts.CleanupMode == "" {
		opts.CleanupMode = CleanupDeferred
	}
	if opts.CleanupMode != CleanupDeferred && opts.CleanupMode != CleanupEager {
		return nil, fmt.Errorf("runlife: cleanup mode must be %q or %q (got %q)",
			CleanupDeferred, CleanupEager, opts.CleanupMode)
	}
	if opts.InterTestPace < 0 || opts.InterTestJitter < 0 || opts.StepTimeout < 0 {
		return nil, errors.New("runlife: pace/jitter/step-timeout must not be negative")
	}
	seed := opts.JitterSeed
	if seed == 0 {
		seed = 1 // fixed → reproducible jitter unless the caller varies it
	}
	return &Engine{
		store:           opts.Store,
		audit:           opts.Audit,
		reg:             opts.Registry,
		inv:             opts.Inventory,
		runners:         opts.Runners,
		detectors:       opts.Detectors,
		limiter:         rate.NewLimiter(opts.GlobalRateTPS),
		hostSem:         rate.NewHostSemaphore(opts.PerHostConcur),
		queryGrace:      opts.QueryGrace,
		cleanupMode:     opts.CleanupMode,
		interTestPace:   opts.InterTestPace,
		interTestJitter: opts.InterTestJitter,
		stepTimeout:     opts.StepTimeout,
		jitterRand:      rand.New(rand.NewSource(seed)), //nolint:gosec // pacing jitter, not security-sensitive
		log:             opts.Logger,
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

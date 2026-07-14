package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/config"
	"github.com/eavalenzuela/eyeexam/internal/detector"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
)

type runFlags struct {
	planFlags
	authorized    bool
	engagement    string
	yes           bool
	iReallyMeanIt bool
	dryRun        bool
	actorApp      string
	cleanupMode   string
	pace          string
	jitter        string
	stepTimeout   string
}

func newRunCmd() *cobra.Command {
	var rf runFlags
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Plan, confirm, execute, score, cleanup-verify, report",
		RunE: func(cmd *cobra.Command, args []string) error {
			return doRun(rf)
		},
	}
	bindRunFlags(cmd, &rf.planFlags)
	cmd.Flags().BoolVar(&rf.authorized, "authorized", false, "required; affirms operator authorization")
	cmd.Flags().StringVar(&rf.engagement, "engagement", "", "engagement id (must match config or override)")
	cmd.Flags().BoolVar(&rf.yes, "yes", false, "skip the confirmation prompt for low/medium destructiveness runs")
	cmd.Flags().BoolVar(&rf.iReallyMeanIt, "i-really-mean-it", false, "required with --yes for high-destructiveness runs")
	cmd.Flags().BoolVar(&rf.dryRun, "dry-run", false, "print the plan and exit (same as 'eyeexam plan')")
	cmd.Flags().StringVar(&rf.actorApp, "actor-app", "", "human identity to record alongside the OS user (e.g. when invoked by a service account)")
	cmd.Flags().StringVar(&rf.cleanupMode, "cleanup-mode", "", "when to run cleanup: deferred|eager (default from config). eager reverts each test immediately after it runs — recommended against a live EDR")
	cmd.Flags().StringVar(&rf.pace, "pace", "", "minimum delay between test executions, e.g. 30s (default from config); spreads activity so EDR burst heuristics don't trip")
	cmd.Flags().StringVar(&rf.jitter, "jitter", "", "extra uniform random delay [0,jitter) added to --pace, e.g. 10s (default from config)")
	cmd.Flags().StringVar(&rf.stepTimeout, "step-timeout", "", "per-step command timeout, e.g. 2m; 0 = runner default (default from config)")
	return cmd
}

// edrKnobs holds the resolved EDR-friendliness settings for a run: flags
// override config, config overrides zero.
type edrKnobs struct {
	cleanupMode string
	pace        time.Duration
	jitter      time.Duration
	step        time.Duration
}

func resolveEDRKnobs(rf runFlags, cfg config.Config) (edrKnobs, error) {
	k := edrKnobs{
		cleanupMode: cfg.Cleanup.EffectiveMode(),
		pace:        cfg.Limits.Pace(),
		jitter:      cfg.Limits.Jitter(),
		step:        cfg.Limits.Step(),
	}
	if rf.cleanupMode != "" {
		if rf.cleanupMode != config.CleanupModeDeferred && rf.cleanupMode != config.CleanupModeEager {
			return k, fmt.Errorf("--cleanup-mode must be %q or %q (got %q)",
				config.CleanupModeDeferred, config.CleanupModeEager, rf.cleanupMode)
		}
		k.cleanupMode = rf.cleanupMode
	}
	var err error
	if k.pace, err = overrideDur(rf.pace, k.pace, "--pace"); err != nil {
		return k, err
	}
	if k.jitter, err = overrideDur(rf.jitter, k.jitter, "--jitter"); err != nil {
		return k, err
	}
	if k.step, err = overrideDur(rf.stepTimeout, k.step, "--step-timeout"); err != nil {
		return k, err
	}
	return k, nil
}

func overrideDur(flag string, def time.Duration, name string) (time.Duration, error) {
	if flag == "" {
		return def, nil
	}
	d, err := time.ParseDuration(flag)
	if err != nil {
		return def, fmt.Errorf("%s: invalid duration %q: %w", name, flag, err)
	}
	if d < 0 {
		return def, fmt.Errorf("%s must not be negative (got %q)", name, flag)
	}
	return d, nil
}

func doRun(rf runFlags) error {
	if !rf.authorized {
		return fmt.Errorf("--authorized is required")
	}

	deps, err := loadRuntime(rf.actorApp)
	if err != nil {
		return err
	}
	defer deps.close()
	cfg := deps.cfg

	if rf.engagement == "" {
		rf.engagement = cfg.Engagement.ID
	}
	if rf.engagement != cfg.Engagement.ID {
		return fmt.Errorf("--engagement %q does not match config engagement.id %q",
			rf.engagement, cfg.Engagement.ID)
	}

	edr, err := resolveEDRKnobs(rf, cfg)
	if err != nil {
		return err
	}

	emitUnsignedPackAudit(ctx(), deps.audit, deps.actor, rf.engagement, deps.unsignedPacks)

	eng, err := runlife.New(runlife.Options{
		Store: deps.store, Audit: deps.audit, Registry: deps.reg, Inventory: deps.inv,
		Runners:         deps.runners,
		Detectors:       deps.detectors,
		GlobalRateTPS:   cfg.Limits.GlobalTestsPerSecond,
		PerHostConcur:   cfg.Limits.PerHostConcurrency,
		CleanupMode:     edr.cleanupMode,
		InterTestPace:   edr.pace,
		InterTestJitter: edr.jitter,
		StepTimeout:     edr.step,
		JitterSeed:      rf.seed,
	})
	if err != nil {
		return err
	}

	maxDest := pack.Dest(rf.maxDest)
	switch maxDest {
	case pack.DestLow, pack.DestMedium, pack.DestHigh:
	default:
		return fmt.Errorf("--max-dest must be low|medium|high (got %q)", rf.maxDest)
	}

	planReq := runlife.PlanRequest{
		EngagementID: rf.engagement,
		Authorized:   rf.authorized,
		MaxDest:      maxDest,
		PackName:     rf.pack,
		Selector: inventory.Selector{
			Hosts: rf.hosts, Tags: rf.tags, NotTags: rf.notTags,
			Tests: rf.tests, NotTests: rf.notTests,
		},
		Seed:    rf.seed,
		Actor:   deps.actor,
		AppUser: deps.appUser,
	}

	runID, plan, err := eng.Plan(ctx(), planReq)
	if err != nil {
		return err
	}

	fmt.Printf("planned run %s — %d test execution(s) on %d host(s) [cleanup=%s]\n",
		runID, len(plan.Tests), countDistinctHosts(plan), edr.cleanupMode)
	if edr.pace > 0 || edr.jitter > 0 || edr.step > 0 {
		fmt.Printf("  pacing: pace=%s jitter=%s step-timeout=%s\n", edr.pace, edr.jitter, edr.step)
	}
	for _, pt := range plan.Tests {
		fmt.Printf("  %s  %s\n", pt.HostName, pt.TestID)
	}
	if rf.dryRun {
		return nil
	}

	if !confirmRun(plan, maxDest, rf, deps.reg) {
		return fmt.Errorf("run cancelled")
	}

	// Audit destructive_run_authorized BEFORE first test executes when the
	// plan contains anything above low.
	if planExceedsLow(plan, deps.reg) {
		payload, _ := jsonMarshal(map[string]any{
			"max_dest":   maxDest,
			"engagement": rf.engagement,
			"plan_size":  len(plan.Tests),
		})
		if _, err := deps.audit.Append(ctx(), audit.Record{
			Actor: deps.actor, Engagement: rf.engagement, RunID: runID,
			Event: "destructive_run_authorized", Payload: payload,
		}); err != nil {
			return err
		}
	}

	if err := runWithGracefulAbort(eng, runID, deps.actor, func(c context.Context) error {
		return eng.Execute(c, runID, deps.actor)
	}); err != nil {
		return err
	}
	fmt.Printf("\nrun %s completed — see 'eyeexam runs show %s'\n", runID, runID)
	return nil
}

// runWithGracefulAbort runs exec (Execute or Resume) under a SIGINT/SIGTERM
// trap. On the first signal it cancels the run and drains cleanup on a fresh
// context, so any in-flight file modifications (authorized_keys, crontab, …)
// are reverted before the process exits. A second signal restores default
// handling and hard-kills. A SIGKILL can't be trapped — recover from that with
// `eyeexam runs cleanup <run-id>`.
func runWithGracefulAbort(eng *runlife.Engine, runID string, actor audit.Actor, exec func(context.Context) error) error {
	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := exec(runCtx)
	if err != nil && runCtx.Err() != nil {
		stop() // restore default handling; a second signal now hard-kills
		fmt.Fprintf(os.Stderr, "\ninterrupted — reverting in-flight changes for run %s ...\n", runID)
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if derr := eng.DrainCleanup(cctx, runID, actor); derr != nil {
			return fmt.Errorf("run %s aborted; cleanup incomplete: %w — run 'eyeexam runs cleanup %s'",
				runID, derr, runID)
		}
		fmt.Fprintf(os.Stderr, "cleanup drained for run %s\n", runID)
		return fmt.Errorf("run %s aborted by signal (cleanup completed)", runID)
	}
	if err != nil {
		return fmt.Errorf("run %s: %w", runID, err)
	}
	return nil
}

func loadAuditKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("audit key: not a PEM file")
	}
	return ed25519.PrivateKey(block.Bytes), nil
}

func confirmRun(p *runlife.Plan, maxDest pack.Dest, rf runFlags, reg *pack.Registry) bool {
	exceeds := planExceedsLow(p, reg)
	high := planContainsHigh(p, reg)
	if !exceeds {
		if rf.yes {
			return true
		}
		fmt.Print("\nproceed? [y/N] ")
		return readYesNo()
	}
	if high && (!rf.yes || !rf.iReallyMeanIt) {
		if !rf.yes {
			fmt.Println("\nthis plan contains HIGH destructiveness tests.")
		}
		fmt.Println("type the engagement id to proceed; pass --yes --i-really-mean-it to skip:")
		if rf.yes && !rf.iReallyMeanIt {
			fmt.Println("(refusing: --yes alone is not enough for high-destructiveness; add --i-really-mean-it)")
			return false
		}
		return readEngagementMatches(rf.engagement)
	}
	// medium destructiveness path
	if rf.yes {
		return true
	}
	fmt.Println("\nthis plan contains MEDIUM destructiveness tests.")
	fmt.Println("type the engagement id to proceed:")
	return readEngagementMatches(rf.engagement)
}

func readYesNo() bool {
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func readEngagementMatches(want string) bool {
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line) == want
}

func planExceedsLow(p *runlife.Plan, reg *pack.Registry) bool {
	for _, pt := range p.Tests {
		for _, t := range reg.All() {
			if t.ID == pt.TestID && t.Destructiveness != pack.DestLow {
				return true
			}
		}
	}
	return false
}

func planContainsHigh(p *runlife.Plan, reg *pack.Registry) bool {
	for _, pt := range p.Tests {
		for _, t := range reg.All() {
			if t.ID == pt.TestID && t.Destructiveness == pack.DestHigh {
				return true
			}
		}
	}
	return false
}

func countDistinctHosts(p *runlife.Plan) int {
	seen := map[string]bool{}
	for _, pt := range p.Tests {
		seen[pt.HostName] = true
	}
	return len(seen)
}

func jsonMarshal(v any) ([]byte, error) {
	// indirection so cmd_run can avoid importing encoding/json directly twice
	return jsonEncode(v)
}

func buildSSHRunner(cfg config.Config) (*runner.SSH, error) {
	connectTO := parseDurOrDefault(cfg.Runner.SSH.ConnectTimeout, 10*time.Second)
	cmdTO := parseDurOrDefault(cfg.Runner.SSH.CommandTimeout, 5*time.Minute)
	return runner.NewSSH(runner.SSHConfig{
		DefaultUser:    cfg.Runner.SSH.DefaultUser,
		DefaultKeyPath: cfg.Runner.SSH.DefaultKey,
		KnownHostsPath: cfg.Runner.SSH.KnownHosts,
		ConnectTimeout: connectTO,
		CommandTimeout: cmdTO,
	})
}

func parseDurOrDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

func hostsUseTransport(inv *inventory.Inventory, transport string) bool {
	for _, h := range inv.Hosts {
		if h.Transport == transport {
			return true
		}
	}
	return false
}

func buildDetectorRegistry(cfg config.Config) (*detector.Registry, error) {
	if len(cfg.Detectors) == 0 {
		return nil, nil
	}
	dets := make([]detector.Detector, 0, len(cfg.Detectors))
	for _, dc := range cfg.Detectors {
		switch dc.Type {
		case "loki":
			ld, err := detector.NewLoki(dc.Name, detector.LokiConfig{
				URL:     stringOpt(dc.Options, "url"),
				Tenant:  stringOpt(dc.Options, "tenant"),
				Timeout: 10 * time.Second,
			})
			if err != nil {
				return nil, err
			}
			dets = append(dets, ld)
		case "slither":
			sd, err := detector.NewSlither(dc.Name, detector.SlitherConfig{
				URL:     stringOpt(dc.Options, "url"),
				APIKey:  envOpt(stringOpt(dc.Options, "api_key_env")),
				Timeout: 10 * time.Second,
			})
			if err != nil {
				return nil, err
			}
			dets = append(dets, sd)
		case "wazuh":
			wd, err := detector.NewWazuh(dc.Name, detector.WazuhConfig{
				URL:            stringOpt(dc.Options, "url"),
				IndexPattern:   stringOpt(dc.Options, "index_pattern"),
				Username:       stringOpt(dc.Options, "username"),
				Password:       envOpt(stringOpt(dc.Options, "password_env")),
				APIKey:         envOpt(stringOpt(dc.Options, "api_key_env")),
				HostField:      stringOpt(dc.Options, "host_field"),
				RuleField:      stringOpt(dc.Options, "rule_field"),
				TagField:       stringOpt(dc.Options, "tag_field"),
				TimestampField: stringOpt(dc.Options, "timestamp_field"),
				InsecureTLS:    boolOpt(dc.Options, "insecure_tls"),
				Timeout:        10 * time.Second,
			})
			if err != nil {
				return nil, err
			}
			dets = append(dets, wd)
		case "elastic":
			ed, err := detector.NewElastic(dc.Name, detector.ElasticConfig{
				URL:            stringOpt(dc.Options, "url"),
				IndexPattern:   stringOpt(dc.Options, "index_pattern"),
				APIKey:         envOpt(stringOpt(dc.Options, "api_key_env")),
				Username:       stringOpt(dc.Options, "username"),
				Password:       envOpt(stringOpt(dc.Options, "password_env")),
				HostField:      stringOpt(dc.Options, "host_field"),
				RuleField:      stringOpt(dc.Options, "rule_field"),
				TagField:       stringOpt(dc.Options, "tag_field"),
				TimestampField: stringOpt(dc.Options, "timestamp_field"),
				InsecureTLS:    boolOpt(dc.Options, "insecure_tls"),
				Timeout:        10 * time.Second,
			})
			if err != nil {
				return nil, err
			}
			dets = append(dets, ed)
		case "splunk":
			sd, err := detector.NewSplunk(dc.Name, detector.SplunkConfig{
				URL:          stringOpt(dc.Options, "url"),
				Token:        envOpt(stringOpt(dc.Options, "token_env")),
				Username:     stringOpt(dc.Options, "username"),
				Password:     envOpt(stringOpt(dc.Options, "password_env")),
				App:          stringOpt(dc.Options, "app"),
				DefaultIndex: stringOpt(dc.Options, "default_index"),
				HostField:    stringOpt(dc.Options, "host_field"),
				PollInterval: durOpt(dc.Options, "poll_interval", 1*time.Second),
				MaxPolls:     intOpt(dc.Options, "max_polls", 30),
				InsecureTLS:  boolOpt(dc.Options, "insecure_tls"),
				Timeout:      30 * time.Second,
			})
			if err != nil {
				return nil, err
			}
			dets = append(dets, sd)
		default:
			return nil, fmt.Errorf("detector %q: unsupported type %q", dc.Name, dc.Type)
		}
	}
	return detector.NewRegistry(dets...), nil
}

func stringOpt(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func envOpt(envName string) string {
	if envName == "" {
		return ""
	}
	return os.Getenv(envName)
}

func boolOpt(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func intOpt(m map[string]interface{}, key string, def int) int {
	if m == nil {
		return def
	}
	v, ok := m[key]
	if !ok {
		return def
	}
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	default:
		return def
	}
}

func durOpt(m map[string]interface{}, key string, def time.Duration) time.Duration {
	s := stringOpt(m, key)
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

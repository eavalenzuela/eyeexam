package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/config"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

type runFlags struct {
	planFlags
	authorized    bool
	engagement    string
	yes           bool
	iReallyMeanIt bool
	dryRun        bool
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
	return cmd
}

func doRun(rf runFlags) error {
	if !rf.authorized {
		return fmt.Errorf("--authorized is required")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if rf.engagement == "" {
		rf.engagement = cfg.Engagement.ID
	}
	if rf.engagement != cfg.Engagement.ID {
		return fmt.Errorf("--engagement %q does not match config engagement.id %q",
			rf.engagement, cfg.Engagement.ID)
	}

	inv, err := inventory.Load(cfg.Inventory.Path)
	if err != nil {
		return err
	}
	reg := pack.NewRegistry(nil)
	for _, p := range cfg.Packs {
		if p.Source == "atomic" {
			return fmt.Errorf("pack %q: atomic source not supported until M4", p.Name)
		}
		if err := reg.AddNative(p.Name, p.Path); err != nil {
			return fmt.Errorf("pack %q: %w", p.Name, err)
		}
	}

	st, err := store.Open(ctx(), cfg.DBPath())
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	priv, err := loadAuditKey(cfg.Audit.KeyPath)
	if err != nil {
		return fmt.Errorf("load audit key: %w", err)
	}
	al, err := audit.Open(cfg.Audit.LogPath, priv)
	if err != nil {
		return err
	}
	defer func() { _ = al.Close() }()

	actor, err := audit.ActorFromOS(ctx())
	if err != nil {
		return err
	}

	runners := map[string]runner.Runner{
		"local": runner.NewLocal(),
	}
	if hostsUseTransport(inv, "ssh") {
		sshR, err := buildSSHRunner(cfg)
		if err != nil {
			return fmt.Errorf("ssh runner: %w", err)
		}
		runners["ssh"] = sshR
		defer func() { _ = sshR.Close() }()
	}

	eng, err := runlife.New(runlife.Options{
		Store: st, Audit: al, Registry: reg, Inventory: inv,
		Runners:       runners,
		GlobalRateTPS: cfg.Limits.GlobalTestsPerSecond,
		PerHostConcur: cfg.Limits.PerHostConcurrency,
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
		Seed:  rf.seed,
		Actor: actor,
	}

	runID, plan, err := eng.Plan(ctx(), planReq)
	if err != nil {
		return err
	}

	fmt.Printf("planned run %s — %d test execution(s) on %d host(s)\n",
		runID, len(plan.Tests), countDistinctHosts(plan))
	for _, pt := range plan.Tests {
		fmt.Printf("  %s  %s\n", pt.HostName, pt.TestID)
	}
	if rf.dryRun {
		return nil
	}

	if !confirmRun(plan, maxDest, rf, reg) {
		return fmt.Errorf("run cancelled")
	}

	// Audit destructive_run_authorized BEFORE first test executes when the
	// plan contains anything above low.
	if planExceedsLow(plan, reg) {
		payload, _ := jsonMarshal(map[string]any{
			"max_dest":   maxDest,
			"engagement": rf.engagement,
			"plan_size":  len(plan.Tests),
		})
		if _, err := al.Append(ctx(), audit.Record{
			Actor: actor, Engagement: rf.engagement, RunID: runID,
			Event: "destructive_run_authorized", Payload: payload,
		}); err != nil {
			return err
		}
	}

	if err := eng.Execute(ctx(), runID, actor); err != nil {
		return fmt.Errorf("run %s: %w", runID, err)
	}
	fmt.Printf("\nrun %s completed — see 'eyeexam runs show %s'\n", runID, runID)
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

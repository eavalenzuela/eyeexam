package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
)

type planFlags struct {
	pack     string
	hosts    []string
	tags     []string
	notTags  []string
	tests    []string
	notTests []string
	maxDest  string
	seed     int64
	json     bool
}

func newPlanCmd() *cobra.Command {
	var pf planFlags
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Resolve a plan (host × test) and print it without executing",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPlan(pf, false)
		},
	}
	bindRunFlags(cmd, &pf)
	return cmd
}

func bindRunFlags(cmd *cobra.Command, pf *planFlags) {
	cmd.Flags().StringVar(&pf.pack, "pack", "", "pack name to draw tests from")
	cmd.Flags().StringSliceVar(&pf.hosts, "hosts", nil, "host names")
	cmd.Flags().StringSliceVar(&pf.tags, "tag", nil, "host tag (repeatable)")
	cmd.Flags().StringSliceVar(&pf.notTags, "tag-not", nil, "exclude tag (repeatable)")
	cmd.Flags().StringSliceVar(&pf.tests, "tests", nil, "test id glob (repeatable)")
	cmd.Flags().StringSliceVar(&pf.notTests, "deny-tests", nil, "test id glob to exclude (repeatable)")
	cmd.Flags().StringVar(&pf.maxDest, "max-dest", "low", "max destructiveness (low|medium|high)")
	cmd.Flags().Int64Var(&pf.seed, "seed", 0, "shuffle seed (0 = stable order)")
	cmd.Flags().BoolVar(&pf.json, "json", false, "emit plan JSON")
	_ = cmd.MarkFlagRequired("pack")
}

// runPlan loads config + registry + inventory, resolves the plan, prints it,
// and returns the loaded engine handle bits (without persisting anything).
// For `eyeexam plan` we never persist or audit.
func runPlan(pf planFlags, _ bool) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
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

	allowed, refused, err := reg.FromPack(pf.pack)
	if err != nil {
		return err
	}
	sel := inventory.Selector{
		Hosts: pf.hosts, Tags: pf.tags, NotTags: pf.notTags,
		Tests: pf.tests, NotTests: pf.notTests,
	}
	hosts, warns, err := inv.Apply(sel)
	if err != nil {
		return err
	}
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}

	var planned []planRow
	for _, h := range hosts {
		hostCap := inv.CapForHost(h)
		runCap := pack.Dest(pf.maxDest)
		eff := hostCap
		if runCap.Rank() < eff.Rank() {
			eff = runCap
		}
		for _, t := range allowed {
			if !sel.MatchTestID(t.ID) {
				continue
			}
			if !platformAllowed(t.Platforms, hostPlatform(h)) {
				continue
			}
			if !t.Destructiveness.AtMost(eff) {
				continue
			}
			planned = append(planned, planRow{
				Host: h.Name, TestID: t.ID,
				Technique: t.Attack.Technique, Dest: string(t.Destructiveness),
			})
		}
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HOST\tTEST_ID\tTECHNIQUE\tDEST")
	for _, p := range planned {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Host, p.TestID, p.Technique, p.Dest)
	}
	_ = tw.Flush()

	if len(refused) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d test(s) refused by hard-refuse list:\n", len(refused))
		for _, t := range refused {
			fmt.Fprintln(os.Stderr, "  -", t.ID)
		}
	}
	if len(planned) == 0 {
		return fmt.Errorf("plan empty after filtering")
	}
	_ = audit.Actor{} // imported for future use
	return nil
}

type planRow struct {
	Host      string
	TestID    string
	Technique string
	Dest      string
}

func platformAllowed(platforms []string, host string) bool {
	if len(platforms) == 0 {
		return true
	}
	for _, p := range platforms {
		if p == host {
			return true
		}
	}
	return false
}

func hostPlatform(h inventory.Host) string {
	for _, t := range h.Tags {
		switch t {
		case "linux", "darwin", "windows":
			return t
		}
	}
	return "linux"
}

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func newRunsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "runs", Short: "Inspect past runs"}
	cmd.AddCommand(newRunsListCmd())
	cmd.AddCommand(newRunsShowCmd())
	cmd.AddCommand(newRunsResumeCmd())
	return cmd
}

func newRunsResumeCmd() *cobra.Command {
	var actorApp string
	cmd := &cobra.Command{
		Use:   "resume <run-id>",
		Short: "Resume a partially complete run from its current phase",
		Long: `Resumes a run that was interrupted (process killed, host unreachable,
power loss). The engine inspects runs.phase and re-enters at the next
phase; already-completed executions inside a phase are skipped via
their idempotency keys (execution_id), so a resume never re-runs a
test that already finished.

A run in phase=reported is already terminal and resume is a no-op.
A run in phase=failed must be inspected before resuming.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := args[0]

			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			inv, err := inventory.Load(cfg.Inventory.Path)
			if err != nil {
				return err
			}
			reg, atomicSkipped, err := buildPackRegistry(cfg)
			if err != nil {
				return err
			}
			for name, skipped := range atomicSkipped {
				for _, s := range skipped {
					fmt.Fprintf(os.Stderr, "atomic pack %q: skipped %s — %s\n", name, s.ID, s.Reason)
				}
			}

			st, err := store.Open(ctx(), cfg.DBPath())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			r, err := st.GetRun(ctx(), runID)
			if err != nil {
				return err
			}
			if r.Phase == "reported" {
				fmt.Printf("run %s already reported; nothing to resume\n", runID)
				return nil
			}
			if r.Phase == "failed" {
				return fmt.Errorf("run %s is in phase=failed; inspect before resuming", runID)
			}

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
			if actorApp != "" {
				if err := audit.ValidateAppUser(actorApp); err != nil {
					return err
				}
				v := actorApp
				actor.AppUser = &v
			}

			runners := map[string]runner.Runner{"local": runner.NewLocal()}
			if hostsUseTransport(inv, "ssh") {
				sshR, err := buildSSHRunner(cfg)
				if err != nil {
					return fmt.Errorf("ssh runner: %w", err)
				}
				runners["ssh"] = sshR
				defer func() { _ = sshR.Close() }()
			}

			dreg, err := buildDetectorRegistry(cfg)
			if err != nil {
				return fmt.Errorf("detector registry: %w", err)
			}

			eng, err := runlife.New(runlife.Options{
				Store: st, Audit: al, Registry: reg, Inventory: inv,
				Runners: runners, Detectors: dreg,
				GlobalRateTPS: cfg.Limits.GlobalTestsPerSecond,
				PerHostConcur: cfg.Limits.PerHostConcurrency,
			})
			if err != nil {
				return err
			}

			fmt.Printf("resuming run %s from phase=%s\n", runID, r.Phase)
			if err := eng.Resume(ctx(), runID, actor); err != nil {
				return fmt.Errorf("resume %s: %w", runID, err)
			}
			fmt.Printf("run %s completed — see 'eyeexam runs show %s'\n", runID, runID)
			return nil
		},
	}
	cmd.Flags().StringVar(&actorApp, "actor-app", "", "human identity to record on the resume actor")
	return cmd
}

func newRunsListCmd() *cobra.Command {
	var (
		engagement string
		limit      int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recent runs",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			st, err := store.Open(ctx(), cfg.DBPath())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			rows, err := st.ListRuns(ctx(), engagement, limit)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "RUN_ID\tPHASE\tENGAGEMENT\tMAX_DEST\tSTARTED\tFINISHED")
			for _, r := range rows {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.ID, r.Phase, r.EngagementID, r.MaxDest,
					r.StartedAt.String, r.FinishedAt.String)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&engagement, "engagement", "", "filter by engagement id")
	cmd.Flags().IntVar(&limit, "limit", 50, "max rows")
	return cmd
}

func newRunsShowCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show <run-id>",
		Short: "Show one run with per-execution detail",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			st, err := store.Open(ctx(), cfg.DBPath())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			r, err := st.GetRun(ctx(), args[0])
			if err != nil {
				return err
			}
			execs, err := st.ListExecutionsForRun(ctx(), r.ID)
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(map[string]any{"run": r, "executions": execs})
			}
			fmt.Printf("run        : %s\n", r.ID)
			fmt.Printf("engagement : %s\n", r.EngagementID)
			fmt.Printf("phase      : %s\n", r.Phase)
			fmt.Printf("max_dest   : %s\n", r.MaxDest)
			fmt.Printf("authorized : %s\n", r.AuthorizedBy)
			fmt.Printf("started    : %s\n", r.StartedAt.String)
			fmt.Printf("finished   : %s\n", r.FinishedAt.String)
			fmt.Println()

			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "EXEC_ID\tHOST\tTEST_ID\tEXIT\tDETECT\tCLEANUP\tVERIFY")
			hostCache := map[string]string{}
			for _, ex := range execs {
				hn := hostCache[ex.HostID]
				if hn == "" {
					if h, err := st.GetHostByID(ctx(), ex.HostID); err == nil {
						hn = h.Name
					}
					hostCache[ex.HostID] = hn
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
					ex.ID, hn, ex.TestID, ex.ExitCode.Int64,
					ex.DetectionState, ex.CleanupState, ex.CleanupVerifyState)
			}
			if err := tw.Flush(); err != nil {
				return err
			}

			// Per-expectation detail.
			anyExpect := false
			for _, ex := range execs {
				exps, err := st.ListExpectedDetectionsForExecution(ctx(), ex.ID)
				if err != nil {
					return err
				}
				if len(exps) == 0 {
					continue
				}
				if !anyExpect {
					fmt.Println()
					fmt.Println("expected detections:")
					anyExpect = true
				}
				fmt.Printf("  %s (%s):\n", ex.ID, ex.TestID)
				for _, ep := range exps {
					reason := ep.Reason.String
					det := ep.DetectorName.String
					if det == "" {
						det = "-"
					}
					if reason != "" {
						fmt.Printf("    [%s] det=%s — %s\n", ep.State, det, reason)
					} else {
						fmt.Printf("    [%s] det=%s\n", ep.State, det)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

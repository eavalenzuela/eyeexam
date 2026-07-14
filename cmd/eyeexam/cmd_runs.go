package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func newRunsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "runs", Short: "Inspect past runs"}
	cmd.AddCommand(newRunsListCmd())
	cmd.AddCommand(newRunsShowCmd())
	cmd.AddCommand(newRunsResumeCmd())
	cmd.AddCommand(newRunsCleanupCmd())
	return cmd
}

// engineFromConfig builds a runlife engine from shared deps using the config's
// EDR settings (cleanup mode, pacing, step timeout). Used by resume + cleanup,
// which take these from config rather than per-invocation flags.
func engineFromConfig(deps *runtimeDeps) (*runlife.Engine, error) {
	return runlife.New(runlife.Options{
		Store: deps.store, Audit: deps.audit, Registry: deps.reg, Inventory: deps.inv,
		Runners:         deps.runners,
		Detectors:       deps.detectors,
		GlobalRateTPS:   deps.cfg.Limits.GlobalTestsPerSecond,
		PerHostConcur:   deps.cfg.Limits.PerHostConcurrency,
		CleanupMode:     deps.cfg.Cleanup.EffectiveMode(),
		InterTestPace:   deps.cfg.Limits.Pace(),
		InterTestJitter: deps.cfg.Limits.Jitter(),
		StepTimeout:     deps.cfg.Limits.Step(),
	})
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

			deps, err := loadRuntime(actorApp)
			if err != nil {
				return err
			}
			defer deps.close()

			r, err := deps.store.GetRun(ctx(), runID)
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

			emitUnsignedPackAudit(ctx(), deps.audit, deps.actor, r.EngagementID, deps.unsignedPacks)

			eng, err := engineFromConfig(deps)
			if err != nil {
				return err
			}

			fmt.Printf("resuming run %s from phase=%s\n", runID, r.Phase)
			if err := runWithGracefulAbort(eng, runID, deps.actor, func(c context.Context) error {
				return eng.Resume(c, runID, deps.actor)
			}); err != nil {
				return err
			}
			fmt.Printf("run %s completed — see 'eyeexam runs show %s'\n", runID, runID)
			return nil
		},
	}
	cmd.Flags().StringVar(&actorApp, "actor-app", "", "human identity to record on the resume actor")
	return cmd
}

func newRunsCleanupCmd() *cobra.Command {
	var (
		allPending bool
		actorApp   string
	)
	cmd := &cobra.Command{
		Use:   "cleanup [run-id]",
		Short: "Revert file-modifying tests left pending by an interrupted run",
		Long: `Drains staged cleanups. For every execution whose cleanup or
cleanup-verify never finished, this re-runs the test's cleanup + verify steps,
independent of the wait/query/score phases. Use it to recover a host after a
run was interrupted — an EDR killed the process, Ctrl-C, a dropped SSH session,
power loss — so changes to files such as ~/.ssh/authorized_keys, the crontab,
or ~/.bashrc are reverted rather than left behind.

  eyeexam runs cleanup <run-id>       # drain one run
  eyeexam runs cleanup --all-pending   # drain every run with pending cleanup

Idempotent: executions already cleaned up are skipped, so it is safe to run
more than once.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if allPending == (len(args) == 1) {
				return fmt.Errorf("provide exactly one of <run-id> or --all-pending")
			}

			deps, err := loadRuntime(actorApp)
			if err != nil {
				return err
			}
			defer deps.close()

			emitUnsignedPackAudit(ctx(), deps.audit, deps.actor, deps.cfg.Engagement.ID, deps.unsignedPacks)

			eng, err := engineFromConfig(deps)
			if err != nil {
				return err
			}

			if allPending {
				ids, err := eng.CleanupAllPending(ctx(), deps.actor)
				if err != nil {
					return err
				}
				if len(ids) == 0 {
					fmt.Println("no runs with pending cleanup")
					return nil
				}
				for _, id := range ids {
					reportCleanup(deps.store, id)
				}
				return nil
			}

			runID := args[0]
			if _, err := deps.store.GetRun(ctx(), runID); err != nil {
				return err
			}
			before, err := deps.store.CountPendingCleanupForRun(ctx(), runID)
			if err != nil {
				return err
			}
			if before == 0 {
				fmt.Printf("run %s: nothing pending to clean up\n", runID)
				return nil
			}
			if err := eng.DrainCleanup(ctx(), runID, deps.actor); err != nil {
				return fmt.Errorf("run %s: drain cleanup: %w", runID, err)
			}
			reportCleanup(deps.store, runID)
			return nil
		},
	}
	cmd.Flags().BoolVar(&allPending, "all-pending", false, "drain cleanups for every run that has any")
	cmd.Flags().StringVar(&actorApp, "actor-app", "", "human identity to record on the cleanup actor")
	return cmd
}

// reportCleanup prints how many executions in runID still await cleanup after
// a drain (0 = fully reverted; >0 = some cleanup steps failed — inspect with
// `eyeexam runs show`).
func reportCleanup(st *store.Store, runID string) {
	remaining, err := st.CountPendingCleanupForRun(ctx(), runID)
	if err != nil {
		fmt.Printf("run %s: drained (could not recount: %v)\n", runID, err)
		return
	}
	if remaining == 0 {
		fmt.Printf("run %s: cleanup complete — no pending executions\n", runID)
		return
	}
	fmt.Printf("run %s: %d execution(s) still pending after drain — see 'eyeexam runs show %s'\n",
		runID, remaining, runID)
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

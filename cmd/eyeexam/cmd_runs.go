package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/store"
)

func newRunsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "runs", Short: "Inspect past runs"}
	cmd.AddCommand(newRunsListCmd())
	cmd.AddCommand(newRunsShowCmd())
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

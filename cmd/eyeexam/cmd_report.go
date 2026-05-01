package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/attack"
	"github.com/eavalenzuela/eyeexam/internal/report"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate engagement-scoped reports from run history",
		Long: `Reports are operator-facing readouts of past run data: quarterly
coverage reviews, audit handoffs, post-incident retrospectives.
They query the SQLite store and render Markdown or JSON suitable
for pasting into tickets, briefing notes, or downstream tooling.

This is read-only over already-collected data — no agents are
contacted and no tests fire.`,
	}
	cmd.AddCommand(newReportCoverageCmd())
	return cmd
}

func newReportCoverageCmd() *cobra.Command {
	var (
		engagement string
		since      time.Duration
		format     string
		out        string
	)
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Coverage summary for one engagement: states, regressions, authorizations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if engagement == "" {
				engagement = cfg.Engagement.ID
			}
			if engagement == "" {
				return fmt.Errorf("--engagement required (or set engagement.id in config)")
			}

			st, err := store.Open(ctx(), cfg.DBPath())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			req := report.CoverageRequest{
				Engagement: engagement,
			}
			if since > 0 {
				req.Since = time.Now().UTC().Add(-since)
			}

			cov, err := report.Build(ctx(), st, attack.EmbeddedFallback(), req)
			if err != nil {
				return err
			}

			var rendered []byte
			switch format {
			case "md", "markdown", "":
				rendered = []byte(report.RenderMarkdown(cov))
			case "json":
				b, err := report.RenderJSON(cov)
				if err != nil {
					return err
				}
				rendered = b
			default:
				return fmt.Errorf("--format must be md or json (got %q)", format)
			}

			if out == "" {
				_, err := os.Stdout.Write(rendered)
				return err
			}
			return os.WriteFile(out, rendered, 0o644)
		},
	}
	cmd.Flags().StringVar(&engagement, "engagement", "", "engagement id (defaults to config.engagement.id)")
	cmd.Flags().DurationVar(&since, "since", 30*24*time.Hour, "lookback window")
	cmd.Flags().StringVar(&format, "format", "md", "output format: md|json")
	cmd.Flags().StringVar(&out, "out", "", "write to file instead of stdout")
	return cmd
}

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
They query the SQLite store and render HTML (eye-candy, suitable
for sharing) or JSON (machine-readable, for ingestion).

This is read-only over already-collected data — no agents are
contacted and no tests fire.`,
	}
	cmd.AddCommand(newReportCoverageCmd())
	cmd.AddCommand(newReportRunCmd())
	cmd.AddCommand(newReportMatrixCmd())
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

			req := report.CoverageRequest{Engagement: engagement}
			if since > 0 {
				req.Since = time.Now().UTC().Add(-since)
			}
			cov, err := report.Build(ctx(), st, attack.EmbeddedFallback(), req)
			if err != nil {
				return err
			}
			return writeReport(out, format, func() ([]byte, error) {
				return report.RenderHTMLCoverage(cov)
			}, func() ([]byte, error) {
				return report.RenderJSONCoverage(cov)
			})
		},
	}
	cmd.Flags().StringVar(&engagement, "engagement", "", "engagement id (defaults to config.engagement.id)")
	cmd.Flags().DurationVar(&since, "since", 30*24*time.Hour, "lookback window")
	cmd.Flags().StringVar(&format, "format", "html", "output format: html|json")
	cmd.Flags().StringVar(&out, "out", "", "write to file instead of stdout")
	return cmd
}

func newReportRunCmd() *cobra.Command {
	var (
		format string
		out    string
	)
	cmd := &cobra.Command{
		Use:   "run <run-id>",
		Short: "Per-run detail: metadata, executions, expectations, audit events",
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
			rep, err := report.BuildRun(ctx(), st, args[0])
			if err != nil {
				return err
			}
			return writeReport(out, format, func() ([]byte, error) {
				return report.RenderHTMLRun(rep)
			}, func() ([]byte, error) {
				return report.RenderJSONRun(rep)
			})
		},
	}
	cmd.Flags().StringVar(&format, "format", "html", "output format: html|json")
	cmd.Flags().StringVar(&out, "out", "", "write to file instead of stdout")
	return cmd
}

func newReportMatrixCmd() *cobra.Command {
	var (
		engagement string
		since      time.Duration
		format     string
		out        string
	)
	cmd := &cobra.Command{
		Use:   "matrix",
		Short: "ATT&CK heatmap (HTML grid or JSON), engagement-scoped if requested",
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

			req := report.MatrixRequest{Engagement: engagement}
			if since > 0 {
				req.Since = time.Now().UTC().Add(-since)
			}
			m, err := report.BuildMatrix(ctx(), st, attack.EmbeddedFallback(), req)
			if err != nil {
				return err
			}
			return writeReport(out, format, func() ([]byte, error) {
				return report.RenderHTMLMatrix(m)
			}, func() ([]byte, error) {
				return report.RenderJSONMatrix(m)
			})
		},
	}
	cmd.Flags().StringVar(&engagement, "engagement", "", "engagement id (omit for cross-engagement)")
	cmd.Flags().DurationVar(&since, "since", 30*24*time.Hour, "lookback window")
	cmd.Flags().StringVar(&format, "format", "html", "output format: html|json")
	cmd.Flags().StringVar(&out, "out", "", "write to file instead of stdout")
	return cmd
}

// writeReport picks the renderer for `format` and writes to `out` (file
// path) or stdout. Centralizes the html-vs-json + stdout-vs-file
// boilerplate that each report subcommand needs.
func writeReport(out, format string, html, jsn func() ([]byte, error)) error {
	var (
		rendered []byte
		err      error
	)
	switch format {
	case "html", "":
		rendered, err = html()
	case "json":
		rendered, err = jsn()
	default:
		return fmt.Errorf("--format must be html or json (got %q)", format)
	}
	if err != nil {
		return err
	}
	if out == "" {
		_, err := os.Stdout.Write(rendered)
		return err
	}
	return os.WriteFile(out, rendered, 0o644)
}

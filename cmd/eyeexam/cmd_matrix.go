package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/attack"
	"github.com/eavalenzuela/eyeexam/internal/matrix"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func newMatrixCmd() *cobra.Command {
	var (
		out        string
		windowDays int
		stixPath   string
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "matrix",
		Short: "Render the ATT&CK coverage matrix to stdout or a file",
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

			bundle := attack.EmbeddedFallback()
			if stixPath != "" {
				b, err := attack.LoadFromSTIX(stixPath)
				if err != nil {
					return err
				}
				bundle = b
			}
			since := time.Now().UTC().Add(-time.Duration(windowDays) * 24 * time.Hour)
			m, err := matrix.Build(ctx(), st, bundle, since)
			if err != nil {
				return err
			}

			var w *os.File
			if out == "" || out == "-" {
				w = os.Stdout
			} else {
				w, err = os.Create(out)
				if err != nil {
					return err
				}
				defer func() { _ = w.Close() }()
			}

			if asJSON {
				if err := m.RenderJSON(w); err != nil {
					return err
				}
			} else {
				if err := m.RenderHTML(w); err != nil {
					return err
				}
			}
			if w != os.Stdout {
				fmt.Fprintf(os.Stderr, "wrote matrix → %s\n", out)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "output path (default stdout)")
	cmd.Flags().IntVar(&windowDays, "window-days", 30, "window in days")
	cmd.Flags().StringVar(&stixPath, "stix", "", "path to enterprise-attack.json (optional)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON instead of HTML")
	return cmd
}

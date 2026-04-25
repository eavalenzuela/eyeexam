package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

func newPackCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pack", Short: "Manage test packs"}
	cmd.AddCommand(newPackListCmd())
	cmd.AddCommand(newPackAddCmd())
	return cmd
}

func newPackListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured packs and their tests",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
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
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "PACK\tTEST_ID\tTECHNIQUE\tDEST\tNAME")
			for _, p := range reg.Packs() {
				for _, t := range p.Tests {
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
						p.Name, t.ID, t.Attack.Technique, t.Destructiveness, t.Name)
				}
			}
			return tw.Flush()
		},
	}
}

func newPackAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <name> <path>",
		Short: "Register a native pack from a local directory in your config",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("pack add: not yet implemented in M1; edit config.yaml directly")
		},
	}
	return cmd
}

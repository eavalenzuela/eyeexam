package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
)

func newInventoryCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "inventory", Short: "Manage host inventory"}
	cmd.AddCommand(newInventoryListCmd())
	return cmd
}

func newInventoryListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List hosts in the configured inventory",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			inv, err := inventory.Load(cfg.Inventory.Path)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NAME\tADDRESS\tTRANSPORT\tTAGS\tMAX_DEST")
			for _, h := range inv.Hosts {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					h.Name, h.Address, h.Transport, strings.Join(h.Tags, ","), h.MaxDest)
			}
			return tw.Flush()
		},
	}
}

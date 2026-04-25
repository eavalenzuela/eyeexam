package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/runner"
)

func newInventoryCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "inventory", Short: "Manage host inventory"}
	cmd.AddCommand(newInventoryListCmd())
	cmd.AddCommand(newInventoryCheckCmd())
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

func newInventoryCheckCmd() *cobra.Command {
	var dialTimeout time.Duration
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Probe each inventory host for reachability and auth",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			inv, err := inventory.Load(cfg.Inventory.Path)
			if err != nil {
				return err
			}

			var sshR *runner.SSH
			if hostsUseTransport(inv, "ssh") {
				sshR, err = buildSSHRunner(cfg)
				if err != nil {
					return fmt.Errorf("ssh runner: %w", err)
				}
				defer func() { _ = sshR.Close() }()
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "HOST\tTRANSPORT\tSTATUS\tDETAIL")
			anyFailure := false
			for _, h := range inv.Hosts {
				status, detail := checkHost(cmd.Context(), h, sshR, dialTimeout)
				if status != "ok" {
					anyFailure = true
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
					h.Name, h.Transport, status, detail)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if anyFailure {
				return fmt.Errorf("one or more hosts unreachable")
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&dialTimeout, "timeout", 10*time.Second, "per-host dial timeout")
	return cmd
}

func checkHost(parent context.Context, h inventory.Host, sshR *runner.SSH, timeout time.Duration) (status, detail string) {
	switch h.Transport {
	case "local":
		return "ok", "localhost"
	case "ssh":
		if sshR == nil {
			return "skipped", "no ssh runner available"
		}
		ctx := parent
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := sshR.HealthCheck(ctx, h); err != nil {
			return "fail", err.Error()
		}
		return "ok", "ssh exec true returned 0"
	case "slither":
		return "skipped", "slither runner lands in M7"
	default:
		return "fail", "unknown transport"
	}
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/alert"
	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/idgen"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runlife"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/scheduler"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func newScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "schedule", Short: "Manage scheduled runs"}
	cmd.AddCommand(newScheduleAddCmd())
	cmd.AddCommand(newScheduleListCmd())
	cmd.AddCommand(newScheduleRemoveCmd())
	return cmd
}

func newSchedulerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scheduler",
		Short: "Run the scheduler daemon (foreground)",
	}
	cmd.AddCommand(newSchedulerRunCmd())
	return cmd
}

func newScheduleAddCmd() *cobra.Command {
	var (
		name      string
		cron      string
		packN     string
		maxDest   string
		hosts     []string
		tags      []string
		notTags   []string
		webhook   []string
		ntfy      []string
		discord   []string
		ntfyTopic string
		actorApp  string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a scheduled run (operator pre-authorizes the schedule)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" || cron == "" || packN == "" {
				return fmt.Errorf("--name, --cron, and --pack are required")
			}
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			st, err := store.Open(ctx(), cfg.DBPath())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

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

			selJSON, _ := json.Marshal(inventory.Selector{
				Hosts: hosts, Tags: tags, NotTags: notTags,
			})

			var sinks []alert.SinkConfig
			for _, u := range webhook {
				sinks = append(sinks, alert.SinkConfig{Type: "webhook", URL: u, Name: "webhook-" + shortHash(u)})
			}
			for _, u := range ntfy {
				sinks = append(sinks, alert.SinkConfig{
					Type: "ntfy", URL: u, Name: "ntfy-" + shortHash(u),
					Opts: map[string]any{"topic": ntfyTopic},
				})
			}
			for _, u := range discord {
				sinks = append(sinks, alert.SinkConfig{Type: "discord", URL: u, Name: "discord-" + shortHash(u)})
			}
			alertsJSON, _ := json.Marshal(sinks)

			if err := st.UpsertEngagement(ctx(), store.Engagement{
				ID: cfg.Engagement.ID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			}); err != nil {
				return err
			}

			sc := store.Schedule{
				ID: idgen.New("s"), Name: name, CronExpr: cron,
				EngagementID: cfg.Engagement.ID, PackName: packN, MaxDest: maxDest,
				SelectorJSON: string(selJSON),
				AlertsJSON:   string(alertsJSON),
				Enabled:      1,
				AuthorizedBy: actor.String(),
			}
			if actorApp != "" {
				sc.AppUser.Valid = true
				sc.AppUser.String = actorApp
			}
			if err := st.InsertSchedule(ctx(), sc); err != nil {
				return err
			}
			fmt.Printf("scheduled %s — cron %q pack %q max_dest %s\n", name, cron, packN, maxDest)
			fmt.Printf("alert sinks: %d\n", len(sinks))
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "schedule name (unique)")
	cmd.Flags().StringVar(&cron, "cron", "", `cron expression (e.g. "0 3 * * *")`)
	cmd.Flags().StringVar(&packN, "pack", "", "pack name to draw tests from")
	cmd.Flags().StringVar(&maxDest, "max-dest", "low", "max destructiveness (low|medium|high)")
	cmd.Flags().StringSliceVar(&hosts, "hosts", nil, "host names")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "host tag")
	cmd.Flags().StringSliceVar(&notTags, "tag-not", nil, "exclude tag")
	cmd.Flags().StringSliceVar(&webhook, "webhook", nil, "POST regression payloads to URL (repeatable)")
	cmd.Flags().StringSliceVar(&ntfy, "ntfy", nil, "ntfy.sh server URL (repeatable)")
	cmd.Flags().StringVar(&ntfyTopic, "ntfy-topic", "eyeexam", "ntfy topic")
	cmd.Flags().StringSliceVar(&discord, "discord", nil, "discord webhook URL (repeatable)")
	cmd.Flags().StringVar(&actorApp, "actor-app", "", "human identity to record on each scheduled fire (e.g. when the scheduler runs as a service account)")
	return cmd
}

func newScheduleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List scheduled runs",
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
			rows, err := st.ListSchedules(ctx(), false)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NAME\tCRON\tPACK\tMAX_DEST\tENABLED\tLAST_RUN")
			for _, r := range rows {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\t%s\n",
					r.Name, r.CronExpr, r.PackName, r.MaxDest, r.Enabled == 1, r.LastRunAt.String)
			}
			return tw.Flush()
		},
	}
}

func newScheduleRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Delete a scheduled run",
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
			return st.DeleteScheduleByName(ctx(), args[0])
		},
	}
}

func newSchedulerRunCmd() *cobra.Command {
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the scheduler in the foreground",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			inv, err := inventory.Load(cfg.Inventory.Path)
			if err != nil {
				return err
			}
			reg, _, err := buildPackRegistry(cfg)
			if err != nil {
				return err
			}
			st, err := store.Open(ctx(), cfg.DBPath())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			priv, err := loadAuditKey(cfg.Audit.KeyPath)
			if err != nil {
				return err
			}
			al, err := audit.Open(cfg.Audit.LogPath, priv)
			if err != nil {
				return err
			}
			defer func() { _ = al.Close() }()

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
				return err
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

			s, err := scheduler.New(scheduler.Options{
				Store: st, Audit: al, Engine: eng,
			})
			if err != nil {
				return err
			}

			ctxSig, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			fmt.Printf("eyeexam scheduler running (interval=%s) — Ctrl-C to exit\n", interval)
			err = s.Run(ctxSig, interval)
			if err == context.Canceled {
				return nil
			}
			return err
		},
	}
	cmd.Flags().DurationVar(&interval, "interval", 30*time.Second, "tick interval")
	// Suppress unused-import error if alert isn't referenced after edits.
	_ = pack.DestLow
	return cmd
}

func shortHash(s string) string {
	h := uint32(0)
	for i := 0; i < len(s); i++ {
		h = h*31 + uint32(s[i])
	}
	return fmt.Sprintf("%08x", h)
}

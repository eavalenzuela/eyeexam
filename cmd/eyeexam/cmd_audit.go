package main

import (
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Audit log operations"}
	cmd.AddCommand(newAuditVerifyCmd())
	cmd.AddCommand(newAuditShowCmd())
	return cmd
}

func newAuditShowCmd() *cobra.Command {
	var (
		runID      string
		engagement string
		event      string
		actor      string
		since      time.Duration
		limit      int
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Query the audit log mirror (audit_log SQLite table)",
		Long: `Reads from the audit_log SQLite mirror, not the on-disk JSONL file.
The mirror is populated transactionally on Append and reconciled at
audit.Open; if you suspect tampering, run 'eyeexam audit verify' which
cross-checks both stores.`,
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

			f := store.AuditFilter{
				RunID:        runID,
				EngagementID: engagement,
				Event:        event,
				Actor:        actor,
				Limit:        limit,
			}
			if since > 0 {
				f.SinceTS = time.Now().UTC().Add(-since).Format(time.RFC3339Nano)
			}

			rows, err := st.ListAudit(ctx(), f)
			if err != nil {
				return err
			}

			if asJSON {
				return printJSON(rows)
			}

			if len(rows) == 0 {
				fmt.Println("(no matching audit records)")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "SEQ\tTS\tEVENT\tRUN\tACTOR")
			for _, r := range rows {
				ts := r.TS
				if t, err := time.Parse(time.RFC3339Nano, r.TS); err == nil {
					ts = t.Format("2026-01-02 15:04:05Z")
				}
				_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n",
					r.Seq, ts, r.Event, r.RunID.String, summarizeActor(r.ActorJSON))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&runID, "run", "", "filter by run id")
	cmd.Flags().StringVar(&engagement, "engagement", "", "filter by engagement id")
	cmd.Flags().StringVar(&event, "event", "", `filter by event name (e.g. "destructive_run_authorized")`)
	cmd.Flags().StringVar(&actor, "actor", "", "filter by actor substring (matches OS user, app user, etc.)")
	cmd.Flags().DurationVar(&since, "since", 0, "only show records within this lookback window (e.g. 24h)")
	cmd.Flags().IntVar(&limit, "limit", 200, "max records to return")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

// summarizeActor extracts a one-line label from the JSON actor blob:
// "alice@svc/svc(uid=1000)" or "svc(uid=1000)".
func summarizeActor(actorJSON string) string {
	var a struct {
		OSUser  string  `json:"os_user"`
		OSUID   int     `json:"os_uid"`
		AppUser *string `json:"app_user,omitempty"`
	}
	if err := json.Unmarshal([]byte(actorJSON), &a); err != nil {
		return actorJSON
	}
	if a.AppUser != nil {
		return fmt.Sprintf("%s/%s(uid=%d)", *a.AppUser, a.OSUser, a.OSUID)
	}
	return fmt.Sprintf("%s(uid=%d)", a.OSUser, a.OSUID)
}

func newAuditVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the hash chain and signatures of audit.log",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			pubBytes, err := os.ReadFile(cfg.Audit.KeyPath + ".pub")
			if err != nil {
				return fmt.Errorf("read public key: %w", err)
			}
			block, _ := pem.Decode(pubBytes)
			if block == nil {
				return fmt.Errorf("audit pub key: not a PEM file")
			}
			pub := ed25519.PublicKey(block.Bytes)

			st, err := store.Open(ctx(), cfg.DBPath())
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			res, err := audit.VerifyWithMirror(cfg.Audit.LogPath, pub, st.DB)
			if err != nil {
				return err
			}
			if !res.OK {
				return fmt.Errorf("audit verify FAILED at seq %d: %s",
					res.FirstBadSeq, res.Reason)
			}
			fmt.Printf("audit verify OK (%d records, file ↔ db mirror match)\n", res.RecordsChecked)
			return nil
		},
	}
}

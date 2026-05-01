package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Audit log operations"}
	cmd.AddCommand(newAuditVerifyCmd())
	return cmd
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

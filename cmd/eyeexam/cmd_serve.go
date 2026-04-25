package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/attack"
	"github.com/eavalenzuela/eyeexam/internal/store"
	"github.com/eavalenzuela/eyeexam/ui"
)

func newServeCmd() *cobra.Command {
	var (
		listen         string
		insecurePublic bool
		windowDays     int
		stixPath       string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the read-only HTTP viewer for runs and the ATT&CK matrix",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if listen == "" {
				listen = cfg.UI.Listen
			}
			if listen == "" {
				listen = "127.0.0.1:8088"
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

			srv, err := ui.New(ui.Options{
				Listen:         listen,
				InsecurePublic: insecurePublic,
				Bundle:         bundle,
				Store:          st,
				MatrixWindow:   time.Duration(windowDays) * 24 * time.Hour,
			})
			if err != nil {
				return err
			}

			fmt.Printf("eyeexam serve listening on http://%s\n", listen)

			ctxSig, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			errCh := make(chan error, 1)
			go func() { errCh <- srv.ListenAndServe() }()
			select {
			case err := <-errCh:
				return err
			case <-ctxSig.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return srv.Shutdown(shutdownCtx)
			}
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address to bind (default 127.0.0.1:8088)")
	cmd.Flags().BoolVar(&insecurePublic, "insecure-public", false, "allow binding a non-loopback address (off by default)")
	cmd.Flags().IntVar(&windowDays, "window-days", 30, "matrix window in days")
	cmd.Flags().StringVar(&stixPath, "stix", "", "path to enterprise-attack.json (optional; uses embedded fallback otherwise)")
	return cmd
}

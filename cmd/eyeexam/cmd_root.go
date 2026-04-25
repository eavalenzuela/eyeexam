package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/eavalenzuela/eyeexam/internal/config"
)

type globalFlags struct {
	configPath string
	dataDir    string
	logLevel   string
	noColor    bool
}

var gflags globalFlags

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "eyeexam",
		Short:         "Breach-and-attack simulation runner that closes the detection loop.",
		SilenceUsage:  true,
		SilenceErrors: false,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			lvl := parseLogLevel(gflags.logLevel)
			h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
			slog.SetDefault(slog.New(h))
		},
	}

	root.PersistentFlags().StringVar(&gflags.configPath, "config", "",
		"path to config.yaml (default: $EYEEXAM_HOME/config.yaml)")
	root.PersistentFlags().StringVar(&gflags.dataDir, "data-dir", "",
		"override data dir ($EYEEXAM_DATA / $XDG_DATA_HOME/eyeexam)")
	root.PersistentFlags().StringVar(&gflags.logLevel, "log-level", "info",
		"log level (debug|info|warn|error)")
	root.PersistentFlags().BoolVar(&gflags.noColor, "no-color", false, "disable color in output")

	root.AddCommand(
		newVersionCmd(),
		newInitCmd(),
		newPackCmd(),
		newInventoryCmd(),
		newPlanCmd(),
		newRunCmd(),
		newRunsCmd(),
		newAuditCmd(),
	)
	return root
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// loadConfig opens the configured config file, applying global overrides.
func loadConfig() (config.Config, error) {
	path := gflags.configPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	if _, err := os.Stat(path); err != nil {
		return config.Config{}, fmt.Errorf("config not found at %s — run 'eyeexam init'", path)
	}
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, err
	}
	if gflags.dataDir != "" {
		cfg.State.DataDir = gflags.dataDir
	}
	return cfg, nil
}

// ctx returns a background context. Future iterations may bind this to
// cobra cancellation.
func ctx() context.Context { return context.Background() }

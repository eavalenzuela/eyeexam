// Package config loads and validates eyeexam's YAML configuration. It also
// resolves XDG-style default paths for state, the audit key, and the SQLite
// database, with EYEEXAM_HOME / EYEEXAM_DATA overrides.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Engagement Engagement       `yaml:"engagement"`
	State      StateConfig      `yaml:"state"`
	Audit      AuditConfig      `yaml:"audit"`
	Runner     RunnerConfig     `yaml:"runner"`
	Detectors  []DetectorConfig `yaml:"detectors"`
	Inventory  InventoryConfig  `yaml:"inventory"`
	Packs      []PackConfig     `yaml:"packs"`
	PackKeys   []string         `yaml:"pack_keys"` // PEM ed25519 pubkey paths used to verify MANIFEST.sig
	Limits     Limits           `yaml:"limits"`
	Cleanup    CleanupConfig    `yaml:"cleanup"`
}

// CleanupMode values. Empty normalises to Deferred.
const (
	CleanupModeDeferred = "deferred"
	CleanupModeEager    = "eager"
)

type Engagement struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
}

type StateConfig struct {
	DataDir  string `yaml:"data_dir"`
	Database string `yaml:"database"`
}

type AuditConfig struct {
	KeyPath string `yaml:"key_path"`
	LogPath string `yaml:"log_path"`
}

type RunnerConfig struct {
	SSH   SSHConfig   `yaml:"ssh"`
	Local LocalConfig `yaml:"local"`
}

type SSHConfig struct {
	DefaultUser    string `yaml:"default_user"`
	DefaultKey     string `yaml:"default_key"`
	KnownHosts     string `yaml:"known_hosts"`
	ConnectTimeout string `yaml:"connect_timeout"`
	CommandTimeout string `yaml:"command_timeout"`
}

type LocalConfig struct {
	Enabled bool `yaml:"enabled"`
}

type DetectorConfig struct {
	Name    string                 `yaml:"name"`
	Type    string                 `yaml:"type"`
	Options map[string]interface{} `yaml:",inline"`
}

type InventoryConfig struct {
	Path string `yaml:"path"`
}

type PackConfig struct {
	Name     string `yaml:"name"`
	Path     string `yaml:"path"`
	Source   string `yaml:"source"`             // "native"|"atomic"
	Unsigned bool   `yaml:"unsigned,omitempty"` // opt-out of signature verification (audit'd at every load)
}

type Limits struct {
	GlobalTestsPerSecond float64 `yaml:"global_tests_per_second"`
	PerHostConcurrency   int     `yaml:"per_host_concurrency"`
	// InterTestPace/InterTestJitter spread executions out on a live-EDR host
	// (duration strings, e.g. "30s"/"10s"; empty = 0). StepTimeout bounds each
	// individual execute/cleanup/verify step (empty/"0" = no engine-level
	// bound; the SSH runner keeps its own command_timeout).
	InterTestPace   string `yaml:"inter_test_pace"`
	InterTestJitter string `yaml:"inter_test_jitter"`
	StepTimeout     string `yaml:"step_timeout"`
}

// Pace/Jitter/Step parse the duration-string limits, returning 0 on empty or
// unparseable input (Validate() rejects unparseable values up front).
func (l Limits) Pace() time.Duration   { return parseDur(l.InterTestPace) }
func (l Limits) Jitter() time.Duration { return parseDur(l.InterTestJitter) }
func (l Limits) Step() time.Duration   { return parseDur(l.StepTimeout) }

func parseDur(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}

// CleanupConfig controls when a test's cleanup runs relative to the rest of
// the run. See runlife's Cleanup* constants.
type CleanupConfig struct {
	Mode string `yaml:"mode"` // "" | "deferred" | "eager"
}

// EffectiveMode normalises the configured cleanup mode, defaulting to deferred.
func (c CleanupConfig) EffectiveMode() string {
	if c.Mode == "" {
		return CleanupModeDeferred
	}
	return c.Mode
}

// Defaults returns a Config populated with sensible defaults. Callers
// override fields after Defaults() and before Validate().
func Defaults() Config {
	return Config{
		State: StateConfig{
			DataDir:  DataDir(),
			Database: "eyeexam.db",
		},
		Audit: AuditConfig{
			KeyPath: filepath.Join(ConfigDir(), "audit.key"),
			LogPath: filepath.Join(DataDir(), "audit.log"),
		},
		Runner: RunnerConfig{
			SSH: SSHConfig{
				DefaultUser:    "eyeexam",
				ConnectTimeout: "10s",
				CommandTimeout: "5m",
			},
			Local: LocalConfig{Enabled: true},
		},
		Limits: Limits{
			GlobalTestsPerSecond: 1,
			PerHostConcurrency:   1,
		},
	}
}

// Load reads the YAML config at path, layering it on top of Defaults().
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Engagement.ID == "" {
		return fmt.Errorf("config: engagement.id is required")
	}
	if c.State.Database == "" {
		return fmt.Errorf("config: state.database is required")
	}
	if c.Audit.KeyPath == "" {
		return fmt.Errorf("config: audit.key_path is required")
	}
	if c.Audit.LogPath == "" {
		return fmt.Errorf("config: audit.log_path is required")
	}
	for i, p := range c.Packs {
		if p.Name == "" || p.Path == "" {
			return fmt.Errorf("config: packs[%d] missing name or path", i)
		}
		if p.Source != "" && p.Source != "native" && p.Source != "atomic" {
			return fmt.Errorf("config: packs[%d] source must be native|atomic (got %q)",
				i, p.Source)
		}
	}
	if m := c.Cleanup.Mode; m != "" && m != CleanupModeDeferred && m != CleanupModeEager {
		return fmt.Errorf("config: cleanup.mode must be %q or %q (got %q)",
			CleanupModeDeferred, CleanupModeEager, m)
	}
	for name, v := range map[string]string{
		"limits.inter_test_pace":   c.Limits.InterTestPace,
		"limits.inter_test_jitter": c.Limits.InterTestJitter,
		"limits.step_timeout":      c.Limits.StepTimeout,
	} {
		if v == "" {
			continue
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("config: %s: invalid duration %q: %w", name, v, err)
		}
		if d < 0 {
			return fmt.Errorf("config: %s must not be negative (got %q)", name, v)
		}
	}
	return nil
}

// DBPath returns the absolute path of the SQLite db.
func (c Config) DBPath() string {
	if filepath.IsAbs(c.State.Database) {
		return c.State.Database
	}
	return filepath.Join(c.State.DataDir, c.State.Database)
}

// ConfigDir is $EYEEXAM_HOME or $XDG_CONFIG_HOME/eyeexam (default
// ~/.config/eyeexam).
func ConfigDir() string {
	if v := os.Getenv("EYEEXAM_HOME"); v != "" {
		return expand(v)
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(homeDir(), ".config")
	}
	return filepath.Join(xdg, "eyeexam")
}

// DataDir is $EYEEXAM_DATA or $XDG_DATA_HOME/eyeexam.
func DataDir() string {
	if v := os.Getenv("EYEEXAM_DATA"); v != "" {
		return expand(v)
	}
	xdg := os.Getenv("XDG_DATA_HOME")
	if xdg == "" {
		xdg = filepath.Join(homeDir(), ".local", "share")
	}
	return filepath.Join(xdg, "eyeexam")
}

func DefaultConfigPath() string { return filepath.Join(ConfigDir(), "config.yaml") }

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/"
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(homeDir(), p[2:])
	}
	return p
}

// Package config loads and validates eyeexam's YAML configuration. It also
// resolves XDG-style default paths for state, the audit key, and the SQLite
// database, with EYEEXAM_HOME / EYEEXAM_DATA overrides.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	Limits     Limits           `yaml:"limits"`
	UI         UIConfig         `yaml:"ui"`
}

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
	SSH     SSHConfig     `yaml:"ssh"`
	Slither SlitherConfig `yaml:"slither"`
	Local   LocalConfig   `yaml:"local"`
}

type SSHConfig struct {
	DefaultUser    string `yaml:"default_user"`
	DefaultKey     string `yaml:"default_key"`
	KnownHosts     string `yaml:"known_hosts"`
	ConnectTimeout string `yaml:"connect_timeout"`
	CommandTimeout string `yaml:"command_timeout"`
}

type SlitherConfig struct {
	Server string `yaml:"server"`
	CA     string `yaml:"ca"`
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
	Name   string `yaml:"name"`
	Path   string `yaml:"path"`
	Source string `yaml:"source"` // "native"|"atomic"
}

type Limits struct {
	GlobalTestsPerSecond float64 `yaml:"global_tests_per_second"`
	PerHostConcurrency   int     `yaml:"per_host_concurrency"`
}

type UIConfig struct {
	Listen string `yaml:"listen"`
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
		UI: UIConfig{Listen: "127.0.0.1:8088"},
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

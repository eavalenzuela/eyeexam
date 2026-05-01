package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/config"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/pack/embedded"
)

func newPackCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pack", Short: "Manage test packs"}
	cmd.AddCommand(newPackListCmd())
	cmd.AddCommand(newPackAddCmd())
	cmd.AddCommand(newPackRemoveCmd())
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
			reg, _, _, err := buildPackRegistry(cfg)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "PACK\tSOURCE\tTEST_ID\tTECHNIQUE\tDEST\tNAME")
			for _, p := range reg.Packs() {
				for _, t := range p.Tests {
					_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
						p.Name, p.Source, t.ID, t.Attack.Technique, t.Destructiveness, t.Name)
				}
			}
			return tw.Flush()
		},
	}
}

func newPackAddCmd() *cobra.Command {
	var source string
	cmd := &cobra.Command{
		Use:   "add <name> <path>",
		Short: "Register a pack (native or atomic) by absolute path; eyeexam does not clone or pull",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, path := args[0], args[1]
			if source != "native" && source != "atomic" {
				return fmt.Errorf("--source must be native|atomic")
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			info, err := os.Stat(abs)
			if err != nil {
				return fmt.Errorf("path %s: %w", abs, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("path %s: not a directory", abs)
			}

			// Validate the pack loads cleanly before persisting.
			r := pack.NewRegistry(nil)
			switch source {
			case "native":
				if err := r.AddNative(name, abs); err != nil {
					return fmt.Errorf("validate native pack: %w", err)
				}
			case "atomic":
				skipped, err := r.AddAtomic(name, abs)
				if err != nil {
					return fmt.Errorf("validate atomic pack: %w", err)
				}
				if len(skipped) > 0 {
					fmt.Fprintf(os.Stderr, "%d atomic test(s) skipped (executor/platform):\n", len(skipped))
					for _, s := range skipped {
						fmt.Fprintf(os.Stderr, "  - %s: %s\n", s.ID, s.Reason)
					}
				}
			}

			cfgPath := configPath()
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			for _, p := range cfg.Packs {
				if p.Name == name {
					return fmt.Errorf("pack %q already registered (path=%s)", name, p.Path)
				}
			}
			cfg.Packs = append(cfg.Packs, config.PackConfig{
				Name: name, Path: abs, Source: source,
			})
			if err := writeConfigYAML(cfgPath, cfg); err != nil {
				return err
			}
			fmt.Printf("registered pack %q (%s) at %s\n", name, source, abs)
			return nil
		},
	}
	cmd.Flags().StringVar(&source, "source", "native", "pack source: native|atomic")
	return cmd
}

func newPackRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Unregister a pack from config (does not touch the on-disk pack)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfgPath := configPath()
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			out := cfg.Packs[:0]
			found := false
			for _, p := range cfg.Packs {
				if p.Name == name {
					found = true
					continue
				}
				out = append(out, p)
			}
			if !found {
				return fmt.Errorf("pack %q not registered", name)
			}
			cfg.Packs = out
			if err := writeConfigYAML(cfgPath, cfg); err != nil {
				return err
			}
			fmt.Printf("removed pack %q\n", name)
			return nil
		},
	}
}

func configPath() string {
	if gflags.configPath != "" {
		return gflags.configPath
	}
	return config.DefaultConfigPath()
}

// writeConfigYAML serialises cfg to path with 0600 perms. The whole file
// is rewritten — comments are not preserved. Operators who want
// comment-stable configs should edit YAML directly instead of using
// `pack add`/`pack remove`.
func writeConfigYAML(path string, cfg config.Config) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, b, 0o600)
}

// buildPackRegistry constructs a registry from cfg.Packs, supporting
// native and atomic sources. The binary-embedded "builtin" pack is
// always added first; operators don't list it in config.
//
// Disk-loaded packs require a valid MANIFEST.sig that verifies against
// at least one trusted public key in cfg.pack_keys. Operators can
// explicitly opt out per-pack by setting `unsigned: true` in the config
// entry; the names of any such packs are returned so the caller can
// emit a `pack_loaded_unsigned` audit record on every load. Skipped
// atomic tests (per-pack) are returned in the second slot.
func buildPackRegistry(cfg config.Config) (*pack.Registry, map[string][]pack.SkippedTest, []string, error) {
	reg := pack.NewRegistry(nil)
	if err := reg.AddEmbedded("builtin", embedded.BuiltinFS()); err != nil {
		return nil, nil, nil, fmt.Errorf("builtin pack: %w", err)
	}

	pubs, err := loadTrustedPackKeys(cfg.PackKeys)
	if err != nil {
		return nil, nil, nil, err
	}

	skipped := map[string][]pack.SkippedTest{}
	var unsignedLoads []string
	for _, p := range cfg.Packs {
		// Refuse a config "builtin" entry — the embedded pack is the
		// only "builtin" eyeexam knows about; honoring a disk path
		// would weaken the trust model.
		if p.Name == "builtin" {
			return nil, nil, nil, fmt.Errorf("pack %q: name reserved for the embedded builtin pack — remove from config", p.Name)
		}

		if p.Unsigned {
			switch p.Source {
			case "native", "":
				if err := reg.AddNative(p.Name, p.Path); err != nil {
					return nil, nil, nil, fmt.Errorf("pack %q: %w", p.Name, err)
				}
			case "atomic":
				sk, err := reg.AddAtomic(p.Name, p.Path)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("pack %q: %w", p.Name, err)
				}
				skipped[p.Name] = sk
			default:
				return nil, nil, nil, fmt.Errorf("pack %q: unknown source %q", p.Name, p.Source)
			}
			unsignedLoads = append(unsignedLoads, p.Name)
			continue
		}

		// Signed path: trusted-keys list must be non-empty.
		if len(pubs) == 0 {
			return nil, nil, nil, fmt.Errorf("pack %q requires a signature but cfg.pack_keys is empty (or set unsigned: true to opt out — see docs/pack-signing.md)", p.Name)
		}
		switch p.Source {
		case "native", "":
			if err := reg.AddNativeSigned(p.Name, p.Path, pubs); err != nil {
				return nil, nil, nil, err // already wrapped with pack name
			}
		case "atomic":
			sk, err := reg.AddAtomicSigned(p.Name, p.Path, pubs)
			if err != nil {
				return nil, nil, nil, err
			}
			skipped[p.Name] = sk
		default:
			return nil, nil, nil, fmt.Errorf("pack %q: unknown source %q", p.Name, p.Source)
		}
	}
	return reg, skipped, unsignedLoads, nil
}

// emitUnsignedPackAudit writes one `pack_loaded_unsigned` event per
// unsigned pack name, on every Open of the audit logger. Operators
// see the event in `eyeexam audit show --event pack_loaded_unsigned`,
// so silently flipping a pack to unsigned and running it is visible.
func emitUnsignedPackAudit(ctx context.Context, al *audit.Logger, actor audit.Actor, engagement string, names []string) {
	if al == nil || len(names) == 0 {
		return
	}
	for _, n := range names {
		payload, _ := json.Marshal(map[string]string{"pack": n})
		_, _ = al.Append(ctx, audit.Record{
			Actor: actor, Engagement: engagement,
			Event: "pack_loaded_unsigned", Payload: payload,
		})
	}
}

func loadTrustedPackKeys(paths []string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("pack key %s: %w", p, err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("pack key %s: not a PEM file", p)
		}
		if len(block.Bytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pack key %s: wrong size %d (want %d)",
				p, len(block.Bytes), ed25519.PublicKeySize)
		}
		out = append(out, ed25519.PublicKey(block.Bytes))
	}
	return out, nil
}

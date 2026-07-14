package main

import (
	"fmt"
	"os"

	"github.com/eavalenzuela/eyeexam/internal/audit"
	"github.com/eavalenzuela/eyeexam/internal/config"
	"github.com/eavalenzuela/eyeexam/internal/detector"
	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

// runtimeDeps bundles the shared plumbing every executing command (run,
// resume, runs cleanup) needs: config, inventory, pack registry, datastore,
// audit logger, runners, detector registry, and the resolved actor. The
// engine itself is NOT built here because callers construct it with
// command-specific runlife.Options (e.g. `run` layers EDR pacing/cleanup-mode
// flags on top of config).
type runtimeDeps struct {
	cfg           config.Config
	inv           *inventory.Inventory
	reg           *pack.Registry
	store         *store.Store
	audit         *audit.Logger
	runners       map[string]runner.Runner
	detectors     *detector.Registry
	actor         audit.Actor
	appUser       *string
	unsignedPacks []string

	closers []func() error
}

// close releases every resource in reverse order of acquisition.
func (d *runtimeDeps) close() {
	for i := len(d.closers) - 1; i >= 0; i-- {
		_ = d.closers[i]()
	}
}

// loadRuntime wires up the shared dependencies for an executing command.
// actorApp is the optional --actor-app human identity. The caller owns the
// returned deps and MUST defer d.close(). Emitting the unsigned-pack audit is
// left to the caller because it needs the command's engagement id; the loaded
// unsigned pack names are returned on the deps for that purpose.
func loadRuntime(actorApp string) (*runtimeDeps, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	d := &runtimeDeps{cfg: cfg}

	inv, err := inventory.Load(cfg.Inventory.Path)
	if err != nil {
		return nil, err
	}
	d.inv = inv

	reg, atomicSkipped, unsignedPacks, err := buildPackRegistry(cfg)
	if err != nil {
		return nil, err
	}
	for name, skipped := range atomicSkipped {
		for _, s := range skipped {
			fmt.Fprintf(os.Stderr, "atomic pack %q: skipped %s — %s\n", name, s.ID, s.Reason)
		}
	}
	d.reg = reg
	d.unsignedPacks = unsignedPacks

	st, err := store.Open(ctx(), cfg.DBPath())
	if err != nil {
		return nil, err
	}
	d.store = st
	d.closers = append(d.closers, st.Close)

	priv, err := loadAuditKey(cfg.Audit.KeyPath)
	if err != nil {
		d.close()
		return nil, fmt.Errorf("load audit key: %w", err)
	}
	al, err := audit.Open(cfg.Audit.LogPath, priv, st.DB)
	if err != nil {
		d.close()
		return nil, err
	}
	d.audit = al
	d.closers = append(d.closers, al.Close)

	actor, err := audit.ActorFromOS(ctx())
	if err != nil {
		d.close()
		return nil, err
	}
	if actorApp != "" {
		if err := audit.ValidateAppUser(actorApp); err != nil {
			d.close()
			return nil, err
		}
		v := actorApp
		actor.AppUser = &v
		d.appUser = &v
	}
	d.actor = actor

	runners := map[string]runner.Runner{"local": runner.NewLocal()}
	if hostsUseTransport(inv, "ssh") {
		sshR, err := buildSSHRunner(cfg)
		if err != nil {
			d.close()
			return nil, fmt.Errorf("ssh runner: %w", err)
		}
		runners["ssh"] = sshR
		d.closers = append(d.closers, sshR.Close)
	}
	d.runners = runners

	dreg, err := buildDetectorRegistry(cfg)
	if err != nil {
		d.close()
		return nil, fmt.Errorf("detector registry: %w", err)
	}
	d.detectors = dreg

	return d, nil
}

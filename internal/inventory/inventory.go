// Package inventory loads the host inventory and applies selectors.
//
// The inventory is the authoritative list of hosts eyeexam is allowed to
// run against. A host can also carry a destructiveness cap; the lowest
// applicable cap (host, tag, run-level) wins at run time.
package inventory

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/eavalenzuela/eyeexam/internal/pack"
)

type Host struct {
	Name      string    `yaml:"name" json:"name"`
	Address   string    `yaml:"address" json:"address"`
	Transport string    `yaml:"transport" json:"transport"` // "ssh"|"slither"|"local"
	User      string    `yaml:"user,omitempty" json:"user,omitempty"`
	KeyPath   string    `yaml:"key,omitempty" json:"key,omitempty"`
	AgentID   string    `yaml:"agent_id,omitempty" json:"agent_id,omitempty"`
	Tags      []string  `yaml:"tags" json:"tags"`
	MaxDest   pack.Dest `yaml:"max_destructiveness,omitempty" json:"max_destructiveness,omitempty"`
}

type TagPolicy struct {
	MaxDestructiveness pack.Dest `yaml:"max_destructiveness" json:"max_destructiveness"`
}

type Inventory struct {
	Hosts []Host               `yaml:"hosts" json:"hosts"`
	Tags  map[string]TagPolicy `yaml:"tags" json:"tags"`
}

// Load reads an inventory YAML file. If path is empty, returns a
// localhost-only inventory suitable for the M1 dev path.
func Load(path string) (*Inventory, error) {
	if path == "" {
		return DefaultLocalhost(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inventory: read %s: %w", path, err)
	}
	var inv Inventory
	if err := yaml.Unmarshal(b, &inv); err != nil {
		return nil, fmt.Errorf("inventory: parse %s: %w", path, err)
	}
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	return &inv, nil
}

func DefaultLocalhost() *Inventory {
	return &Inventory{
		Hosts: []Host{{
			Name:      "localhost",
			Address:   "127.0.0.1",
			Transport: "local",
			Tags:      []string{"linux", "local"},
		}},
		Tags: map[string]TagPolicy{},
	}
}

func (i *Inventory) Validate() error {
	seen := map[string]bool{}
	for idx, h := range i.Hosts {
		if h.Name == "" {
			return fmt.Errorf("inventory: host[%d] missing name", idx)
		}
		if seen[h.Name] {
			return fmt.Errorf("inventory: duplicate host name %q", h.Name)
		}
		seen[h.Name] = true
		switch h.Transport {
		case "ssh", "slither", "local":
		case "":
			return fmt.Errorf("inventory: host %q missing transport", h.Name)
		default:
			return fmt.Errorf("inventory: host %q unknown transport %q",
				h.Name, h.Transport)
		}
	}
	return nil
}

// CapForHost computes the lowest destructiveness cap that applies to a host:
// per-host MaxDest (if set) intersected with all tag MaxDestructiveness from
// matched tags. Returns DestHigh if no caps apply (ie. unbounded).
func (i *Inventory) CapForHost(h Host) pack.Dest {
	cap := pack.DestHigh
	if h.MaxDest != "" && h.MaxDest.Rank() < cap.Rank() {
		cap = h.MaxDest
	}
	for _, tag := range h.Tags {
		if pol, ok := i.Tags[tag]; ok && pol.MaxDestructiveness != "" {
			if pol.MaxDestructiveness.Rank() < cap.Rank() {
				cap = pol.MaxDestructiveness
			}
		}
	}
	return cap
}

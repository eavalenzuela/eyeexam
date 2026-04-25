package attack

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// LoadFromSTIX parses MITRE's enterprise-attack.json STIX 2.1 bundle and
// returns a populated Bundle. The full file is many MB; loading is one-
// shot at process start.
//
// We parse only the fields the matrix needs:
//   - x-mitre-tactic objects → Tactic{ID,Name,Order}
//   - attack-pattern objects → Technique{ID,Name,Tactics,ParentID}
//   - kill_chain_phases on attack-pattern → tactic shortname → tactic id
func LoadFromSTIX(path string) (*Bundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("attack: read %s: %w", path, err)
	}
	var doc stixBundle
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("attack: parse %s: %w", path, err)
	}

	// First pass: tactics, indexed by shortname (kill chain phase).
	var tactics []Tactic
	tacticByShortname := map[string]string{} // shortname -> TA id
	for _, obj := range doc.Objects {
		if obj.Type != "x-mitre-tactic" {
			continue
		}
		taID := pickExternalID(obj.ExternalReferences, "mitre-attack")
		if taID == "" {
			continue
		}
		tactics = append(tactics, Tactic{ID: taID, Name: obj.Name})
		if obj.Shortname != "" {
			tacticByShortname[obj.Shortname] = taID
		}
	}
	sort.SliceStable(tactics, func(i, j int) bool { return tactics[i].ID < tactics[j].ID })
	for i := range tactics {
		tactics[i].Order = i
	}

	// Second pass: techniques.
	var techniques []Technique
	for _, obj := range doc.Objects {
		if obj.Type != "attack-pattern" {
			continue
		}
		if obj.Revoked || obj.XMitreDeprecated {
			continue
		}
		tid := pickExternalID(obj.ExternalReferences, "mitre-attack")
		if tid == "" {
			continue
		}
		t := Technique{ID: tid, Name: obj.Name}
		for _, ph := range obj.KillChainPhases {
			if ph.KillChainName != "mitre-attack" {
				continue
			}
			if taID, ok := tacticByShortname[ph.PhaseName]; ok {
				t.Tactics = append(t.Tactics, taID)
			}
		}
		if obj.XMitreIsSubtechnique && strings.Contains(tid, ".") {
			t.ParentID = strings.SplitN(tid, ".", 2)[0]
		}
		techniques = append(techniques, t)
	}

	bundle := &Bundle{Tactics: tactics, Techniques: techniques}
	bundle.rebuildIndex()
	return bundle, nil
}

type stixBundle struct {
	Type    string       `json:"type"`
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type                 string                  `json:"type"`
	Name                 string                  `json:"name"`
	Shortname            string                  `json:"x_mitre_shortname,omitempty"`
	Revoked              bool                    `json:"revoked,omitempty"`
	XMitreDeprecated     bool                    `json:"x_mitre_deprecated,omitempty"`
	XMitreIsSubtechnique bool                    `json:"x_mitre_is_subtechnique,omitempty"`
	ExternalReferences   []stixExternalReference `json:"external_references,omitempty"`
	KillChainPhases      []stixKillChainPhase    `json:"kill_chain_phases,omitempty"`
}

type stixExternalReference struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

type stixKillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

func pickExternalID(refs []stixExternalReference, source string) string {
	for _, r := range refs {
		if r.SourceName == source {
			return r.ExternalID
		}
	}
	return ""
}

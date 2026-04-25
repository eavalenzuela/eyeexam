// Package attack provides MITRE ATT&CK Enterprise tactic / technique
// metadata. The full STIX bundle is multiple MB; eyeexam loads it from
// disk when present (run `make refresh-attack` to download), and falls
// back to a small embedded subset that covers the techniques the
// builtin pack and atomic refuse-list mention.
//
// The matrix package consumes a Bundle to render cells; cells whose
// technique id is not in the bundle render as grey.
package attack

import (
	"sort"
	"strings"
)

// Tactic is one column in the ATT&CK matrix.
type Tactic struct {
	ID    string // e.g. "TA0005"
	Name  string // e.g. "Defense Evasion"
	Order int    // display order in the matrix (0..n)
}

// Technique is one cell in the matrix. Subtechniques are flattened: a
// subtechnique like T1059.004 is a Technique with ParentID="T1059".
type Technique struct {
	ID       string   // e.g. "T1070.003"
	Name     string   // e.g. "Clear Command History"
	Tactics  []string // tactic IDs the technique participates in
	ParentID string   // empty when this is a parent technique
}

// Bundle is the loaded ATT&CK metadata.
type Bundle struct {
	Tactics    []Tactic
	Techniques []Technique
	idIndex    map[string]Technique
}

// Index returns a technique by id, or zero-value + false.
func (b *Bundle) Index(id string) (Technique, bool) {
	if b == nil {
		return Technique{}, false
	}
	if b.idIndex == nil {
		b.rebuildIndex()
	}
	t, ok := b.idIndex[id]
	return t, ok
}

func (b *Bundle) rebuildIndex() {
	b.idIndex = make(map[string]Technique, len(b.Techniques))
	for _, t := range b.Techniques {
		b.idIndex[t.ID] = t
	}
}

// TacticByID returns the named tactic or zero-value.
func (b *Bundle) TacticByID(id string) (Tactic, bool) {
	for _, t := range b.Tactics {
		if t.ID == id {
			return t, true
		}
	}
	return Tactic{}, false
}

// SortedTactics returns tactics in display order.
func (b *Bundle) SortedTactics() []Tactic {
	out := make([]Tactic, len(b.Tactics))
	copy(out, b.Tactics)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out
}

// TechniquesForTactic returns the techniques (parents only) that
// participate in the given tactic, sorted by id.
func (b *Bundle) TechniquesForTactic(tacticID string) []Technique {
	var out []Technique
	for _, t := range b.Techniques {
		if t.ParentID != "" {
			continue
		}
		if hasString(t.Tactics, tacticID) {
			out = append(out, t)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SubtechniquesOf returns the subtechniques (T1059.004 etc.) of a parent
// technique.
func (b *Bundle) SubtechniquesOf(parentID string) []Technique {
	var out []Technique
	for _, t := range b.Techniques {
		if t.ParentID == parentID {
			out = append(out, t)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func hasString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// EmbeddedFallback returns a minimal Bundle covering the techniques that
// eyeexam itself references in its builtin pack, atomic fixtures, and
// builtin refuse list. Operators get the full enterprise matrix by
// running `make refresh-attack` to populate packs/attack/enterprise-attack.json
// and pointing the loader at it.
func EmbeddedFallback() *Bundle {
	tactics := []Tactic{
		{ID: "TA0001", Name: "Initial Access", Order: 0},
		{ID: "TA0002", Name: "Execution", Order: 1},
		{ID: "TA0003", Name: "Persistence", Order: 2},
		{ID: "TA0004", Name: "Privilege Escalation", Order: 3},
		{ID: "TA0005", Name: "Defense Evasion", Order: 4},
		{ID: "TA0006", Name: "Credential Access", Order: 5},
		{ID: "TA0007", Name: "Discovery", Order: 6},
		{ID: "TA0008", Name: "Lateral Movement", Order: 7},
		{ID: "TA0009", Name: "Collection", Order: 8},
		{ID: "TA0010", Name: "Exfiltration", Order: 9},
		{ID: "TA0011", Name: "Command and Control", Order: 10},
		{ID: "TA0040", Name: "Impact", Order: 11},
	}
	techniques := []Technique{
		// Execution (T1059)
		{ID: "T1059", Name: "Command and Scripting Interpreter", Tactics: []string{"TA0002"}},
		{ID: "T1059.004", Name: "Unix Shell", Tactics: []string{"TA0002"}, ParentID: "T1059"},

		// Defense Evasion: Indicator Removal (T1070)
		{ID: "T1070", Name: "Indicator Removal", Tactics: []string{"TA0005"}},
		{ID: "T1070.003", Name: "Clear Command History", Tactics: []string{"TA0005"}, ParentID: "T1070"},

		// Command and Control: Ingress Tool Transfer (T1105)
		{ID: "T1105", Name: "Ingress Tool Transfer", Tactics: []string{"TA0011"}},

		// Credential Access: OS Credential Dumping (T1003)
		{ID: "T1003", Name: "OS Credential Dumping", Tactics: []string{"TA0006"}},
		{ID: "T1003.006", Name: "DCSync", Tactics: []string{"TA0006"}, ParentID: "T1003"},

		// Persistence / Defense Evasion: Modify Authentication Process (T1556)
		{ID: "T1556", Name: "Modify Authentication Process", Tactics: []string{"TA0003", "TA0005", "TA0006"}},
		{ID: "T1556.001", Name: "Domain Controller Authentication", Tactics: []string{"TA0003", "TA0005", "TA0006"}, ParentID: "T1556"},

		// Defense Evasion: Impair Defenses (T1562)
		{ID: "T1562", Name: "Impair Defenses", Tactics: []string{"TA0005"}},
		{ID: "T1562.001", Name: "Disable or Modify Tools", Tactics: []string{"TA0005"}, ParentID: "T1562"},
		{ID: "T1562.002", Name: "Disable Windows Event Logging", Tactics: []string{"TA0005"}, ParentID: "T1562"},
		{ID: "T1562.004", Name: "Disable or Modify System Firewall", Tactics: []string{"TA0005"}, ParentID: "T1562"},

		// Defense Evasion: Pre-OS Boot (T1542)
		{ID: "T1542", Name: "Pre-OS Boot", Tactics: []string{"TA0005"}},
		{ID: "T1542.001", Name: "System Firmware", Tactics: []string{"TA0005"}, ParentID: "T1542"},
		{ID: "T1542.003", Name: "Bootkit", Tactics: []string{"TA0005"}, ParentID: "T1542"},

		// Credential Access: Steal or Forge Kerberos Tickets (T1558)
		{ID: "T1558", Name: "Steal or Forge Kerberos Tickets", Tactics: []string{"TA0006"}},
		{ID: "T1558.001", Name: "Golden Ticket", Tactics: []string{"TA0006"}, ParentID: "T1558"},
		{ID: "T1558.002", Name: "Silver Ticket", Tactics: []string{"TA0006"}, ParentID: "T1558"},
		{ID: "T1558.003", Name: "Kerberoasting", Tactics: []string{"TA0006"}, ParentID: "T1558"},
		{ID: "T1558.004", Name: "AS-REP Roasting", Tactics: []string{"TA0006"}, ParentID: "T1558"},
	}
	b := &Bundle{Tactics: tactics, Techniques: techniques}
	b.rebuildIndex()
	return b
}

// CanonicalTechniqueID strips trailing whitespace and uppercases the
// "T" prefix. It does NOT strip subtechnique suffixes — callers wanting
// the parent should call ParentOf.
func CanonicalTechniqueID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "t") {
		s = "T" + s[1:]
	}
	return s
}

// ParentOf returns the parent technique id for a subtechnique. If id is
// already a parent (no dot), it returns id unchanged.
func ParentOf(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return id
}

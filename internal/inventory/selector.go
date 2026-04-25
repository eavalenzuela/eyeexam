package inventory

import (
	"fmt"
	"path/filepath"
)

// Selector captures the host/test filters from CLI flags.
type Selector struct {
	Hosts    []string
	Tags     []string
	NotTags  []string
	Tests    []string // glob
	NotTests []string
}

// Apply returns the subset of hosts that match. A nil/empty selector matches
// all hosts. Each filter is AND-ed: a host must match Hosts (if set) AND all
// Tags AND none of NotTags.
func (i *Inventory) Apply(s Selector) ([]Host, []string, error) {
	if i == nil {
		return nil, nil, fmt.Errorf("inventory: nil")
	}
	hostSet := stringSet(s.Hosts)
	wantTags := stringSet(s.Tags)
	notTags := stringSet(s.NotTags)

	var matched []Host
	var warnings []string
	for _, h := range i.Hosts {
		if len(hostSet) > 0 && !hostSet[h.Name] {
			continue
		}
		if len(wantTags) > 0 {
			ok := true
			for tag := range wantTags {
				if !hasTag(h.Tags, tag) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}
		if len(notTags) > 0 {
			skip := false
			for _, t := range h.Tags {
				if notTags[t] {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
		}
		matched = append(matched, h)
	}
	if len(hostSet) > 0 {
		known := map[string]bool{}
		for _, h := range i.Hosts {
			known[h.Name] = true
		}
		for n := range hostSet {
			if !known[n] {
				warnings = append(warnings,
					fmt.Sprintf("selector: host %q not in inventory", n))
			}
		}
	}
	return matched, warnings, nil
}

// MatchTestID returns true if testID matches the test filters. Empty filters
// = pass-all.
func (s Selector) MatchTestID(testID string) bool {
	if len(s.Tests) > 0 {
		ok := false
		for _, glob := range s.Tests {
			if matched, _ := filepath.Match(glob, testID); matched {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, glob := range s.NotTests {
		if matched, _ := filepath.Match(glob, testID); matched {
			return false
		}
	}
	return true
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func stringSet(ss []string) map[string]bool {
	out := make(map[string]bool, len(ss))
	for _, s := range ss {
		out[s] = true
	}
	return out
}

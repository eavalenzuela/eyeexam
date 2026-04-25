package pack

import (
	"fmt"
	"path/filepath"
	"sort"
)

// Registry is the loaded set of packs. Tests are addressed as "<test-id>"
// (unique across packs) — the registry rejects collisions at Add time.
type Registry struct {
	packs   []Pack
	byID    map[string]Test
	refuser *Refuser
}

func NewRegistry(refuser *Refuser) *Registry {
	if refuser == nil {
		refuser = NewRefuser(nil)
	}
	return &Registry{byID: map[string]Test{}, refuser: refuser}
}

// AddNative loads a native pack from the given directory and registers it.
func (r *Registry) AddNative(name, root string) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	tests, err := LoadNativeDir(abs)
	if err != nil {
		return err
	}
	return r.add(Pack{Name: name, Path: abs, Source: SourceNative, Tests: tests})
}

// AddAtomic loads an Atomic Red Team-format pack and registers it. The
// sidecar layout (expectations/<test-id>.yaml) is honored automatically.
// Skipped tests (PowerShell on Linux, unsupported executor, platform
// mismatch) are not registered but are returned for caller reporting.
func (r *Registry) AddAtomic(name, root string) ([]SkippedTest, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	tests, skipped, err := LoadAtomicDir(abs)
	if err != nil {
		return nil, err
	}
	if err := r.add(Pack{Name: name, Path: abs, Source: SourceAtomic, Tests: tests}); err != nil {
		return nil, err
	}
	return skipped, nil
}

func (r *Registry) add(p Pack) error {
	for _, t := range p.Tests {
		if existing, dup := r.byID[t.ID]; dup {
			return fmt.Errorf("pack: duplicate test id %q in pack %q (also in %q)",
				t.ID, p.Name, existing.Source)
		}
	}
	for _, t := range p.Tests {
		r.byID[t.ID] = t
	}
	r.packs = append(r.packs, p)
	sort.Slice(r.packs, func(i, j int) bool { return r.packs[i].Name < r.packs[j].Name })
	return nil
}

func (r *Registry) Packs() []Pack { return r.packs }

// All returns every loaded test, sorted by id.
func (r *Registry) All() []Test {
	out := make([]Test, 0, len(r.byID))
	for _, t := range r.byID {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Resolve returns tests by id, applying the hard-refuse list.
func (r *Registry) Resolve(testIDs []string) ([]Test, error) {
	var out []Test
	for _, id := range testIDs {
		t, ok := r.byID[id]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrTestNotFound, id)
		}
		if r.refuser.Refused(t.ID) {
			return nil, fmt.Errorf("%w: %q (%s)",
				ErrTestRefused, t.ID, r.refuser.Reason(t.ID))
		}
		out = append(out, t)
	}
	return out, nil
}

// FromPack returns all tests in the named pack, applying the hard-refuse list
// (refused tests are returned in a separate slice for plan-time reporting).
func (r *Registry) FromPack(name string) (allowed, refused []Test, err error) {
	for _, p := range r.packs {
		if p.Name == name {
			for _, t := range p.Tests {
				if r.refuser.Refused(t.ID) {
					refused = append(refused, t)
					continue
				}
				allowed = append(allowed, t)
			}
			return allowed, refused, nil
		}
	}
	return nil, nil, fmt.Errorf("%w: %q", ErrUnknownPackName, name)
}

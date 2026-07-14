package runlife

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/eavalenzuela/eyeexam/internal/inventory"
	"github.com/eavalenzuela/eyeexam/internal/pack"
	"github.com/eavalenzuela/eyeexam/internal/runner"
	"github.com/eavalenzuela/eyeexam/internal/store"
)

func baseOpts(t *testing.T) Options {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "eye.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return Options{
		Store:     st,
		Registry:  pack.NewRegistry(nil),
		Inventory: inventory.DefaultLocalhost(),
		Runners:   map[string]runner.Runner{"local": runner.NewLocal()},
	}
}

func TestNewValidatesCleanupMode(t *testing.T) {
	cases := []struct {
		mode    string
		wantErr bool
		wantSet string
	}{
		{"", false, CleanupDeferred}, // default
		{CleanupDeferred, false, CleanupDeferred},
		{CleanupEager, false, CleanupEager},
		{"nonsense", true, ""},
	}
	for _, tc := range cases {
		opts := baseOpts(t)
		opts.CleanupMode = tc.mode
		eng, err := New(opts)
		if tc.wantErr {
			if err == nil {
				t.Errorf("cleanup mode %q: expected error", tc.mode)
			}
			continue
		}
		if err != nil {
			t.Errorf("cleanup mode %q: unexpected error %v", tc.mode, err)
			continue
		}
		if eng.cleanupMode != tc.wantSet {
			t.Errorf("cleanup mode %q: engine set %q, want %q", tc.mode, eng.cleanupMode, tc.wantSet)
		}
	}
}

func TestNewRejectsNegativePacing(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts func(*Options)
	}{
		{"pace", func(o *Options) { o.InterTestPace = -time.Second }},
		{"jitter", func(o *Options) { o.InterTestJitter = -time.Second }},
		{"step", func(o *Options) { o.StepTimeout = -time.Second }},
	} {
		opts := baseOpts(t)
		tc.opts(&opts)
		if _, err := New(opts); err == nil {
			t.Errorf("%s: expected error for negative duration", tc.name)
		}
	}
}

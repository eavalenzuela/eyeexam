package runlife

import (
	"errors"
	"fmt"
	"testing"

	"github.com/eavalenzuela/eyeexam/internal/runner"
)

// TestIsHostLevelErrorRecognizesUnsupportedShell guards the boundary
// where a missing pwsh on a target host is treated as a host-level
// skip (run keeps going for other hosts) rather than a run-level
// failure. PS-only Atomic tests against a host without pwsh installed
// must not nuke the entire run.
func TestIsHostLevelErrorRecognizesUnsupportedShell(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"unsupported shell direct",
			fmt.Errorf("%w: pwsh not on PATH", runner.ErrUnsupportedShell),
			true,
		},
		{
			"unsupported shell wrapped",
			fmt.Errorf("runner local: %w: pwsh not on PATH", runner.ErrUnsupportedShell),
			true,
		},
		{
			"ssh dial",
			errors.New("ssh: handshake failed"),
			true,
		},
		{
			"runner local prefix",
			errors.New("runner local: exec error"),
			true,
		},
		{
			"unrelated error",
			errors.New("disk full"),
			false,
		},
	}
	for _, tc := range cases {
		got := isHostLevelError(tc.err)
		if got != tc.want {
			t.Errorf("%s: isHostLevelError(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

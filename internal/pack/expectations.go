package pack

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SidecarExpectations is the on-disk shape of an Atomic Red Team expectations
// sidecar file: packs/<root>/expectations/<atomic-id>.yaml.
type SidecarExpectations struct {
	Expectations []Expectation `yaml:"expected_detections"`
	WaitSeconds  int           `yaml:"wait_seconds"`
}

// LoadSidecar resolves the expectations sidecar for an Atomic test id, if one
// exists at packRoot/expectations/<id>.yaml. Returns (nil, nil) if absent.
func LoadSidecar(packRoot, testID string) (*SidecarExpectations, error) {
	path := filepath.Join(packRoot, "expectations", testID+".yaml")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pack: read sidecar %s: %w", path, err)
	}
	var s SidecarExpectations
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("pack: parse sidecar %s: %w", path, err)
	}
	return &s, nil
}

package e2e

import (
	"errors"
	"os"
	"path/filepath"
)

// repoRoot walks upward from cwd until it finds a directory containing go.mod.
func repoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := cwd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
	}
	return "", errors.New("repoRoot: no go.mod found")
}

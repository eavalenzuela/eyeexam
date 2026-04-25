// Package pack defines eyeexam's internal test-pack model and loaders.
//
// Two on-disk formats are supported (eyeexam-native and Atomic Red Team) but
// callers see only the normalized Test struct. Loaders are responsible for
// translating their format into Test and recording the source-bytes sha256
// so executions remain auditable.
package pack

import "errors"

type Source string

const (
	SourceNative Source = "native"
	SourceAtomic Source = "atomic"
)

type Dest string

const (
	DestLow    Dest = "low"
	DestMedium Dest = "medium"
	DestHigh   Dest = "high"
)

// Rank returns 0 for low, 1 for medium, 2 for high. Used for cap arithmetic.
func (d Dest) Rank() int {
	switch d {
	case DestHigh:
		return 2
	case DestMedium:
		return 1
	case DestLow:
		return 0
	default:
		return 0
	}
}

// AtMost returns true if d is at most cap.
func (d Dest) AtMost(cap Dest) bool { return d.Rank() <= cap.Rank() }

type AttackRef struct {
	Technique string `yaml:"technique" json:"technique"`
	Tactic    string `yaml:"tactic" json:"tactic"`
}

type InputSpec struct {
	Type    string `yaml:"type" json:"type"`
	Default string `yaml:"default" json:"default"`
}

type Step struct {
	Shell   string `yaml:"shell" json:"shell"`
	Command string `yaml:"command" json:"command"`
}

type Expectation struct {
	SigmaID     string `yaml:"sigma_id,omitempty" json:"sigma_id,omitempty"`
	Tag         string `yaml:"tag,omitempty" json:"tag,omitempty"`
	Query       string `yaml:"query,omitempty" json:"query,omitempty"`
	Backend     string `yaml:"backend,omitempty" json:"backend,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Test is the normalized eyeexam representation of a single test.
type Test struct {
	ID              string               `yaml:"id" json:"id"`
	Source          Source               `yaml:"-" json:"source"`
	YAMLSHA256      string               `yaml:"-" json:"yaml_sha256"`
	Name            string               `yaml:"name" json:"name"`
	Description     string               `yaml:"description" json:"description"`
	Attack          AttackRef            `yaml:"attack" json:"attack"`
	Destructiveness Dest                 `yaml:"destructiveness" json:"destructiveness"`
	Platforms       []string             `yaml:"platforms" json:"platforms"`
	Inputs          map[string]InputSpec `yaml:"inputs" json:"inputs"`
	Execute         []Step               `yaml:"execute" json:"execute"`
	Cleanup         []Step               `yaml:"cleanup" json:"cleanup"`
	VerifyCleanup   []Step               `yaml:"verify_cleanup" json:"verify_cleanup"`
	Expectations    []Expectation        `yaml:"expected_detections" json:"expected_detections"`
	WaitSeconds     int                  `yaml:"wait_seconds" json:"wait_seconds"`
}

// Pack is a loaded set of Tests from a single registered pack source.
type Pack struct {
	Name   string
	Path   string
	Source Source
	Tests  []Test
}

var (
	ErrTestRefused     = errors.New("pack: test is on the hard refuse list")
	ErrTestNotFound    = errors.New("pack: test id not found")
	ErrInvalidTest     = errors.New("pack: invalid test definition")
	ErrUnknownPackName = errors.New("pack: unknown pack name")
)

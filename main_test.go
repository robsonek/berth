package main

import (
	"path/filepath"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

// TestExampleConfigsAreValid loads every examples/*.yml through config.Load (the
// authoritative validator) so the shipped examples can never drift out of sync
// with the config schema. A broken example is worse than none.
func TestExampleConfigsAreValid(t *testing.T) {
	matches, err := filepath.Glob("examples/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no examples/*.yml found — did the examples directory move?")
	}
	for _, path := range matches {
		t.Run(path, func(t *testing.T) {
			if _, err := config.Load(path); err != nil {
				t.Errorf("config.Load(%s) = %v; every shipped example must validate", path, err)
			}
		})
	}
}

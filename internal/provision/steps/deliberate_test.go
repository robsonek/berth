package steps

import (
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
)

// TestPreflightIsTheOnlyDeliberatelyUnsatisfiedStep pins the marker to exactly
// one step. A read-only inspection (berth status --drift) subtracts marked
// steps from its drift count; marking a step whose Check is honest would hide
// real drift, and forgetting the marker on preflight would report every
// healthy host as drifted.
func TestPreflightIsTheOnlyDeliberatelyUnsatisfiedStep(t *testing.T) {
	srv := &config.Server{
		ID: "t", Host: "h",
		PHP:      config.PHP{Version: "8.4"},
		Database: config.Database{Engine: "mariadb"},
		Sites:    []config.Site{{Domain: "app.example.com"}},
	}
	var marked []string
	// The registry lives in THIS package, so Pipeline is unqualified.
	for _, s := range Pipeline(srv, secret.NewRedactor(), false) {
		if provision.IsDeliberatelyUnsatisfied(s) {
			marked = append(marked, s.Name())
		}
	}
	if len(marked) != 1 || marked[0] != "preflight" {
		t.Fatalf("marked steps = %v, want exactly [preflight]", marked)
	}
}

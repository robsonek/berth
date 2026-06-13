package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision/steps"
	"github.com/robsonek/berth/internal/secret"
)

func writeValidConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "srv.yml")
	cfg := `host: 203.0.113.10
ssh: {user: root, port: 22}
php: {version: "8.5", source: auto}
database: {engine: mariadb, name: myapp, user: myapp}
valkey: true
sites:
  - {domain: app.example.com, deploy_path: /home/deploy/myapp}
`
	if err := os.WriteFile(p, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestProvisionLoadsConfigAndAssemblesPipeline verifies the offline portion of
// `berth provision`: config load + pipeline assembly. The live ssh dial in
// runProvision can no longer run without a reachable host, so this asserts the
// pre-dial wiring directly rather than executing the cobra command.
func TestProvisionLoadsConfigAndAssemblesPipeline(t *testing.T) {
	cfgPath := writeValidConfig(t)
	srv, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load error = %v", err)
	}
	pipeline := steps.Pipeline(srv, secret.NewRedactor(), false)
	if len(pipeline) == 0 {
		t.Fatal("expected a non-empty pipeline")
	}
	// The sample config enables valkey, so the valkey step must be present.
	var hasValkey bool
	for _, s := range pipeline {
		if s.Name() == "valkey" {
			hasValkey = true
		}
	}
	if !hasValkey {
		t.Error("expected valkey step for a config with valkey: true")
	}
}

func TestProvisionRejectsInvalidConfigPath(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"provision", "/no/such/file.yml"})
	if err := root.Execute(); err == nil {
		t.Error("expected error for missing config file")
	}
}

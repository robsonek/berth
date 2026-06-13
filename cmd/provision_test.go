package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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

func TestProvisionLoadsConfigAndRunsEmptyPipeline(t *testing.T) {
	cfgPath := writeValidConfig(t)
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"provision", cfgPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("provision error = %v", err)
	}
	// Empty pipeline (no steps registered yet in Plan 1) → succeeds with no FAIL.
	if bytes.Contains(out.Bytes(), []byte("FAIL")) {
		t.Errorf("unexpected failure in output: %q", out.String())
	}
}

func TestProvisionRejectsInvalidConfigPath(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"provision", "/no/such/file.yml"})
	if err := root.Execute(); err == nil {
		t.Error("expected error for missing config file")
	}
}

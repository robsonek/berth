package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision/steps"
	"github.com/robsonek/berth/internal/secret"
	"github.com/spf13/cobra"
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
  - {domain: app.example.com, deploy_path: /var/www/app}
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

func TestWantTUIDisabledForDryRunVerboseNoTTY(t *testing.T) {
	cases := []struct {
		name string
		tty  bool
		f    provisionFlags
		want bool
	}{
		{"tty plain run", true, provisionFlags{}, true},
		{"not a tty", false, provisionFlags{}, false},
		{"dry-run forces plain", true, provisionFlags{dryRun: true}, false},
		{"verbose forces plain", true, provisionFlags{verbose: true}, false},
		{"no-tty forces plain", true, provisionFlags{noTTY: true}, false},
		{"dry-run without tty stays plain", false, provisionFlags{dryRun: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wantTUI(tc.tty, &tc.f); got != tc.want {
				t.Errorf("wantTUI(%v, %+v) = %v, want %v", tc.tty, tc.f, got, tc.want)
			}
		})
	}
}

func TestConfirmFingerprintPromptNamesKeyType(t *testing.T) {
	// The printed fingerprint is what the operator pins as ssh.fingerprint;
	// the key type disambiguates it from ssh-keyscan's other output lines.
	prompt := func(answer string) (bool, string) {
		c := &cobra.Command{}
		var out bytes.Buffer
		c.SetOut(&out)
		c.SetIn(strings.NewReader(answer))
		ok := confirmFingerprint(c)("host:22", "SHA256:abc", "ecdsa-sha2-nistp256")
		return ok, out.String()
	}
	ok, out := prompt("y\n")
	if !ok {
		t.Fatal("expected y to confirm")
	}
	for _, want := range []string{"SHA256:abc", "ecdsa-sha2-nistp256"} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt missing %q; got:\n%s", want, out)
		}
	}
	if ok, _ := prompt("n\n"); ok {
		t.Error("expected n to refuse")
	}
}

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/secret"
)

// writeSecretTestConfig writes a minimal valid server config and points the
// secret cache at a temp HOME (mirrors internal/secret's envelope tests,
// which already pass on the 3-OS CI matrix).
func writeSecretTestConfig(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows os.UserHomeDir
	dir := t.TempDir()
	cfg := filepath.Join(dir, "srv.yml")
	yaml := `id: cmd-secret-test-1
host: 203.0.113.20
ssh: {user: deploy, port: 22, key: ~/.ssh/id_rsa}
php: {version: "8.4"}
database: {engine: mariadb}
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    user: deploy
    database: {name: myapp, user: myapp}
`
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestSecretSetStoresValueInCache(t *testing.T) {
	cfg := writeSecretTestConfig(t)
	c := newSecretCmd()
	c.SetArgs([]string{"set", cfg, secret.OffsiteS3AccessKey})
	c.SetIn(strings.NewReader("AKIAEXAMPLE123\n"))
	var out bytes.Buffer
	c.SetOut(&out)
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	env, err := secret.LoadEnvelope("cmd-secret-test-1")
	if err != nil {
		t.Fatal(err)
	}
	if env == nil || env.Secrets[secret.OffsiteS3AccessKey] != "AKIAEXAMPLE123" {
		t.Fatalf("cache did not store the value: %+v", env)
	}
	if env.Endpoint == nil || env.Endpoint.Host != "203.0.113.20" || env.Endpoint.Port != 22 {
		t.Fatalf("envelope endpoint not bound: %+v", env.Endpoint)
	}
	if !strings.Contains(out.String(), secret.OffsiteS3AccessKey) {
		t.Errorf("confirmation output missing the name: %q", out.String())
	}
}

func TestSecretSetPreservesOtherSecrets(t *testing.T) {
	cfg := writeSecretTestConfig(t)
	if err := secret.SaveEnvelope("cmd-secret-test-1", secret.Envelope{
		Endpoint: &secret.Endpoint{Host: "203.0.113.20", Port: 22},
		Secrets:  map[string]string{"db_password_app": "keepme"},
	}); err != nil {
		t.Fatal(err)
	}
	c := newSecretCmd()
	c.SetArgs([]string{"set", cfg, secret.OffsiteS3SecretKey})
	c.SetIn(strings.NewReader("sekrit/Value+123\n"))
	c.SetOut(&bytes.Buffer{})
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	env, err := secret.LoadEnvelope("cmd-secret-test-1")
	if err != nil {
		t.Fatal(err)
	}
	if env.Secrets["db_password_app"] != "keepme" {
		t.Error("unrelated secret was lost on set")
	}
	if env.Secrets[secret.OffsiteS3SecretKey] != "sekrit/Value+123" {
		t.Error("new secret missing")
	}
}

func TestSecretSetRejections(t *testing.T) {
	cfg := writeSecretTestConfig(t)
	cases := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{"unknown-name", "db_password_app", "x", "not settable"},
		{"empty-value", secret.OffsiteS3AccessKey, "\n", "empty"},
		{"multiline", secret.OffsiteS3AccessKey, "a\nb\n", "single line"},
		{"single-quote", secret.OffsiteS3AccessKey, "a'b\n", "single quotes"},
		{"control-chars", secret.OffsiteS3AccessKey, "a\x07b\n", "control characters"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newSecretCmd()
			c.SetArgs([]string{"set", cfg, tc.key})
			c.SetIn(strings.NewReader(tc.value))
			c.SetOut(&bytes.Buffer{})
			c.SetErr(&bytes.Buffer{})
			err := c.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

//go:build integration

// Package integration holds berth's release-gate smoke test. It is guarded by
// the `integration` build tag so the default `go test ./...` never compiles or
// runs it. Provide a real Debian 13 target via BERTH_TEST_SERVER to exercise it;
// see README.md for how to stand one up (LXD/Incus container or ephemeral VPS).
package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/provision/steps"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// TestProvisionFreshDebian13 provisions a throwaway host described by
// BERTH_TEST_SERVER (a servers/*.yml) and asserts the end state. TLS is skipped
// (it needs real DNS), so the run goes through every phase except the ACME step.
//
// End state asserted (design §9):
//   - `systemctl is-active nginx php{ver}-fpm mariadb valkey-server` all "active"
//   - `nginx -t` exits 0
//   - `mysql --protocol=socket -e 'SELECT 1'` exits 0
//   - HTTP GET / returns a response (502 is acceptable pre-deploy: no app yet)
func TestProvisionFreshDebian13(t *testing.T) {
	cfgPath := os.Getenv("BERTH_TEST_SERVER")
	if cfgPath == "" {
		t.Skip("set BERTH_TEST_SERVER to a Debian 13 target to run")
	}

	srv, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config %q: %v", cfgPath, err)
	}

	// A long-lived context: provisioning a fresh box (apt, builds) is slow.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Connect exactly as `berth provision` does, but without interactive TOFU:
	// the test harness is non-interactive, so the target's key must already be
	// pinned (ssh.fingerprint) or present in the known_hosts file.
	client, err := bssh.Connect(ctx, srv, bssh.HostKeyPolicy{
		Pinned:     srv.SSH.Fingerprint,
		KnownHosts: knownHostsPath(),
	})
	if err != nil {
		t.Fatalf("connect to %s: %v", srv.Host, err)
	}
	defer client.Close()

	// Run the full pipeline with TLS skipped (no real DNS in CI).
	red := secret.NewRedactor()
	eng := provision.New(steps.Pipeline(srv, red, true /* skipSSL */)...)
	events, err := eng.Run(ctx, srv, client, provision.Options{})
	if err != nil {
		t.Fatalf("pipeline pre-flight: %v", err)
	}
	for ev := range events {
		switch ev.Kind {
		case provision.EventFailed:
			t.Fatalf("step %q failed: %v", ev.Step, ev.Err)
		case provision.EventApplied:
			t.Logf("applied %s", ev.Step)
		case provision.EventSatisfied:
			t.Logf("satisfied %s", ev.Step)
		}
	}

	// Assert the documented end state over the same connection.
	assertServicesActive(ctx, t, client, srv)
	assertExitZero(ctx, t, client, "nginx -t", "sudo nginx -t")
	assertExitZero(ctx, t, client, "mariadb socket",
		`sudo mysql --protocol=socket -e 'SELECT 1'`)
	assertHTTPResponds(t, srv.Host)
}

// assertServicesActive fails unless every core service is reported "active".
func assertServicesActive(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	units := []string{
		"nginx",
		fmt.Sprintf("php%s-fpm", srv.PHP.Version),
		"mariadb",
	}
	if srv.Valkey {
		units = append(units, "valkey-server")
	}
	for _, unit := range units {
		res, err := c.Run(ctx, "systemctl is-active "+unit, nil)
		if err != nil {
			t.Fatalf("is-active %s: %v", unit, err)
		}
		if got := strings.TrimSpace(res.Stdout); got != "active" {
			t.Errorf("service %s: is-active = %q (exit %d, stderr %q), want \"active\"",
				unit, got, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
	}
}

// assertExitZero fails unless cmd exits 0 on the target.
func assertExitZero(ctx context.Context, t *testing.T, c *bssh.Client, label, cmd string) {
	t.Helper()
	res, err := c.Run(ctx, cmd, nil)
	if err != nil {
		t.Fatalf("%s: run: %v", label, err)
	}
	if res.ExitCode != 0 {
		t.Errorf("%s: exit %d, stderr %q", label, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
}

// assertHTTPResponds fails only if the server never answers an HTTP request.
// A 502 (Bad Gateway) is acceptable: nginx is up but no app is deployed yet.
func assertHTTPResponds(t *testing.T, host string) {
	t.Helper()
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Get("http://" + net.JoinHostPort(host, "80") + "/")
	if err != nil {
		t.Errorf("HTTP GET /: %v", err)
		return
	}
	defer resp.Body.Close()
	t.Logf("HTTP GET / -> %d (502 acceptable pre-deploy)", resp.StatusCode)
}

// knownHostsPath returns ~/.ssh/known_hosts, or "" if the home dir is unknown.
func knownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.ssh/known_hosts"
}

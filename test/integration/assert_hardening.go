//go:build integration

package integration

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertHardeningEndState verifies the live hardened end state: sshd disables root +
// password login, ufw is active with exactly the expected ports, the fail2ban sshd
// jail is up, AND a fresh `berth` key+sudo connection still works (anti-lockout left a
// usable admin path).
func assertHardeningEndState(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()

	sshd, err := c.Run(ctx, "sudo sshd -T", nil)
	if err != nil {
		t.Fatalf("sshd -T: %v", err)
	}
	dump := strings.ToLower(sshd.Stdout)
	for _, want := range []string{"permitrootlogin no", "passwordauthentication no"} {
		if !strings.Contains(dump, want) {
			t.Errorf("sshd -T missing %q", want)
		}
	}

	ufw, err := c.Run(ctx, "sudo ufw status", nil)
	if err != nil {
		t.Fatalf("ufw status: %v", err)
	}
	if !strings.Contains(ufw.Stdout, "Status: active") {
		t.Errorf("ufw not active:\n%s", ufw.Stdout)
	}
	// berth opens web ports with one `ufw allow 80,443/tcp`, so ufw reports a single
	// combined `80,443/tcp` row — asserting a separate `80/tcp` substring would false-fail.
	for _, port := range []string{fmt.Sprintf("%d/tcp", srv.SSH.Port), "80,443/tcp"} {
		if !strings.Contains(ufw.Stdout, port) {
			t.Errorf("ufw missing rule for %s:\n%s", port, ufw.Stdout)
		}
	}
	if anySiteHTTP3(srv) && !regexp.MustCompile(`(^|[^0-9])443/udp`).MatchString(ufw.Stdout) {
		t.Errorf("ufw missing 443/udp for HTTP/3:\n%s", ufw.Stdout)
	}

	assertExitZero(ctx, t, c, "fail2ban sshd jail", "sudo fail2ban-client status sshd")

	// Anti-lockout end state: a brand-new berth connection with key + passwordless sudo.
	assertBerthAdminUsable(ctx, t, srv)
}

// anySiteHTTP3 reports whether any site enables HTTP/3 (needs ufw 443/udp).
func anySiteHTTP3(srv *config.Server) bool {
	for _, s := range srv.Sites {
		if s.HTTP3 {
			return true
		}
	}
	return false
}

// assertBerthAdminUsable dials a FRESH connection as the berth account (key auth) and
// confirms passwordless sudo — proving hardening did not lock out the admin path.
// Mirrors the hardening step's anti-lockout gate.
func assertBerthAdminUsable(ctx context.Context, t *testing.T, srv *config.Server) {
	t.Helper()
	auth, err := bssh.AuthMethods(srv.SSH.Key)
	if err != nil {
		t.Fatalf("berth auth methods: %v", err)
	}
	policy := bssh.HostKeyPolicy{Pinned: srv.SSH.Fingerprint, KnownHosts: knownHostsPath()}
	addr := fmt.Sprintf("%s:%d", srv.Host, srv.SSH.Port)
	bc, err := bssh.Dial(ctx, addr, bssh.ClientConfig("berth", auth, policy), true)
	if err != nil {
		t.Fatalf("fresh berth dial: %v", err)
	}
	defer bc.Close()
	res, err := bc.Run(ctx, "sudo -n true", nil)
	if err != nil {
		t.Fatalf("berth sudo -n: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("berth sudo -n failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
}

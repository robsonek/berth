//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertValkeyIsolation proves the per-site Valkey model end to end: each
// instance answers PONG over its socket AS ITS OWN site user, a sibling
// tenant is denied at the socket (the audit's cross-tenant attack, inverted
// into an assert), the stock shared service is off, and the seeded .env
// points at the socket.
func assertValkeyIsolation(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	if !srv.Valkey {
		return
	}
	sock := func(domain string) string { return "/run/berth-valkey/" + config.PoolName(domain) + "/valkey.sock" }

	for _, site := range srv.Sites {
		user := srv.SiteUser(site)
		assertExitZero(ctx, t, c, "valkey PONG as owner "+site.Domain,
			valkeyPingAs(user, sock(site.Domain)))

		env, err := c.Run(ctx, "sudo cat "+site.DeployPath+"/shared/.env", nil)
		if err != nil {
			t.Fatalf("read %s .env: %v", site.Domain, err)
		}
		if env.ExitCode != 0 {
			t.Fatalf("%s shared/.env unreadable (exit %d): %s", site.Domain, env.ExitCode, env.Stderr)
		}
		for _, want := range []string{"REDIS_HOST=" + sock(site.Domain), "REDIS_PORT=0"} {
			if !strings.Contains(env.Stdout, want) {
				t.Errorf("%s .env missing %q", site.Domain, want)
			}
		}
	}

	// Cross-tenant negative: user of site A must be DENIED at site B's socket
	// (connect(2) on a path under a 0700 directory fails immediately with
	// EACCES — no hang). Anything but a nonzero exit is an isolation breach.
	if len(srv.Sites) >= 2 {
		a, b := srv.Sites[0], srv.Sites[1]
		res, err := c.Run(ctx, valkeyPingAs(srv.SiteUser(a), sock(b.Domain)), nil)
		if err != nil {
			t.Fatalf("cross-tenant probe: %v", err)
		}
		if res.ExitCode == 0 {
			t.Errorf("tenant %s reached %s's valkey socket (exit 0, stdout %q) — isolation broken",
				srv.SiteUser(a), b.Domain, strings.TrimSpace(res.Stdout))
		}
	}

	stock, err := c.Run(ctx, "sudo systemctl is-enabled valkey-server", nil)
	if err != nil {
		t.Fatalf("probe stock valkey enablement: %v", err)
	}
	if stock.ExitCode == 0 {
		t.Error("stock valkey-server must be disabled")
	}
}

// valkeyPingAs mirrors valkeyPingCmd's composition (internal/provision/steps/
// valkey.go) under the suite's sudo prefix — a deliberate copy, not a call:
// the production helper is unexported, and this assertion's job is to prove
// the exact command production ships works (and stays denied cross-tenant) on
// a real host, so a shared helper would re-bless any production change
// automatically. If valkeyPingCmd changes shape, update this in the same PR.
// --init-groups is part of what is being proven: it grants the site user's
// supplementary groups, which socket access can depend on.
func valkeyPingAs(user, sock string) string {
	return fmt.Sprintf("sudo setpriv --reuid '%s' --regid '%s' --init-groups -- valkey-cli -s '%s' ping",
		user, user, sock)
}

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
			fmt.Sprintf("sudo runuser -u %s -- valkey-cli -s %s ping", user, sock(site.Domain)))

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
		res, err := c.Run(ctx, fmt.Sprintf("sudo runuser -u %s -- valkey-cli -s %s ping",
			srv.SiteUser(a), sock(b.Domain)), nil)
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

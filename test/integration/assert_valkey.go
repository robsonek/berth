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
	queueSock := func(domain string) string { return "/run/berth-valkey/" + config.PoolName(domain) + "/queue.sock" }

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
		// The queue instance (valkey_queue): its own socket in the same
		// runtime dir, answering the owner. The REDIS_QUEUE_* keys are
		// seed-time-only (an existing .env is never rewritten), and this
		// suite cannot tell a fresh seed from an upgrade-path host — the
		// suite's own env-overwrite assertion rewrites the file, so not even
		// its mtime says when it was seeded. Their presence is therefore
		// reported, not asserted; the seed content is pinned by the unit
		// test TestSeedSharedEnvWithValkeyQueue.
		if srv.ValkeyQueue {
			assertExitZero(ctx, t, c, "valkey queue PONG as owner "+site.Domain,
				valkeyPingAs(user, queueSock(site.Domain)))
			for _, want := range []string{"REDIS_QUEUE_HOST=" + queueSock(site.Domain), "REDIS_QUEUE_PORT=0"} {
				if !strings.Contains(env.Stdout, want) {
					t.Logf("%s .env lacks %q — seed-time-only key; expected when the .env predates valkey_queue (add it by hand)", site.Domain, want)
				}
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
		if srv.ValkeyQueue {
			res, err := c.Run(ctx, valkeyPingAs(srv.SiteUser(a), queueSock(b.Domain)), nil)
			if err != nil {
				t.Fatalf("cross-tenant queue probe: %v", err)
			}
			if res.ExitCode == 0 {
				t.Errorf("tenant %s reached %s's valkey queue socket (exit 0, stdout %q) — isolation broken",
					srv.SiteUser(a), b.Domain, strings.TrimSpace(res.Stdout))
			}
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

// valkeyPingAs mirrors valkeyPingOver's composition (internal/provision/steps/
// valkey.go) under the suite's sudo prefix — a deliberate copy, not a call:
// the production helper is unexported, and this assertion's job is to prove
// the exact command production ships works (and stays denied cross-tenant) on
// a real host, so a shared helper would re-bless any production change
// automatically. If valkeyPingOver changes shape, update this in the same PR.
// --init-groups is part of what is being proven: it grants the site user's
// supplementary groups, which socket access can depend on.
func valkeyPingAs(user, sock string) string {
	return fmt.Sprintf("sudo setpriv --reuid '%s' --regid '%s' --init-groups -- valkey-cli -s '%s' ping",
		user, user, sock)
}

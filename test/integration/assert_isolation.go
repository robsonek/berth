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

// assertMultiSiteIsolation proves kernel- and sudoers-enforced tenant isolation for
// every ordered site pair: site B's OS user cannot read site A's secrets, enter its
// deploy_path, or drive its supervisor program. It runs only for multi-site configs.
func assertMultiSiteIsolation(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	if len(srv.Sites) < 2 {
		t.Log("single-site config: skipping cross-tenant isolation assertions")
		return
	}
	for _, a := range srv.Sites {
		userA := srv.SiteUser(a)
		poolA := config.PoolName(a.Domain)
		// Each site's FPM pool runs as its OWN user (the socket is www-data:0660 for
		// nginx, so we assert the *process* owner, not the socket).
		assertExitZero(ctx, t, c, "fpm socket exists "+a.Domain, "test -S /run/php/berth-"+poolA+".sock")
		assertExitZero(ctx, t, c, "fpm pool runs as "+userA,
			fmt.Sprintf("pgrep -u %s -f 'pool %s'", userA, poolA))
		for _, b := range srv.Sites {
			if b.Domain == a.Domain {
				continue
			}
			userB := srv.SiteUser(b)
			// B cannot read A's shared/.env (shared is 0700 userA).
			assertDenied(ctx, t, c, fmt.Sprintf("%s reads %s shared/.env", userB, a.Domain),
				fmt.Sprintf("sudo -u %s cat %s/shared/.env", userB, a.DeployPath))
			// B cannot enter A's deploy_path (0710 userA:www-data; B is "other").
			assertDenied(ctx, t, c, fmt.Sprintf("%s lists %s deploy_path", userB, a.Domain),
				fmt.Sprintf("sudo -u %s ls %s", userB, a.DeployPath))
			// B is not AUTHORIZED to drive A's supervisor program. Assert the sudoers
			// grant via `sudo -l <cmd>` (non-zero when not permitted) — NOT an actual
			// restart: the program is autostart=false/dormant, so a real restart could
			// exit non-zero from the command itself even if wrongly authorized, which
			// would false-pass while a sudoers hole exists. `sudo -l` tests the grant.
			assertDenied(ctx, t, c, fmt.Sprintf("%s authorized for %s supervisor program", userB, a.Domain),
				fmt.Sprintf("sudo -u %s sudo -n -l /usr/bin/supervisorctl restart 'berth-%s:*'", userB, poolA))
			// Also deny the iter-2 exploit shape: B's OWN target PLUS A's appended as an
			// extra arg — an unescaped sudoers `*` matched across whitespace, letting B
			// drive A's program. The escaped grant (literal `berth-<pool>:*`) rejects it.
			poolB := config.PoolName(b.Domain)
			assertDenied(ctx, t, c, fmt.Sprintf("%s appends %s program to its own", userB, a.Domain),
				fmt.Sprintf("sudo -u %s sudo -n -l /usr/bin/supervisorctl restart 'berth-%s:*' 'berth-%s:*'", userB, poolB, poolA))
		}
	}
}

// assertDenied fails if cmd EXITS ZERO — the command is expected to be rejected
// (permission denied / not in sudoers). A transport error still fails the test.
func assertDenied(ctx context.Context, t *testing.T, c *bssh.Client, label, cmd string) {
	t.Helper()
	res, err := c.Run(ctx, cmd, nil)
	if err != nil {
		t.Fatalf("%s: run: %v", label, err)
	}
	if res.ExitCode == 0 {
		t.Errorf("ISOLATION HOLE: %q succeeded (exit 0) but must be denied; stdout=%q", label, strings.TrimSpace(res.Stdout))
	}
}

//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertDBAuth proves, per site, that the app user authenticates to its OWN database
// the way Laravel would (socket or TCP per the engine's EnvConnection) and CANNOT
// write to a sibling's database. For Postgres it also asserts the app user can CREATE
// in the public schema (the PG15 ALTER DATABASE OWNER fix, #29). It first asserts PHP
// has the PDO driver for the configured engine — without it a Laravel app can't
// connect even though the CLI can.
//
// Probe hygiene mirrors the restore drill's: every probe is built EXCLUSIVELY
// from trusted identities (config + EnvConnection) after a fidelity guard has
// proven the live .env agrees with them; passwords come from the LOCAL secret
// cache (converged by the provision), are exit-code-verified against the live
// .env, and ride SSH stdin — the tenant-writable file is never interpolated
// into a root command and never read back over stdout.
func assertDBAuth(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	// PHP must carry the engine's PDO driver (pdo_pgsql for postgres, else pdo_mysql).
	pdo := "pdo_mysql"
	if srv.Database.Engine == "postgres" {
		pdo = "pdo_pgsql"
	}
	assertExitZero(ctx, t, c, "php has "+pdo,
		fmt.Sprintf("php%s -m | grep -qi %s", srv.PHP.Version, pdo))
	const createDrop = "CREATE TABLE berth_probe(x int); DROP TABLE berth_probe;"

	conn := trustedDBConnFor(t, srv)
	cache, err := secret.LoadCache(srv.CacheKey())
	if err != nil {
		t.Fatalf("db auth: load local secret cache: %v", err)
	}
	for _, site := range srv.Sites {
		envPath := site.DeployPath + "/shared/.env"
		dbUser, dbName := srv.SiteDBUser(site), srv.SiteDBName(site)
		pw := cache[dbUser]
		if pw == "" {
			t.Fatalf("db auth: local cache lacks the DB credential for %s; the provision should have converged it", site.Domain)
		}
		assertEnvIdentityFidelity(ctx, t, c, "db auth "+site.Domain, envPath, conn, dbUser, dbName)
		// The cached password must be the one the app reads — exit-code-only,
		// the secret rides stdin into the production match script.
		if exit := envFieldExit(ctx, t, c, envPath, "DB_PASSWORD", pw); exit != 0 {
			t.Fatalf("db auth %s: live DB_PASSWORD in %s disagrees with the local secret cache (probe exit %d)", site.Domain, envPath, exit)
		}
		// Own DB reachable over the app's real connection path.
		assertExitZeroIn(ctx, t, c, site.Domain+" app user reaches own db",
			dbProbeStdinCmd(conn.driver, conn.host, conn.port, conn.socket, dbUser, dbName, "SELECT 1"), []byte(pw+"\n"))
		// Postgres: app user owns its DB → can CREATE in public (#29).
		if srv.Database.Engine == "postgres" {
			assertExitZeroIn(ctx, t, c, site.Domain+" pg app user CREATE in public",
				dbProbeStdinCmd(conn.driver, conn.host, conn.port, conn.socket, dbUser, dbName, createDrop), []byte(pw+"\n"))
		}
		// Sibling DB: WRITE must be denied. (A bare SELECT 1 would pass on Postgres via
		// the default PUBLIC CONNECT, so probe a CREATE — denied on both engines: MySQL
		// has no grant on the sibling db; PG non-owner cannot CREATE in its public schema.)
		for _, other := range srv.Sites {
			if other.Domain == site.Domain {
				continue
			}
			otherDB := srv.SiteDBName(other)
			if otherDB == dbName {
				continue
			}
			assertDeniedIn(ctx, t, c, site.Domain+" app user writes sibling db "+otherDB,
				dbProbeStdinCmd(conn.driver, conn.host, conn.port, conn.socket, dbUser, otherDB, createDrop), []byte(pw+"\n"))
		}
	}
}

// assertExitZeroIn is assertExitZero with stdin — the transport for probes
// whose command string must stay secret-free (the password rides stdin).
func assertExitZeroIn(ctx context.Context, t *testing.T, c *bssh.Client, label, cmd string, stdin []byte) {
	t.Helper()
	res, err := c.Run(ctx, cmd, stdin)
	if err != nil {
		t.Fatalf("%s: run: %v", label, err)
	}
	if res.ExitCode != 0 {
		t.Errorf("%s: exit %d, stderr %q", label, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
}

// assertDeniedIn is assertDenied with stdin (same secret-free-command
// contract). It deliberately does not echo the probe's stdout on failure —
// probe output stays out of test logs, like every other secret-adjacent path.
func assertDeniedIn(ctx context.Context, t *testing.T, c *bssh.Client, label, cmd string, stdin []byte) {
	t.Helper()
	res, err := c.Run(ctx, cmd, stdin)
	if err != nil {
		t.Fatalf("%s: run: %v", label, err)
	}
	if res.ExitCode == 0 {
		t.Errorf("ISOLATION HOLE: %q succeeded (exit 0) but must be denied", label)
	}
}

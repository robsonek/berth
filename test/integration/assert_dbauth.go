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

// assertDBAuth proves, per site, that the app user authenticates to its OWN database
// the way Laravel would (socket or TCP per .env) and CANNOT write to a sibling's
// database. For Postgres it also asserts the app user can CREATE in the public schema
// (the PG15 ALTER DATABASE OWNER fix, #29). It first asserts PHP has the PDO driver for
// the configured engine — without it a Laravel app can't connect even though the CLI can.
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
	envs := map[string]map[string]string{}
	for _, site := range srv.Sites {
		envs[site.Domain] = readSiteEnv(ctx, t, c, site)
	}
	for _, site := range srv.Sites {
		env := envs[site.Domain]
		ownDB := env["DB_DATABASE"]
		// Own DB reachable over the app's real .env path.
		assertExitZero(ctx, t, c, site.Domain+" app user reaches own db",
			dbProbeCmd(env, ownDB, "SELECT 1"))
		// Postgres: app user owns its DB → can CREATE in public (#29).
		if srv.Database.Engine == "postgres" {
			assertExitZero(ctx, t, c, site.Domain+" pg app user CREATE in public",
				dbProbeCmd(env, ownDB, createDrop))
		}
		// Sibling DB: WRITE must be denied. (A bare SELECT 1 would pass on Postgres via
		// the default PUBLIC CONNECT, so probe a CREATE — denied on both engines: MySQL
		// has no grant on the sibling db; PG non-owner cannot CREATE in its public schema.)
		for _, other := range srv.Sites {
			if other.Domain == site.Domain {
				continue
			}
			otherDB := envs[other.Domain]["DB_DATABASE"]
			if otherDB == ownDB {
				continue
			}
			assertDenied(ctx, t, c, site.Domain+" app user writes sibling db "+otherDB,
				dbProbeCmd(env, otherDB, createDrop))
		}
	}
}

// readSiteEnv reads and parses a site's shared/.env from the host (root via the
// sudo-wrapped client). It never echoes the parsed secrets.
func readSiteEnv(ctx context.Context, t *testing.T, c *bssh.Client, site config.Site) map[string]string {
	t.Helper()
	res, err := c.Run(ctx, "cat "+site.DeployPath+"/shared/.env", nil)
	if err != nil {
		t.Fatalf("read .env for %s: %v", site.Domain, err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("read .env for %s: exit %d (%s)", site.Domain, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return parseEnv(res.Stdout)
}

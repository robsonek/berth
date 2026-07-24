//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertClientDBAuth proves each site user's seeded client-credentials file
// (~/.my.cnf / ~/.pgpass) is private AND actually authenticates: the engine CLI
// runs as the site user with NO inline credentials — MariaDB with no arguments
// at all (the [client] credential plus the [mysql] database preselection must
// carry everything), Postgres with only host/user/db (the password must come
// from ~/.pgpass, which libpq ignores unless it is exactly 0600).
func assertClientDBAuth(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	eng, err := dbpkg.Get(srv.Database.Engine)
	if err != nil {
		t.Fatalf("engine %q: %v", srv.Database.Engine, err)
	}
	name := eng.ClientAuthFileName()
	for _, site := range srv.Sites {
		user := srv.SiteUser(site)
		path := "/home/" + user + "/" + name
		st, err := c.Run(ctx, "stat -c '%U:%G %a' "+path, nil)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if st.ExitCode != 0 {
			t.Errorf("%s missing (exit %d): %s", path, st.ExitCode, strings.TrimSpace(st.Stderr))
			continue
		}
		if got, want := strings.TrimSpace(st.Stdout), user+":"+user+" 600"; got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
		var probe string
		if srv.Database.Engine == "postgres" {
			probe = fmt.Sprintf("sudo -u %s -H psql -h 127.0.0.1 -U %s -d %s -tAc 'SELECT 1'",
				user, srv.SiteDBUser(site), srv.SiteDBName(site))
		} else {
			probe = fmt.Sprintf("sudo -u %s -H mariadb -N -e 'SELECT 1'", user)
		}
		assertExitZero(ctx, t, c, site.Domain+" client-creds login as "+user, probe)
	}
}

// assertDeployKeys verifies each repository site's deploy key pair (generated
// by the accounts step) exists and the public half is a printable ed25519 key —
// what `berth site key` surfaces. Sites without a repository have no managed
// key by design and are skipped.
func assertDeployKeys(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	for _, site := range srv.Sites {
		if site.Repository == "" {
			continue
		}
		user := srv.SiteUser(site)
		pub := "/home/" + user + "/.ssh/id_ed25519.pub"
		res, err := c.Run(ctx, "cat "+pub, nil)
		if err != nil {
			t.Fatalf("cat %s: %v", pub, err)
		}
		if res.ExitCode != 0 {
			t.Errorf("%s: deploy key pubkey missing (exit %d)", site.Domain, res.ExitCode)
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(res.Stdout), "ssh-ed25519 ") {
			t.Errorf("%s: pubkey is not ed25519: %q", site.Domain, strings.TrimSpace(res.Stdout))
		}
	}
}

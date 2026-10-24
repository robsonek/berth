//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

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

// assertDeployKeys verifies each repository site's deploy key PAIR (generated
// by the accounts step, or installed from repository_key): the private half
// is present, owned by the site user and 0600, the public half is a printable
// key (what `berth site key` surfaces; ed25519 when berth generated it), and
// the two actually match (`ssh-keygen -y` re-derivation) — a pubkey orphaned
// from its private key would paste fine into the repo host and then never
// authenticate. With repository_key the pair must also BE that key: the
// host's re-derived public half equals the one derived locally from the
// configured file. Sites without a repository have no managed key by design
// and are skipped.
func assertDeployKeys(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	for _, site := range srv.Sites {
		if site.Repository == "" {
			continue
		}
		user := srv.SiteUser(site)
		priv := "/home/" + user + "/.ssh/id_ed25519"
		pub := priv + ".pub"
		st, err := c.Run(ctx, "stat -c '%U %a' "+priv, nil)
		if err != nil {
			t.Fatalf("stat %s: %v", priv, err)
		}
		if st.ExitCode != 0 {
			t.Errorf("%s: deploy private key missing (exit %d)", site.Domain, st.ExitCode)
			continue
		}
		if got, want := strings.TrimSpace(st.Stdout), user+" 600"; got != want {
			t.Errorf("%s: private key owner/mode = %q, want %q", site.Domain, got, want)
		}
		res, err := c.Run(ctx, "cat "+pub, nil)
		if err != nil {
			t.Fatalf("cat %s: %v", pub, err)
		}
		if res.ExitCode != 0 {
			t.Errorf("%s: deploy key pubkey missing (exit %d)", site.Domain, res.ExitCode)
			continue
		}
		pubLine := strings.TrimSpace(res.Stdout)
		// A generated key is ed25519; a repository_key may be any type ssh
		// loads, and is held to the stronger equality check below instead.
		if site.RepositoryKey == "" && !strings.HasPrefix(pubLine, "ssh-ed25519 ") {
			t.Errorf("%s: pubkey is not ed25519: %q", site.Domain, pubLine)
			continue
		}
		derived, err := c.Run(ctx, "ssh-keygen -y -f "+priv, nil)
		if err != nil {
			t.Fatalf("ssh-keygen -y %s: %v", priv, err)
		}
		if derived.ExitCode != 0 {
			t.Errorf("%s: private key unreadable/corrupt (ssh-keygen -y exit %d)", site.Domain, derived.ExitCode)
			continue
		}
		// Compare type + blob; the .pub carries an extra comment field.
		pubFields, derFields := strings.Fields(pubLine), strings.Fields(derived.Stdout)
		if len(pubFields) < 2 || len(derFields) < 2 || pubFields[0] != derFields[0] || pubFields[1] != derFields[1] {
			t.Errorf("%s: pubkey does not match the private key", site.Domain)
			continue
		}
		if site.RepositoryKey != "" {
			want, err := localAuthorizedKey(site.RepositoryKey)
			if err != nil {
				t.Fatalf("%s: %v", site.Domain, err)
			}
			// Public halves only: nothing secret is compared or printed.
			if got := derFields[0] + " " + derFields[1]; got != want {
				t.Errorf("%s: the host's deploy key is not repository_key %s", site.Domain, site.RepositoryKey)
			}
		}
	}
}

// localAuthorizedKey derives "<type> <base64>" from the local private key at
// path (a leading ~/ is the local home) — the derivation berth makes before
// it installs a repository_key.
func localAuthorizedKey(path string) (string, error) {
	local := path
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve ~ in repository_key %s: %w", path, err)
		}
		local = filepath.Join(home, rest)
	}
	b, err := os.ReadFile(local)
	if err != nil {
		return "", fmt.Errorf("repository_key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return "", fmt.Errorf("repository_key %s: %w", path, err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

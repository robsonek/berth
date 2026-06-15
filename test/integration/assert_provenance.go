//go:build integration

package integration

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertAptProvenance verifies, per configured upstream source: (1) the on-disk signing
// keyring carries the pinned 40-hex fingerprint (apt trust core), (2) the source list
// binds that keyring via signed-by and uses the upstream URI, and (3) the INSTALLED
// package version originates from the upstream repo (not Debian).
func assertAptProvenance(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	for _, ck := range aptProvenanceChecks(srv) {
		keyring := "/usr/share/keyrings/" + ck.repo.Name + ".gpg"
		if fp, err := c.Run(ctx, "gpg --show-keys --with-colons "+keyring, nil); err != nil {
			t.Fatalf("%s: read keyring: %v", ck.repo.Name, err)
		} else if !strings.Contains(fp.Stdout, ck.repo.Fingerprint) {
			t.Errorf("%s: keyring %s missing pinned fingerprint %s (exit %d)", ck.repo.Name, keyring, ck.repo.Fingerprint, fp.ExitCode)
		}
		// Source list binds the keyring (signed-by) + uses the upstream URI.
		listFile := "/etc/apt/sources.list.d/" + ck.repo.Name + ".list"
		if src, err := c.Run(ctx, "cat "+listFile, nil); err != nil {
			t.Fatalf("%s: read source list: %v", ck.repo.Name, err)
		} else {
			if !strings.Contains(src.Stdout, "signed-by="+keyring) {
				t.Errorf("%s: source list %s does not bind signed-by=%s:\n%s", ck.repo.Name, listFile, keyring, src.Stdout)
			}
			if !strings.Contains(src.Stdout, ck.repo.URI) {
				t.Errorf("%s: source list %s does not use upstream URI %s", ck.repo.Name, listFile, ck.repo.URI)
			}
		}
		// Installed version originates from the upstream repo.
		host := repoHost(ck.repo.URI)
		if pol, err := c.Run(ctx, "apt-cache policy "+ck.pkg, nil); err != nil {
			t.Fatalf("%s: apt-cache policy %s: %v", ck.repo.Name, ck.pkg, err)
		} else if !installedFromHost(pol.Stdout, host) {
			t.Errorf("%s: installed %s did not originate from %s; apt-cache policy:\n%s", ck.repo.Name, ck.pkg, host, pol.Stdout)
		}
	}
}

// repoHost extracts the host from a repo URI for the installed-origin check.
func repoHost(uri string) string {
	if u, err := url.Parse(uri); err == nil && u.Host != "" {
		return u.Host
	}
	return uri
}

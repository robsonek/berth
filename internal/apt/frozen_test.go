package apt

import (
	"strings"
	"testing"
)

// TestRepoIdentifiersAreFrozen pins the on-host identity surface of berth's
// apt repos: source-list paths, keyring paths, the user-repo namespace prefix
// and the pre-E1 (marker-less) source-line bytes that the adoption allowlist
// promises to recognize on every already-provisioned host. Changing ANY of
// these requires a conscious BREAKING changelog entry and a migration story.
func TestRepoIdentifiersAreFrozen(t *testing.T) {
	if UserRepoPrefix != "berth-" {
		t.Fatalf("UserRepoPrefix changed: %q", UserRepoPrefix)
	}
	cases := []struct {
		repo                Repo
		name, list, keyring string
	}{
		{Sury(), "sury-php", "/etc/apt/sources.list.d/sury-php.list", "/usr/share/keyrings/sury-php.gpg"},
		{NginxOrg(), "nginx-org", "/etc/apt/sources.list.d/nginx-org.list", "/usr/share/keyrings/nginx-org.gpg"},
		{PostgresPGDG(), "pgdg", "/etc/apt/sources.list.d/pgdg.list", "/usr/share/keyrings/pgdg.gpg"},
		{MariaDBOrg(), "mariadb-org", "/etc/apt/sources.list.d/mariadb-org.list", "/usr/share/keyrings/mariadb-org.gpg"},
	}
	for _, c := range cases {
		if c.repo.Name != c.name {
			t.Errorf("repo name changed: got %q want %q", c.repo.Name, c.name)
		}
		if got := c.repo.SourceListPath(); got != c.list {
			t.Errorf("SourceListPath(%s) = %q, want %q", c.name, got, c.list)
		}
		if got := c.repo.KeyringPath(); got != c.keyring {
			t.Errorf("KeyringPath(%s) = %q, want %q", c.name, got, c.keyring)
		}
	}
	// The legacy allowlists are a compatibility promise to every host any
	// released berth version ever provisioned: APPEND-ONLY. MariaDB shipped
	// three URIs (deb.mariadb.org 11.8, deb.mariadb.org 12.3, then the
	// current dlm.mariadb.com endpoint); the others never changed.
	legacy := map[string][]string{
		"nginx-org": {
			"deb [signed-by=/usr/share/keyrings/nginx-org.gpg] https://nginx.org/packages/mainline/debian/ trixie nginx\n",
		},
		"mariadb-org": {
			"deb [signed-by=/usr/share/keyrings/mariadb-org.gpg] https://dlm.mariadb.com/repo/mariadb-server/12.3/repo/debian/ trixie main\n",
			"deb [signed-by=/usr/share/keyrings/mariadb-org.gpg] https://deb.mariadb.org/12.3/debian/ trixie main\n",
			"deb [signed-by=/usr/share/keyrings/mariadb-org.gpg] https://deb.mariadb.org/11.8/debian/ trixie main\n",
		},
	}
	for _, c := range cases {
		if want, pinned := legacy[c.name]; pinned {
			got := c.repo.LegacySourceContents()
			if len(got) != len(want) {
				t.Fatalf("LegacySourceContents(%s) has %d entries, want %d (append-only!)", c.name, len(got), len(want))
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("LegacySourceContents(%s)[%d]:\n got %q\nwant %q", c.name, i, got[i], want[i])
				}
			}
		}
		// The berth- namespace is permanently exclusive to USER repos: a
		// future built-in repo named berth-* would be swept by the apt step.
		if strings.HasPrefix(c.repo.Name, UserRepoPrefix) {
			t.Errorf("built-in repo %q claims the user-repo namespace", c.repo.Name)
		}
	}
}

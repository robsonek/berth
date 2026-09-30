package steps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
)

func TestUpstreamRepos(t *testing.T) {
	cases := []struct {
		name    string
		php     config.PHP
		nginx   string
		db      config.Database
		want    []string // repo names, in order
		wantErr string
	}{
		{"all debian", config.PHP{Version: "8.4", Source: "auto"}, "debian", config.Database{Engine: "mariadb", Source: "debian"}, nil, ""},
		{"php 8.4 explicit sury", config.PHP{Version: "8.4", Source: "sury"}, "debian", config.Database{Engine: "mariadb", Source: "debian"}, []string{"sury-php"}, ""},
		{"php 8.5 auto", config.PHP{Version: "8.5", Source: "auto"}, "debian", config.Database{Engine: "mariadb", Source: "debian"}, []string{"sury-php"}, ""},
		{"nginx.org only", config.PHP{Version: "8.4", Source: "debian"}, "nginx", config.Database{Engine: "mariadb", Source: "debian"}, []string{"nginx-org"}, ""},
		{"mariadb upstream only", config.PHP{Version: "8.4", Source: "auto"}, "debian", config.Database{Engine: "mariadb", Source: "mariadb"}, []string{"mariadb-org"}, ""},
		{"postgres debian", config.PHP{Version: "8.4", Source: "auto"}, "debian", config.Database{Engine: "postgres", Source: "debian"}, nil, ""},
		{"everything upstream (pgdg)", config.PHP{Version: "8.5", Source: "sury"}, "nginx", config.Database{Engine: "postgres", Source: "pgdg"}, []string{"sury-php", "nginx-org", "pgdg"}, ""},
		{"php debian cannot provide 8.5", config.PHP{Version: "8.5", Source: "debian"}, "debian", config.Database{Engine: "mariadb", Source: "debian"}, nil, "cannot provide 8.5"},
		{"unknown engine", config.PHP{Version: "8.4", Source: "auto"}, "debian", config.Database{Engine: "oracle", Source: "oracle"}, nil, `unknown database engine "oracle"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &config.Server{PHP: c.php, Nginx: config.Nginx{Source: c.nginx}, Database: c.db}
			repos, err := upstreamRepos(s)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, r := range repos {
				got = append(got, r.Name)
				if r.Origin == "" {
					t.Errorf("%s: upstream repo without a pinned Origin", r.Name)
				}
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("repos = %v, want %v", got, c.want)
			}
		})
	}
}

// TestUserReposCarryNoOrigin: an E1 repo must never gain an Origin, or base
// would start auto-upgrading from it.
func TestUserReposCarryNoOrigin(t *testing.T) {
	r := userRepo(config.AptRepo{Name: "example", URI: "https://apt.example.com/debian", Suite: "trixie"})
	if r.Origin != "" {
		t.Errorf("user repo Origin = %q, want empty", r.Origin)
	}
}

// TestOwnRepoConstructorsAreSingleSourced keeps base's drop-in and the
// installing steps on ONE source of truth: outside autoupdates.go no step file
// may build an own upstream repo, ask an engine for its repo, or decide the
// Sury/nginx.org question itself. A step that bypassed phpUpstream /
// nginxUpstream / databaseUpstream could install from a repo the drop-in does
// not name.
func TestOwnRepoConstructorsAreSingleSourced(t *testing.T) {
	forbidden := []string{"apt.Sury()", "apt.NginxOrg()", "apt.MariaDBOrg()", "apt.PostgresPGDG()", ".UpstreamRepo()", "useSury(", `Nginx.Source == "nginx"`, `Nginx.Source != "nginx"`}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "autoupdates.go" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, needle := range forbidden {
			if needle == "useSury(" && f == "php.go" {
				// php.go DEFINES useSury; only its definition may mention it.
				if strings.Count(string(b), "useSury(") != 1 || !strings.Contains(string(b), "func useSury(") {
					t.Errorf("php.go: useSury must only be defined there, called via phpUpstream")
				}
				continue
			}
			if strings.Contains(string(b), needle) {
				t.Errorf("%s calls %s directly — go through phpUpstream/nginxUpstream/databaseUpstream in autoupdates.go", f, needle)
			}
		}
	}
}

func TestRenderUnattendedOrigins(t *testing.T) {
	got, err := renderUnattendedOrigins([]apt.Repo{apt.Sury(), apt.NginxOrg(), apt.PostgresPGDG()})
	if err != nil {
		t.Fatal(err)
	}
	want := `# managed by berth
Unattended-Upgrade::Origins-Pattern {
        "origin=deb.sury.org,codename=trixie,site=packages.sury.org";
        "origin=nginx,codename=trixie,site=nginx.org";
        "origin=apt.postgresql.org,codename=trixie-pgdg,site=apt.postgresql.org";
};
Unattended-Upgrade::Package-Blacklist {
        "php(?![0-9])(?!.*common)(-.+)?$";
        "libapache2-mod-php$";
        "libphp-embed$";
        "postgresql(?!.*common)(?!.*-[0-9][0-9.]*(-|$))(-.+)?$";
};
`
	if string(got) != want {
		t.Errorf("rendered drop-in:\n%s\nwant:\n%s", got, want)
	}

	maria, err := renderUnattendedOrigins([]apt.Repo{apt.MariaDBOrg()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(maria), "Package-Blacklist") {
		t.Errorf("MariaDB must not get a blacklist:\n%s", maria)
	}

	none, err := renderUnattendedOrigins(nil)
	if err != nil || none != nil {
		t.Errorf("empty set = (%q, %v), want (nil, nil)", none, err)
	}

	if _, err := renderUnattendedOrigins([]apt.Repo{{Name: "berth-example", URI: "https://apt.example.com/x", Suite: "trixie"}}); err == nil {
		t.Error("a repo without a pinned Origin must be refused, not rendered as an unmatchable pattern")
	}
}

// TestUnattendedOriginsPath pins the drop-in's on-host path: base (and every
// host it provisioned) owns exactly this file, and it must sort after the
// stock 50unattended-upgrades it extends.
func TestUnattendedOriginsPath(t *testing.T) {
	if unattendedOriginsPath != "/etc/apt/apt.conf.d/52berth-unattended-upgrades" {
		t.Errorf("unattendedOriginsPath = %q", unattendedOriginsPath)
	}
	if base := filepath.Base(unattendedOriginsPath); base <= "50unattended-upgrades" {
		t.Errorf("%s must sort after the stock 50unattended-upgrades", base)
	}
}

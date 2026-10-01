package steps

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// The guard must not pass vacuously: the installing steps' files have to be
	// among the ones scanned.
	scanned := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "autoupdates.go" {
			continue
		}
		scanned[f] = true
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range singleSourceViolations(t, f, src) {
			t.Errorf("%s — go through phpUpstream/nginxUpstream/databaseUpstream in autoupdates.go", v)
		}
	}
	for _, f := range []string{"php.go", "nginx.go", "database.go"} {
		if !scanned[f] {
			t.Errorf("%s was not scanned (glob matched %v); the guard would pass vacuously", f, files)
		}
	}
}

// ownRepoConstructors are the apt constructors of berth's four upstream repos.
var ownRepoConstructors = map[string]bool{"Sury": true, "NginxOrg": true, "MariaDBOrg": true, "PostgresPGDG": true}

// singleSourceViolations parses one Go file and reports every place that builds
// an own upstream repo or decides an upstream question itself: a call to an
// own-repo constructor, to an engine's UpstreamRepo or to useSury, and any
// ==/!= comparison or switch on <x>.Nginx.Source, <x>.Database.Source or
// <x>.PHP.Source. Working on the syntax tree catches reversed operands and
// switches, and never trips on the same text inside comments or strings.
// (useSury's own `switch p.Source` reads a parameter, not <x>.PHP.Source, so
// its definition in php.go is not a violation.)
func singleSourceViolations(t *testing.T, filename string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var out []string
	report := func(n ast.Node, what string) {
		out = append(out, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), what))
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			switch fn := n.Fun.(type) {
			case *ast.SelectorExpr:
				if pkg, ok := fn.X.(*ast.Ident); ok && pkg.Name == "apt" && ownRepoConstructors[fn.Sel.Name] {
					report(n, "calls apt."+fn.Sel.Name+"() directly")
				}
				if fn.Sel.Name == "UpstreamRepo" {
					report(n, "calls .UpstreamRepo() directly")
				}
			case *ast.Ident:
				if fn.Name == "useSury" {
					report(n, "calls useSury() directly")
				}
			}
		case *ast.BinaryExpr:
			if n.Op == token.EQL || n.Op == token.NEQ {
				for _, side := range []ast.Expr{n.X, n.Y} {
					if c := sourceComponent(side); c != "" {
						report(n, "decides on "+c+".Source directly")
					}
				}
			}
		case *ast.SwitchStmt:
			if c := sourceComponent(n.Tag); c != "" {
				report(n, "switches on "+c+".Source directly")
			}
		}
		return true
	})
	return out
}

// sourceComponent returns "Nginx", "Database" or "PHP" when e is
// <x>.<Component>.Source, else "".
func sourceComponent(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Source" {
		return ""
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	switch inner.Sel.Name {
	case "Nginx", "Database", "PHP":
		return inner.Sel.Name
	}
	return ""
}

// TestSingleSourceGuardCatchesEveryShape proves the guard sees every forbidden
// shape — including a reversed comparison and a switch, which a plain string
// match misses — and ignores the same text inside comments and strings.
func TestSingleSourceGuardCatchesEveryShape(t *testing.T) {
	src := `package steps

func bad(s *config.Server, eng dbpkg.Engine) {
	_ = apt.Sury()
	_ = apt.NginxOrg()
	_ = apt.MariaDBOrg()
	_ = apt.PostgresPGDG()
	_, _ = eng.UpstreamRepo()
	_, _ = useSury(s.PHP)
	_ = s.Nginx.Source == "nginx"
	_ = "debian" != s.Database.Source
	switch s.PHP.Source {
	}
}

func fine(s *config.Server) string {
	// apt.Sury() and s.Nginx.Source == "nginx" in a comment are not code.
	return "apt.Sury() useSury(" + s.Nginx.Source
}
`
	got := singleSourceViolations(t, "probe.go", []byte(src))
	if len(got) != 9 {
		t.Fatalf("got %d violations, want 9 (one per line of bad):\n%s", len(got), strings.Join(got, "\n"))
	}
	for _, v := range got {
		if !strings.Contains(v, "probe.go:") || strings.Contains(v, "probe.go:17") || strings.Contains(v, "probe.go:18") {
			t.Errorf("violation outside bad(): %s", v)
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
	if want := `        "origin=MariaDB,codename=trixie,site=dlm.mariadb.com";`; !strings.Contains(string(maria), want) {
		t.Errorf("MariaDB pattern missing, want line %q in:\n%s", want, maria)
	}

	none, err := renderUnattendedOrigins(nil)
	if err != nil || none != nil {
		t.Errorf("empty set = (%q, %v), want (nil, nil)", none, err)
	}

	if _, err := renderUnattendedOrigins([]apt.Repo{{Name: "berth-example", URI: "https://apt.example.com/x", Suite: "trixie"}}); err == nil {
		t.Error("a repo without a pinned Origin must be refused, not rendered as an unmatchable pattern")
	}
	if _, err := renderUnattendedOrigins([]apt.Repo{{Name: "hostless", URI: "packages.example.org/php/", Suite: "trixie", Origin: "example"}}); err == nil {
		t.Error("a repo whose URI has no host must be refused: its site= would match nothing")
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

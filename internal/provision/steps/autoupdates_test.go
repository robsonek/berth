package steps

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
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
// an own upstream repo or decides an upstream question itself: any reference —
// call, function value or method value — to an own-repo constructor of the apt
// package (under whatever name the file imports it), to an engine's
// UpstreamRepo or to useSury (outside its own declaration); and any ==/!=
// comparison, switch tag or switch initialiser that reads <x>.Nginx.Source,
// <x>.Database.Source or <x>.PHP.Source anywhere in its operands (so
// parentheses and concatenation do not hide it). Working on the syntax tree
// never trips on the same text inside comments or strings. useSury's own
// `switch p.Source` reads a parameter, not <x>.PHP.Source, so its definition in
// php.go is not a violation.
func singleSourceViolations(t *testing.T, filename string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	aptName := ""
	for _, imp := range file.Imports {
		if imp.Path.Value == `"github.com/robsonek/berth/internal/apt"` {
			aptName = "apt"
			if imp.Name != nil {
				aptName = imp.Name.Name
			}
		}
	}
	declared := map[*ast.Ident]bool{} // function names in their own declarations
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			declared[fd.Name] = true
		}
	}
	var out []string
	report := func(n ast.Node, what string) {
		out = append(out, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), what))
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if pkg, ok := n.X.(*ast.Ident); ok && aptName != "" && pkg.Name == aptName && ownRepoConstructors[n.Sel.Name] {
				report(n, "uses apt."+n.Sel.Name+" directly")
			}
			if n.Sel.Name == "UpstreamRepo" {
				report(n, "uses .UpstreamRepo directly")
			}
		case *ast.Ident:
			if n.Name == "useSury" && !declared[n] {
				report(n, "uses useSury directly")
			}
		case *ast.BinaryExpr:
			if (n.Op == token.EQL || n.Op == token.NEQ) && (readsSource(n.X) || readsSource(n.Y)) {
				report(n, "decides on a Source field directly")
			}
		case *ast.SwitchStmt:
			if readsSource(n.Tag) || readsSource(n.Init) {
				report(n, "switches on a Source field directly")
			}
		}
		return true
	})
	return out
}

// readsSource reports whether the subtree n reads <x>.Nginx.Source,
// <x>.Database.Source or <x>.PHP.Source.
func readsSource(n ast.Node) bool {
	if n == nil {
		return false
	}
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if e, ok := m.(ast.Expr); ok && sourceComponent(e) != "" {
			found = true
		}
		return !found
	})
	return found
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

// TestSingleSourceGuardShapes pins, one snippet at a time, exactly how many
// reports the guard makes: every forbidden shape (including reversed,
// parenthesised and concatenated comparisons, switch tags and initialisers,
// tagless-switch cases, function and method values, and an aliased apt import)
// is reported once, and legitimate code — comments, strings, diagnostic
// concatenation, useSury's own definition — is not. Dataflow through a local
// variable (`src := s.PHP.Source; if src == …`) is deliberately out of scope:
// this is a regression check on how the steps are written, not a security
// boundary.
func TestSingleSourceGuardShapes(t *testing.T) {
	const aptImport = `"github.com/robsonek/berth/internal/apt"`
	cases := []struct {
		name, imports, body string
		want                int
	}{
		{"comment and string mentions", aptImport, `func f() string {
	// apt.Sury() and s.Nginx.Source == "nginx" in a comment are not code.
	return "apt.Sury() useSury( .UpstreamRepo()"
}`, 0},
		{"diagnostic concatenation", aptImport, `func f(s *config.Server) string { return "source " + s.Nginx.Source }`, 0},
		{"useSury's own definition", aptImport, `func useSury(p config.PHP) (bool, error) {
	switch p.Source {
	}
	return false, nil
}`, 0},
		{"constructor call", aptImport, `func f() { _ = apt.Sury() }`, 1},
		{"constructor value", aptImport, `func f() { mk := apt.NginxOrg; _ = mk }`, 1},
		{"aliased apt import", `repos "github.com/robsonek/berth/internal/apt"`, `func f() { _ = repos.MariaDBOrg() }`, 1},
		{"UpstreamRepo call", aptImport, `func f(eng dbpkg.Engine) { _, _ = eng.UpstreamRepo() }`, 1},
		{"UpstreamRepo method value", aptImport, `func f(eng dbpkg.Engine) { mk := eng.UpstreamRepo; _ = mk }`, 1},
		{"useSury call", aptImport, `func f(s *config.Server) { _, _ = useSury(s.PHP) }`, 1},
		{"useSury function value", aptImport, `func f() { fn := useSury; _ = fn }`, 1},
		{"comparison", aptImport, `func f(s *config.Server) bool { return s.Nginx.Source == "nginx" }`, 1},
		{"reversed comparison", aptImport, `func f(s *config.Server) bool { return "debian" != s.Database.Source }`, 1},
		{"parenthesised comparison", aptImport, `func f(s *config.Server) bool { return (s.PHP.Source) == "sury" }`, 1},
		{"concatenated comparison", aptImport, `func f(s *config.Server) bool { return "" + s.Nginx.Source == "nginx" }`, 1},
		{"switch tag", aptImport, `func f(s *config.Server) {
	switch s.PHP.Source {
	}
}`, 1},
		{"switch initialiser", aptImport, `func f(s *config.Server) {
	switch src := s.PHP.Source; src {
	}
}`, 1},
		{"tagless switch case", aptImport, `func f(s *config.Server) {
	switch {
	case s.Database.Source == "debian":
	}
}`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "package steps\n\nimport (\n\t" + c.imports + "\n)\n\n" + c.body + "\n"
			got := singleSourceViolations(t, "probe.go", []byte(src))
			if len(got) != c.want {
				t.Errorf("got %d reports, want %d:\n%s", len(got), c.want, strings.Join(got, "\n"))
			}
		})
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

// manualUpstreamServer installs php, nginx and the database from their
// producer repos (upstreamServer's mix) but sets apt.upstream_updates: manual,
// so unattended-upgrades must not be extended to those repos.
func manualUpstreamServer() *config.Server {
	s := upstreamServer()
	s.Apt.UpstreamUpdates = "manual"
	return s
}

// manualRemoveReason is base's plan line for berth's drop-in under manual.
const manualRemoveReason = "remove /etc/apt/apt.conf.d/52berth-unattended-upgrades (apt.upstream_updates: manual)"

// baseCheckWithOrigins runs base.Check with every base package installed and
// 20auto-upgrades up to date, so the verdict is the origins drop-in's alone.
func baseCheckWithOrigins(t *testing.T, s *config.Server, origins bssh.Result, force bool) provision.CheckResult {
	t.Helper()
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{Stdout: "Status: install ok installed\n"})
	}
	auto, err := renderAutoUpgrades()
	if err != nil {
		t.Fatal(err)
	}
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{Stdout: string(auto)})
	f.On(originsCat, origins)
	cr, err := SystemBase().Check(context.Background(), provision.RunCtx{Force: force}, s, f)
	if err != nil {
		t.Fatalf("Check (force=%v): %v", force, err)
	}
	return cr
}

// assertOriginsUntouched fails if base.Apply did anything to the drop-in
// beyond reading it: no validation, no write, no removal.
func assertOriginsUntouched(t *testing.T, o *orderedRunner, label string) {
	t.Helper()
	for _, e := range o.events {
		if e == "run:"+aptConfigValidateCmd || (strings.Contains(e, unattendedOriginsPath) && e != "run:"+originsCat) {
			t.Errorf("%s: the drop-in was touched: %q", label, e)
		}
	}
}

func TestUnattendedRepos(t *testing.T) {
	for _, mode := range []string{"", "auto", "manual"} {
		s := upstreamServer()
		s.Apt.UpstreamUpdates = mode
		got, err := unattendedRepos(s)
		if err != nil {
			t.Fatalf("%q: %v", mode, err)
		}
		var names []string
		for _, r := range got {
			names = append(names, r.Name)
		}
		want := "sury-php,nginx-org,mariadb-org"
		if mode == "manual" {
			want = ""
		}
		if strings.Join(names, ",") != want {
			t.Errorf("upstream_updates %q: repos = %v, want %q", mode, names, want)
		}
	}
}

// A host provisioned under the default keeps berth's drop-in listing every
// upstream repo; switching to manual removes it.
func TestUnattendedOriginsManualRemovesBerthFile(t *testing.T) {
	berthFile := bssh.Result{Stdout: string(upstreamDropIn(t))}
	cr := baseCheckWithOrigins(t, manualUpstreamServer(), berthFile, false)
	if cr.Satisfied {
		t.Errorf("Check satisfied with berth's drop-in present under manual: %+v", cr)
	}
	if !slices.Contains(cr.Changes, manualRemoveReason) {
		t.Errorf("Changes = %q, want an entry exactly %q", cr.Changes, manualRemoveReason)
	}

	o := baseApplyRunner()
	o.On(originsCat, berthFile)
	o.On("rm -f '/etc/apt/apt.conf.d/52berth-unattended-upgrades'", bssh.Result{})
	if err := SystemBase().Apply(context.Background(), provision.RunCtx{}, manualUpstreamServer(), o); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if eventIndex(o.events, "run:rm -f '/etc/apt/apt.conf.d/52berth-unattended-upgrades'") < 0 {
		t.Errorf("berth's drop-in was not removed; events:\n%s", strings.Join(o.events, "\n"))
	}
	for _, e := range o.events {
		if e == "run:"+aptConfigValidateCmd || e == "write:"+unattendedOriginsPath {
			t.Errorf("manual must not validate or write the drop-in: %q", e)
		}
	}
}

// A foreign file at the path is the operator's: manual leaves it alone, also
// with --force.
func TestUnattendedOriginsManualLeavesForeignFile(t *testing.T) {
	foreign := bssh.Result{Stdout: "// operator file\n"}
	for _, force := range []bool{false, true} {
		if cr := baseCheckWithOrigins(t, manualUpstreamServer(), foreign, force); !cr.Satisfied {
			t.Errorf("force=%v: Check unsatisfied on a foreign drop-in under manual: %+v", force, cr)
		}
		o := baseApplyRunner()
		o.On(originsCat, foreign)
		if err := SystemBase().Apply(context.Background(), provision.RunCtx{Force: force}, manualUpstreamServer(), o); err != nil {
			t.Fatalf("force=%v: Apply: %v", force, err)
		}
		assertOriginsUntouched(t, o, fmt.Sprintf("force=%v", force))
	}
}

func TestUnattendedOriginsManualAbsentIsSatisfied(t *testing.T) {
	absent := bssh.Result{ExitCode: 1}
	if cr := baseCheckWithOrigins(t, manualUpstreamServer(), absent, false); !cr.Satisfied {
		t.Errorf("Check unsatisfied with no drop-in under manual: %+v", cr)
	}
	o := baseApplyRunner()
	o.On(originsCat, absent)
	if err := SystemBase().Apply(context.Background(), provision.RunCtx{}, manualUpstreamServer(), o); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	assertOriginsUntouched(t, o, "absent")
	for _, w := range o.Writes() {
		if w.Path != autoUpgradesPath {
			t.Errorf("unexpected write under manual with no drop-in: %s", w.Path)
		}
	}
}

// assertInstalledWith fails unless the step issued exactly one package
// install and it is want. (FakeRunner already fails Apply on an unstubbed
// install command; this pins the count and names the command on failure.)
func assertInstalledWith(t *testing.T, f *bssh.FakeRunner, want string) {
	t.Helper()
	var got []string
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "apt-get install") {
			got = append(got, c.Cmd)
		}
	}
	if len(got) != 1 || got[0] != want {
		t.Errorf("package installs = %q, want exactly [%q]", got, want)
	}
}

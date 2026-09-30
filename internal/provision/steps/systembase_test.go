package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// debianOnlyServer selects no upstream repo: base's unattended-upgrades
// origins drop-in must then be ABSENT (or foreign, left alone).
func debianOnlyServer() *config.Server {
	return &config.Server{
		PHP:      config.PHP{Version: "8.4", Source: "auto"},
		Nginx:    config.Nginx{Source: "debian"},
		Database: config.Database{Engine: "mariadb", Source: "debian"},
	}
}

// upstreamServer selects Sury + nginx.org + MariaDB upstream (smoke.yml's mix).
func upstreamServer() *config.Server {
	return &config.Server{
		PHP:      config.PHP{Version: "8.5", Source: "sury"},
		Nginx:    config.Nginx{Source: "nginx"},
		Database: config.Database{Engine: "mariadb", Source: "mariadb"},
	}
}

// originsCat is the one read-only probe base issues for the drop-in (the
// managed-file classifier, managedFilePresent and assertManagedWritable all
// cat the same path).
var originsCat = "cat " + shQuote(unattendedOriginsPath)

// eventIndex is the position of entry in an orderedRunner event log, -1 if absent.
func eventIndex(events []string, entry string) int {
	for i, e := range events {
		if e == entry {
			return i
		}
	}
	return -1
}

func TestSystemBaseRequiresPreflight(t *testing.T) {
	if got := SystemBase().Requires(); len(got) != 1 || got[0] != "preflight" {
		t.Fatalf("Requires() = %v, want [preflight]", got)
	}
}

func TestSystemBaseCheckSatisfiedWhenAllInstalled(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	}
	want, err := renderAutoUpgrades()
	if err != nil {
		t.Fatal(err)
	}
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{Stdout: string(want), ExitCode: 0})
	f.On(originsCat, bssh.Result{ExitCode: 1})
	var cr provision.CheckResult
	cr, err = SystemBase().Check(context.Background(), provision.RunCtx{}, debianOnlyServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when all base packages present; got %+v", cr)
	}
}

func TestSystemBaseCheckAbortsOnUnmanagedAutoUpgrades(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	}
	f.On("dpkg -s git", bssh.Result{ExitCode: 1}) // a base package is missing
	// An unmanaged 20auto-upgrades already exists (no berth marker).
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{Stdout: "APT::Periodic::Unattended-Upgrade \"1\";\n", ExitCode: 0})
	f.On(originsCat, bssh.Result{ExitCode: 1})
	// Without --force: must abort (drift policy) EVEN THOUGH a package is missing.
	if _, err := SystemBase().Check(context.Background(), provision.RunCtx{}, debianOnlyServer(), f); err == nil {
		t.Error("expected abort on an unmanaged 20auto-upgrades even when a base package is missing")
	}
	// With --force: reconciles instead (no error, unsatisfied).
	cr, err := SystemBase().Check(context.Background(), provision.RunCtx{Force: true}, debianOnlyServer(), f)
	if err != nil {
		t.Fatalf("with --force expected no error; got %v", err)
	}
	if cr.Satisfied {
		t.Error("with --force on an unmanaged file, expected unsatisfied (will reconcile)")
	}
}

func TestSystemBaseCheckUnsatisfiedWhenMissing(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	}
	f.On("dpkg -s git", bssh.Result{ExitCode: 1})                    // git missing
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{ExitCode: 1}) // file absent (cat now runs even when a package is missing)
	f.On(originsCat, bssh.Result{ExitCode: 1})
	cr, err := SystemBase().Check(context.Background(), provision.RunCtx{}, debianOnlyServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when a base package is missing")
	}
}

func TestBasePackagesIncludeDeployerTools(t *testing.T) {
	// The deployer clones over git and uploads built assets over rsync; both must
	// be provisioned because a minimal Debian 13 ships neither.
	for _, want := range []string{"git", "rsync"} {
		found := false
		for _, p := range basePackages {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("basePackages must include %q (required by the deployer)", want)
		}
	}
}

func TestSystemBaseCheckUnsatisfiedWhenAutoUpgradesMissing(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	}
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{ExitCode: 1}) // periodic file absent
	f.On(originsCat, bssh.Result{ExitCode: 1})
	cr, err := SystemBase().Check(context.Background(), provision.RunCtx{}, debianOnlyServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the 20auto-upgrades periodic file is absent")
	}
}

func TestSystemBaseApplyInstallsAndConfigures(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(basePackages, " "), bssh.Result{})
	f.On("systemctl enable --now unattended-upgrades", bssh.Result{})
	f.On(originsCat, bssh.Result{ExitCode: 1})
	if err := SystemBase().Apply(context.Background(), provision.RunCtx{}, debianOnlyServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var saw []string
	for _, c := range f.Calls() {
		saw = append(saw, c.Cmd)
	}
	joined := strings.Join(saw, "\n")
	for _, want := range []string{"apt-get install -y", "systemctl enable --now unattended-upgrades"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
	var auto *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == autoUpgradesPath {
			auto = &f.Writes()[i]
		}
	}
	if auto == nil {
		t.Fatalf("Apply must write the managed %s periodic config", autoUpgradesPath)
	}
	if !strings.HasPrefix(string(auto.Content), "# managed by berth") {
		t.Errorf("%s content must start with the managed marker", autoUpgradesPath)
	}
	if auto.Owner != "root" || auto.Group != "root" || auto.Mode != 0o644 || !auto.Sudo {
		t.Errorf("unexpected FileSpec for %s: %+v", autoUpgradesPath, *auto)
	}
}

// stockEnabled is a LOCAL copy of the debconf-written "enabled" bytes (docker-
// verified against debian:trixie). Deliberately not stockAutoUpgrades[0]: the
// test must prove the REAL Debian bytes are allowlisted, not that whatever is
// allowlisted adopts itself.
const stockEnabled = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"

func TestSystemBaseCheckAdoptsStockAutoUpgrades(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	}
	// The exact debconf-written stock file (no berth marker) ships on
	// Debian/OVH images; it must be ADOPTED: unsatisfied, no error, no --force.
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{Stdout: stockEnabled, ExitCode: 0})
	f.On(originsCat, bssh.Result{ExitCode: 1})
	cr, err := SystemBase().Check(context.Background(), provision.RunCtx{}, debianOnlyServer(), f)
	if err != nil {
		t.Fatalf("the stock image file must be adopted without --force; got %v", err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied (adoption rewrites the managed file on Apply)")
	}
}

func TestSystemBaseCheckStillAbortsOnDisabledVariant(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	}
	// The "0" values are an explicit operator choice (auto-upgrades OFF):
	// adoption must NOT apply — abort unless --force, like any foreign file.
	disabled := "APT::Periodic::Update-Package-Lists \"0\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n"
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{Stdout: disabled, ExitCode: 0})
	f.On(originsCat, bssh.Result{ExitCode: 1})
	if _, err := SystemBase().Check(context.Background(), provision.RunCtx{}, debianOnlyServer(), f); err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("the disabled variant must keep aborting without --force; got %v", err)
	}
}

func TestSystemBaseCheckUnattendedOrigins(t *testing.T) {
	want, err := renderUnattendedOrigins([]apt.Repo{apt.Sury(), apt.NginxOrg(), apt.MariaDBOrg()})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name          string
		srv           *config.Server
		cat           bssh.Result
		force         bool
		wantSatisfied bool
		wantErr       bool
		wantChange    string
	}{
		{"upstream, up to date", upstreamServer(), bssh.Result{Stdout: string(want)}, false, true, false, ""},
		{"upstream, absent", upstreamServer(), bssh.Result{ExitCode: 1}, false, false, false, "write " + unattendedOriginsPath},
		{"upstream, drifted", upstreamServer(), bssh.Result{Stdout: "# managed by berth\n// old\n"}, false, false, false, "write " + unattendedOriginsPath},
		{"upstream, foreign, no force", upstreamServer(), bssh.Result{Stdout: "// operator file\n"}, false, false, true, ""},
		{"upstream, foreign, force", upstreamServer(), bssh.Result{Stdout: "// operator file\n"}, true, false, false, "write " + unattendedOriginsPath},
		{"debian, berth file lingers", debianOnlyServer(), bssh.Result{Stdout: string(want)}, false, false, false, "remove " + unattendedOriginsPath},
		{"debian, absent", debianOnlyServer(), bssh.Result{ExitCode: 1}, false, true, false, ""},
		{"debian, foreign", debianOnlyServer(), bssh.Result{Stdout: "// operator file\n"}, false, true, false, ""},
		{"debian, foreign, force", debianOnlyServer(), bssh.Result{Stdout: "// operator file\n"}, true, true, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			for _, pkg := range basePackages {
				f.On("dpkg -s "+pkg, bssh.Result{Stdout: "Status: install ok installed\n"})
			}
			auto, err := renderAutoUpgrades()
			if err != nil {
				t.Fatal(err)
			}
			f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{Stdout: string(auto)})
			f.On(originsCat, c.cat)
			cr, err := SystemBase().Check(context.Background(), provision.RunCtx{Force: c.force}, c.srv, f)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected an error for a foreign drop-in without --force")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cr.Satisfied != c.wantSatisfied {
				t.Errorf("Satisfied = %v, want %v (%+v)", cr.Satisfied, c.wantSatisfied, cr)
			}
			if c.wantChange != "" && !strings.Contains(strings.Join(cr.Changes, "\n"), c.wantChange) {
				t.Errorf("Changes = %v, want one containing %q", cr.Changes, c.wantChange)
			}
			for _, call := range f.Calls() {
				if !strings.HasPrefix(call.Cmd, "dpkg -s ") && !strings.HasPrefix(call.Cmd, "cat ") {
					t.Errorf("Check issued a non-probe command: %q", call.Cmd)
				}
			}
		})
	}
}

// The drop-in is evaluated even when base packages are missing (the
// unconditional-evaluation rule 20auto-upgrades already follows).
func TestSystemBaseCheckEvaluatesOriginsWhenPackagesMissing(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 1})
	}
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{ExitCode: 1})
	f.On(originsCat, bssh.Result{Stdout: "// operator file\n"})
	if _, err := SystemBase().Check(context.Background(), provision.RunCtx{}, upstreamServer(), f); err == nil {
		t.Error("a foreign drop-in must abort Check even while base packages are missing")
	}
}

func TestSystemBaseCheckSurfacesUpstreamErrors(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{Stdout: "Status: install ok installed\n"})
	}
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{ExitCode: 1})
	s := debianOnlyServer()
	s.PHP = config.PHP{Version: "8.5", Source: "debian"}
	if _, err := SystemBase().Check(context.Background(), provision.RunCtx{}, s, f); err == nil || !strings.Contains(err.Error(), "cannot provide 8.5") {
		t.Errorf("err = %v, want useSury's error surfaced", err)
	}
}

func baseApplyRunner() *orderedRunner {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(basePackages, " "), bssh.Result{})
	f.On("systemctl enable --now unattended-upgrades", bssh.Result{})
	return &orderedRunner{FakeRunner: f}
}

func upstreamDropIn(t *testing.T) []byte {
	t.Helper()
	want, err := renderUnattendedOrigins([]apt.Repo{apt.Sury(), apt.NginxOrg(), apt.MariaDBOrg()})
	if err != nil {
		t.Fatal(err)
	}
	return want
}

// Validation happens before publication, on the exact bytes that are then
// published — for a fresh write, a drift rewrite and a --force adoption of a
// foreign file alike.
func TestSystemBaseApplyValidatesOriginsBeforePublishing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cat   bssh.Result
		force bool
	}{
		{"absent", bssh.Result{ExitCode: 1}, false},
		{"drifted", bssh.Result{Stdout: "# managed by berth\n// old\n"}, false},
		{"foreign adopted with --force", bssh.Result{Stdout: "// operator file\n"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := baseApplyRunner()
			o.On(originsCat, tc.cat)
			o.On(aptConfigValidateCmd, bssh.Result{})
			if err := SystemBase().Apply(context.Background(), provision.RunCtx{Force: tc.force}, upstreamServer(), o); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			want := upstreamDropIn(t)
			validate := eventIndex(o.events, "run:"+aptConfigValidateCmd)
			publish := eventIndex(o.events, "write:"+unattendedOriginsPath)
			if validate < 0 || publish < 0 || validate > publish {
				t.Fatalf("want validate before publish, got %d / %d; events:\n%s", validate, publish, strings.Join(o.events, "\n"))
			}
			for _, c := range o.Calls() {
				if c.Cmd == aptConfigValidateCmd && string(c.Stdin) != string(want) {
					t.Errorf("validated bytes differ from the rendered drop-in:\n%s", c.Stdin)
				}
			}
			for _, w := range o.Writes() {
				if w.Path == unattendedOriginsPath {
					if string(w.Content) != string(want) {
						t.Errorf("published bytes differ from the validated drop-in")
					}
					if w.Owner != "root" || w.Group != "root" || w.Mode != 0o644 || !w.Sudo {
						t.Errorf("unexpected FileSpec: %+v", w)
					}
				}
			}
		})
	}
}

// A rejected candidate, or a transport failure/cancellation during validation,
// publishes nothing: the previous file (here: a drifted berth file) stays.
func TestSystemBaseApplyRejectedOriginsAreNotPublished(t *testing.T) {
	for _, tc := range []struct {
		name    string
		stub    func(o *orderedRunner)
		wantErr string
	}{
		{"apt-config rejects", func(o *orderedRunner) {
			o.On(aptConfigValidateCmd, bssh.Result{ExitCode: 100, Stderr: "E: Syntax error /var/lib/berth/unattended-upgrades.x:3: Extra junk"})
		}, "Syntax error"},
		{"transport fails", func(o *orderedRunner) {
			o.OnError(aptConfigValidateCmd, context.Canceled)
		}, context.Canceled.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := baseApplyRunner()
			o.On(originsCat, bssh.Result{Stdout: "# managed by berth\n// previous\n"})
			tc.stub(o)
			err := SystemBase().Apply(context.Background(), provision.RunCtx{}, upstreamServer(), o)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
			}
			for _, e := range o.events {
				if e == "write:"+unattendedOriginsPath || strings.HasPrefix(e, "run:rm ") {
					t.Errorf("the previous drop-in was touched after failed validation: %q", e)
				}
			}
		})
	}
}

func TestSystemBaseApplyRefusesForeignOriginsWithoutForce(t *testing.T) {
	o := baseApplyRunner()
	o.On(originsCat, bssh.Result{Stdout: "// operator file\n"})
	if err := SystemBase().Apply(context.Background(), provision.RunCtx{}, upstreamServer(), o); err == nil {
		t.Fatal("expected refusal of a foreign drop-in without --force")
	}
	if eventIndex(o.events, "run:"+aptConfigValidateCmd) >= 0 {
		t.Error("nothing may be validated/staged once the target is known to be foreign")
	}
}

func TestSystemBaseApplyRemovesOwnOriginsWhenNoUpstream(t *testing.T) {
	o := baseApplyRunner()
	o.On(originsCat, bssh.Result{Stdout: "# managed by berth\nUnattended-Upgrade::Origins-Pattern {\n};\n"})
	o.On("rm -f "+shQuote(unattendedOriginsPath), bssh.Result{})
	if err := SystemBase().Apply(context.Background(), provision.RunCtx{}, debianOnlyServer(), o); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if eventIndex(o.events, "run:rm -f "+shQuote(unattendedOriginsPath)) < 0 {
		t.Errorf("berth's own drop-in was not removed; events:\n%s", strings.Join(o.events, "\n"))
	}
}

func TestSystemBaseApplyLeavesForeignOriginsWhenNoUpstream(t *testing.T) {
	for _, force := range []bool{false, true} {
		o := baseApplyRunner()
		o.On(originsCat, bssh.Result{Stdout: "// operator file\n"})
		if err := SystemBase().Apply(context.Background(), provision.RunCtx{Force: force}, debianOnlyServer(), o); err != nil {
			t.Fatalf("force=%v: Apply: %v", force, err)
		}
		for _, e := range o.events {
			if strings.Contains(e, unattendedOriginsPath) && e != "run:"+originsCat {
				t.Errorf("force=%v: a foreign drop-in was touched: %q", force, e)
			}
		}
	}
}

// While the drop-in is missing or drifted, base is unsatisfied and `--only
// php` refuses on it; once base has converged (the file reads up to date) the
// same `--only php` is admitted. base's own Apply success is covered by the
// Apply tests above; this pins the gate's dependence on the drop-in state.
func TestOnlyPHPGatedOnOriginsDropIn(t *testing.T) {
	auto, err := renderAutoUpgrades()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		cat       bssh.Result
		wantAdmit bool
	}{
		{"missing", bssh.Result{ExitCode: 1}, false},
		{"drifted", bssh.Result{Stdout: "# managed by berth\n// old\n"}, false},
		{"converged", bssh.Result{Stdout: string(upstreamDropIn(t))}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			for _, pkg := range basePackages {
				f.On("dpkg -s "+pkg, bssh.Result{Stdout: "Status: install ok installed\n"})
			}
			f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{Stdout: string(auto)})
			f.On(originsCat, tc.cat)
			// Preflight must be registered: base requires it, and an
			// UNREGISTERED prerequisite counts as missing ("(undefined)").
			// It is AlwaysRun, so the gate never Checks it.
			eng := provision.New(Preflight(), SystemBase(), PHP())
			ctx, cancel := context.WithCancel(context.Background())
			events, err := eng.Run(ctx, upstreamServer(), f, provision.Options{Only: "php"})
			if !tc.wantAdmit {
				if err == nil || !strings.Contains(err.Error(), "unmet prerequisites: [base]") {
					t.Fatalf("err = %v, want exactly `unmet prerequisites: [base]`", err)
				}
				cancel()
				return
			}
			if err != nil {
				t.Fatalf("a converged base must admit --only php: %v", err)
			}
			cancel() // stop execution; only admission is under test
			for range events {
			}
		})
	}
}

package steps

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestNginxRequiresBase(t *testing.T) {
	if got := Nginx().Requires(); len(got) != 1 || got[0] != "base" {
		t.Fatalf("Requires() = %v, want [base]", got)
	}
}

// stubDefaultsAbsent makes both stock catch-all sites read back as absent, so
// Check's "defaults disabled" probe is satisfied.
func stubDefaultsAbsent(f *bssh.FakeRunner) {
	f.On("test -e "+shQuote(debianDefaultSite), bssh.Result{ExitCode: 1})
	f.On("test -e "+shQuote(nginxOrgDefaultConf), bssh.Result{ExitCode: 1})
}

// stubNginxRepoAbsent makes the nginx.org source-list probe read back as
// absent: the debian-source paths (ownRepoLingers) see nothing to sweep, and
// the nginx-source Apply path (ensureOwnRepo) proceeds to the full EnsureRepo
// chain.
func stubNginxRepoAbsent(f *bssh.FakeRunner) {
	f.On("cat "+shQuote(apt.NginxOrg().SourceListPath()), bssh.Result{ExitCode: 1})
}

// stubNginxRepoConverged makes the nginx.org repo probes read back converged
// (managed byte-exact list + keyring holding exactly the pinned key), so
// ownRepoUpToDate is satisfied and ensureOwnRepo skips EnsureRepo.
func stubNginxRepoConverged(t *testing.T, f *bssh.FakeRunner) {
	t.Helper()
	repo := apt.NginxOrg()
	f.On("cat "+shQuote(repo.SourceListPath()), bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, repo))})
	f.On("gpg --no-options --no-keyring --trust-model always --show-keys --with-colons "+repo.KeyringPath(), bssh.Result{ExitCode: 0, Stdout: gpgColonsFor(repo.Fingerprint)})
}

// stubEnsureRepoChain stubs apt.EnsureRepo's full command sequence for repo:
// key trust via the /run/berth staging files (the staging keyring ends up
// holding exactly the pinned primary key), the keyring install, the index
// refresh and the single-source index verification.
func stubEnsureRepoChain(f *bssh.FakeRunner, repo apt.Repo) {
	tmpKey := "/run/berth/key-" + repo.Name
	tmpRing := "/run/berth/keyring-" + repo.Name + ".gpg"
	tmpOut := "/run/berth/pinned-" + repo.Name + ".gpg"
	f.On("install -d -m 700 /run/berth", bssh.Result{})
	f.On("curl -fsSL -o "+tmpKey+" -- "+shQuote(repo.KeyURL), bssh.Result{})
	f.On("gpg --yes -o "+tmpRing+" --dearmor "+tmpKey, bssh.Result{})
	f.On("gpg --no-default-keyring --keyring "+tmpRing+" --yes -o "+tmpOut+" --export "+repo.Fingerprint, bssh.Result{})
	f.On("gpg --show-keys --with-colons "+tmpOut, bssh.Result{Stdout: gpgColonsFor(repo.Fingerprint)})
	f.On("install -m 0644 "+tmpOut+" "+repo.KeyringPath(), bssh.Result{})
	f.On("rm -f "+tmpKey+" "+tmpRing+" "+tmpOut, bssh.Result{})
	f.On("apt-get update", bssh.Result{})
	f.On(fmt.Sprintf("apt-get update -o Dir::Etc::sourcelist=sources.list.d/%s.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any", repo.Name), bssh.Result{})
}

// stubNginxApplyTail stubs the tail of Apply: disabling the stock defaults,
// the validate+reload that follows, and the reload-stamp bookkeeping around
// them (invalidate up front, mark after the successful reload). Apply always
// probes the nginx.org source list first (ensureOwnRepo/removeOwnRepo); the
// default here is absent — tests exercising a converged or lingering repo
// override that stub after calling this.
func stubNginxApplyTail(f *bssh.FakeRunner) {
	stubNginxRepoAbsent(f)
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})
	f.On("rm -f "+shQuote(debianDefaultSite), bssh.Result{})
	f.On(fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(nginxOrgDefaultConf)), bssh.Result{})
	f.On("nginx -t", bssh.Result{})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0}) // running → graceful reload
	f.On("systemctl reload nginx", bssh.Result{})
	f.On(markReloadedCmd("nginx"), bssh.Result{})
}

func TestNginxCheckSatisfiedWhenInstalledAndUp(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	stubDefaultsAbsent(f)
	stubNginxRepoAbsent(f)
	f.On(reloadedSinceCmd("nginx", nginxConfPath), bssh.Result{}) // stamp fresh
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when nginx installed, running, defaults disabled; got %+v", cr)
	}
}

func TestNginxCheckUnsatisfiedWhenConfNewerThanStamp(t *testing.T) {
	// A crash between Apply's core-config writes and its reload leaves the
	// daemon on the old config while every byte-level probe reads converged —
	// only the reload stamp catches it.
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	stubDefaultsAbsent(f)
	stubNginxRepoAbsent(f)
	f.On(reloadedSinceCmd("nginx", nginxConfPath), bssh.Result{ExitCode: 1})
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("nginx.conf newer than the reload stamp must be unsatisfied (written but not reloaded)")
	}
}

func TestNginxCheckUnsatisfiedWhenNotInstalled(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 1})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	stubDefaultsAbsent(f)
	stubNginxRepoAbsent(f)
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when nginx is not installed")
	}
}

func TestNginxCheckUnsatisfiedWhenNotRunning(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 3}) // inactive
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	stubDefaultsAbsent(f)
	stubNginxRepoAbsent(f)
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when nginx is not active")
	}
}

func TestNginxCheckUnsatisfiedWhenDefaultSiteEnabled(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	// The Debian default catch-all is still enabled.
	f.On("test -e "+shQuote(debianDefaultSite), bssh.Result{ExitCode: 0})
	f.On("test -e "+shQuote(nginxOrgDefaultConf), bssh.Result{ExitCode: 1})
	stubNginxRepoAbsent(f)
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while the stock default site is still enabled")
	}
}

func TestNginxApplyDisablesStockDefaults(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("systemctl enable nginx", bssh.Result{})
	stubNginxApplyTail(f)
	if err := Nginx().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var sawRm, sawRename bool
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote(debianDefaultSite) {
			sawRm = true
		}
		if strings.Contains(c.Cmd, "mv -f "+shQuote(nginxOrgDefaultConf)) {
			sawRename = true
		}
	}
	if !sawRm {
		t.Error("Apply must remove the Debian default-site symlink")
	}
	if !sawRename {
		t.Error("Apply must rename nginx.org's conf.d/default.conf")
	}
}

func TestNginxCheckSourceNginxRequiresRepo(t *testing.T) {
	s := &config.Server{Nginx: config.Nginx{Source: "nginx"}}
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	stubDefaultsAbsent(f)
	// Worker user reconciled, bridge managed and stamp fresh (so only the repo
	// gates this test). source=nginx probes the bridge file too.
	f.On("grep -qE '^[[:space:]]*user[[:space:]]+www-data;' "+nginxConfPath, bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(nginxBridgePath), bssh.Result{ExitCode: 0, Stdout: string(nginxBridgeContent())})
	f.On(reloadedSinceCmd("nginx", nginxConfPath, nginxBridgePath), bssh.Result{})
	// nginx.org repo not yet registered -> not satisfied even though nginx runs.
	stubNginxRepoAbsent(f)
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("source=nginx must be unsatisfied until the nginx.org repo is registered")
	}
	// Once the repo is converged (managed list + exact keyring), it is satisfied.
	stubNginxRepoConverged(t, f)
	cr, err = Nginx().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("source=nginx with repo present should be satisfied; got %+v", cr)
	}
}

func TestNginxCheckUnsatisfiedWhenBridgeMissingOrForeign(t *testing.T) {
	// source=nginx: without the conf.d bridge nginx.org's nginx never loads
	// sites-enabled/, so Check must flag a missing bridge (Apply rewrites it)
	// and hard-error on a foreign one (abort-unless---force contract).
	s := &config.Server{Nginx: config.Nginx{Source: "nginx"}}
	stubs := func(bridge bssh.Result) *bssh.FakeRunner {
		f := bssh.NewFakeRunner()
		f.On("dpkg -s nginx", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
		f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
		f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
		stubDefaultsAbsent(f)
		f.On("grep -qE '^[[:space:]]*user[[:space:]]+www-data;' "+nginxConfPath, bssh.Result{ExitCode: 0})
		stubNginxRepoConverged(t, f)
		f.On("cat "+shQuote(nginxBridgePath), bridge)
		return f
	}

	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, s, stubs(bssh.Result{ExitCode: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a missing sites bridge must be unsatisfied (site server blocks would never load)")
	}

	_, err = Nginx().Check(context.Background(), provision.RunCtx{}, s, stubs(bssh.Result{ExitCode: 0, Stdout: "include /srv/legacy/*.conf;\n"}))
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal for a foreign bridge", err)
	}
}

func TestNginxApplyRefusesForeignSitesBridge(t *testing.T) {
	// A hand-written /etc/nginx/conf.d/berth-sites.conf (no marker) must not be
	// clobbered by Apply without --force.
	s := &config.Server{Nginx: config.Nginx{Source: "nginx"}}
	f := bssh.NewFakeRunner()
	stubNginxRepoConverged(t, f) // repo converged: ensureOwnRepo skips EnsureRepo
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{}) // stamp invalidation up front
	f.On("install -d /etc/nginx/sites-available /etc/nginx/sites-enabled", bssh.Result{})
	f.On("cat "+shQuote("/etc/nginx/conf.d/berth-sites.conf"), bssh.Result{ExitCode: 0, Stdout: "include /srv/legacy/*.conf;\n"}) // foreign

	err := Nginx().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	for _, w := range f.Writes() {
		if w.Path == "/etc/nginx/conf.d/berth-sites.conf" {
			t.Error("a foreign sites bridge must not be overwritten without --force")
		}
	}
}

func TestNginxApplySourceNginxAddsRepoAndBridge(t *testing.T) {
	s := &config.Server{Nginx: config.Nginx{Source: "nginx"}}
	f := bssh.NewFakeRunner()
	// The source list reads back absent (stubNginxApplyTail), so ensureOwnRepo
	// runs the full EnsureRepo chain.
	stubEnsureRepoChain(f, apt.NginxOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("install -d /etc/nginx/sites-available /etc/nginx/sites-enabled", bssh.Result{})
	f.On("cat "+shQuote("/etc/nginx/conf.d/berth-sites.conf"), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sed -ri 's|^[[:space:]]*user[[:space:]]+[^;]*;|user  www-data;|' "+nginxConfPath, bssh.Result{})
	f.On("systemctl enable nginx", bssh.Result{})
	stubNginxApplyTail(f)
	if err := Nginx().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "nginx.org/keys/nginx_signing.key") {
		t.Errorf("source=nginx must fetch the nginx.org signing key; calls:\n%s", joined)
	}
	if !strings.Contains(joined, "user  www-data;") {
		t.Errorf("source=nginx must reconcile the worker user to www-data; calls:\n%s", joined)
	}
	// The conf.d bridge must be written so the site step's server blocks load.
	var bridgeWritten, sourceListWritten bool
	for _, w := range f.Writes() {
		if w.Path == "/etc/nginx/conf.d/berth-sites.conf" {
			bridgeWritten = true
		}
		if w.Path == apt.NginxOrg().SourceListPath() {
			sourceListWritten = true
		}
	}
	if !bridgeWritten {
		t.Error("expected the conf.d sites bridge to be written for source=nginx")
	}
	if !sourceListWritten {
		t.Error("expected the nginx-org apt source list to be written")
	}
}

func TestNginxApplyInvalidatesBeforeMutationAndStampsAfterReload(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("systemctl enable nginx", bssh.Result{})
	stubNginxApplyTail(f)
	if err := Nginx().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idx := func(want string) int {
		for i, c := range f.Calls() {
			if c.Cmd == want {
				return i
			}
		}
		return -1
	}
	// apt itself can mutate nginx's config (conffiles, maintainer scripts), so
	// the stamp must be invalidated BEFORE the package transaction — not just
	// before the first config mutation this step performs itself.
	invalidate := idx("rm -f " + shQuote("/var/lib/berth/nginx.reloaded"))
	install := idx("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx")
	firstMutation := idx("rm -f " + shQuote(debianDefaultSite))
	reload := idx("systemctl reload nginx")
	mark := idx(markReloadedCmd("nginx"))
	if invalidate < 0 || install < 0 || invalidate > install {
		t.Errorf("nginx stamp must be invalidated BEFORE the apt install; rm=%d install=%d", invalidate, install)
	}
	if firstMutation < 0 || invalidate > firstMutation {
		t.Errorf("nginx stamp must be invalidated BEFORE the stock-default removal; rm=%d mutation=%d", invalidate, firstMutation)
	}
	if mark < 0 || reload < 0 || reload > mark {
		t.Errorf("nginx stamp must be recorded AFTER systemctl reload nginx; reload=%d mark=%d", reload, mark)
	}
}

// stubNginxApplyUpToValidate stubs Apply's prefix through the stock-default
// removal, leaving nginx -t (and everything after) to the caller. The
// nginx.org source-list probe reads back absent (nothing to sweep).
func stubNginxApplyUpToValidate(f *bssh.FakeRunner) {
	stubNginxRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("systemctl enable nginx", bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})
	f.On("rm -f "+shQuote(debianDefaultSite), bssh.Result{})
	f.On(fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(nginxOrgDefaultConf)), bssh.Result{})
}

func TestNginxApplyDefersUnitValidationFailureToSite(t *testing.T) {
	// nginx -t validates the WHOLE unit and this step's own writes are fixed,
	// known-good content — a failure is a vhost owned by the LATER site step
	// (or a foreign file). Defer: warn, skip start/reload/stamp, return nil so
	// the pipeline reaches site, which re-renders its vhosts, validates and
	// reloads. No differential here: removing the sites bridge would unload
	// sites-enabled/* and misattribute a vhost fault to berth's own file.
	// Enablement runs BEFORE -t and without --now: with a dead nginx and a
	// broken vhost, `enable --now` would fail on the start and never reach
	// this deferral (the old deadlock).
	f := bssh.NewFakeRunner()
	stubNginxApplyUpToValidate(f)
	f.On("nginx -t", bssh.Result{ExitCode: 1, Stderr: "unexpected end of file"})
	// is-active/start/reload/stamp intentionally NOT stubbed.

	var warned []string
	rc := provision.RunCtx{FullRun: true, Warn: func(msg string) { warned = append(warned, msg) }}
	if err := Nginx().Apply(context.Background(), rc, &config.Server{}, f); err != nil {
		t.Fatalf("a unit validation failure must defer to site, not fail: %v", err)
	}
	if len(warned) != 1 {
		t.Fatalf("want exactly one warning, got %q", warned)
	}
	for _, want := range []string{"unexpected end of file", "/etc/nginx/sites-available/", "site step"} {
		if !strings.Contains(warned[0], want) {
			t.Errorf("warning %q must contain %q", warned[0], want)
		}
	}
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "systemctl enable --now nginx", "systemctl start nginx",
			"systemctl is-active nginx", "systemctl reload nginx", markReloadedCmd("nginx"):
			t.Errorf("%q must not run when validation failed and the reload is deferred", c.Cmd)
		}
	}
}

func TestNginxApplyUnderOnlyFailsHardOnValidationFailure(t *testing.T) {
	// Under --only (FullRun=false) site never runs, so deferring would report
	// Applied and exit 0 while nginx keeps serving the old config.
	f := bssh.NewFakeRunner()
	stubNginxApplyUpToValidate(f)
	f.On("nginx -t", bssh.Result{ExitCode: 1, Stderr: "unexpected end of file"})

	var warned []string
	rc := provision.RunCtx{FullRun: false, Warn: func(msg string) { warned = append(warned, msg) }}
	err := Nginx().Apply(context.Background(), rc, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), "nginx -t failed") {
		t.Fatalf("err = %v, want the nginx -t failure", err)
	}
	for _, want := range []string{"/etc/nginx/sites-available/", "full provision"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}
	if len(warned) != 0 {
		t.Errorf("no warning under --only, got %q", warned)
	}
}

func TestNginxApplyStartsInactiveNginxAfterValidation(t *testing.T) {
	// A dead nginx with a VALID config must be started (not reloaded), and
	// only after -t passed — never before validation.
	f := bssh.NewFakeRunner()
	stubNginxApplyUpToValidate(f)
	f.On("nginx -t", bssh.Result{})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 3}) // dead
	f.On("systemctl start nginx", bssh.Result{})
	f.On(markReloadedCmd("nginx"), bssh.Result{})

	if err := Nginx().Apply(context.Background(), provision.RunCtx{FullRun: true}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idx := func(want string) int {
		for i, c := range f.Calls() {
			if c.Cmd == want {
				return i
			}
		}
		return -1
	}
	enable, validate, start, mark := idx("systemctl enable nginx"), idx("nginx -t"), idx("systemctl start nginx"), idx(markReloadedCmd("nginx"))
	if enable < 0 || validate < 0 || start < 0 || mark < 0 {
		t.Fatalf("missing calls: enable=%d -t=%d start=%d mark=%d\n%+v", enable, validate, start, mark, f.Calls())
	}
	if !(enable < validate && validate < start && start < mark) {
		t.Errorf("order must be enable → -t → start → mark; got enable=%d -t=%d start=%d mark=%d", enable, validate, start, mark)
	}
	if idx("systemctl reload nginx") >= 0 {
		t.Error("a freshly started nginx must not also be reloaded")
	}
}

func TestNginxApplyInstallsAndEnables(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("systemctl enable nginx", bssh.Result{})
	stubNginxApplyTail(f)
	if err := Nginx().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"apt-get install -y nginx", "systemctl enable nginx"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

func TestNginxCheckDebianSourceFlagsLingeringRepo(t *testing.T) {
	// Stock source with a berth-managed nginx.org list left over from an
	// earlier upstream provision: drift, Apply removes it (E1).
	repo := apt.NginxOrg()
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	stubDefaultsAbsent(f)
	f.On("cat "+shQuote(repo.SourceListPath()), bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, repo))})
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a lingering berth-owned nginx.org repo under the stock source must be unsatisfied")
	}
	if !strings.Contains(cr.Reason, "lingering") {
		t.Errorf("Reason = %q, want it to mention the lingering repo", cr.Reason)
	}
}

func TestNginxApplyDebianSourceRemovesLingeringRepo(t *testing.T) {
	repo := apt.NginxOrg()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("systemctl enable nginx", bssh.Result{})
	stubNginxApplyTail(f)
	// Override the tail's absent default: the list is a berth-managed leftover,
	// so removeOwnRepo sweeps list + keyring and refreshes the indexes.
	f.On("cat "+shQuote(repo.SourceListPath()), bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, repo))})
	f.On("rm -f "+repo.SourceListPath()+" "+repo.KeyringPath(), bssh.Result{ExitCode: 0})
	f.On("apt-get update", bssh.Result{ExitCode: 0})

	var warns []string
	rc := provision.RunCtx{Warn: func(msg string) { warns = append(warns, msg) }}
	if err := Nginx().Apply(context.Background(), rc, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var sawRm, sawUpdate bool
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+repo.SourceListPath()+" "+repo.KeyringPath() {
			sawRm = true
		}
		if c.Cmd == "apt-get update" {
			sawUpdate = true
		}
	}
	if !sawRm {
		t.Error("Apply must remove the lingering berth-owned source list and keyring")
	}
	if !sawUpdate {
		t.Error("Apply must refresh the apt indexes after removing the repo")
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "upstream versions") {
		t.Fatalf("want one upstream-versions warning, got %v", warns)
	}
}

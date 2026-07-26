package steps

import (
	"context"
	"fmt"
	"strings"
	"testing"

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

// stubNginxApplyTail stubs the tail of Apply: disabling the stock defaults,
// the validate+reload that follows, and the reload-stamp bookkeeping around
// them (invalidate up front, mark after the successful reload).
func stubNginxApplyTail(f *bssh.FakeRunner) {
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})
	f.On("rm -f "+shQuote(debianDefaultSite), bssh.Result{})
	f.On(fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(nginxOrgDefaultConf)), bssh.Result{})
	f.On("nginx -t", bssh.Result{})
	f.On("systemctl reload nginx", bssh.Result{})
	f.On(markReloadedCmd("nginx"), bssh.Result{})
}

func TestNginxCheckSatisfiedWhenInstalledAndUp(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	stubDefaultsAbsent(f)
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
	f.On("systemctl enable --now nginx", bssh.Result{})
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
	f.On("test -e "+shQuote(nginxOrgSourceList), bssh.Result{ExitCode: 1})
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("source=nginx must be unsatisfied until the nginx.org repo is registered")
	}
	// Once the repo file exists, it is satisfied.
	f.On("test -e "+shQuote(nginxOrgSourceList), bssh.Result{ExitCode: 0})
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
		f.On("test -e "+shQuote(nginxOrgSourceList), bssh.Result{ExitCode: 0})
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
	stubRepoKeyTrust(f, "nginx-org", "https://nginx.org/keys/nginx_signing.key", "8540A6F18833A80E9C1653A42FD21310B49F6B46")
	f.On("apt-get update", bssh.Result{})
	f.On("apt-get update -o Dir::Etc::sourcelist=sources.list.d/nginx-org.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any", bssh.Result{ExitCode: 0})
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
	stubRepoKeyTrust(f, "nginx-org", "https://nginx.org/keys/nginx_signing.key", "8540A6F18833A80E9C1653A42FD21310B49F6B46")
	f.On("apt-get update", bssh.Result{})
	f.On("apt-get update -o Dir::Etc::sourcelist=sources.list.d/nginx-org.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any", bssh.Result{ExitCode: 0})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("install -d /etc/nginx/sites-available /etc/nginx/sites-enabled", bssh.Result{})
	f.On("cat "+shQuote("/etc/nginx/conf.d/berth-sites.conf"), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sed -ri 's|^[[:space:]]*user[[:space:]]+[^;]*;|user  www-data;|' "+nginxConfPath, bssh.Result{})
	f.On("systemctl enable --now nginx", bssh.Result{})
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
		if w.Path == nginxOrgSourceList {
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
	f.On("systemctl enable --now nginx", bssh.Result{})
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

func TestNginxApplyTestFailureNamesSitesAvailable(t *testing.T) {
	// nginx -t validates the WHOLE unit, so the failure may be a vhost owned by
	// the LATER site step — the error must point the operator there, and no
	// reload or stamp may follow.
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("systemctl enable --now nginx", bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})
	f.On("rm -f "+shQuote(debianDefaultSite), bssh.Result{})
	f.On(fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(nginxOrgDefaultConf)), bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 1, Stderr: "unexpected end of file"})
	// systemctl reload nginx and the stamp mark intentionally NOT stubbed.

	err := Nginx().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), "nginx -t failed") {
		t.Fatalf("err = %v, want the nginx -t failure", err)
	}
	if !strings.Contains(err.Error(), "/etc/nginx/sites-available/") {
		t.Errorf("err = %v, want a remediation hint naming the vhost directory", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl reload nginx" || c.Cmd == markReloadedCmd("nginx") {
			t.Errorf("%q must not run after a failed nginx -t", c.Cmd)
		}
	}
}

func TestNginxApplyInstallsAndEnables(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("systemctl enable --now nginx", bssh.Result{})
	stubNginxApplyTail(f)
	if err := Nginx().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"apt-get install -y nginx", "systemctl enable --now nginx"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

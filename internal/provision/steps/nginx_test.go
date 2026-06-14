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

// stubNginxApplyTail stubs the tail of Apply: disabling the stock defaults and
// the validate+reload that follows.
func stubNginxApplyTail(f *bssh.FakeRunner) {
	f.On("rm -f "+shQuote(debianDefaultSite), bssh.Result{})
	f.On(fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(nginxOrgDefaultConf)), bssh.Result{})
	f.On("nginx -t", bssh.Result{})
	f.On("systemctl reload nginx", bssh.Result{})
}

func TestNginxCheckSatisfiedWhenInstalledAndUp(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	stubDefaultsAbsent(f)
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when nginx installed, running, defaults disabled; got %+v", cr)
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
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0})
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
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0})
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
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	stubDefaultsAbsent(f)
	// Worker user already reconciled to www-data (so only the repo gates this test).
	f.On("grep -qE '^[[:space:]]*user[[:space:]]+www-data;' "+nginxConfPath, bssh.Result{ExitCode: 0})
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

func TestNginxApplySourceNginxAddsRepoAndBridge(t *testing.T) {
	s := &config.Server{Nginx: config.Nginx{Source: "nginx"}}
	f := bssh.NewFakeRunner()
	f.On("curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor --yes -o /usr/share/keyrings/nginx-org.gpg", bssh.Result{})
	f.On("gpg --show-keys --with-colons /usr/share/keyrings/nginx-org.gpg", bssh.Result{Stdout: "fpr:::::::::8540A6F18833A80E9C1653A42FD21310B49F6B46:\n"})
	f.On("apt-get update", bssh.Result{})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("install -d /etc/nginx/sites-available /etc/nginx/sites-enabled", bssh.Result{})
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

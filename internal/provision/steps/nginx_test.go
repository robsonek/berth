package steps

import (
	"context"
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

func TestNginxCheckSatisfiedWhenInstalledAndUp(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when nginx installed and running; got %+v", cr)
	}
}

func TestNginxCheckUnsatisfiedWhenNotInstalled(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 1})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
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
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when nginx is not active")
	}
}

func TestNginxCheckSourceNginxRequiresRepo(t *testing.T) {
	s := &config.Server{Nginx: config.Nginx{Source: "nginx"}}
	f := bssh.NewFakeRunner()
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
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
	f.On("systemctl enable --now nginx", bssh.Result{})
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

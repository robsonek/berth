package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func appdirsServer() *config.Server {
	return &config.Server{
		Sites: []config.Site{{
			Domain:     "app.example.com",
			DeployPath: "/home/deploy/myapp",
		}},
	}
}

func TestAppDirsRequiresAccounts(t *testing.T) {
	if got := AppDirs().Requires(); len(got) != 1 || got[0] != "accounts" {
		t.Fatalf("Requires() = %v, want [accounts]", got)
	}
}

func TestAppDirsCheckSatisfiedWhenAllDirsPresentWithOwners(t *testing.T) {
	s := appdirsServer() // single site -> user "deploy"
	f := bssh.NewFakeRunner()
	// deploy_path owned deploy:www-data (nginx can traverse); shared deploy:deploy
	// (private); acme webroot www-data:www-data.
	f.On("stat -c %U:%G "+shQuote("/home/deploy/myapp"), bssh.Result{Stdout: "deploy:www-data\n"})
	f.On("stat -c %U:%G "+shQuote("/home/deploy/myapp/shared"), bssh.Result{Stdout: "deploy:deploy\n"})
	f.On("stat -c %U:%G "+shQuote("/var/www/berth-acme/app.example.com"), bssh.Result{Stdout: "www-data:www-data\n"})
	cr, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when all dirs present with isolating owners; got %+v", cr)
	}
}

func TestAppDirsCheckUnsatisfiedWhenDirMissing(t *testing.T) {
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	f.On("stat -c %U:%G "+shQuote("/home/deploy/myapp"), bssh.Result{ExitCode: 1, Stderr: "No such file or directory"})
	cr, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when a directory is missing")
	}
}

func TestAppDirsCheckUnsatisfiedWhenWrongOwner(t *testing.T) {
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	f.On("stat -c %U:%G "+shQuote("/home/deploy/myapp"), bssh.Result{Stdout: "root:root\n"})
	cr, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when a directory has the wrong owner")
	}
}

func TestAppDirsApplyCreatesDirsWithIsolatingOwners(t *testing.T) {
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	f.On("install -d -o deploy -g www-data -m 0710 '/home/deploy/myapp'", bssh.Result{})
	f.On("install -d -o deploy -g deploy -m 0700 '/home/deploy/myapp/shared'", bssh.Result{})
	f.On("install -d -o www-data -g www-data -m 0755 '/var/www/berth-acme/app.example.com'", bssh.Result{})
	if err := AppDirs().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	joined := strings.Join(callCmds(f), "\n")
	for _, want := range []string{
		"install -d -o deploy -g www-data -m 0710 '/home/deploy/myapp'",
		"install -d -o deploy -g deploy -m 0700 '/home/deploy/myapp/shared'",
		"install -d -o www-data -g www-data -m 0755 '/var/www/berth-acme/app.example.com'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

func TestAppDirsApplyMultiSitePerUser(t *testing.T) {
	s := &config.Server{Sites: []config.Site{
		{Domain: "one.example.com", DeployPath: "/var/www/one"},
		{Domain: "two.example.com", DeployPath: "/var/www/two"},
	}}
	u1, u2 := s.SiteUser(s.Sites[0]), s.SiteUser(s.Sites[1])
	f := bssh.NewFakeRunner()
	for _, u := range []struct{ user, path string }{{u1, "/var/www/one"}, {u2, "/var/www/two"}} {
		f.On("install -d -o "+u.user+" -g www-data -m 0710 '"+u.path+"'", bssh.Result{})
		f.On("install -d -o "+u.user+" -g "+u.user+" -m 0700 '"+u.path+"/shared'", bssh.Result{})
	}
	f.On("install -d -o www-data -g www-data -m 0755 '/var/www/berth-acme/one.example.com'", bssh.Result{})
	f.On("install -d -o www-data -g www-data -m 0755 '/var/www/berth-acme/two.example.com'", bssh.Result{})
	if err := AppDirs().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	joined := strings.Join(callCmds(f), "\n")
	// Each site's deploy_path must be owned by its own distinct user.
	if !strings.Contains(joined, "-o "+u1+" -g www-data -m 0710 '/var/www/one'") ||
		!strings.Contains(joined, "-o "+u2+" -g www-data -m 0710 '/var/www/two'") {
		t.Errorf("each site must be owned by its own user; calls:\n%s", joined)
	}
}

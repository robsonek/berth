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
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	// deploy_path and shared owned by deploy:deploy; acme webroot by www-data:www-data.
	f.On("stat -c %U:%G "+shQuote("/home/deploy/myapp"), bssh.Result{Stdout: "deploy:deploy\n"})
	f.On("stat -c %U:%G "+shQuote("/home/deploy/myapp/shared"), bssh.Result{Stdout: "deploy:deploy\n"})
	f.On("stat -c %U:%G "+shQuote("/var/www/berth-acme/app.example.com"), bssh.Result{Stdout: "www-data:www-data\n"})
	cr, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when all dirs present with correct owners; got %+v", cr)
	}
}

func TestAppDirsCheckUnsatisfiedWhenDirMissing(t *testing.T) {
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	// A missing dir: stat exits non-zero.
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

func TestAppDirsApplyCreatesDirsWithOwners(t *testing.T) {
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	f.On("sudo install -d -o deploy -g deploy '/home/deploy/myapp' '/home/deploy/myapp/shared'", bssh.Result{})
	f.On("sudo install -d -o www-data -g www-data '/var/www/berth-acme/app.example.com'", bssh.Result{})
	if err := AppDirs().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"install -d -o deploy -g deploy '/home/deploy/myapp' '/home/deploy/myapp/shared'",
		"install -d -o www-data -g www-data '/var/www/berth-acme/app.example.com'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

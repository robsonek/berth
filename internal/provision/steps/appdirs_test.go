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
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	// deploy_path deploy:www-data 0710 (nginx can traverse); shared deploy:deploy
	// 0700 (private); acme webroot www-data:www-data 0755.
	f.On("stat -c '%U:%G %a' "+shQuote("/home/deploy/myapp"), bssh.Result{Stdout: "deploy:www-data 710\n"})
	f.On("stat -c '%U:%G %a' "+shQuote("/home/deploy/myapp/shared"), bssh.Result{Stdout: "deploy:deploy 700\n"})
	f.On("stat -c '%U:%G %a' "+shQuote("/home/deploy/myapp/shared/tmp"), bssh.Result{Stdout: "deploy:deploy 700\n"})
	f.On("stat -c '%U:%G %a' "+shQuote("/var/www/berth-acme/app.example.com"), bssh.Result{Stdout: "www-data:www-data 755\n"})
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
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	f.On("stat -c '%U:%G %a' "+shQuote("/home/deploy/myapp"), bssh.Result{ExitCode: 1, Stderr: "No such file or directory"})
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
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	f.On("stat -c '%U:%G %a' "+shQuote("/home/deploy/myapp"), bssh.Result{Stdout: "root:root 710\n"})
	cr, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when a directory has the wrong owner")
	}
}

func TestAppDirsCheckUnsatisfiedOnModeDrift(t *testing.T) {
	s := appdirsServer() // single site -> user "deploy"
	f := bssh.NewFakeRunner()
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	// Correct owner but a world-traversable mode: sibling tenants could enter.
	f.On("stat -c '%U:%G %a' "+shQuote(s.Sites[0].DeployPath), bssh.Result{Stdout: "deploy:www-data 755\n"})
	res, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if res.Satisfied {
		t.Fatal("a 755 deploy_path must be unsatisfied — 0710 is the tenant-isolation contract")
	}
}

func TestAppDirsCheckUnsatisfiedWhenTmpDirMissing(t *testing.T) {
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	f.On("stat -c '%U:%G %a' "+shQuote("/home/deploy/myapp"), bssh.Result{Stdout: "deploy:www-data 710\n"})
	f.On("stat -c '%U:%G %a' "+shQuote("/home/deploy/myapp/shared"), bssh.Result{Stdout: "deploy:deploy 700\n"})
	// shared/tmp backs the pool's sys_temp_dir/upload_tmp_dir; absent here.
	f.On("stat -c '%U:%G %a' "+shQuote("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 1, Stderr: "No such file or directory"})
	f.On("stat -c '%U:%G %a' "+shQuote("/var/www/berth-acme/app.example.com"), bssh.Result{Stdout: "www-data:www-data 755\n"})
	cr, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when shared/tmp is missing")
	}
}

func TestAppDirsApplyCreatesDirsWithIsolatingOwners(t *testing.T) {
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	f.On("install -d -o deploy -g www-data -m 0710 '/home/deploy/myapp'", bssh.Result{})
	f.On("install -d -o deploy -g deploy -m 0700 '/home/deploy/myapp/shared'", bssh.Result{})
	f.On("install -d -o deploy -g deploy -m 0700 '/home/deploy/myapp/shared/tmp'", bssh.Result{})
	f.On("install -d -o www-data -g www-data -m 0755 '/var/www/berth-acme/app.example.com'", bssh.Result{})
	if err := AppDirs().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	joined := strings.Join(callCmds(f), "\n")
	for _, want := range []string{
		"install -d -o deploy -g www-data -m 0710 '/home/deploy/myapp'",
		"install -d -o deploy -g deploy -m 0700 '/home/deploy/myapp/shared'",
		"install -d -o deploy -g deploy -m 0700 '/home/deploy/myapp/shared/tmp'",
		"install -d -o www-data -g www-data -m 0755 '/var/www/berth-acme/app.example.com'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

func TestAppDirsApplyRefusesSymlinkInDeployTree(t *testing.T) {
	s := appdirsServer()
	site := s.Sites[0]
	symCmd := noSymlinkCmd(site.DeployPath + "/shared/tmp")
	f := bssh.NewFakeRunner()
	f.On(symCmd, bssh.Result{ExitCode: 1}) // a component is a symlink
	err := AppDirs().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Apply() = %v, want a refusal naming the symlink", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "install -d") {
			t.Errorf("no install -d may run once a symlink is detected; ran %q", c.Cmd)
		}
	}
}

func TestAppDirsCheckErrorsOnSymlinkInDeployTree(t *testing.T) {
	s := appdirsServer()
	site := s.Sites[0]
	f := bssh.NewFakeRunner()
	f.On(noSymlinkCmd(site.DeployPath+"/shared/tmp"), bssh.Result{ExitCode: 1})
	_, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Check() = %v, want a hard error on a symlinked deploy component", err)
	}
}

// noSymlinkCmd mirrors the production command builder so the exact FakeRunner
// stub matches. Keep it in lockstep with noSymlinkInPath.
func noSymlinkCmd(p string) string {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := ""
	var tests []string
	for _, part := range parts {
		cur += "/" + part
		tests = append(tests, "test ! -L "+shQuote(cur))
	}
	return strings.Join(tests, " && ")
}

func TestAppDirsApplyMultiSitePerUser(t *testing.T) {
	s := &config.Server{Sites: []config.Site{
		{Domain: "one.example.com", DeployPath: "/var/www/one"},
		{Domain: "two.example.com", DeployPath: "/var/www/two"},
	}}
	u1, u2 := s.SiteUser(s.Sites[0]), s.SiteUser(s.Sites[1])
	f := bssh.NewFakeRunner()
	for _, u := range []struct{ user, path string }{{u1, "/var/www/one"}, {u2, "/var/www/two"}} {
		f.On(noSymlinkCmd(u.path+"/shared/tmp"), bssh.Result{ExitCode: 0})
		f.On("install -d -o "+u.user+" -g www-data -m 0710 '"+u.path+"'", bssh.Result{})
		f.On("install -d -o "+u.user+" -g "+u.user+" -m 0700 '"+u.path+"/shared'", bssh.Result{})
		f.On("install -d -o "+u.user+" -g "+u.user+" -m 0700 '"+u.path+"/shared/tmp'", bssh.Result{})
	}
	f.On(noSymlinkCmd(acmeWebroot("one.example.com")), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("two.example.com")), bssh.Result{ExitCode: 0})
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

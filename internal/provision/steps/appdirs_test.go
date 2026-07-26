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
			User:       "deploy",
		}},
	}
}

func TestAppDirsRequiresAccounts(t *testing.T) {
	if got := AppDirs().Requires(); len(got) != 1 || got[0] != "accounts" {
		t.Fatalf("Requires() = %v, want [accounts]", got)
	}
}

func TestAppDirsCheckSatisfiedWhenAllDirsPresentWithOwners(t *testing.T) {
	s := appdirsServer() // user pinned "deploy"
	f := bssh.NewFakeRunner()
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	stubSiteTreeOwned(f, "/home/deploy/myapp", "deploy")
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
	stubSiteTreeAbsent(f, "/home/deploy/myapp")
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
	f.On(ownerProbeCmd("/home/deploy/myapp"), bssh.Result{Stdout: "root 0 directory\n"})
	_, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("Check() err = %v, want an owner-mismatch refusal (pack 9 guard)", err)
	}
}

func TestAppDirsCheckUnsatisfiedOnModeDrift(t *testing.T) {
	s := appdirsServer() // user pinned "deploy"
	f := bssh.NewFakeRunner()
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	stubSiteTreeOwned(f, "/home/deploy/myapp", "deploy")
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
	// Guard probes: two owned dirs plus an absent shared/tmp (mixed state, so
	// the all-or-nothing helpers do not fit here).
	f.On(ownerProbeCmd("/home/deploy/myapp"), bssh.Result{Stdout: "deploy 1000 directory\n"})
	f.On(ownerProbeCmd("/home/deploy/myapp/shared"), bssh.Result{Stdout: "deploy 1000 directory\n"})
	f.On(ownerProbeCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 1, Stderr: "stat: cannot statx: No such file or directory"})
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
	stubSiteTreeAbsent(f, "/home/deploy/myapp")
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
		q := shQuote(cur)
		tests = append(tests, "{ test ! -e "+q+" || { test ! -L "+q+" && test -d "+q+"; }; }")
	}
	return strings.Join(tests, " && ")
}

// ownerProbeCmd mirrors the guard's exact probe so FakeRunner stubs match.
// Keep in lockstep with assertSiteTreeOwners. %F goes last: file types
// contain spaces ("regular file"); owner names cannot.
func ownerProbeCmd(p string) string { return "LC_ALL=C stat -c '%U %u %F' " + shQuote(p) }

// stubSiteTreeAbsent stubs the owner-guard probes for a fresh host: all three
// per-site directories absent, so the guard passes and the step proceeds.
func stubSiteTreeAbsent(f *bssh.FakeRunner, deployPath string) {
	for _, p := range []string{deployPath, deployPath + "/shared", deployPath + "/shared/tmp"} {
		f.On(ownerProbeCmd(p), bssh.Result{ExitCode: 1, Stderr: "stat: cannot statx: No such file or directory"})
	}
}

// stubSiteTreeOwned stubs the owner-guard probes with all three directories
// present as directories owned by user (the uid is arbitrary — the guard
// matches by name).
func stubSiteTreeOwned(f *bssh.FakeRunner, deployPath, user string) {
	for _, p := range []string{deployPath, deployPath + "/shared", deployPath + "/shared/tmp"} {
		f.On(ownerProbeCmd(p), bssh.Result{Stdout: user + " 1000 directory\n"})
	}
}

// stubSiteTreeFresh stubs the whole tree-safety preflight for a fresh host:
// deploy tree symlink-free and all three directories absent. Accounts tests
// use this (accounts asserts symlink freedom itself before probing owners).
func stubSiteTreeFresh(f *bssh.FakeRunner, deployPath string) {
	f.On(noSymlinkCmd(deployPath+"/shared/tmp"), bssh.Result{ExitCode: 0})
	stubSiteTreeAbsent(f, deployPath)
}

func TestAppDirsCheckRefusesForeignOwnedDeployPath(t *testing.T) {
	s := appdirsServer() // user pinned "deploy"
	f := bssh.NewFakeRunner()
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	// The tree belongs to a different (e.g. previously derived) account —
	// a valid candidate, so the error must offer the pin remediation.
	f.On(ownerProbeCmd("/home/deploy/myapp"), bssh.Result{Stdout: "b_old_12345678 1003 directory\n"})
	for _, rc := range []provision.RunCtx{{}, {Force: true}} {
		_, err := AppDirs().Check(context.Background(), rc, s, f)
		if err == nil || !strings.Contains(err.Error(), `sites[].user: "b_old_12345678"`) {
			t.Fatalf("Force=%v: Check() err = %v, want an owner-mismatch refusal with the pin remediation", rc.Force, err)
		}
	}
}

func TestAppDirsApplyRefusesForeignOwnedShared(t *testing.T) {
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	// deploy_path owner matches, but shared/ belongs to root: install -d
	// would re-own only the directory, never its contents — a cosmetic heal —
	// so the guard must refuse. root is reserved, so the error must NOT
	// suggest pinning it (finding #5).
	f.On(ownerProbeCmd("/home/deploy/myapp"), bssh.Result{Stdout: "deploy 1001 directory\n"})
	f.On(ownerProbeCmd("/home/deploy/myapp/shared"), bssh.Result{Stdout: "root 0 directory\n"})
	err := AppDirs().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("Apply() = %v, want refusal on foreign-owned shared/", err)
	}
	if strings.Contains(err.Error(), `sites[].user: "root"`) {
		t.Errorf("the error must never suggest pinning a reserved user; got %v", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "install -d") {
			t.Errorf("no install -d may run after an owner mismatch; ran %q", c.Cmd)
		}
	}
}

func TestAppDirsRefusesNonDirectoryDeployPath(t *testing.T) {
	// A regular file in place of deploy_path must refuse loudly instead of
	// sailing into install -d's confusing failure. (A symlinked deploy_path
	// is already caught by the symlink assertion before the owner probes.)
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	f.On(noSymlinkCmd("/home/deploy/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	f.On(ownerProbeCmd("/home/deploy/myapp"), bssh.Result{Stdout: "deploy 1001 regular file\n"})
	_, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("Check() err = %v, want a not-a-directory refusal", err)
	}
}

func TestAppDirsPreflightsEverySiteBeforeActing(t *testing.T) {
	// Check must inspect EVERY site's tree before returning its (first)
	// drift result: otherwise a dry-run would print a plan for site 1 while
	// site 2's foreign tree only explodes mid-Apply — and Apply must refuse
	// BEFORE mutating site 1 (Codex plan-review finding #1, the blocker).
	s := &config.Server{Sites: []config.Site{
		{Domain: "one.example.com", DeployPath: "/var/www/one", User: "one_user"},
		{Domain: "two.example.com", DeployPath: "/var/www/two", User: "two_user"},
	}}
	f := bssh.NewFakeRunner()
	for _, d := range []string{"/var/www/one", "/var/www/two"} {
		f.On(noSymlinkCmd(d+"/shared/tmp"), bssh.Result{ExitCode: 0})
	}
	f.On(noSymlinkCmd(acmeWebroot("one.example.com")), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("two.example.com")), bssh.Result{ExitCode: 0})
	stubSiteTreeAbsent(f, "/var/www/one") // site 1: fresh — mere drift
	f.On(ownerProbeCmd("/var/www/two"), bssh.Result{Stdout: "somebody_else 1002 directory\n"})
	_, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "two.example.com") {
		t.Fatalf("Check() err = %v, want site 2's mismatch reported despite site 1 drifting first", err)
	}
	if aerr := AppDirs().Apply(context.Background(), provision.RunCtx{}, s, f); aerr == nil {
		t.Fatal("Apply() must refuse when any site mismatches")
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "install -d") {
			t.Errorf("Apply must not mutate ANY site once ANY site mismatches; ran %q", c.Cmd)
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
		f.On(noSymlinkCmd(u.path+"/shared/tmp"), bssh.Result{ExitCode: 0})
		stubSiteTreeAbsent(f, u.path)
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

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

func appdirsServer() *config.Server {
	return &config.Server{
		Sites: []config.Site{{
			Domain:     "app.example.com",
			DeployPath: "/var/www/myapp",
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
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	f.On(noSymlinkCmd("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	stubSiteTreeOwned(f, "/var/www/myapp", "deploy")
	f.On(groupProbeCmd("deploy"), bssh.Result{Stdout: "deploy\n"})
	// deploy_path deploy:www-data 0710 (nginx can traverse); shared deploy:deploy
	// 0700 (private); acme webroot www-data:www-data 0755.
	f.On("stat -c '%U:%G %a' "+shQuote("/var/www/myapp"), bssh.Result{Stdout: "deploy:www-data 710\n"})
	f.On("stat -c '%U:%G %a' "+shQuote("/var/www/myapp/shared"), bssh.Result{Stdout: "deploy:deploy 700\n"})
	f.On("stat -c '%U:%G %a' "+shQuote("/var/www/myapp/shared/tmp"), bssh.Result{Stdout: "deploy:deploy 700\n"})
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
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	f.On(noSymlinkCmd("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	stubSiteTreeAbsent(f, "/var/www/myapp")
	f.On(groupProbeCmd("deploy"), bssh.Result{Stdout: "deploy\n"})
	f.On("stat -c '%U:%G %a' "+shQuote("/var/www/myapp"), bssh.Result{ExitCode: 1, Stderr: "No such file or directory"})
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
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	f.On(noSymlinkCmd("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	f.On(ownerProbeCmd("/var/www/myapp"), bssh.Result{Stdout: "root 0 directory\n"})
	_, err := AppDirs().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("Check() err = %v, want an owner-mismatch refusal (pack 9 guard)", err)
	}
}

func TestAppDirsCheckUnsatisfiedOnModeDrift(t *testing.T) {
	s := appdirsServer() // user pinned "deploy"
	f := bssh.NewFakeRunner()
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	f.On(noSymlinkCmd("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	stubSiteTreeOwned(f, "/var/www/myapp", "deploy")
	f.On(groupProbeCmd("deploy"), bssh.Result{Stdout: "deploy\n"})
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
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	f.On(noSymlinkCmd("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	// Guard probes: two owned dirs plus an absent shared/tmp (mixed state, so
	// the all-or-nothing helpers do not fit here).
	f.On(ownerProbeCmd("/var/www/myapp"), bssh.Result{Stdout: "deploy 1000 directory\n"})
	f.On(ownerProbeCmd("/var/www/myapp/shared"), bssh.Result{Stdout: "deploy 1000 directory\n"})
	f.On(ownerProbeCmd("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 1, Stderr: "stat: cannot statx: No such file or directory"})
	f.On(groupProbeCmd("deploy"), bssh.Result{Stdout: "deploy\n"})
	f.On("stat -c '%U:%G %a' "+shQuote("/var/www/myapp"), bssh.Result{Stdout: "deploy:www-data 710\n"})
	f.On("stat -c '%U:%G %a' "+shQuote("/var/www/myapp/shared"), bssh.Result{Stdout: "deploy:deploy 700\n"})
	// shared/tmp backs the pool's sys_temp_dir/upload_tmp_dir; absent here.
	f.On("stat -c '%U:%G %a' "+shQuote("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 1, Stderr: "No such file or directory"})
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
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	f.On(noSymlinkCmd("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	stubSiteTreeAbsent(f, "/var/www/myapp")
	f.On(groupProbeCmd("deploy"), bssh.Result{Stdout: "deploy\n"})
	f.On("install -d -o deploy -g www-data -m 00710 '/var/www/myapp'", bssh.Result{})
	f.On("sudo -u deploy install -d -g deploy -m 00700 '/var/www/myapp/shared'", bssh.Result{})
	f.On("sudo -u deploy install -d -g deploy -m 00700 '/var/www/myapp/shared/tmp'", bssh.Result{})
	f.On("install -d -o www-data -g www-data -m 00755 '/var/www/berth-acme/app.example.com'", bssh.Result{})
	if err := AppDirs().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	joined := strings.Join(callCmds(f), "\n")
	for _, want := range []string{
		"install -d -o deploy -g www-data -m 00710 '/var/www/myapp'",
		"sudo -u deploy install -d -g deploy -m 00700 '/var/www/myapp/shared'",
		"sudo -u deploy install -d -g deploy -m 00700 '/var/www/myapp/shared/tmp'",
		"install -d -o www-data -g www-data -m 00755 '/var/www/berth-acme/app.example.com'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

func TestAppDirsApplyUsesFiveDigitModes(t *testing.T) {
	// GNU preserves a directory's setgid bit under numeric modes shorter than
	// five octal digits, so `-m 0700` can leave an existing 2700 directory at
	// 2700 while Check demands 700 — the step would then apply forever. A
	// tenant can trigger it on its own directory with `chmod g+s`.
	s := appdirsServer()
	f := bssh.NewFakeRunner()
	stubAppDirsFresh(f, s) // helper added in Step 1, above
	if err := AppDirs().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, cmd := range callCmds(f) {
		if !strings.Contains(cmd, "install -d") {
			continue
		}
		if strings.Contains(cmd, " -m 0700 ") || strings.Contains(cmd, " -m 0710 ") ||
			strings.Contains(cmd, " -m 0755 ") || strings.Contains(cmd, " -m 700 ") {
			t.Errorf("mode must be five octal digits to clear setuid/setgid; got %q", cmd)
		}
	}
}

func TestAppDirsApplyRefusesSymlinkInDeployTree(t *testing.T) {
	s := appdirsServer()
	site := s.Sites[0]
	symCmd := noSymlinkCmd(site.DeployPath + "/shared/tmp")
	f := bssh.NewFakeRunner()
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
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
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
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
// deploy tree symlink-free, all three directories absent, and the /home
// ancestry root-controlled (accounts' home-directory gate). Accounts tests
// use this (accounts asserts symlink freedom itself before probing owners).
func stubSiteTreeFresh(f *bssh.FakeRunner, deployPath string) {
	f.On(noSymlinkCmd(deployPath+"/shared/tmp"), bssh.Result{ExitCode: 0})
	stubSiteTreeAbsent(f, deployPath)
	stubSafeAncestry(f, "/", "/home")
}

// stubAppDirsFresh stubs every probe and mutation of a clean single-site
// Apply: symlink probes, ancestry, absent owner probes, the group-membership
// probe, and the four directory commands.
func stubAppDirsFresh(f *bssh.FakeRunner, s *config.Server) {
	for _, site := range s.Sites {
		user := s.SiteUser(site)
		f.On(noSymlinkCmd(site.DeployPath+"/shared/tmp"), bssh.Result{ExitCode: 0})
		f.On(noSymlinkCmd(acmeWebroot(site.Domain)), bssh.Result{ExitCode: 0})
		stubSiteTreeAbsent(f, site.DeployPath)
		f.On(groupProbeCmd(user), bssh.Result{Stdout: user + "\n"})
		f.On(fmt.Sprintf("install -d -o %s -g www-data -m 00710 %s", user, shQuote(site.DeployPath)), bssh.Result{})
		f.On(fmt.Sprintf("sudo -u %s install -d -g %s -m 00700 %s", user, user, shQuote(site.DeployPath+"/shared")), bssh.Result{})
		f.On(fmt.Sprintf("sudo -u %s install -d -g %s -m 00700 %s", user, user, shQuote(site.DeployPath+"/shared/tmp")), bssh.Result{})
		f.On(fmt.Sprintf("install -d -o www-data -g www-data -m 00755 %s", shQuote(acmeWebroot(site.Domain))), bssh.Result{})
	}
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
}

func TestAppDirsCheckRefusesForeignOwnedDeployPath(t *testing.T) {
	s := appdirsServer() // user pinned "deploy"
	f := bssh.NewFakeRunner()
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	f.On(noSymlinkCmd("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	// The tree belongs to a different (e.g. previously derived) account —
	// a valid candidate, so the error must offer the pin remediation.
	f.On(ownerProbeCmd("/var/www/myapp"), bssh.Result{Stdout: "b_old_12345678 1003 directory\n"})
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
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	f.On(noSymlinkCmd("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	// deploy_path owner matches, but shared/ belongs to root: install -d
	// would re-own only the directory, never its contents — a cosmetic heal —
	// so the guard must refuse. root is reserved, so the error must NOT
	// suggest pinning it (finding #5).
	f.On(ownerProbeCmd("/var/www/myapp"), bssh.Result{Stdout: "deploy 1001 directory\n"})
	f.On(ownerProbeCmd("/var/www/myapp/shared"), bssh.Result{Stdout: "root 0 directory\n"})
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
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	f.On(noSymlinkCmd("/var/www/myapp/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("app.example.com")), bssh.Result{ExitCode: 0})
	f.On(ownerProbeCmd("/var/www/myapp"), bssh.Result{Stdout: "deploy 1001 regular file\n"})
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
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	for _, d := range []string{"/var/www/one", "/var/www/two"} {
		f.On(noSymlinkCmd(d+"/shared/tmp"), bssh.Result{ExitCode: 0})
	}
	f.On(noSymlinkCmd(acmeWebroot("one.example.com")), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("two.example.com")), bssh.Result{ExitCode: 0})
	stubSiteTreeAbsent(f, "/var/www/one") // site 1: fresh — mere drift
	f.On(groupProbeCmd("one_user"), bssh.Result{Stdout: "one_user\n"})
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
	stubSafeAncestry(f, "/", "/var", "/var/www", "/var/www/berth-acme")
	for _, u := range []struct{ user, path string }{{u1, "/var/www/one"}, {u2, "/var/www/two"}} {
		f.On(noSymlinkCmd(u.path+"/shared/tmp"), bssh.Result{ExitCode: 0})
		stubSiteTreeAbsent(f, u.path)
		f.On(groupProbeCmd(u.user), bssh.Result{Stdout: u.user + "\n"})
		f.On("install -d -o "+u.user+" -g www-data -m 00710 '"+u.path+"'", bssh.Result{})
		f.On("sudo -u "+u.user+" install -d -g "+u.user+" -m 00700 '"+u.path+"/shared'", bssh.Result{})
		f.On("sudo -u "+u.user+" install -d -g "+u.user+" -m 00700 '"+u.path+"/shared/tmp'", bssh.Result{})
	}
	f.On(noSymlinkCmd(acmeWebroot("one.example.com")), bssh.Result{ExitCode: 0})
	f.On(noSymlinkCmd(acmeWebroot("two.example.com")), bssh.Result{ExitCode: 0})
	f.On("install -d -o www-data -g www-data -m 00755 '/var/www/berth-acme/one.example.com'", bssh.Result{})
	f.On("install -d -o www-data -g www-data -m 00755 '/var/www/berth-acme/two.example.com'", bssh.Result{})
	if err := AppDirs().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	joined := strings.Join(callCmds(f), "\n")
	// Each site's deploy_path must be owned by its own distinct user.
	if !strings.Contains(joined, "-o "+u1+" -g www-data -m 00710 '/var/www/one'") ||
		!strings.Contains(joined, "-o "+u2+" -g www-data -m 00710 '/var/www/two'") {
		t.Errorf("each site must be owned by its own user; calls:\n%s", joined)
	}
}

// safeAncestryCmd mirrors the production probe so FakeRunner stubs match.
// Keep in lockstep with assertSafeAncestry.
func safeAncestryCmd(paths ...string) string {
	var q []string
	for _, p := range paths {
		q = append(q, shQuote(p))
	}
	return "export LC_ALL=C; for p in " + strings.Join(q, " ") +
		"; do if [ -e \"$p\" ] || [ -L \"$p\" ]; then stat -c '%n %u %a %F' \"$p\" || exit 91; fi; done"
}

// stubSafeAncestry stubs the ancestry probe for a conventional Debian layout:
// every ancestor is a root-owned, non-group-writable directory.
func stubSafeAncestry(f *bssh.FakeRunner, paths ...string) {
	var out strings.Builder
	for _, p := range paths {
		out.WriteString(p + " 0 755 directory\n")
	}
	f.On(safeAncestryCmd(paths...), bssh.Result{Stdout: out.String()})
}

func TestAncestorsOf(t *testing.T) {
	// / is included: a non-root-owned or writable root directory would let a
	// tenant create or replace a top-level component after the probe, which is
	// exactly the class this gate exists for.
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"/var/www/app", []string{"/", "/var", "/var/www"}},
		{"/var/www/berth-acme/app.example.com", []string{"/", "/var", "/var/www", "/var/www/berth-acme"}},
		{"/srv/apps/site", []string{"/", "/srv", "/srv/apps"}},
		{"/home/x", []string{"/", "/home"}},
	} {
		got := ancestorsOf(tc.in)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("ancestorsOf(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSafeAncestryAcceptsRootOwnedChain(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubSafeAncestry(f, "/", "/var", "/var/www")
	if err := assertSafeAncestry(context.Background(), f, "app.example.com", "/var/www/app"); err != nil {
		t.Fatalf("a root-owned 0755 chain must pass; got %v", err)
	}
}

func TestSafeAncestryAcceptsMissingComponents(t *testing.T) {
	// A fresh host may not have the tree yet: absent components are fine —
	// root creates them, and a created component is root-owned by definition.
	f := bssh.NewFakeRunner()
	f.On(safeAncestryCmd("/", "/srv", "/srv/apps"), bssh.Result{Stdout: "/ 0 755 directory\n/srv 0 755 directory\n"})
	if err := assertSafeAncestry(context.Background(), f, "app.example.com", "/srv/apps/site"); err != nil {
		t.Fatalf("missing ancestors must pass; got %v", err)
	}
}

func TestSafeAncestryRefusesTenantOwnedAncestor(t *testing.T) {
	// The whole point: ValidateDeployPath allows /srv/apps/site, and a
	// tenant-owned /srv/apps lets the tenant swap `site` after the probe, so
	// root's install -d would still chown an arbitrary target.
	f := bssh.NewFakeRunner()
	f.On(safeAncestryCmd("/", "/srv", "/srv/apps"),
		bssh.Result{Stdout: "/ 0 755 directory\n/srv 0 755 directory\n/srv/apps 1001 755 directory\n"})
	err := assertSafeAncestry(context.Background(), f, "app.example.com", "/srv/apps/site")
	if err == nil || !strings.Contains(err.Error(), "/srv/apps") {
		t.Fatalf("err = %v, want a refusal naming the tenant-owned ancestor", err)
	}
	if !strings.Contains(err.Error(), "uid 1001") {
		t.Errorf("the refusal must report the offending uid; got %v", err)
	}
}

func TestSafeAncestryRefusesWritableRoot(t *testing.T) {
	// / is part of the chain: a writable root directory lets a tenant replace or
	// create a top-level component after the probe.
	f := bssh.NewFakeRunner()
	f.On(safeAncestryCmd("/", "/var", "/var/www"),
		bssh.Result{Stdout: "/ 0 777 directory\n/var 0 755 directory\n/var/www 0 755 directory\n"})
	err := assertSafeAncestry(context.Background(), f, "app.example.com", "/var/www/app")
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("err = %v, want a refusal for a writable /", err)
	}
}

func TestSafeAncestryRefusesUnsearchableAncestor(t *testing.T) {
	// Root-owned 0700 passes ownership and writability, yet the SITE USER cannot
	// traverse it — the tenant-run `install -d …/shared` would fail with EACCES
	// on every run and the step would never converge; www-data would likewise be
	// cut off from the ACME webroot. Refuse with a remedy instead of shipping a
	// permanently unsatisfiable step.
	f := bssh.NewFakeRunner()
	f.On(safeAncestryCmd("/", "/srv", "/srv/apps"),
		bssh.Result{Stdout: "/ 0 755 directory\n/srv 0 755 directory\n/srv/apps 0 700 directory\n"})
	err := assertSafeAncestry(context.Background(), f, "app.example.com", "/srv/apps/site")
	if err == nil || !strings.Contains(err.Error(), "traverse") {
		t.Fatalf("err = %v, want a refusal about traversal", err)
	}
	if !strings.Contains(err.Error(), "chmod o+x") {
		t.Errorf("the refusal must carry the remedy; got %v", err)
	}
}

func TestSafeAncestryRefusesGroupWritableAncestor(t *testing.T) {
	// Root-owned but group-writable is equally fatal: anyone in that group can
	// swap the final component.
	f := bssh.NewFakeRunner()
	f.On(safeAncestryCmd("/", "/srv", "/srv/apps"),
		bssh.Result{Stdout: "/ 0 755 directory\n/srv 0 755 directory\n/srv/apps 0 775 directory\n"})
	err := assertSafeAncestry(context.Background(), f, "app.example.com", "/srv/apps/site")
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("err = %v, want a refusal naming the writable ancestor", err)
	}
}

func TestSafeAncestryRefusesNonDirectoryAncestor(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(safeAncestryCmd("/", "/srv", "/srv/apps"),
		bssh.Result{Stdout: "/ 0 755 directory\n/srv 0 755 directory\n/srv/apps 0 777 symbolic link\n"})
	err := assertSafeAncestry(context.Background(), f, "app.example.com", "/srv/apps/site")
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("err = %v, want a refusal naming the component type", err)
	}
}

func TestSafeAncestryHardErrorsOnProbeFailure(t *testing.T) {
	// Exit 91 is the probe's own "stat failed" signal: never read as "absent"
	// (that would be fail-open on the one check that gates a root chown).
	f := bssh.NewFakeRunner()
	f.On(safeAncestryCmd("/", "/var", "/var/www"), bssh.Result{ExitCode: 91})
	if err := assertSafeAncestry(context.Background(), f, "app.example.com", "/var/www/app"); err == nil {
		t.Fatal("a failed probe must be a hard error, not a pass")
	}
}

func TestAppDirsRefusesTenantOwnedAncestryEvenWithForce(t *testing.T) {
	s := &config.Server{Sites: []config.Site{
		{Domain: "app.example.com", DeployPath: "/srv/apps/site", User: "deploy"},
	}}
	for _, rc := range []provision.RunCtx{{}, {Force: true}} {
		f := bssh.NewFakeRunner()
		f.On(safeAncestryCmd("/", "/srv", "/srv/apps"),
			bssh.Result{Stdout: "/ 0 755 directory\n/srv 0 755 directory\n/srv/apps 1001 755 directory\n"})
		if _, err := AppDirs().Check(context.Background(), rc, s, f); err == nil {
			t.Fatalf("Force=%v: Check must refuse unsafe ancestry", rc.Force)
		}
		if err := AppDirs().Apply(context.Background(), rc, s, f); err == nil {
			t.Fatalf("Force=%v: Apply must refuse unsafe ancestry", rc.Force)
		}
		for _, c := range f.Calls() {
			if strings.HasPrefix(c.Cmd, "install -d") {
				t.Errorf("no install -d may run on unsafe ancestry; ran %q", c.Cmd)
			}
		}
	}
}

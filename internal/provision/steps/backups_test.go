package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func backupServer() *config.Server {
	return &config.Server{
		Host:     "vps.example.com",
		PHP:      config.PHP{Version: "8.5"},
		Database: config.Database{Engine: "mariadb"},
		Backups:  config.Backups{Enabled: true},
		Sites: []config.Site{{Domain: "app.example.com", DeployPath: "/var/www/app",
			Database: config.SiteDatabase{Name: "myapp", User: "myapp"}}},
	}
}

// ok is a zero-exit Result.
var okResult = bssh.Result{ExitCode: 0}

// freshBackupsApplyFixture stubs everything Apply touches on a fresh box for
// backupServer(): prereqs present, no managed file exists yet, the orphan scan
// finds only the desired files. Tests override individual stubs via On.
func freshBackupsApplyFixture(s *config.Server) *bssh.FakeRunner {
	site := s.Sites[0]
	f := bssh.NewFakeRunner()
	// prereqs present
	f.On("systemctl is-active cron", okResult)
	f.On("systemctl is-enabled cron", okResult)
	f.On("command -v mysqldump >/dev/null 2>&1", okResult)
	// dir installs
	f.On("install -d -o root -g root -m 0755 '"+backupBaseDir+"'", okResult)
	f.On("install -d -o root -g root -m 0755 '"+backupLogDir+"'", okResult)
	f.On("install -d -o root -g root -m 0700 '"+backupDir(site.Domain)+"'", okResult)
	// write-guards: all managed files absent on a fresh box
	f.On("cat '"+backupLogrotatePath+"'", bssh.Result{ExitCode: 1})
	f.On("cat '"+backupScriptPath(site.Domain)+"'", bssh.Result{ExitCode: 1})
	f.On("cat '"+backupCronPath(site.Domain)+"'", bssh.Result{ExitCode: 1})
	f.On("cat '"+backupManifestPath(site.Domain)+"'", bssh.Result{ExitCode: 1})
	// logrotate fragment validation
	f.On("logrotate -d '"+backupLogrotatePath+"'", okResult)
	// script validation
	f.On("bash -n '"+backupScriptPath(site.Domain)+"'", okResult)
	// orphan scan finds only the desired files
	f.On("ls -1 "+backupScriptGlob+" 2>/dev/null", bssh.Result{Stdout: backupScriptPath(site.Domain) + "\n"})
	f.On("ls -1 "+backupCronGlob+" 2>/dev/null", bssh.Result{Stdout: backupCronPath(site.Domain) + "\n"})
	f.On("ls -1 "+backupManifestGlob+" 2>/dev/null", bssh.Result{Stdout: backupManifestPath(site.Domain) + "\n"})
	return f
}

func TestBackupsApplyWritesScriptCronDirAndPrereqs(t *testing.T) {
	s := backupServer()
	site := s.Sites[0]
	f := freshBackupsApplyFixture(s)

	if err := (backups{}).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wantPaths := map[string]int{backupLogrotatePath: 0o644, backupScriptPath(site.Domain): 0o755,
		backupCronPath(site.Domain): 0o644, backupManifestPath(site.Domain): 0o600}
	got := map[string]bssh.FileSpec{}
	for _, w := range f.Writes() {
		got[w.Path] = w
	}
	for p, mode := range wantPaths {
		w, ok := got[p]
		if !ok {
			t.Fatalf("missing write for %s", p)
		}
		if int(w.Mode) != mode || w.Owner != "root" || w.Group != "root" {
			t.Errorf("%s: mode=%o owner=%s:%s, want %o root:root", p, w.Mode, w.Owner, w.Group, mode)
		}
	}
	if !strings.Contains(string(got[backupScriptPath(site.Domain)].Content), "mysqldump --protocol=socket --single-transaction --no-tablespaces --routines --events 'myapp'") {
		t.Errorf("script missing dump command:\n%s", got[backupScriptPath(site.Domain)].Content)
	}
	if !strings.HasPrefix(string(got[backupScriptPath(site.Domain)].Content), "# managed by berth\nset -euo pipefail") {
		t.Errorf("script should start with marker then set -euo pipefail")
	}
}

func TestBackupsApplyRefusesForeignScript(t *testing.T) {
	// A pre-existing, hand-written backup script (no berth marker) must not be
	// clobbered by Apply without --force.
	s := backupServer()
	site := s.Sites[0]
	f := freshBackupsApplyFixture(s)
	f.On("cat '"+backupScriptPath(site.Domain)+"'", bssh.Result{ExitCode: 0, Stdout: "#!/bin/sh\n# operator's own backup\n"}) // foreign

	err := (backups{}).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	for _, w := range f.Writes() {
		if w.Path == backupScriptPath(site.Domain) {
			t.Error("a foreign backup script must not be overwritten without --force")
		}
	}
}

// satisfiedBackupsCheckFixture stubs every probe Check makes for backupServer()
// in its fully-converged state. Drift tests override individual stubs via On.
func satisfiedBackupsCheckFixture(t *testing.T, s *config.Server) *bssh.FakeRunner {
	t.Helper()
	site := s.Sites[0]
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		t.Fatal(err)
	}
	script, err := renderBackupScript(s, site, eng)
	if err != nil {
		t.Fatal(err)
	}
	cron, err := renderBackupCron(s, site)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := renderBackupManifest(s, site)
	if err != nil {
		t.Fatal(err)
	}
	lr, err := renderBackupLogrotate()
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("cat '"+backupScriptPath(site.Domain)+"'", bssh.Result{Stdout: string(script)})
	f.On("stat -c '%U:%G %a' '"+backupScriptPath(site.Domain)+"'", bssh.Result{Stdout: "root:root 755\n"})
	f.On("cat '"+backupCronPath(site.Domain)+"'", bssh.Result{Stdout: string(cron)})
	f.On("stat -c '%U:%G %a' '"+backupCronPath(site.Domain)+"'", bssh.Result{Stdout: "root:root 644\n"})
	f.On("cat '"+backupManifestPath(site.Domain)+"'", bssh.Result{Stdout: string(manifest)})
	f.On("stat -c '%U:%G %a' '"+backupManifestPath(site.Domain)+"'", bssh.Result{Stdout: "root:root 600\n"})
	f.On("stat -c '%U:%G %a' '"+backupDir(site.Domain)+"'", bssh.Result{Stdout: "root:root 700\n"})
	f.On("stat -c '%U:%G %a' '"+backupBaseDir+"'", bssh.Result{Stdout: "root:root 755\n"})
	f.On("stat -c '%U:%G %a' '"+backupLogDir+"'", bssh.Result{Stdout: "root:root 755\n"})
	f.On("ls -1 "+backupScriptGlob+" 2>/dev/null", bssh.Result{Stdout: backupScriptPath(site.Domain) + "\n"})
	f.On("ls -1 "+backupCronGlob+" 2>/dev/null", bssh.Result{Stdout: backupCronPath(site.Domain) + "\n"})
	f.On("ls -1 "+backupManifestGlob+" 2>/dev/null", bssh.Result{Stdout: backupManifestPath(site.Domain) + "\n"})
	f.On("cat '"+backupLogrotatePath+"'", bssh.Result{Stdout: string(lr)})
	f.On("stat -c '%U:%G %a' '"+backupLogrotatePath+"'", bssh.Result{Stdout: "root:root 644\n"})
	f.On("systemctl is-active cron", okResult)
	f.On("systemctl is-enabled cron", okResult)
	f.On("command -v mysqldump >/dev/null 2>&1", okResult)
	return f
}

func TestBackupsCheckSatisfiedInPlace(t *testing.T) {
	s := backupServer()
	f := satisfiedBackupsCheckFixture(t, s)

	res, err := (backups{}).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.Satisfied {
		t.Errorf("Check not satisfied: %s %v", res.Reason, res.Changes)
	}
}

// hasChange reports whether the exact change entry is present.
func hasChange(changes []string, want string) bool {
	for _, c := range changes {
		if c == want {
			return true
		}
	}
	return false
}

func TestBackupsCheckFlagsManifestDrift(t *testing.T) {
	s := backupServer()
	mp := backupManifestPath(s.Sites[0].Domain)

	// A missing manifest must yield a write change entry.
	f := satisfiedBackupsCheckFixture(t, s)
	f.On("cat '"+mp+"'", bssh.Result{ExitCode: 1})
	f.On("stat -c '%U:%G %a' '"+mp+"'", bssh.Result{ExitCode: 1})
	f.On("ls -1 "+backupManifestGlob+" 2>/dev/null", okResult)
	res, err := (backups{}).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatalf("Check (absent manifest): %v", err)
	}
	if res.Satisfied || !hasChange(res.Changes, "write "+mp) {
		t.Errorf("absent manifest: satisfied=%v changes=%v, want %q", res.Satisfied, res.Changes, "write "+mp)
	}

	// Correct content but drifted owner/mode must yield a fix change entry.
	f2 := satisfiedBackupsCheckFixture(t, s)
	f2.On("stat -c '%U:%G %a' '"+mp+"'", bssh.Result{Stdout: "root:root 644\n"})
	res, err = (backups{}).Check(context.Background(), provision.RunCtx{}, s, f2)
	if err != nil {
		t.Fatalf("Check (mode drift): %v", err)
	}
	if res.Satisfied || !hasChange(res.Changes, "fix owner/mode of "+mp) {
		t.Errorf("mode drift: satisfied=%v changes=%v, want %q", res.Satisfied, res.Changes, "fix owner/mode of "+mp)
	}
}

func TestBackupsApplyWritesManifest(t *testing.T) {
	s := backupServer()
	site := s.Sites[0]
	f := freshBackupsApplyFixture(s)

	if err := (backups{}).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var manifest *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == backupManifestPath(site.Domain) {
			manifest = &f.Writes()[i]
		}
	}
	if manifest == nil {
		t.Fatalf("missing write for %s", backupManifestPath(site.Domain))
	}
	if manifest.Owner != "root" || manifest.Group != "root" || int(manifest.Mode) != 0o600 || !manifest.Sudo {
		t.Errorf("manifest spec = %s:%s %o sudo=%v, want root:root 600 sudo=true",
			manifest.Owner, manifest.Group, manifest.Mode, manifest.Sudo)
	}
	for _, want := range []string{"# managed by berth\n", "BERTH_VERSION=dev\n", "DB_NAME=myapp\n", "DEPLOY_PATH=/var/www/app\n"} {
		if !strings.Contains(string(manifest.Content), want) {
			t.Errorf("manifest missing %q:\n%s", want, manifest.Content)
		}
	}
}

func TestBackupsApplySweepsOrphanManifest(t *testing.T) {
	// A manifest lingering for a site no longer in the config is swept like the
	// script/cron; the archives (*.gz) sharing its directory are never touched.
	s := backupServer()
	site := s.Sites[0]
	orphan := backupBaseDir + "/old_example_com/manifest"
	f := freshBackupsApplyFixture(s)
	f.On("ls -1 "+backupManifestGlob+" 2>/dev/null",
		bssh.Result{Stdout: backupManifestPath(site.Domain) + "\n" + orphan + "\n"})
	f.On("cat '"+orphan+"'", bssh.Result{Stdout: "# managed by berth\nBERTH_VERSION=v0.0.1\n"})
	f.On("rm -f '"+orphan+"'", okResult)

	if err := (backups{}).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var removedOrphan bool
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f '"+orphan+"'" {
			removedOrphan = true
		}
		if strings.HasPrefix(c.Cmd, "rm -f") && strings.Contains(c.Cmd, ".gz") {
			t.Errorf("sweep must never remove archives, got %q", c.Cmd)
		}
	}
	if !removedOrphan {
		t.Errorf("orphan manifest %s not removed", orphan)
	}
}

func TestBackupsDisabledDriftRemovesOrphan(t *testing.T) {
	// Backups off everywhere, but a managed cron+script linger on disk for a
	// removed pool -> Check flags them, Apply removes them.
	s := backupServer()
	s.Backups.Enabled = false
	orphanScript := "/usr/local/sbin/berth-backup-old_example_com"
	orphanCron := "/etc/cron.d/berth-backup-old_example_com"
	f := bssh.NewFakeRunner()
	f.On("ls -1 "+backupScriptGlob+" 2>/dev/null", bssh.Result{Stdout: orphanScript + "\n"})
	f.On("ls -1 "+backupCronGlob+" 2>/dev/null", bssh.Result{Stdout: orphanCron + "\n"})
	f.On("ls -1 "+backupManifestGlob+" 2>/dev/null", okResult)
	f.On("cat '"+orphanScript+"'", bssh.Result{Stdout: "# managed by berth\nset -euo pipefail\n"})
	f.On("cat '"+orphanCron+"'", bssh.Result{Stdout: "# managed by berth\n30 3 * * * root bash x\n"})
	f.On("cat '"+backupLogrotatePath+"'", bssh.Result{ExitCode: 1}) // absent

	res, err := (backups{}).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Satisfied {
		t.Fatalf("Check should be unsatisfied (orphans present)")
	}

	f2 := bssh.NewFakeRunner()
	f2.On("ls -1 "+backupScriptGlob+" 2>/dev/null", bssh.Result{Stdout: orphanScript + "\n"})
	f2.On("ls -1 "+backupCronGlob+" 2>/dev/null", bssh.Result{Stdout: orphanCron + "\n"})
	f2.On("ls -1 "+backupManifestGlob+" 2>/dev/null", okResult)
	f2.On("cat '"+orphanScript+"'", bssh.Result{Stdout: "# managed by berth\n"})
	f2.On("cat '"+orphanCron+"'", bssh.Result{Stdout: "# managed by berth\n"})
	f2.On("cat '"+backupLogrotatePath+"'", bssh.Result{ExitCode: 1})
	f2.On("rm -f '"+orphanScript+"'", okResult)
	f2.On("rm -f '"+orphanCron+"'", okResult)
	if err := (backups{}).Apply(context.Background(), provision.RunCtx{}, s, f2); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var removed int
	for _, c := range f2.Calls() {
		if strings.HasPrefix(c.Cmd, "rm -f '/usr/local/sbin/berth-backup-old") || strings.HasPrefix(c.Cmd, "rm -f '/etc/cron.d/berth-backup-old") {
			removed++
		}
	}
	if removed != 2 {
		t.Errorf("removed %d orphans, want 2", removed)
	}
}

func TestBackupsUnmanagedScriptAborts(t *testing.T) {
	// A foreign (non-berth) file at the script path aborts Check without --force.
	s := backupServer()
	site := s.Sites[0]
	f := bssh.NewFakeRunner()
	f.On("cat '"+backupScriptPath(site.Domain)+"'", bssh.Result{Stdout: "#!/bin/sh\necho not berth\n"})
	_, err := (backups{}).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatalf("Check should abort on an unmanaged file without --force")
	}
}

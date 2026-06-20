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
		Database: config.Database{Engine: "mariadb", Name: "myapp", User: "myapp"},
		Backups:  config.Backups{Enabled: true},
		Sites:    []config.Site{{Domain: "app.example.com", DeployPath: "/home/deploy/app"}},
	}
}

// ok is a zero-exit Result.
var okResult = bssh.Result{ExitCode: 0}

func TestBackupsApplyWritesScriptCronDirAndPrereqs(t *testing.T) {
	s := backupServer()
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
	// logrotate fragment validation
	f.On("logrotate -d '"+backupLogrotatePath+"'", okResult)
	// script validation
	f.On("bash -n '"+backupScriptPath(site.Domain)+"'", okResult)
	// orphan scan finds only the desired files
	f.On("ls -1 "+backupScriptGlob+" 2>/dev/null", bssh.Result{Stdout: backupScriptPath(site.Domain) + "\n"})
	f.On("ls -1 "+backupCronGlob+" 2>/dev/null", bssh.Result{Stdout: backupCronPath(site.Domain) + "\n"})

	if err := (backups{}).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wantPaths := map[string]int{backupLogrotatePath: 0o644, backupScriptPath(site.Domain): 0o755, backupCronPath(site.Domain): 0o644}
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
	if !strings.Contains(string(got[backupScriptPath(site.Domain)].Content), "mysqldump --protocol=socket --single-transaction --no-tablespaces --routines --events myapp") {
		t.Errorf("script missing dump command:\n%s", got[backupScriptPath(site.Domain)].Content)
	}
	if !strings.HasPrefix(string(got[backupScriptPath(site.Domain)].Content), "# managed by berth\nset -euo pipefail") {
		t.Errorf("script should start with marker then set -euo pipefail")
	}
}

func TestBackupsCheckSatisfiedInPlace(t *testing.T) {
	s := backupServer()
	site := s.Sites[0]
	eng, _ := dbpkg.Get(s.Database.Engine)
	script, _ := renderBackupScript(s, site, eng)
	cron, _ := renderBackupCron(s, site)
	lr, _ := renderBackupLogrotate()
	f := bssh.NewFakeRunner()
	f.On("cat '"+backupScriptPath(site.Domain)+"'", bssh.Result{Stdout: string(script)})
	f.On("stat -c '%U:%G %a' '"+backupScriptPath(site.Domain)+"'", bssh.Result{Stdout: "root:root 755\n"})
	f.On("cat '"+backupCronPath(site.Domain)+"'", bssh.Result{Stdout: string(cron)})
	f.On("stat -c '%U:%G %a' '"+backupCronPath(site.Domain)+"'", bssh.Result{Stdout: "root:root 644\n"})
	f.On("stat -c '%U:%G %a' '"+backupDir(site.Domain)+"'", bssh.Result{Stdout: "root:root 700\n"})
	f.On("stat -c '%U:%G %a' '"+backupBaseDir+"'", bssh.Result{Stdout: "root:root 755\n"})
	f.On("stat -c '%U:%G %a' '"+backupLogDir+"'", bssh.Result{Stdout: "root:root 755\n"})
	f.On("ls -1 "+backupScriptGlob+" 2>/dev/null", bssh.Result{Stdout: backupScriptPath(site.Domain) + "\n"})
	f.On("ls -1 "+backupCronGlob+" 2>/dev/null", bssh.Result{Stdout: backupCronPath(site.Domain) + "\n"})
	f.On("cat '"+backupLogrotatePath+"'", bssh.Result{Stdout: string(lr)})
	f.On("systemctl is-active cron", okResult)
	f.On("systemctl is-enabled cron", okResult)
	f.On("command -v mysqldump >/dev/null 2>&1", okResult)

	res, err := (backups{}).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.Satisfied {
		t.Errorf("Check not satisfied: %s %v", res.Reason, res.Changes)
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

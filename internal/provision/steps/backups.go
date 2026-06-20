package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

const (
	backupBaseDir       = "/var/backups/berth"
	backupLogDir        = "/var/log/berth"
	backupLogrotatePath = "/etc/logrotate.d/berth-backup"
	backupScriptGlob    = "/usr/local/sbin/berth-backup-*"
	backupCronGlob      = "/etc/cron.d/berth-backup-*"
)

func backupScriptPath(domain string) string {
	return "/usr/local/sbin/berth-backup-" + poolName(domain)
}
func backupCronPath(domain string) string { return "/etc/cron.d/berth-backup-" + poolName(domain) }
func backupDir(domain string) string      { return backupBaseDir + "/" + poolName(domain) }
func backupLogPath(domain string) string {
	return backupLogDir + "/backup-" + poolName(domain) + ".log"
}
func backupLockPath(domain string) string { return backupDir(domain) + "/.lock" }

// dumpClientPackage / dumpClientBinary name the apt package shipping the engine's
// logical-dump tool and the binary the backup script invokes.
func dumpClientPackage(engine string) string {
	if engine == "postgres" {
		return "postgresql-client"
	}
	return "mariadb-client"
}

func dumpClientBinary(engine string) string {
	if engine == "postgres" {
		return "pg_dump"
	}
	return "mysqldump"
}

func renderBackupScript(s *config.Server, site config.Site, eng dbpkg.Engine) ([]byte, error) {
	return templates.Render("backup.sh.tmpl", struct {
		Pool, DumpCommand, DBName, DeployPath, BackupDir, LogFile, LockFile string
		RetentionDays                                                       int
	}{
		Pool:          poolName(site.Domain),
		DumpCommand:   eng.DumpCommand(s.SiteDBName(site)),
		DBName:        s.SiteDBName(site),
		DeployPath:    site.DeployPath,
		BackupDir:     backupDir(site.Domain),
		LogFile:       backupLogPath(site.Domain),
		LockFile:      backupLockPath(site.Domain),
		RetentionDays: s.Backups.RetentionDaysEff(),
	})
}

func renderBackupCron(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("backup.cron.tmpl", struct{ Schedule, ScriptPath string }{
		Schedule:   s.Backups.ScheduleEff(),
		ScriptPath: backupScriptPath(site.Domain),
	})
}

func renderBackupLogrotate() ([]byte, error) {
	return templates.Render("backup_logrotate.conf.tmpl", nil)
}

// managedFileOK reports whether path holds berth's exact desired content. An
// unmanaged conflicting file aborts unless force (managedFileSatisfied policy).
func managedFileOK(ctx context.Context, r bssh.Runner, path string, desired []byte, force bool) (bool, error) {
	state, err := checkManagedFile(ctx, r, path, desired)
	if err != nil {
		return false, err
	}
	return managedFileSatisfied(state, path, force)
}

// statOwnerMode returns "<owner>:<group> <octal-mode>" for path; ok=false if absent.
func statOwnerMode(ctx context.Context, r bssh.Runner, path string) (string, bool, error) {
	res, err := r.Run(ctx, "stat -c '%U:%G %a' "+shQuote(path), nil)
	if err != nil {
		return "", false, err
	}
	if res.ExitCode != 0 {
		return "", false, nil
	}
	return strings.TrimSpace(res.Stdout), true, nil
}

// lsGlob lists files matching glob (one per line); empty when none match.
func lsGlob(ctx context.Context, r bssh.Runner, glob string) ([]string, error) {
	res, err := r.Run(ctx, "ls -1 "+glob+" 2>/dev/null", nil)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		if p := strings.TrimSpace(line); p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// commandExists reports whether bin is on root's PATH (command -v exit 0).
func commandExists(ctx context.Context, r bssh.Runner, bin string) (bool, error) {
	res, err := r.Run(ctx, "command -v "+bin+" >/dev/null 2>&1", nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

type backups struct{}

// Backups installs per-site scheduled local backups: an engine-aware passwordless
// DB dump plus a tar of shared/, pruned by age, driven by one managed root cron +
// script per site. ALWAYS in the pipeline (like System) so disabling backups — per
// site or by removing a site — drift-removes the cron/script it left behind. It runs
// after database (needs the DB) and appdirs (needs shared/); existing archives are
// never deleted on disable.
func Backups() provision.Step { return backups{} }

func (backups) Name() string       { return "backups" }
func (backups) Requires() []string { return []string{"appdirs", "database"} }

func (b backups) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		return provision.CheckResult{}, err
	}
	var changes []string
	desired := map[string]bool{}

	for _, site := range s.Sites {
		if !s.BackupsEnabled(site) {
			continue
		}
		sp, cp := backupScriptPath(site.Domain), backupCronPath(site.Domain)
		desired[sp], desired[cp] = true, true

		script, err := renderBackupScript(s, site, eng)
		if err != nil {
			return provision.CheckResult{}, err
		}
		ok, err := managedFileOK(ctx, r, sp, script, rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, "write "+sp)
		}
		if meta, present, err := statOwnerMode(ctx, r, sp); err != nil {
			return provision.CheckResult{}, err
		} else if present && meta != "root:root 755" {
			changes = append(changes, "fix owner/mode of "+sp)
		}

		cron, err := renderBackupCron(s, site)
		if err != nil {
			return provision.CheckResult{}, err
		}
		ok, err = managedFileOK(ctx, r, cp, cron, rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, "write "+cp)
		}
		if meta, present, err := statOwnerMode(ctx, r, cp); err != nil {
			return provision.CheckResult{}, err
		} else if present && meta != "root:root 644" {
			changes = append(changes, "fix owner/mode of "+cp)
		}

		// Backup dir is root-owned (Decision 1): a root cron must NOT write into a
		// tenant-owned dir (symlink-TOCTOU privesc). root:root 0700.
		if meta, present, err := statOwnerMode(ctx, r, backupDir(site.Domain)); err != nil {
			return provision.CheckResult{}, err
		} else if !present || meta != "root:root 700" {
			changes = append(changes, "create "+backupDir(site.Domain)+" (root:root 700)")
		}
	}

	// Orphan drift-removal: a berth-managed backup script/cron on disk whose path is
	// not desired (site disabled or removed) must be deleted.
	for _, glob := range []string{backupScriptGlob, backupCronGlob} {
		paths, err := lsGlob(ctx, r, glob)
		if err != nil {
			return provision.CheckResult{}, err
		}
		for _, p := range paths {
			if desired[p] {
				continue
			}
			present, err := managedFilePresent(ctx, r, p)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if present {
				changes = append(changes, "remove "+p+" (backups disabled)")
			}
		}
	}

	// Global prerequisites + logrotate fragment.
	if s.AnyBackupsEnabled() {
		// The base dirs are part of desired state and their root:root 0755 ownership
		// is load-bearing: a tenant-writable /var/log/berth or /var/backups/berth
		// would reopen the symlink/entry-replacement vector the per-site root-owned
		// dir closes (Decision 1). Stat them so out-of-band drift is detected, not
		// just absence.
		for _, d := range []string{backupBaseDir, backupLogDir} {
			if meta, present, err := statOwnerMode(ctx, r, d); err != nil {
				return provision.CheckResult{}, err
			} else if !present || meta != "root:root 755" {
				changes = append(changes, "create "+d+" (root:root 755)")
			}
		}
		lr, err := renderBackupLogrotate()
		if err != nil {
			return provision.CheckResult{}, err
		}
		ok, err := managedFileOK(ctx, r, backupLogrotatePath, lr, rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, "write "+backupLogrotatePath)
		}
		if meta, present, err := statOwnerMode(ctx, r, backupLogrotatePath); err != nil {
			return provision.CheckResult{}, err
		} else if present && meta != "root:root 644" {
			changes = append(changes, "fix owner/mode of "+backupLogrotatePath)
		}
		up, err := serviceUp(ctx, r, "cron")
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !up {
			changes = append(changes, "install + enable cron")
		}
		has, err := commandExists(ctx, r, dumpClientBinary(s.Database.Engine))
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !has {
			changes = append(changes, "install "+dumpClientPackage(s.Database.Engine))
		}
	} else {
		present, err := managedFilePresent(ctx, r, backupLogrotatePath)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if present {
			changes = append(changes, "remove "+backupLogrotatePath+" (backups disabled)")
		}
	}

	if len(changes) == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "backups in desired state"}, nil
	}
	return provision.CheckResult{Satisfied: false, Reason: "backups not in desired state", Changes: changes}, nil
}

func (b backups) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		return err
	}

	if s.AnyBackupsEnabled() {
		if err := ensureCron(ctx, r); err != nil {
			return err
		}
		if err := ensureDumpClient(ctx, r, s.Database.Engine); err != nil {
			return err
		}
		for _, d := range []string{backupBaseDir, backupLogDir} {
			if err := runOK(ctx, r, "install -d -o root -g root -m 0755 "+shQuote(d)); err != nil {
				return err
			}
		}
		lr, err := renderBackupLogrotate()
		if err != nil {
			return err
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{Path: backupLogrotatePath, Content: lr, Owner: "root", Group: "root", Mode: 0o644, Sudo: true}); err != nil {
			return fmt.Errorf("write %s: %w", backupLogrotatePath, err)
		}
		// Validate the fragment before trusting the host's logrotate to it (mirrors site.go).
		if err := runOK(ctx, r, "logrotate -d "+shQuote(backupLogrotatePath)); err != nil {
			return fmt.Errorf("backup logrotate fragment failed logrotate -d: %w", err)
		}
	} else if present, err := managedFilePresent(ctx, r, backupLogrotatePath); err != nil {
		return err
	} else if present {
		if err := runOK(ctx, r, "rm -f "+shQuote(backupLogrotatePath)); err != nil {
			return err
		}
	}

	desired := map[string]bool{}
	for _, site := range s.Sites {
		if !s.BackupsEnabled(site) {
			continue
		}
		sp, cp := backupScriptPath(site.Domain), backupCronPath(site.Domain)
		desired[sp], desired[cp] = true, true

		// Root-owned backup dir (Decision 1) — never the site user, so a root cron
		// never writes predictably-named files into a tenant-controlled directory.
		if err := runOK(ctx, r, "install -d -o root -g root -m 0700 "+shQuote(backupDir(site.Domain))); err != nil {
			return err
		}
		script, err := renderBackupScript(s, site, eng)
		if err != nil {
			return err
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{Path: sp, Content: script, Owner: "root", Group: "root", Mode: 0o755, Sudo: true}); err != nil {
			return fmt.Errorf("write %s: %w", sp, err)
		}
		// Validate the generated script before trusting cron to run it (mirrors nginx -t).
		if err := runOK(ctx, r, "bash -n "+shQuote(sp)); err != nil {
			return fmt.Errorf("backup script for %s failed bash -n: %w", site.Domain, err)
		}
		cron, err := renderBackupCron(s, site)
		if err != nil {
			return err
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{Path: cp, Content: cron, Owner: "root", Group: "root", Mode: 0o644, Sudo: true}); err != nil {
			return fmt.Errorf("write %s: %w", cp, err)
		}
	}

	// Orphan removal: a berth-managed backup script/cron not desired by the current config.
	for _, glob := range []string{backupScriptGlob, backupCronGlob} {
		paths, err := lsGlob(ctx, r, glob)
		if err != nil {
			return err
		}
		for _, p := range paths {
			if desired[p] {
				continue
			}
			present, err := managedFilePresent(ctx, r, p)
			if err != nil {
				return err
			}
			if present {
				if err := runOK(ctx, r, "rm -f "+shQuote(p)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ensureCron installs + enables the cron daemon (the /etc/cron.d drop-ins are inert
// without it; basePackages does not include it).
func ensureCron(ctx context.Context, r bssh.Runner) error {
	up, err := serviceUp(ctx, r, "cron")
	if err != nil {
		return err
	}
	if up {
		return nil
	}
	if err := aptInstall(ctx, r, "cron"); err != nil {
		return err
	}
	return runOK(ctx, r, "systemctl enable --now cron")
}

// ensureDumpClient installs the engine's dump client when its binary is absent.
func ensureDumpClient(ctx context.Context, r bssh.Runner, engine string) error {
	has, err := commandExists(ctx, r, dumpClientBinary(engine))
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	return aptInstall(ctx, r, dumpClientPackage(engine))
}

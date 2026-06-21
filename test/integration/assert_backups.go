//go:build integration

package integration

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertBackups verifies the live end state of the backups step. For each site
// with backups enabled it checks the managed root cron + script (owner/mode +
// content + `bash -n`) and the root:root 0700 per-site dir, then RUNS the script
// once and asserts it produced a gzip'd DB dump and a shared/ tarball — both
// root:root 0600 — and that an aged *.gz is pruned by the same run. When any
// site is enabled it also checks the global logrotate fragment. A no-op (beyond
// a no-leftover check) when no site is enabled.
//
// Commands run unprivileged here are auto-elevated by ssh.Client.Run (it wraps
// `sudo -n -- /bin/sh -c …` when connected non-root), so reads of the 0700 dir
// and 0600 archives succeed without an explicit sudo.
func assertBackups(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()

	if !srv.AnyBackupsEnabled() {
		// Disabled everywhere: no berth-managed backup cron/script may linger.
		for _, glob := range []string{"/etc/cron.d/berth-backup-*", "/usr/local/sbin/berth-backup-*"} {
			res, err := c.Run(ctx, "ls -1 "+glob+" 2>/dev/null", nil)
			if err != nil {
				t.Fatalf("ls %s: %v", glob, err)
			}
			if strings.TrimSpace(res.Stdout) != "" {
				t.Errorf("backups disabled but found managed files:\n%s", res.Stdout)
			}
		}
		return
	}

	// Global logrotate fragment: root:root 0644, valid per `logrotate -d`.
	assertStatMode(ctx, t, c, "/etc/logrotate.d/berth-backup", "root:root 644")
	assertExitZero(ctx, t, c, "backup logrotate -d", "logrotate -d /etc/logrotate.d/berth-backup")

	for _, site := range srv.Sites {
		if !srv.BackupsEnabled(site) {
			continue
		}
		pool := config.PoolName(site.Domain)
		script := "/usr/local/sbin/berth-backup-" + pool
		cron := "/etc/cron.d/berth-backup-" + pool
		dir := "/var/backups/berth/" + pool
		db := srv.SiteDBName(site)

		// Managed cron: root:root 0644, invokes the script via `bash`.
		assertStatMode(ctx, t, c, cron, "root:root 644")
		assertExitZero(ctx, t, c, "cron references script "+pool,
			"grep -Fq 'root bash "+script+"' "+cron)

		// Managed script: root:root 0755, syntactically valid.
		assertStatMode(ctx, t, c, script, "root:root 755")
		assertExitZero(ctx, t, c, "backup script bash -n "+pool, "bash -n "+script)

		// Per-site dir: root:root 0700 (Decision 1 — never the site user, so a root
		// cron never creates predictably-named files in a tenant-writable dir).
		assertStatMode(ctx, t, c, dir, "root:root 700")

		// Seed an aged *.gz so the age-based prune has something old to delete.
		staleDays := strconv.Itoa(srv.Backups.RetentionDaysEff() + 3)
		aged := dir + "/berth-aged-prune-test.gz"
		assertExitZero(ctx, t, c, "seed aged archive "+pool,
			fmt.Sprintf("touch -d '%s days ago' %s", staleDays, aged))

		// Run the backup once (it redirects its own output to /var/log/berth, so a
		// clean exit is the signal; a non-zero exit means the dump or tar failed).
		assertExitZero(ctx, t, c, "run backup "+pool, "bash "+script)

		// The DB dump + files tarball must now exist, each root:root 0600.
		dbGlob := dir + "/" + db + "-*.sql.gz"
		filesGlob := dir + "/" + pool + "-files-*.tar.gz"
		assertGlobOwnerMode(ctx, t, c, dbGlob, "root:root 600")
		assertGlobOwnerMode(ctx, t, c, filesGlob, "root:root 600")

		// The DB dump must be a valid gzip stream.
		assertExitZero(ctx, t, c, "db dump valid gzip "+pool,
			"gunzip -t "+dbGlob)

		// The same run must have pruned the aged archive.
		res, err := c.Run(ctx, "test -e "+aged+" && echo present || echo gone", nil)
		if err != nil {
			t.Fatalf("check aged pruned %s: %v", pool, err)
		}
		if strings.TrimSpace(res.Stdout) != "gone" {
			t.Errorf("aged archive %s not pruned (retention %d days)", aged, srv.Backups.RetentionDaysEff())
		}
	}
}

// assertStatMode fails unless `stat -c '%U:%G %a' path` equals want (e.g.
// "root:root 644"). Run auto-elevates, so a 0700 dir / 0600 file is statable.
func assertStatMode(ctx context.Context, t *testing.T, c *bssh.Client, path, want string) {
	t.Helper()
	res, err := c.Run(ctx, "stat -c '%U:%G %a' "+path, nil)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := strings.TrimSpace(res.Stdout); got != want {
		t.Errorf("stat %s = %q, want %q (exit %d, stderr %q)",
			path, got, want, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
}

// assertGlobOwnerMode expands glob (under root, since the dir is 0700) and fails
// unless at least one file matches and every match's owner:group + octal mode
// equal want.
func assertGlobOwnerMode(ctx context.Context, t *testing.T, c *bssh.Client, glob, want string) {
	t.Helper()
	res, err := c.Run(ctx, "stat -c '%U:%G %a' "+glob, nil)
	if err != nil {
		t.Fatalf("stat glob %s: %v", glob, err)
	}
	out := strings.TrimSpace(res.Stdout)
	if res.ExitCode != 0 || out == "" {
		t.Errorf("no file matched %s (exit %d, stderr %q)", glob, res.ExitCode, strings.TrimSpace(res.Stderr))
		return
	}
	for _, ln := range strings.Split(out, "\n") {
		if strings.TrimSpace(ln) != want {
			t.Errorf("file matching %s has perms %q, want %q", glob, strings.TrimSpace(ln), want)
		}
	}
}

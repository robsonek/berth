package status

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func backupSrv() *config.Server {
	return &config.Server{
		ID: "t", Host: "h",
		PHP:      config.PHP{Version: "8.4"},
		Database: config.Database{Engine: "mariadb"},
		Backups:  config.Backups{Enabled: true, Schedule: "30 3 * * *", Retention: 7},
		Sites:    []config.Site{{Domain: "app.example.com"}},
	}
}

func TestProbeBackupsFreshSite(t *testing.T) {
	s := backupSrv()
	// 2026-07-29 03:30 UTC — today's scheduled run.
	newest := time.Date(2026, 7, 29, 3, 30, 0, 0, time.UTC)
	cmd := backupsCmd([]string{"/var/backups/berth/app_example_com"})
	f := bssh.NewFakeRunner().On(cmd, bssh.Result{
		Stdout: "/var/backups/berth/app_example_com\t7\t418000000\t" +
			itoa64(newest.Unix()) + ".0000000000\n"})

	got, err := probeBackups(context.Background(), f, s, time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("probeBackups: %v", err)
	}
	b := got["app.example.com"]
	if !b.Enabled || b.Count != 7 || b.Bytes != 418000000 {
		t.Fatalf("backup = %+v", b)
	}
	if b.Newest == nil || !b.Newest.Equal(newest) {
		t.Errorf("Newest = %v, want %s", b.Newest, newest)
	}
	if b.Stale {
		t.Error("a backup from today's scheduled run must not be stale")
	}
}

func TestProbeBackupsStaleAfterTwoMissedCycles(t *testing.T) {
	s := backupSrv()
	old := time.Date(2026, 7, 26, 3, 30, 0, 0, time.UTC) // three days back
	cmd := backupsCmd([]string{"/var/backups/berth/app_example_com"})
	f := bssh.NewFakeRunner().On(cmd, bssh.Result{
		Stdout: "/var/backups/berth/app_example_com\t7\t1\t" + itoa64(old.Unix()) + ".0\n"})

	got, err := probeBackups(context.Background(), f, s, time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !got["app.example.com"].Stale {
		t.Error("a backup older than two scheduled cycles must be stale")
	}
}

// Yesterday's backup has missed nothing yet — one full cycle of grace means a
// single transient failure does not immediately flag the site.
func TestProbeBackupsOneMissedCycleIsNotStale(t *testing.T) {
	s := backupSrv()
	y := time.Date(2026, 7, 28, 3, 30, 0, 0, time.UTC)
	cmd := backupsCmd([]string{"/var/backups/berth/app_example_com"})
	f := bssh.NewFakeRunner().On(cmd, bssh.Result{
		Stdout: "/var/backups/berth/app_example_com\t7\t1\t" + itoa64(y.Unix()) + ".0\n"})

	got, err := probeBackups(context.Background(), f, s, time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if got["app.example.com"].Stale {
		t.Error("yesterday's backup is within the one-cycle grace window")
	}
}

func TestProbeBackupsEmptyDirectoryIsNotAnError(t *testing.T) {
	s := backupSrv()
	cmd := backupsCmd([]string{"/var/backups/berth/app_example_com"})
	f := bssh.NewFakeRunner().On(cmd, bssh.Result{
		Stdout: "/var/backups/berth/app_example_com\t0\t0\t\n"})

	got, err := probeBackups(context.Background(), f, s, time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	b := got["app.example.com"]
	if b.Newest != nil || b.Count != 0 {
		t.Errorf("backup = %+v, want no artifacts and a nil timestamp", b)
	}
	if !b.Stale {
		t.Error("an enabled site with zero artifacts is stale")
	}
}

// The command itself must select freshness from the completion sidecar. This
// assertion is what actually pins the behaviour: a fixture-only test would
// still pass if backupsCmd regressed to picking the newest arbitrary file,
// because the stub controls the 4th column either way.
func TestBackupsCmdTakesFreshnessFromTheSidecar(t *testing.T) {
	const sidecarName = `-name "$(basename "$d")-meta-*.manifest"`
	cmd := backupsCmd([]string{"/var/backups/berth/app_example_com"})
	if !strings.Contains(cmd, sidecarName) {
		t.Errorf("freshness must come from the completion sidecar:\n%s", cmd)
	}
	// The %T@ selection must be the sidecar find, not the general one.
	i := strings.Index(cmd, "%T@")
	if i < 0 {
		t.Fatalf("no mtime selection in:\n%s", cmd)
	}
	if !strings.Contains(cmd[:i], sidecarName) {
		t.Errorf("the mtime column is not taken from the sidecar find:\n%s", cmd)
	}
	// Half-written artifacts must not even be counted.
	if !strings.Contains(cmd, "! -name '.tmp-*'") {
		t.Errorf("in-progress .tmp-* artifacts must be excluded:\n%s", cmd)
	}
}

// The sidecar pattern must be scoped to the directory's OWN pool: a foreign
// `other-meta-*.manifest` parked in the directory must not supply freshness
// for a backup that never completed.
func TestBackupsCmdScopesSidecarToOwnPool(t *testing.T) {
	cmd := backupsCmd([]string{"/var/backups/berth/app_example_com"})
	if strings.Contains(cmd, "'*-meta-*.manifest'") {
		t.Errorf("the sidecar find accepts any pool's sidecar:\n%s", cmd)
	}
	if !strings.Contains(cmd, `-name "$(basename "$d")-meta-*.manifest"`) {
		t.Errorf("the sidecar pattern must derive from the directory's own pool:\n%s", cmd)
	}
}

// And the parsed result honours it: a stale sidecar keeps the site stale even
// when the directory is full of newer files.
func TestProbeBackupsIgnoresNewerHalfRunArtifacts(t *testing.T) {
	s := backupSrv()
	oldSidecar := time.Date(2026, 7, 26, 3, 30, 0, 0, time.UTC) // three days back
	cmd := backupsCmd([]string{"/var/backups/berth/app_example_com"})
	// count/bytes include the fresh half-run files; freshness does not.
	f := bssh.NewFakeRunner().On(cmd, bssh.Result{
		Stdout: "/var/backups/berth/app_example_com\t9\t500000000\t" + itoa64(oldSidecar.Unix()) + ".0\n"})

	got, err := probeBackups(context.Background(), f, s, time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	b := got["app.example.com"]
	if !b.Stale {
		t.Error("a fresh half-run artifact must not clear staleness — only a completed run does")
	}
	if b.Newest == nil || !b.Newest.Equal(oldSidecar) {
		t.Errorf("Newest = %v, want the sidecar mtime %s", b.Newest, oldSidecar)
	}
}

func TestProbeBackupsDisabledIssuesNoCommand(t *testing.T) {
	s := backupSrv()
	s.Backups.Enabled = false
	f := bssh.NewFakeRunner()
	got, err := probeBackups(context.Background(), f, s, time.Now())
	if err != nil {
		t.Fatalf("probeBackups with backups off: %v", err)
	}
	if len(f.Calls()) != 0 {
		t.Errorf("issued %d commands, want 0", len(f.Calls()))
	}
	if b, ok := got["app.example.com"]; ok && b.Enabled {
		t.Error("site must report backups disabled")
	}
}

func TestProbeBackupsFailsOnNonZeroExit(t *testing.T) {
	s := backupSrv()
	cmd := backupsCmd([]string{"/var/backups/berth/app_example_com"})
	f := bssh.NewFakeRunner().On(cmd,
		bssh.Result{ExitCode: 1, Stderr: "sudo: a password is required\n"})

	got, err := probeBackups(context.Background(), f, s, time.Now())
	if err == nil {
		t.Fatalf("probeBackups = %v, want error on exit 1", got)
	}
	if !strings.Contains(err.Error(), "sudo: a password is required") {
		t.Errorf("error %q does not surface the host's stderr", err)
	}
}

package status

import (
	"context"
	"strings"
	"testing"
	"time"

	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestProbeOffsiteLatestSnapshot(t *testing.T) {
	f := bssh.NewFakeRunner().On(offsiteCmd("prod", ""), bssh.Result{Stdout: `[{"time":"2026-07-29T04:15:11.123456Z","short_id":"a91f2c","hostname":"prod"}]` + "\n"})
	got, err := probeOffsite(context.Background(), f, "prod", "")
	if err != nil {
		t.Fatalf("probeOffsite: %v", err)
	}
	if !got.Configured {
		t.Fatal("want Configured")
	}
	if got.SnapshotID != "a91f2c" {
		t.Errorf("SnapshotID = %q, want a91f2c", got.SnapshotID)
	}
	want := time.Date(2026, 7, 29, 4, 15, 11, 123456000, time.UTC)
	if got.LastSnapshot == nil || !got.LastSnapshot.Equal(want) {
		t.Errorf("LastSnapshot = %v, want %s", got.LastSnapshot, want)
	}
}

// restic's --latest 1 groups by (hostname, paths): a repository holding
// snapshots for this host id under a DIFFERENT path returns one object per
// group. Blindly taking the first let an unrelated backup stand in for a
// missing berth snapshot; the newest must win.
func TestProbeOffsitePicksNewestSnapshot(t *testing.T) {
	f := bssh.NewFakeRunner().On(offsiteCmd("prod", ""), bssh.Result{Stdout: `[` +
		`{"time":"2026-07-25T04:15:11Z","short_id":"aaaaaa"},` +
		`{"time":"2026-07-29T04:15:11Z","short_id":"bbbbbb"}]` + "\n"})
	got, err := probeOffsite(context.Background(), f, "prod", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.SnapshotID != "bbbbbb" {
		t.Errorf("SnapshotID = %q, want the newest snapshot bbbbbb", got.SnapshotID)
	}
	want := time.Date(2026, 7, 29, 4, 15, 11, 0, time.UTC)
	if got.LastSnapshot == nil || !got.LastSnapshot.Equal(want) {
		t.Errorf("LastSnapshot = %v, want %s", got.LastSnapshot, want)
	}
}

// The query must be scoped to the path berth actually backs up
// (offsite.sh.tmpl runs `restic backup /var/backups/berth`): without --path,
// any other backup of the same host id can supply the "latest" snapshot.
func TestProbeOffsiteCommandScopesToBerthPath(t *testing.T) {
	if cmd := offsiteCmd("prod", ""); !strings.Contains(cmd, "--path '/var/backups/berth'") {
		t.Errorf("offsiteCmd must scope the query to berth's backup path:\n%s", cmd)
	}
}

// NOENV means the host env file is missing or unreadable. The caller only
// probes when the CONFIG declares offsite, so this is a real discrepancy —
// berth was told to back up offsite and the host is not set up for it — and it
// must surface as a probe failure, not as a quiet "nothing to report".
func TestProbeOffsiteMissingEnvFileIsAFailure(t *testing.T) {
	f := bssh.NewFakeRunner().On(offsiteCmd("prod", ""), bssh.Result{Stdout: "NOENV\n"})
	got, err := probeOffsite(context.Background(), f, "prod", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Configured {
		t.Errorf("got %+v, want Configured false", got)
	}
	if got.Error == "" {
		t.Error("a missing env file on an offsite-enabled server must be reported, not swallowed")
	}
}

func TestProbeOffsiteEmptyRepository(t *testing.T) {
	f := bssh.NewFakeRunner().On(offsiteCmd("prod", ""), bssh.Result{Stdout: "[]\n"})
	got, err := probeOffsite(context.Background(), f, "prod", "")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Configured || got.LastSnapshot != nil {
		t.Errorf("got %+v, want configured with no snapshot", got)
	}
}

// The probe must never echo the env file: it holds the restic password and
// the S3 credentials.
func TestProbeOffsiteCommandNeverPrintsTheEnv(t *testing.T) {
	// Forbid the forms that would ECHO the file, not the substring "env" —
	// the command legitimately names /etc/berth/offsite.env in order to source it.
	for _, bad := range []string{"cat /etc/berth/offsite.env", "echo $RESTIC_PASSWORD", "printenv", "; env", "&& env"} {
		if strings.Contains(offsiteCmd("prod", ""), bad) {
			t.Errorf("offsiteCmd contains %q — it must never surface secrets", bad)
		}
	}
}

// restic must not write: without --no-cache it populates a local cache, and
// without --no-lock it creates a lock object in the REMOTE repository.
func TestProbeOffsiteCommandIsNonMutating(t *testing.T) {
	for _, want := range []string{"--no-cache", "--no-lock"} {
		if !strings.Contains(offsiteCmd("prod", ""), want) {
			t.Errorf("offsiteCmd missing %q — the probe would write to the repository", want)
		}
	}
}

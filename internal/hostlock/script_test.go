package hostlock

import (
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/version/versiontest"
)

// fixSeams pins every seam HolderLine and Run read, so script keys and
// holder lines are deterministic, and restores them when the test ends.
// Heartbeats are pushed far out unless a test asks for them.
func fixSeams(t *testing.T) {
	t.Helper()
	versiontest.Set(t, "1.0.0")
	oldNow, oldWhoami, oldPid := now, whoami, pid
	oldHeartbeat, oldRelease := heartbeatInterval, releaseWait
	now = func() time.Time { return time.Date(2026, 11, 2, 9, 32, 0, 0, time.UTC) }
	whoami = func() string { return "ops@ws" }
	pid = func() int { return 4711 }
	heartbeatInterval = time.Hour
	releaseWait = time.Second
	t.Cleanup(func() {
		now, whoami, pid = oldNow, oldWhoami, oldPid
		heartbeatInterval, releaseWait = oldHeartbeat, oldRelease
	})
}

// TestLockScriptsAreFrozen pins both lock scripts byte for byte, so any
// accidental drift fails here. Only part of what it pins is a contract
// between berth binaries (spec §5.1): the path, the root:root 0600 file
// prepared only by a mutating run, the flock(2) mechanism through
// `flock -n -E 75` on that exact path, and the content being one line of
// free text. Every future berth binary must take exactly this lock this way —
// flock(2) and POSIX fcntl locks do not exclude each other on Linux, and a
// replaced inode is a different lock — so changing any of that is a BREAKING
// change. The rest (the ready and absent lines, the 90 s lease, the busy-path
// `cat`) is this binary's private protocol with its own held command: it may
// be tuned, updating this pin, without a BREAKING entry.
func TestLockScriptsAreFrozen(t *testing.T) {
	if Path != "/var/lib/berth/session.lock" {
		t.Fatalf("Path = %q — frozen", Path)
	}
	line := "berth v1.0.0 provision by ops@ws (pid 4711) since 2026-11-02T09:32:00Z"
	const tail = `flock -n -E 75 /var/lib/berth/session.lock bash -c 'printf "%s\n" "$1" >/var/lib/berth/session.lock; echo locked; while read -r -t 90 _; do :; done' berth-session 'berth v1.0.0 provision by ops@ws (pid 4711) since 2026-11-02T09:32:00Z'; rc=$?; if [ "$rc" -eq 75 ]; then cat /var/lib/berth/session.lock; fi; exit "$rc"`
	wantMut := `install -d -o root -g root -m 0755 /var/lib/berth && umask 077 && : >>/var/lib/berth/session.lock && chown root:root /var/lib/berth/session.lock && chmod 0600 /var/lib/berth/session.lock || exit 1; ` + tail
	wantRO := `if [ ! -e /var/lib/berth/session.lock ]; then echo absent; exit 0; fi; ` + tail
	if got := Script(Mutating, line); got != wantMut {
		t.Errorf("Script(Mutating) =\n%s\nwant\n%s", got, wantMut)
	}
	if got := Script(ReadOnly, line); got != wantRO {
		t.Errorf("Script(ReadOnly) =\n%s\nwant\n%s", got, wantRO)
	}
}

// TestLockTimingDefaultsAreFrozen pins the heartbeat and release wait the
// 90 s lease in the script is sized against (lease = 4.5 x heartbeat, so a
// couple of late heartbeats never expire a live session). They are this
// binary's private timing, not a contract between binaries: retuning them
// together with the lease updates this pin, never a BREAKING entry.
func TestLockTimingDefaultsAreFrozen(t *testing.T) {
	if heartbeatInterval != 20*time.Second {
		t.Errorf("heartbeatInterval = %s, want 20s", heartbeatInterval)
	}
	if releaseWait != 5*time.Second {
		t.Errorf("releaseWait = %s, want 5s", releaseWait)
	}
}

func TestLockScriptQuotesHolderLine(t *testing.T) {
	got := Script(ReadOnly, "berth v1.0.0 provision by o'brien@ws (pid 1) since x")
	want := `berth-session 'berth v1.0.0 provision by o'\''brien@ws (pid 1) since x';`
	if !strings.Contains(got, want) {
		t.Fatalf("Script(ReadOnly) =\n%s\nwant it to contain\n%s", got, want)
	}
}

func TestHolderLine(t *testing.T) {
	fixSeams(t)
	if got, want := HolderLine("provision --dry-run"), "berth v1.0.0 provision --dry-run by ops@ws (pid 4711) since 2026-11-02T09:32:00Z"; got != want {
		t.Errorf("HolderLine = %q, want %q", got, want)
	}

	// The start time is reported in UTC whatever the workstation's zone.
	now = func() time.Time { return time.Date(2026, 11, 2, 10, 32, 0, 0, time.FixedZone("CET", 3600)) }
	if got, want := HolderLine("status --drift"), "berth v1.0.0 status --drift by ops@ws (pid 4711) since 2026-11-02T09:32:00Z"; got != want {
		t.Errorf("HolderLine (CET clock) = %q, want %q", got, want)
	}

	// A development build reports its raw version string.
	versiontest.Set(t, "dev")
	if got, want := HolderLine("provision"), "berth dev provision by ops@ws (pid 4711) since 2026-11-02T09:32:00Z"; got != want {
		t.Errorf("HolderLine (dev) = %q, want %q", got, want)
	}
}

func TestDefaultWhoamiIsUserAtHost(t *testing.T) {
	got := localIdentity()
	if i := strings.Index(got, "@"); i <= 0 || i == len(got)-1 {
		t.Fatalf("localIdentity() = %q, want user@host", got)
	}
}

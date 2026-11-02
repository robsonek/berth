package hostlock

import (
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/robsonek/berth/internal/version"
)

// Path is the host session lock file. FROZEN (spec §5.1, pinned by
// TestLockScriptsAreFrozen): every berth binary must take exactly this lock,
// with flock(2), on exactly this path, root:root 0600. The mode is part of the
// security model — flock(2) needs only a read descriptor, so a file a tenant
// could open would let that tenant hold every berth session off the host.
const Path = "/var/lib/berth/session.lock"

// The lock script's fixed words (spec §5.1/§5.2). The lease is the held
// command's silence budget: it gives up after leaseSeconds without a
// heartbeat. 4.5 x heartbeatInterval, so a couple of late heartbeats never
// expire a live session; under the ~2 min the SSH transport itself needs to
// declare a silent peer dead (30 s keepalives, 3 misses), so a vanished
// workstation never holds the host longer than berth would wait for it.
const (
	busyCode     = 75
	readyLine    = "locked"
	absentLine   = "absent"
	scriptName   = "berth-session"
	leaseSeconds = 90
)

// Script returns the remote command that takes the host session lock and
// holds it until its stdin closes or stays silent for the lease. The caller
// (Run) holds it with the readyLine; it exits busyCode after printing the
// current holder line when another session holds the lock.
//
// A Mutating run first prepares /var/lib/berth (root:root 0755) and the lock
// file (root:root 0600) — append-creating it, never replacing it: the lock
// lives on the inode, so an install/mv/rm on the path would let two sessions
// hold "the" lock at once. A ReadOnly run creates nothing: with no lock file
// it prints absentLine and exits 0, and the caller runs without a lock.
//
// The holder line is written into the locked file (same inode, truncated in
// place) as free text that only humans read. bash is explicit because
// `read -t` is not POSIX sh. The surface is FROZEN (TestLockScriptsAreFrozen).
func Script(mode Mode, holderLine string) string {
	lease := strconv.Itoa(leaseSeconds)
	busy := strconv.Itoa(busyCode)
	tail := "flock -n -E " + busy + " " + Path +
		` bash -c 'printf "%s\n" "$1" >` + Path + "; echo " + readyLine +
		"; while read -r -t " + lease + " _; do :; done' " +
		scriptName + " " + shQuote(holderLine) +
		`; rc=$?; if [ "$rc" -eq ` + busy + ` ]; then cat ` + Path + `; fi; exit "$rc"`
	if mode == ReadOnly {
		return "if [ ! -e " + Path + " ]; then echo " + absentLine + "; exit 0; fi; " + tail
	}
	return "install -d -o root -g root -m 0755 /var/lib/berth && umask 077 && : >>" + Path +
		" && chown root:root " + Path + " && chmod 0600 " + Path + " || exit 1; " + tail
}

// Seams for HolderLine; tests pin them.
var (
	now    = time.Now
	whoami = localIdentity
	pid    = os.Getpid
)

// HolderLine describes this session for whoever finds the host busy:
// "berth <version> <command> by <user>@<host> (pid <pid>) since <UTC start>".
// It is free text — displayed, never parsed — so its shape may change
// between releases. command names what runs (e.g. "provision --dry-run").
func HolderLine(command string) string {
	return "berth " + binaryVersion() + " " + command + " by " + whoami() +
		" (pid " + strconv.Itoa(pid()) + ") since " + now().UTC().Format(time.RFC3339)
}

// binaryVersion is the canonical form of a parseable build version and the
// raw string of a development build.
func binaryVersion() string {
	if v, ok := version.Binary(); ok {
		return v.String()
	}
	return version.Version
}

// localIdentity is the workstation's user@host; a part that cannot be
// determined reads "unknown".
func localIdentity() string {
	name, host := "unknown", "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		host = h
	}
	return name + "@" + host
}

// shQuote single-quotes s for POSIX sh (same as internal/ssh).
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

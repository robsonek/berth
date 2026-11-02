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
// heartbeat. lease = 4.5 x heartbeatInterval, so a couple of late heartbeats
// never expire a live session; under the ~2 min the SSH transport itself
// needs to declare a silent peer dead (30 s keepalives, 3 misses), so a
// vanished workstation never holds the host longer than berth would wait for
// it.
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
// place) as free text that only humans read, and cleared again (truncated to
// empty in place) when the held command ends — on EOF, at the end of the
// lease, or on HUP/INT/TERM — while it still holds the lock, so a busy
// message never names a session that has finished. The traps are set before
// the line is written. SIGKILL cannot be trapped: a holder killed that way
// (or a host that crashed) leaves its line until the next holder overwrites
// it; the line is displayed, never parsed. An empty file is a valid "no
// details" state — between sessions, and in the instant after a new holder
// took the lock and before it wrote its line. bash is explicit because
// `read -t` is not POSIX sh. Pinned byte for byte by TestLockScriptsAreFrozen;
// only the path, the mode, the flock mechanism and the content (one line of
// free text, or none) are a contract between binaries (see Path) — the rest
// is this binary's own protocol with its held command.
func Script(mode Mode, holderLine string) string {
	lease := strconv.Itoa(leaseSeconds)
	busy := strconv.Itoa(busyCode)
	tail := "flock -n -E " + busy + " " + Path +
		` bash -c 'trap ": >` + Path + `" EXIT; trap "exit 1" HUP INT TERM; printf "%s\n" "$1" >` + Path +
		"; echo " + readyLine + "; while read -r -t " + lease + " _; do :; done' " +
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

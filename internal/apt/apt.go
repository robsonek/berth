// Package apt installs Debian packages from the stock repos or a pinned upstream.
package apt

import (
	"context"
	"fmt"
	"strings"
	"time"

	bssh "github.com/robsonek/berth/internal/ssh"
)

// aptLockSleep is the pause between apt-lock retries; a package var so tests can
// stub it to return immediately.
var aptLockSleep = func() { time.Sleep(5 * time.Second) }

// aptLockMaxAttempts bounds the wait for a concurrent apt holder to release
// (5s × 120 ≈ 10 min, matching berth's DPkg::Lock::Timeout philosophy).
const aptLockMaxAttempts = 120

// repoIndexRetries bounds how many times EnsureRepo re-verifies that a freshly
// added upstream source actually indexed before failing loud. An upstream mirror
// or CDN can transiently fail to index; a later attempt may succeed.
const repoIndexRetries = 3

// repoIndexSleep is the pause between repo-index retries; a package var so tests
// stub it to return immediately.
var repoIndexSleep = func() { time.Sleep(3 * time.Second) }

// isAptLockBusy reports whether an apt failure is transient lock contention
// (another process holds the dpkg/lists lock) rather than a real error.
// DPkg::Lock::Timeout makes apt wait for the dpkg/archives locks, but NOT for
// apt-get update's separate lists lock, so a freshly-booted box's
// unattended-upgrades can still fail an update instantly; we wait it out.
func isAptLockBusy(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "could not get lock") ||
		strings.Contains(s, "unable to lock") ||
		strings.Contains(s, "is held by process")
}

// runAptWaitingForLock runs an apt command, retrying only while it fails purely
// because another process holds an apt lock. Any other non-zero exit is a real
// error surfaced immediately.
func (m *Manager) runAptWaitingForLock(ctx context.Context, cmd, what string) error {
	for attempt := 1; ; attempt++ {
		res, err := m.r.Run(ctx, cmd, nil)
		if err != nil {
			return err
		}
		if res.ExitCode == 0 {
			return nil
		}
		if isAptLockBusy(res.Stderr) && attempt < aptLockMaxAttempts {
			aptLockSleep()
			continue
		}
		return fmt.Errorf("%s: %s", what, res.Stderr)
	}
}

// Repo describes a pinned third-party apt repository.
type Repo struct {
	Name        string // e.g. "sury-php"
	URI         string
	Suite       string
	Components  []string
	KeyURL      string
	Fingerprint string // pinned; EnsureRepo aborts on mismatch
}

// Sury returns the Ondřej Surý PHP repository definition for Debian 13 (used by
// the php step when php.source selects it, e.g. for PHP versions Debian does not
// ship). Fingerprint is the full 40-hex DEB.SURY.ORG signing key.
func Sury() Repo {
	return Repo{
		Name:        "sury-php",
		URI:         "https://packages.sury.org/php/",
		Suite:       "trixie",
		Components:  []string{"main"},
		KeyURL:      "https://packages.sury.org/php/apt.gpg",
		Fingerprint: "15058500A0235D97F5D10063B188E2B695BD4743",
	}
}

// NginxOrg returns the official nginx.org mainline repository for Debian 13,
// used by the nginx step when nginx.source is "nginx". Fingerprint is the full
// 40-hex nginx signing key.
func NginxOrg() Repo {
	return Repo{
		Name:        "nginx-org",
		URI:         "https://nginx.org/packages/mainline/debian/",
		Suite:       "trixie",
		Components:  []string{"nginx"},
		KeyURL:      "https://nginx.org/keys/nginx_signing.key",
		Fingerprint: "8540A6F18833A80E9C1653A42FD21310B49F6B46",
	}
}

// PostgresPGDG returns the official PostgreSQL Global Development Group (PGDG)
// repository for Debian 13, used by the database step when database.source is
// "pgdg". Fingerprint is the full 40-hex PGDG signing key.
func PostgresPGDG() Repo {
	return Repo{
		Name:        "pgdg",
		URI:         "https://apt.postgresql.org/pub/repos/apt/",
		Suite:       "trixie-pgdg",
		Components:  []string{"main"},
		KeyURL:      "https://www.postgresql.org/media/keys/ACCC4CF8.asc",
		Fingerprint: "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8",
	}
}

// MariaDBOrg returns the official MariaDB 12.3 LTS repository for Debian 13, used
// by the database step when database.source is "mariadb". The URI is dlm.mariadb.com
// (MariaDB's official download-manager endpoint, the one their own mariadb_repo_setup
// configures) rather than the deb.mariadb.org MirrorBrain redirector: the redirector
// geo-routes to third-party mirrors that are frequently unreachable, which made the
// install silently fall back to Debian's package; dlm.mariadb.com serves the identical
// signed repo from a reliable CDN. Fingerprint is the full 40-hex MariaDB release
// signing key (the 12.3 repo is signed by the same key as 11.8; the key bundle also
// carries a newer key for rotation).
func MariaDBOrg() Repo {
	return Repo{
		Name:        "mariadb-org",
		URI:         "https://dlm.mariadb.com/repo/mariadb-server/12.3/repo/debian/",
		Suite:       "trixie",
		Components:  []string{"main"},
		KeyURL:      "https://mariadb.org/mariadb_release_signing_key.asc",
		Fingerprint: "177F4010FE56CA3336300305F1656F24C74CD1D8",
	}
}

// Manager installs packages over an ssh.Runner.
type Manager struct{ r bssh.Runner }

func New(r bssh.Runner) *Manager { return &Manager{r: r} }

// EnsureRepo installs the signing key, verifies its fingerprint, and writes the
// source with signed-by. It aborts on a fingerprint mismatch.
func (m *Manager) EnsureRepo(ctx context.Context, repo Repo) error {
	keyring := "/usr/share/keyrings/" + repo.Name + ".gpg"
	// Fetch the signing key from its published URL and dearmor it into a keyring.
	dl := fmt.Sprintf("curl -fsSL %s | gpg --dearmor --yes -o %s", repo.KeyURL, keyring)
	if res, err := m.r.Run(ctx, dl, nil); err != nil {
		return fmt.Errorf("download key for %s: %w", repo.Name, err)
	} else if res.ExitCode != 0 {
		return fmt.Errorf("download key for %s: %s", repo.Name, res.Stderr)
	}
	res, err := m.r.Run(ctx, "gpg --show-keys --with-colons "+keyring, nil)
	if err != nil {
		return fmt.Errorf("read key for %s: %w", repo.Name, err)
	}
	if !strings.Contains(res.Stdout, repo.Fingerprint) {
		return fmt.Errorf("repo %s: key fingerprint does not match pinned %s", repo.Name, repo.Fingerprint)
	}
	src := fmt.Sprintf("deb [signed-by=%s] %s %s %s\n",
		keyring, repo.URI, repo.Suite, strings.Join(repo.Components, " "))
	if err := m.r.WriteFile(ctx, bssh.FileSpec{
		Path:    "/etc/apt/sources.list.d/" + repo.Name + ".list",
		Content: []byte(src), Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write source: %w", err)
	}
	if err := m.runAptWaitingForLock(ctx, "apt-get update", "apt-get update after adding "+repo.Name); err != nil {
		return err
	}
	// Guard against silent Debian fallback: `apt-get update` exits 0 even when a
	// source fails to download (it "ignores" it), so a dead upstream would let the
	// later install resolve to Debian's package. Re-update ONLY this source with
	// Error-Mode=any (non-zero iff THIS source failed), retrying — a transient
	// upstream/CDN hiccup may clear on a later attempt. After repoIndexRetries, fail loud.
	// apt-lock contention is waited out separately (another apt process can grab the
	// lock between the full update above and this one) and is NOT an index failure.
	//
	// APT::Get::List-Cleanup=0 is LOAD-BEARING, not optional: restricting the source
	// set to this one repo (sourceparts=-) makes apt treat every OTHER source as
	// unconfigured and, by default, prune their downloaded lists from
	// /var/lib/apt/lists — so the immediately-following install would lose Debian
	// main (unresolvable deps, "held broken packages"). Disabling the cleanup keeps
	// the other sources' lists intact while still indexing this one for the exit code.
	verify := fmt.Sprintf(
		"apt-get update -o Dir::Etc::sourcelist=sources.list.d/%s.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any",
		repo.Name)
	var last string
	indexAttempts, lockAttempts := 0, 0
	for {
		res, err := m.r.Run(ctx, verify, nil)
		if err != nil {
			return err
		}
		if res.ExitCode == 0 {
			return nil
		}
		if isAptLockBusy(res.Stderr) {
			lockAttempts++
			if lockAttempts >= aptLockMaxAttempts {
				return fmt.Errorf("verify index for %s: %s", repo.Name, res.Stderr)
			}
			aptLockSleep()
			continue
		}
		indexAttempts++
		if last = res.Stderr; last == "" {
			last = res.Stdout // apt prints Err:/acquisition lines on stdout
		}
		if indexAttempts >= repoIndexRetries {
			break
		}
		repoIndexSleep()
	}
	return fmt.Errorf("upstream repo %s (%s) failed to index after %d attempts; refusing to install the Debian fallback (last: %s)",
		repo.Name, repo.URI, repoIndexRetries, last)
}

// EnsurePackages installs packages non-interactively from the stock repos (or
// from any upstream repo already registered via EnsureRepo). The non-interactive
// frontend keeps existing conffiles, so an upstream-repo upgrade of a stock
// package does not hang on a prompt. A non-zero apt exit is surfaced as an error.
func (m *Manager) EnsurePackages(ctx context.Context, _ *Repo, pkgs ...string) error {
	cmd := "DEBIAN_FRONTEND=noninteractive apt-get install -y " + strings.Join(pkgs, " ")
	return m.runAptWaitingForLock(ctx, cmd, "apt-get install "+strings.Join(pkgs, " "))
}

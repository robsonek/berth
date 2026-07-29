// Package apt installs Debian packages from the stock repos or a pinned upstream.
package apt

import (
	"context"
	"fmt"
	"strings"
	"time"

	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

// UserRepoPrefix namespaces the source lists and keyrings of user-declared
// repos (config block `apt.repos`): /etc/apt/sources.list.d/berth-<name>.list.
// It is the sweep-discovery namespace of the `apt` step and is FROZEN by
// contract test — changing it would orphan every deployed user-repo file.
const UserRepoPrefix = "berth-"

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

// SourceListPath is the apt source file EnsureRepo writes this repo to; steps
// probe its presence to know the configured upstream source is in effect.
func (r Repo) SourceListPath() string { return "/etc/apt/sources.list.d/" + r.Name + ".list" }

// KeyringPath is the dearmored, pinned keyring EnsureRepo installs for this
// repo — the signed-by anchor of its source line.
func (r Repo) KeyringPath() string { return "/usr/share/keyrings/" + r.Name + ".gpg" }

// SourceContent returns the managed bytes of this repo's .list file (marker +
// one-line deb entry): the single source for EnsureRepo's write and for every
// step Check's drift comparison.
func (r Repo) SourceContent() ([]byte, error) {
	return templates.Render("apt_source.list.tmpl", map[string]string{
		"Keyring":    r.KeyringPath(),
		"URI":        r.URI,
		"Suite":      r.Suite,
		"Components": strings.Join(r.Components, " "),
	})
}

// LegacySourceContents returns every EXACT marker-less byte variant berth has
// ever shipped for this repo (index 0 = the current constructor values) — the
// adoption allowlist that lets ANY pre-E1 host upgrade its source list
// without --force, including hosts provisioned by older releases. APPEND-ONLY
// and FROZEN by contract test: entries are a compatibility promise, not an
// implementation detail.
func (r Repo) LegacySourceContents() []string {
	line := func(uri string) string {
		return fmt.Sprintf("deb [signed-by=%s] %s %s %s\n",
			r.KeyringPath(), uri, r.Suite, strings.Join(r.Components, " "))
	}
	out := []string{line(r.URI)}
	for _, uri := range legacyRepoURIs[r.Name] {
		out = append(out, line(uri))
	}
	return out
}

// legacyRepoURIs holds the URIs of PAST releases per repo name (the current
// URI is derived from the constructor and deliberately not repeated here).
// APPEND-ONLY: MariaDB shipped deb.mariadb.org 11.8, then deb.mariadb.org
// 12.3, then the current dlm.mariadb.com endpoint; suites/components never
// changed. The other repos never changed at all.
var legacyRepoURIs = map[string][]string{
	"mariadb-org": {
		"https://deb.mariadb.org/12.3/debian/",
		"https://deb.mariadb.org/11.8/debian/",
	},
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

// primaryFingerprints returns the primary-key fingerprints in
// `gpg --show-keys --with-colons` output: the fpr record immediately following
// a pub record. Subkey fingerprints (fpr after sub) are ignored — apt's
// signed-by trust is anchored at primary keys.
func primaryFingerprints(colons string) []string {
	var out []string
	prevPub := false
	for _, line := range strings.Split(colons, "\n") {
		fields := strings.Split(line, ":")
		if fields[0] == "fpr" && prevPub && len(fields) > 9 {
			out = append(out, fields[9])
		}
		prevPub = fields[0] == "pub"
	}
	return out
}

// KeyringHoldsExactly reports whether the repo's installed keyring exists and
// holds EXACTLY the pinned primary key. Part of every Check's repo
// convergence: a config fingerprint change, a truncated/extra-key keyring, or
// a crash between the keyring and list writes must re-trigger EnsureRepo —
// never read as satisfied.
func (m *Manager) KeyringHoldsExactly(ctx context.Context, repo Repo) (bool, error) {
	res, err := m.r.Run(ctx, "gpg --show-keys --with-colons "+repo.KeyringPath(), nil)
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, nil // absent or unreadable keyring: not converged
	}
	prims := primaryFingerprints(res.Stdout)
	if len(prims) == 0 {
		return false, nil
	}
	for _, fp := range prims {
		if fp != repo.Fingerprint {
			return false, nil
		}
	}
	return true, nil
}

// shQuote single-quotes s for safe interpolation into a root shell command
// (mirrors the ssh/steps helpers). Constructor values are constants, but
// user-declared repos put config-derived URLs on the curl command line —
// quoting at the SINK is the shell-safety boundary; config validation is
// only a UX layer and must never be relied on for that.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// UpdateIndexes refreshes the apt package indexes, waiting out lock
// contention. Callers that removed sources use it to prune their lists.
func (m *Manager) UpdateIndexes(ctx context.Context) error {
	return m.runAptWaitingForLock(ctx, "apt-get update", "apt-get update")
}

// RemoveRepo deletes the repo's source list and keyring, then refreshes the
// indexes so the removed source's downloaded lists are pruned. Callers decide
// WHETHER removal is due (marker/ownership classification lives in the
// steps); this helper only executes it. If the update fails AFTER the rm the
// step fails loudly and the next run's preflight (AlwaysRun, re-runs apt-get
// update every run) prunes the stale lists — no retry journal needed.
func (m *Manager) RemoveRepo(ctx context.Context, repo Repo) error {
	if res, err := m.r.Run(ctx, "rm -f "+repo.SourceListPath()+" "+repo.KeyringPath(), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("remove repo %s: %s", repo.Name, res.Stderr)
	}
	return m.runAptWaitingForLock(ctx, "apt-get update", "apt-get update after removing "+repo.Name)
}

// EnsureRepo installs the signing key, verifies it against the pinned
// fingerprint, and writes the source with signed-by. The trusted keyring ends
// up holding EXACTLY the pinned key: signed-by trusts every key in the file,
// so a multi-key bundle (e.g. MariaDB publishes a rotation key alongside the
// release key) must not land in it wholesale — an extra key smuggled into the
// published bundle would otherwise sign Release files unnoticed. A future key
// rotation therefore fails loud until the pin is updated, by design.
func (m *Manager) EnsureRepo(ctx context.Context, repo Repo) error {
	keyring := repo.KeyringPath()
	// Temp files live in a root-owned 0700 workdir under /run: predictable names
	// in world-writable /tmp would let a local user pre-create or symlink them
	// before root writes through the path.
	tmpKey := "/run/berth/key-" + repo.Name
	tmpRing := "/run/berth/keyring-" + repo.Name + ".gpg"
	tmpOut := "/run/berth/pinned-" + repo.Name + ".gpg"
	if res, err := m.r.Run(ctx, "install -d -m 700 /run/berth", nil); err != nil {
		return fmt.Errorf("create key workdir for %s: %w", repo.Name, err)
	} else if res.ExitCode != 0 {
		return fmt.Errorf("create key workdir for %s: %s", repo.Name, res.Stderr)
	}
	// Download to a file so curl's exit code surfaces a failed fetch directly.
	// (Piping into gpg would take gpg's exit code — 0 even on empty stdin — and
	// the failure would only show up later as a misleading fingerprint error.)
	// The URL is quoted at the sink and placed after `--` (option-parsing stop):
	// E1 makes KeyURL config-derived, so it must never splice into the root
	// shell or masquerade as a curl option.
	if res, err := m.r.Run(ctx, "curl -fsSL -o "+tmpKey+" -- "+shQuote(repo.KeyURL), nil); err != nil {
		return fmt.Errorf("download key for %s: %w", repo.Name, err)
	} else if res.ExitCode != 0 {
		return fmt.Errorf("download key for %s: %s", repo.Name, res.Stderr)
	}
	// Normalize to a binary keyring (handles armored and binary keys alike).
	if res, err := m.r.Run(ctx, "gpg --yes -o "+tmpRing+" --dearmor "+tmpKey, nil); err != nil {
		return fmt.Errorf("dearmor key for %s: %w", repo.Name, err)
	} else if res.ExitCode != 0 {
		return fmt.Errorf("dearmor key for %s: %s", repo.Name, res.Stderr)
	}
	// Extract only the pinned key into a STAGING keyring.
	if res, err := m.r.Run(ctx, "gpg --no-default-keyring --keyring "+tmpRing+" --yes -o "+tmpOut+" --export "+repo.Fingerprint, nil); err != nil {
		return fmt.Errorf("extract pinned key for %s: %w", repo.Name, err)
	} else if res.ExitCode != 0 {
		return fmt.Errorf("extract pinned key for %s: %s", repo.Name, res.Stderr)
	}
	// Verify the STAGING keyring holds exactly the pinned primary key; only
	// then install it at the trusted path. An aborted run never leaves an
	// unverified file under /usr/share/keyrings. `--export` of an absent
	// fingerprint writes nothing, so show-keys failing (or listing no primary
	// key) means the bundle did not contain the pinned key at all.
	res, err := m.r.Run(ctx, "gpg --show-keys --with-colons "+tmpOut, nil)
	if err != nil {
		return fmt.Errorf("read key for %s: %w", repo.Name, err)
	}
	prims := primaryFingerprints(res.Stdout)
	if res.ExitCode != 0 || len(prims) == 0 {
		return fmt.Errorf("repo %s: pinned key fingerprint %s not found in the downloaded bundle", repo.Name, repo.Fingerprint)
	}
	for _, fp := range prims {
		if fp != repo.Fingerprint {
			return fmt.Errorf("repo %s: keyring contains unpinned key fingerprint %s (pinned %s)", repo.Name, fp, repo.Fingerprint)
		}
	}
	if res, err := m.r.Run(ctx, "install -m 0644 "+tmpOut+" "+keyring, nil); err != nil {
		return fmt.Errorf("install keyring for %s: %w", repo.Name, err)
	} else if res.ExitCode != 0 {
		return fmt.Errorf("install keyring for %s: %s", repo.Name, res.Stderr)
	}
	// Temp cleanup; only a transport error matters (leftover tmp files are inert).
	if _, err := m.r.Run(ctx, "rm -f "+tmpKey+" "+tmpRing+" "+tmpOut, nil); err != nil {
		return err
	}
	src, err := repo.SourceContent()
	if err != nil {
		return fmt.Errorf("render source for %s: %w", repo.Name, err)
	}
	if err := m.r.WriteFile(ctx, bssh.FileSpec{
		Path:    repo.SourceListPath(),
		Content: src, Mode: 0o644, Sudo: true,
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
	// Roll back the just-written source: an unindexable repo must not linger
	// as a trusted source (Check would otherwise read list+keyring as
	// converged while the index verification never succeeded). Best-effort —
	// the error below is the primary signal either way.
	_, _ = m.r.Run(ctx, "rm -f "+repo.SourceListPath()+" "+repo.KeyringPath(), nil)
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

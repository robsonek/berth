package steps

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// Own-repo declarative helpers (E1). berth's four upstream repos (sury-php,
// nginx-org, mariadb-org, pgdg) are managed files like everything else: when
// the config selects the upstream source the list must be berth-managed and
// byte-exact (pre-E1 marker-less lists adopt via the exact-bytes allowlist);
// when the config returns to the stock source, a lingering berth-owned list
// is drift and is removed. A foreign file is respected in BOTH directions:
// upstream-selected -> abort unless --force (standard managed-file policy),
// stock-selected -> left alone (retention asymmetry: false-keep is cheap,
// false-delete destroys operator intent).

// aptListStrictlyManaged reports whether content's FIRST LINE is exactly the
// hash marker. Deletion paths use this INSTEAD of hasManagedMarker: the
// generic helper also accepts the INI variant ("; managed by berth"), which
// berth never writes into a .list — a foreign file claiming it must stay
// foreign where the consequence is an rm (E3 retention asymmetry). The
// overwrite path (checkManagedFileAdopt) keeps the tool-wide semantics.
func aptListStrictlyManaged(content string) bool {
	line, _, _ := strings.Cut(content, "\n")
	return line == managedMarker
}

// The host keeps the copy of a repo's signing key fetched when the repo was
// registered. Upstreams extend a key's validity under the SAME fingerprint
// (Surý has done so repeatedly), so a pinned-fingerprint check alone would
// keep an old copy forever and apt would start rejecting the repository the
// day that copy expires. keyRefreshWindow is how long before expiry berth
// starts re-fetching the key; keyRefreshInterval spaces the attempts, keyed
// on the keyring file's mtime (every EnsureRepo installs a fresh file), so a
// host whose upstream has not published the extension yet reads as converged
// between attempts instead of re-running the step on every provision.
const (
	keyRefreshWindow   = 180 * 24 * time.Hour
	keyRefreshInterval = 7 * 24 * time.Hour
)

// timeNow is the clock the key-refresh policy reads; a var so tests pin it.
var timeNow = time.Now

// keyExpiringSoon reports whether the keyring's key expires inside the
// refresh window (or already has).
func keyExpiringSoon(info apt.KeyringInfo, now time.Time) bool {
	return !info.Expires.IsZero() && info.Expires.Sub(now) <= keyRefreshWindow
}

// keyRefreshDue reports whether an expiring key's copy is old enough to
// fetch again: the keyring file was last written at least keyRefreshInterval
// ago. An unreadable or unparsable mtime reads as due — re-fetching is the
// safe side.
func keyRefreshDue(ctx context.Context, r bssh.Runner, repo apt.Repo, now time.Time) (bool, error) {
	res, err := r.Run(ctx, "stat -c %Y "+shQuote(repo.KeyringPath()), nil)
	if err != nil {
		return false, err
	}
	secs, parseErr := strconv.ParseInt(strings.TrimSpace(res.Stdout), 10, 64)
	if unreadable := res.ExitCode != 0 || parseErr != nil; unreadable {
		return true, nil // not a failure: re-fetching is the safe answer
	}
	return now.Sub(time.Unix(secs, 0)) >= keyRefreshInterval, nil
}

// keyringConverged reports whether the repo's installed keyring holds
// exactly the pinned key and no key refresh is due; refresh reports that the
// keyring is exact and the refresh is the only thing missing. Shared by
// berth's own repos and the declared ones (aptextras.go).
func keyringConverged(ctx context.Context, r bssh.Runner, repo apt.Repo) (converged, refresh bool, err error) {
	now := timeNow()
	info, err := apt.New(r).Keyring(ctx, repo, now)
	if err != nil || !info.Exact {
		return false, false, err
	}
	if !keyExpiringSoon(info, now) {
		return true, false, nil
	}
	due, err := keyRefreshDue(ctx, r, repo, now)
	if err != nil {
		return false, false, err
	}
	return !due, due, nil
}

// warnIfKeyStillExpiring runs after a key refresh: when the freshly fetched
// key still expires inside the window, the upstream has not published an
// extension yet — the operator is warned with the date, and berth tries
// again after keyRefreshInterval.
func warnIfKeyStillExpiring(ctx context.Context, rc provision.RunCtx, r bssh.Runner, repo apt.Repo) error {
	now := timeNow()
	info, err := apt.New(r).Keyring(ctx, repo, now)
	if err != nil {
		return err
	}
	if keyExpiringSoon(info, now) {
		rc.Warnf("the %s repository signing key on this host expires on %s and the upstream has not published an extended key yet; berth fetches it again on a provision after %d days — once the key expires, apt rejects this repository",
			repo.Name, info.Expires.UTC().Format("2006-01-02"), int(keyRefreshInterval.Hours()/24))
	}
	return nil
}

// ownRepoState classifies the repo: converged reports whether its source
// list is berth-managed and byte-exact AND its pinned keyring holds exactly
// the pinned key AND no key refresh is due; refresh reports that the only
// thing missing is that refresh. Absent/drifted/legacy states return
// converged=false with a nil error — Apply reconciles via EnsureRepo. A
// foreign file returns the abort-unless---force error. The keyring probe is
// semantic (apt.Keyring), not mere existence: a config fingerprint change or
// a half-written keyring must re-trigger Apply.
func ownRepoState(ctx context.Context, r bssh.Runner, repo apt.Repo, force bool) (converged, refresh bool, err error) {
	want, err := repo.SourceContent()
	if err != nil {
		return false, false, err
	}
	state, err := checkManagedFileAdopt(ctx, r, repo.SourceListPath(), want, repo.LegacySourceContents())
	if err != nil {
		return false, false, err
	}
	ok, err := managedFileSatisfied(state, repo.SourceListPath(), force)
	if err != nil || !ok {
		return false, false, err
	}
	return keyringConverged(ctx, r, repo)
}

// ownRepoUpToDate reports whether the repo is converged (see ownRepoState).
func ownRepoUpToDate(ctx context.Context, r bssh.Runner, repo apt.Repo, force bool) (bool, error) {
	converged, _, err := ownRepoState(ctx, r, repo, force)
	return converged, err
}

// ensureOwnRepo is the Apply-side twin of ownRepoUpToDate: it re-classifies
// the live state immediately before writing (the writeManagedFile doctrine —
// Check's verdict may be stale, and Apply often runs for UNRELATED drift, so
// the write path must enforce the abort-unless---force contract itself) and
// runs EnsureRepo only when the repo is not converged. When the run was a
// key refresh and the freshly fetched key still expires inside the window,
// the upstream has not published an extension yet: the operator is warned
// with the date, and berth tries again after keyRefreshInterval.
func ensureOwnRepo(ctx context.Context, rc provision.RunCtx, r bssh.Runner, repo apt.Repo) error {
	ok, refresh, err := ownRepoState(ctx, r, repo, rc.Force)
	if err != nil || ok {
		return err
	}
	if err := apt.New(r).EnsureRepo(ctx, repo); err != nil {
		return err
	}
	if !refresh {
		return nil
	}
	return warnIfKeyStillExpiring(ctx, rc, r, repo)
}

// ownRepoLingers reports whether a berth-OWNED upstream source list sits at
// the repo's frozen path while the config no longer selects that source.
// Only a strict-marker list or EXACT bytes of any shipped pre-E1 variant
// count as berth's; anything else is a foreign file and never a removal
// candidate.
func ownRepoLingers(ctx context.Context, r bssh.Runner, repo apt.Repo) (bool, error) {
	res, err := r.Run(ctx, "cat "+shQuote(repo.SourceListPath()), nil)
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, nil
	}
	if aptListStrictlyManaged(res.Stdout) {
		return true, nil
	}
	for _, legacy := range repo.LegacySourceContents() {
		if res.Stdout == legacy {
			return true, nil
		}
	}
	return false, nil
}

// removeOwnRepo sweeps a lingering upstream repo (list + keyring + index
// refresh) and warns that already-installed packages keep their upstream
// versions — apt never auto-downgrades; the README documents the manual
// recipe. Re-probes ownership itself so Apply can call it unconditionally on
// the stock-source path.
func removeOwnRepo(ctx context.Context, rc provision.RunCtx, r bssh.Runner, repo apt.Repo) error {
	lingers, err := ownRepoLingers(ctx, r, repo)
	if err != nil || !lingers {
		return err
	}
	if err := apt.New(r).RemoveRepo(ctx, repo); err != nil {
		return err
	}
	rc.Warnf("removed upstream repo %s (%s); already-installed packages keep their upstream versions until manually downgraded — see README", repo.Name, repo.URI)
	return nil
}

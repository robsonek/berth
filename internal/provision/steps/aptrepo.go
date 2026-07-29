package steps

import (
	"context"
	"strings"

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

// ownRepoUpToDate reports whether the repo's source list is berth-managed and
// byte-exact AND its pinned keyring holds exactly the pinned key. Absent/
// drifted/legacy states return (false, nil) — Apply reconciles via
// EnsureRepo. A foreign file returns the abort-unless---force error. The
// keyring probe is semantic (KeyringHoldsExactly), not mere existence: a
// config fingerprint change or a half-written keyring must re-trigger Apply.
func ownRepoUpToDate(ctx context.Context, r bssh.Runner, repo apt.Repo, force bool) (bool, error) {
	want, err := repo.SourceContent()
	if err != nil {
		return false, err
	}
	state, err := checkManagedFileAdopt(ctx, r, repo.SourceListPath(), want, repo.LegacySourceContents())
	if err != nil {
		return false, err
	}
	ok, err := managedFileSatisfied(state, repo.SourceListPath(), force)
	if err != nil || !ok {
		return false, err
	}
	return apt.New(r).KeyringHoldsExactly(ctx, repo)
}

// ensureOwnRepo is the Apply-side twin of ownRepoUpToDate: it re-classifies
// the live state immediately before writing (the writeManagedFile doctrine —
// Check's verdict may be stale, and Apply often runs for UNRELATED drift, so
// the write path must enforce the abort-unless---force contract itself) and
// runs EnsureRepo only when the repo is not converged.
func ensureOwnRepo(ctx context.Context, rc provision.RunCtx, r bssh.Runner, repo apt.Repo) error {
	ok, err := ownRepoUpToDate(ctx, r, repo, rc.Force)
	if err != nil || ok {
		return err
	}
	return apt.New(r).EnsureRepo(ctx, repo)
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

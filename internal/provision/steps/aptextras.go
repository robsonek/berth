package steps

import (
	"context"
	"fmt"
	gopath "path"
	"regexp"
	"strings"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// aptUserListsCmd discovers the source lists of user-declared repos: every
// list this step writes lives at /etc/apt/sources.list.d/berth-<name>.list
// (apt.UserRepoPrefix), so the name pattern is the sweep-discovery namespace.
// find (not ls): it exits 0 with empty output when nothing matches, so a
// NON-zero exit is a real failure and surfaces as an error instead of
// masquerading as "no files" and silently skipping the sweep. -print0 keeps a
// hostile filename with an embedded newline from splitting into phantom
// entries. A clean host with an empty apt: block pays exactly this one probe.
const aptUserListsCmd = "find /etc/apt/sources.list.d -maxdepth 1 -name 'berth-*.list' -print0"

// reAptUserListBase is the canonical shape of a berth-written user list
// filename. Anything else inside the namespace (berth-.list, uppercase,
// over-long) is FOREIGN by definition — berth never wrote it, so the sweep
// must not own it, and its paired .gpg must never be derived and removed.
var reAptUserListBase = regexp.MustCompile(`^berth-[a-z0-9][a-z0-9-]{0,31}\.list$`)

// Apt reconciles the config's apt: block — user-declared third-party
// repositories (fully declarative: undeclared berth-managed lists are swept
// with their keyrings) and extra packages (INSTALL-ONLY: berth installs
// missing ones and never uninstalls — no ledger). ALWAYS registered, so a
// config that drops its apt: block still sweeps the leftovers.
func Apt() provision.Step { return aptExtras{} }

// aptExtras deliberately isn't named `apt`: that would shadow the package.
type aptExtras struct{}

func (aptExtras) Name() string { return "apt" }

// Requires: base installs curl + gnupg, which EnsureRepo needs.
func (aptExtras) Requires() []string { return []string{"base"} }

// userRepo maps a validated config entry onto its on-host identity.
func userRepo(cfg config.AptRepo) apt.Repo {
	return apt.Repo{
		Name:        apt.UserRepoPrefix + cfg.Name,
		URI:         cfg.URI,
		Suite:       cfg.Suite,
		Components:  cfg.ComponentsEff(),
		KeyURL:      cfg.KeyURL,
		Fingerprint: strings.ToUpper(cfg.Fingerprint),
	}
}

// discoverUserLists returns the berth-namespaced source lists on the host.
// A non-zero find exit is a REAL error (permission/fs failure), never "no
// matches" — find exits 0 with empty output for those.
func discoverUserLists(ctx context.Context, r bssh.Runner) ([]string, error) {
	res, err := r.Run(ctx, aptUserListsCmd, nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("discover berth apt source lists: %s", res.Stderr)
	}
	var out []string
	for _, p := range strings.Split(res.Stdout, "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// sweepCandidates splits the namespace's undeclared files into berth-owned
// (sweep targets) and foreign (never touched — not even with --force; the
// scheduler-cron precedent). Ownership of the list+keyring PAIR requires
// BOTH the canonical filename shape AND the strict hash marker as the first
// line (aptListStrictlyManaged — the generic marker helper also accepts the
// INI variant berth never writes into a .list, and a deletion path must not
// honor an impostor). The paired keyring is only ever derived from an owned
// list, so a foreign keyring can never be deleted through this step.
func (aptExtras) sweepCandidates(ctx context.Context, r bssh.Runner, s *config.Server) (managed, foreign []string, err error) {
	lists, err := discoverUserLists(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	declared := map[string]bool{}
	for _, cfg := range s.Apt.Repos {
		declared[apt.UserRepoPrefix+cfg.Name] = true
	}
	for _, path := range lists {
		base := gopath.Base(path)
		name := strings.TrimSuffix(base, ".list")
		if declared[name] {
			continue
		}
		if !reAptUserListBase.MatchString(base) {
			foreign = append(foreign, path)
			continue
		}
		res, err := r.Run(ctx, "cat "+shQuote(path), nil)
		if err != nil {
			return nil, nil, err
		}
		if res.ExitCode == 0 && aptListStrictlyManaged(res.Stdout) {
			managed = append(managed, path)
		} else {
			foreign = append(foreign, path)
		}
	}
	return managed, foreign, nil
}

func (a aptExtras) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	m := apt.New(r)
	var changes []string
	sweep, _, err := a.sweepCandidates(ctx, r, s)
	if err != nil {
		return provision.CheckResult{}, err
	}
	for _, path := range sweep {
		changes = append(changes, "remove undeclared repo "+strings.TrimSuffix(gopath.Base(path), ".list")+" (.list + keyring)")
	}
	for _, cfg := range s.Apt.Repos {
		repo := userRepo(cfg)
		want, err := repo.SourceContent()
		if err != nil {
			return provision.CheckResult{}, err
		}
		state, err := checkManagedFile(ctx, r, repo.SourceListPath(), want)
		if err != nil {
			return provision.CheckResult{}, err
		}
		ok, err := managedFileSatisfied(state, repo.SourceListPath(), rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, "register repo "+cfg.Name+" ("+cfg.URI+")")
			continue
		}
		// Semantic keyring probe (not mere existence): a fingerprint change
		// in the config or a half-written keyring must re-trigger Apply.
		keyOK, err := m.KeyringHoldsExactly(ctx, repo)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !keyOK {
			changes = append(changes, "restore keyring for repo "+cfg.Name)
		}
	}
	missing, err := missingPackages(ctx, r, s.Apt.Packages)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if len(missing) > 0 {
		changes = append(changes, "install packages: "+strings.Join(missing, " "))
	}
	if len(changes) == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "declared apt repos and packages converged; no undeclared berth-managed repos"}, nil
	}
	return provision.CheckResult{Satisfied: false, Reason: "declared apt repos/packages not converged, or undeclared berth-managed repos linger", Changes: changes}, nil
}

// missingPackages returns the declared packages dpkg does not report installed.
func missingPackages(ctx context.Context, r bssh.Runner, pkgs []string) ([]string, error) {
	var missing []string
	for _, p := range pkgs {
		inst, err := pkgInstalled(ctx, r, p)
		if err != nil {
			return nil, err
		}
		if !inst {
			missing = append(missing, p)
		}
	}
	return missing, nil
}

func (a aptExtras) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	m := apt.New(r)
	// 1. Sweep undeclared berth-managed lists (+ their paired keyrings), then
	// refresh indexes ONCE. Foreign files in the namespace are respected and
	// only warned about (opportunistically — the warning fires when Apply
	// runs for any reason; a fully-converged host never reaches it).
	sweep, foreign, err := a.sweepCandidates(ctx, r, s)
	if err != nil {
		return err
	}
	for _, path := range foreign {
		rc.Warnf("foreign file %s sits in berth's apt namespace (no managed marker): left untouched — remove or rename it manually", path)
	}
	if len(sweep) > 0 {
		for _, path := range sweep {
			ghost := apt.Repo{Name: strings.TrimSuffix(gopath.Base(path), ".list")}
			if res, err := r.Run(ctx, "rm -f "+shQuote(ghost.SourceListPath())+" "+shQuote(ghost.KeyringPath()), nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("remove undeclared repo %s: %s", ghost.Name, res.Stderr)
			}
		}
		if err := m.UpdateIndexes(ctx); err != nil {
			return err
		}
	}
	// 2. Declared repos: EnsureRepo for every absent/drifted one (each call
	// pins the key and verifies the source indexed).
	for _, cfg := range s.Apt.Repos {
		repo := userRepo(cfg)
		want, err := repo.SourceContent()
		if err != nil {
			return err
		}
		state, err := checkManagedFile(ctx, r, repo.SourceListPath(), want)
		if err != nil {
			return err
		}
		ok, err := managedFileSatisfied(state, repo.SourceListPath(), rc.Force)
		if err != nil {
			return err
		}
		if ok {
			keyOK, err := m.KeyringHoldsExactly(ctx, repo)
			if err != nil {
				return err
			}
			if keyOK {
				continue
			}
		}
		if err := m.EnsureRepo(ctx, repo); err != nil {
			return fmt.Errorf("register apt repo %s: %w", cfg.Name, err)
		}
	}
	// 3. Packages — install-only by design.
	missing, err := missingPackages(ctx, r, s.Apt.Packages)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		if err := m.EnsurePackages(ctx, nil, missing...); err != nil {
			return fmt.Errorf("install apt.packages: %w", err)
		}
	}
	return nil
}

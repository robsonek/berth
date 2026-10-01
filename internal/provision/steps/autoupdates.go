package steps

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

// phpUpstream returns the Surý repo and whether this config installs PHP from
// it. The php step and upstreamRepos both go through here, so base's
// unattended-upgrades drop-in can never disagree with the installed source.
// The repo is returned even when unused: the removal branch needs it.
func phpUpstream(s *config.Server) (apt.Repo, bool, error) {
	used, err := useSury(s.PHP)
	return apt.Sury(), used, err
}

// nginxUpstream returns the nginx.org repo and whether the nginx step installs
// from it.
func nginxUpstream(s *config.Server) (apt.Repo, bool) {
	return apt.NginxOrg(), s.Nginx.Source == "nginx"
}

// databaseUpstream returns the engine's producer repo, whether the engine has
// one, and whether the config installs from it (any database.source other
// than "debian").
func databaseUpstream(eng dbpkg.Engine, s *config.Server) (repo apt.Repo, has bool, used bool) {
	repo, has = eng.UpstreamRepo()
	return repo, has, has && s.Database.Source != "debian"
}

// upstreamRepos returns berth's own upstream apt repos this config installs
// from, in a fixed order (sury, nginx, database) — composed from the same
// per-component functions the php, nginx and database steps use.
func upstreamRepos(s *config.Server) ([]apt.Repo, error) {
	var repos []apt.Repo
	sury, used, err := phpUpstream(s)
	if err != nil {
		return nil, err
	}
	if used {
		repos = append(repos, sury)
	}
	if repo, used := nginxUpstream(s); used {
		repos = append(repos, repo)
	}
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		return nil, err
	}
	if repo, _, used := databaseUpstream(eng, s); used {
		repos = append(repos, repo)
	}
	return repos, nil
}

// unattendedOriginsPath is base's drop-in extending unattended-upgrades to the
// upstream repos the config uses. It sorts after the stock
// 50unattended-upgrades; apt.conf list values accumulate across files, so the
// stock Debian patterns stay in force.
const unattendedOriginsPath = "/etc/apt/apt.conf.d/52berth-unattended-upgrades"

// upstreamBlacklist holds the Package-Blacklist entries a repo's
// default-tracking metapackages need (Python regexes, matched by
// unattended-upgrades with re.match). Unversioned names in Sury and PGDG
// follow the repo's DEFAULT major; upgrading one would install a second PHP
// branch / PostgreSQL major beside the running one. MariaDB (series-pinned
// URI) and nginx.org (a single package) need none. Verified against the
// 2026-09-30 indexes — see the spec before touching these.
var upstreamBlacklist = map[string][]string{
	"sury-php": {`php(?![0-9])(?!.*common)(-.+)?$`, `libapache2-mod-php$`, `libphp-embed$`},
	"pgdg":     {`postgresql(?!.*common)(?!.*-[0-9][0-9.]*(-|$))(-.+)?$`},
}

// unattendedOriginsData is the apt_unattended_origins.conf.tmpl input.
type unattendedOriginsData struct {
	Patterns  []string
	Blacklist []string
}

// originPattern is the Origins-Pattern entry for one upstream repo: its signed
// Release's Origin, its codename (Suite) and its site (URI host).
func originPattern(r apt.Repo) string {
	return "origin=" + r.Origin + ",codename=" + r.Suite + ",site=" + r.Site()
}

// renderUnattendedOrigins renders the drop-in for repos; nil, nil for an empty
// set (berth then keeps no file). A repo without a pinned Origin or a parsable
// site is refused: its pattern would match nothing, silently.
func renderUnattendedOrigins(repos []apt.Repo) ([]byte, error) {
	if len(repos) == 0 {
		return nil, nil
	}
	var d unattendedOriginsData
	for _, r := range repos {
		if r.Origin == "" || r.Site() == "" {
			return nil, fmt.Errorf("repo %s has no pinned Origin or site; refusing to render an unmatchable unattended-upgrades pattern", r.Name)
		}
		d.Patterns = append(d.Patterns, originPattern(r))
		d.Blacklist = append(d.Blacklist, upstreamBlacklist[r.Name]...)
	}
	return templates.Render("apt_unattended_origins.conf.tmpl", d)
}

// checkUnattendedOrigins classifies base's origins drop-in against the config.
// Read-only: the only probe is `cat` of the path. The string is the plan line
// when the file needs work, "" when satisfied. With no upstream repo in use, a
// berth-managed file is due for removal while an absent or FOREIGN file is
// fine — in that branch a foreign file is never berth's to touch, not even
// with --force.
func checkUnattendedOrigins(ctx context.Context, r bssh.Runner, s *config.Server, force bool) (bool, string, error) {
	repos, err := upstreamRepos(s)
	if err != nil {
		return false, "", err
	}
	want, err := renderUnattendedOrigins(repos)
	if err != nil {
		return false, "", err
	}
	if want == nil {
		present, err := managedFilePresent(ctx, r, unattendedOriginsPath)
		if err != nil {
			return false, "", err
		}
		if present {
			return false, "remove " + unattendedOriginsPath + " (no upstream repo in use)", nil
		}
		return true, "", nil
	}
	state, err := checkManagedFile(ctx, r, unattendedOriginsPath, want)
	if err != nil {
		return false, "", err
	}
	ok, err := managedFileSatisfied(state, unattendedOriginsPath, force)
	if err != nil || ok {
		return ok, "", err
	}
	names := make([]string, 0, len(repos))
	for _, repo := range repos {
		names = append(names, repo.Name)
	}
	return false, "write " + unattendedOriginsPath + " (unattended-upgrades origins: " + strings.Join(names, ", ") + ")", nil
}

// aptConfigValidateCmd proves candidate drop-in bytes (on stdin) parse with
// apt's own configuration parser — the one every apt invocation uses — before
// they are published. It is ONE remote shell: the candidate lands in a unique
// mktemp file inside berth's root-owned state dir (outside every apt parts
// directory, so no concurrent apt run can read it), and the trap removes it on
// every exit path, including a dropped SSH session (HUP) or an interrupt. Only
// a host that dies mid-command can leave the candidate behind, and nothing
// ever reads it there.
var aptConfigValidateCmd = "install -d -o root -g root -m 0755 " + berthStateDir +
	` && t=$(mktemp ` + berthStateDir + `/unattended-upgrades.XXXXXX) && trap 'rm -f "$t"' EXIT HUP INT TERM && cat > "$t" && apt-config -c "$t" dump >/dev/null`

// applyUnattendedOrigins reconciles base's origins drop-in. A syntax error in
// apt.conf.d breaks EVERY apt operation — including the next run's preflight
// `apt-get update`, which runs before base could repair it — so the bytes are
// validated first and only then published through the normal atomic managed
// write. On any failure the previous file stays exactly as it was.
func applyUnattendedOrigins(ctx context.Context, r bssh.Runner, s *config.Server, force bool) error {
	repos, err := upstreamRepos(s)
	if err != nil {
		return err
	}
	want, err := renderUnattendedOrigins(repos)
	if err != nil {
		return err
	}
	if want == nil {
		present, err := managedFilePresent(ctx, r, unattendedOriginsPath)
		if err != nil || !present {
			return err
		}
		return runOK(ctx, r, "rm -f "+shQuote(unattendedOriginsPath))
	}
	// Refuse a foreign target BEFORE validating anything (writeManagedFile
	// re-checks at publish time — the Apply-reclassifies doctrine).
	if err := assertManagedWritable(ctx, r, force, unattendedOriginsPath); err != nil {
		return err
	}
	res, err := r.Run(ctx, aptConfigValidateCmd, want)
	if err != nil {
		return fmt.Errorf("validate %s (not published; the previous file is untouched): %w", unattendedOriginsPath, err)
	}
	if res.ExitCode != 0 {
		// Neutral wording: any stage of the one-shell command can fail (install
		// -d, mktemp, cat, a signal), and `apt-config -c` parses the whole
		// config, so a broken foreign fragment elsewhere fails it too.
		msg := fmt.Sprintf("validation of the rendered %s failed (exit %d; not published, the previous file is untouched)", unattendedOriginsPath, res.ExitCode)
		if stderr := strings.TrimSpace(res.Stderr); stderr != "" {
			msg += ": " + stderr
		}
		return errors.New(msg)
	}
	return writeManagedFile(ctx, r, force, bssh.FileSpec{
		Path: unattendedOriginsPath, Content: want, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	})
}

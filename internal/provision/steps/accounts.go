package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

const (
	sudoersBerthPath = "/etc/sudoers.d/berth"
	sudoersBerthBody = managedMarker + "\nberth ALL=(ALL) NOPASSWD:ALL\n"
)

type accounts struct{}

func Accounts() provision.Step { return accounts{} }

func (accounts) Name() string       { return "accounts" }
func (accounts) Requires() []string { return []string{"base"} }

// siteUsers returns the distinct OS users that own/run the sites, in site order.
// Single-site keeps the legacy shared "deploy"; multi-site isolates per site.
func siteUsers(s *config.Server) []string {
	var users []string
	seen := map[string]bool{}
	for _, site := range s.Sites {
		u := s.SiteUser(site)
		if !seen[u] {
			seen[u] = true
			users = append(users, u)
		}
	}
	return users
}

// managedAccounts is every account berth owns: the provisioning account plus the
// per-site application users.
func managedAccounts(s *config.Server) []string {
	return append([]string{"berth"}, siteUsers(s)...)
}

func sudoersPath(user string) string { return "/etc/sudoers.d/" + user }

func authorizedKeysPath(user string) string {
	return fmt.Sprintf("/home/%s/.ssh/authorized_keys", user)
}

// renderSiteSudoers renders the narrow per-site deploy sudoers (reload its
// php-fpm version + manage only its own supervisor program), as the site user.
//
// The '*' in the supervisorctl grants is ESCAPED (\*) on purpose. In sudoers, an
// unescaped '*' is an fnmatch wildcard that matches ACROSS WHITESPACE, so a site
// user could append another tenant's program to the command
// (e.g. `supervisorctl restart berth-a\:* berth-b\:*`) and the `berth-a\:*` rule
// would still match — silently acting on berth-b too. Escaping to a literal
// `berth-<prog>:*` removes the wildcard, so sudoers requires an EXACT (same
// arg-count) match and denies any extra target. This preserves per-tenant
// isolation; the deployer still works because it passes the literal `:*` group
// form. Do not "simplify" `\:\*` back to `\:*` — that reopens the cross-tenant
// control hole.
func renderSiteSudoers(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("sudoers_deploy.tmpl", struct {
		User, PHPVersion string
		Programs         []string
	}{User: s.SiteUser(site), PHPVersion: s.PHP.Version, Programs: s.SiteProgramNames(site)})
}

// authorizedKeys is the managed authorized_keys body for an account: the berth
// marker plus the operator's public key.
func authorizedKeys(operatorKey string) []byte {
	return []byte(managedMarker + "\n" + operatorKey + "\n")
}

func userExists(ctx context.Context, r bssh.Runner, user string) (bool, error) {
	res, err := r.Run(ctx, "id "+user, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

func sudoersValid(ctx context.Context, r bssh.Runner, path string) (bool, error) {
	res, err := r.Run(ctx, "visudo -cf "+shQuote(path), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

func (a accounts) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	operatorKey, err := operatorPublicKey(s.SSH.Key)
	if err != nil {
		return provision.CheckResult{}, err
	}
	want := authorizedKeys(operatorKey)

	// Desired sudoers body per managed account: berth's full grant plus each
	// site user's narrow per-program grant. Content-drift (not just existence) so
	// a changed program list converges on an already-provisioned host.
	sudoersWant := map[string][]byte{"berth": []byte(sudoersBerthBody)}
	for _, site := range s.Sites {
		body, err := renderSiteSudoers(s, site)
		if err != nil {
			return provision.CheckResult{}, err
		}
		sudoersWant[s.SiteUser(site)] = body
	}

	for _, u := range managedAccounts(s) {
		ok, err := userExists(ctx, r, u)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			return provision.CheckResult{Satisfied: false, Reason: "account " + u + " missing", Changes: a.changes()}, nil
		}
		// sudoers carries the managed marker and matches the desired content.
		p := sudoersPath(u)
		state, err := checkManagedFile(ctx, r, p, sudoersWant[u])
		if err != nil {
			return provision.CheckResult{}, err
		}
		okSudo, err := managedFileSatisfied(state, p, rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !okSudo {
			return provision.CheckResult{Satisfied: false, Reason: p + " not up to date", Changes: a.changes()}, nil
		}
		// authorized_keys carries the managed marker + the expected key.
		state, err = checkManagedFile(ctx, r, authorizedKeysPath(u), want)
		if err != nil {
			return provision.CheckResult{}, err
		}
		okKey, err := managedFileSatisfied(state, authorizedKeysPath(u), rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !okKey {
			return provision.CheckResult{Satisfied: false, Reason: u + " authorized_keys not up to date", Changes: a.changes()}, nil
		}
	}
	return provision.CheckResult{Satisfied: true, Reason: "accounts, sudoers and keys present"}, nil
}

func (a accounts) changes() []string {
	return []string{
		"create the berth account and one OS user per site",
		"write /etc/sudoers.d/<account> (berth: full; site users: narrow)",
		"install operator key into each authorized_keys; per-site deploy keys",
	}
}

func (a accounts) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	operatorKey, err := operatorPublicKey(s.SSH.Key)
	if err != nil {
		return err
	}
	want := authorizedKeys(operatorKey)

	// 1) Create every managed account with a private (0700) home.
	for _, u := range managedAccounts(s) {
		if err := ensureUser(ctx, r, u); err != nil {
			return err
		}
	}

	// 2) berth: full NOPASSWD sudo.
	if err := writeValidatedSudoers(ctx, r, sudoersBerthPath, []byte(sudoersBerthBody)); err != nil {
		return err
	}

	// 3) Per-site users: narrow sudoers (validated).
	for _, site := range s.Sites {
		body, err := renderSiteSudoers(s, site)
		if err != nil {
			return fmt.Errorf("render sudoers for %s: %w", site.Domain, err)
		}
		if err := writeValidatedSudoers(ctx, r, sudoersPath(s.SiteUser(site)), body); err != nil {
			return err
		}
	}

	// 4) Install the operator key into every account.
	for _, u := range managedAccounts(s) {
		if err := installAuthorizedKey(ctx, r, u, want); err != nil {
			return err
		}
	}

	// 5) Per-site deploy keys (only sites with a repository).
	for _, site := range s.Sites {
		if err := a.ensureDeployKey(ctx, s, site, r); err != nil {
			return err
		}
	}
	return nil
}

// ensureUser creates the account (idempotent) and locks its home to 0700.
// A pre-existing account may be a reserved system user whose home is not
// /home/<user> (e.g. Debian's stock "sync" with home /bin); berth's whole
// layout (authorized_keys, deploy keys, appdirs) assumes /home/<user>, so we
// refuse such a collision with an actionable error instead of blindly operating
// on a path that may not exist.
func ensureUser(ctx context.Context, r bssh.Runner, user string) error {
	ok, err := userExists(ctx, r, user)
	if err != nil {
		return err
	}
	if !ok {
		res, err := r.Run(ctx, "useradd -m -s /bin/bash "+user, nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("create user %s: %s", user, res.Stderr)
		}
	}
	home, err := userHome(ctx, r, user)
	if err != nil {
		return err
	}
	if want := "/home/" + user; home != want {
		return fmt.Errorf("user %s already exists with home %q, not %q — it is likely a reserved system account; choose a different sites[].user", user, home, want)
	}
	// Private, present home (idempotent: create if missing, own it, lock to
	// 0700) so one site user cannot traverse into another's home.
	if res, err := r.Run(ctx, fmt.Sprintf("install -d -o %s -g %s -m 700 %s", user, user, shQuote("/home/"+user)), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("lock home for %s: %s", user, res.Stderr)
	}
	return nil
}

// userHome returns the account's home directory from its passwd entry
// (field 6 of name:x:uid:gid:gecos:home:shell).
func userHome(ctx context.Context, r bssh.Runner, user string) (string, error) {
	res, err := r.Run(ctx, "getent passwd "+user, nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("getent passwd %s: exit %d", user, res.ExitCode)
	}
	fields := strings.Split(strings.TrimSpace(res.Stdout), ":")
	if len(fields) < 7 {
		return "", fmt.Errorf("unexpected passwd entry for %s: %q", user, res.Stdout)
	}
	return fields[5], nil
}

// writeValidatedSudoers writes a sudoers drop-in (mode 0440) and validates it.
func writeValidatedSudoers(ctx context.Context, r bssh.Runner, path string, body []byte) error {
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: path, Content: body, Owner: "root", Group: "root", Mode: 0o440, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if valid, err := sudoersValid(ctx, r, path); err != nil {
		return err
	} else if !valid {
		return fmt.Errorf("%s failed visudo -cf validation", path)
	}
	return nil
}

// installAuthorizedKey creates ~/.ssh and writes the managed authorized_keys.
func installAuthorizedKey(ctx context.Context, r bssh.Runner, user string, want []byte) error {
	sshDir := fmt.Sprintf("/home/%s/.ssh", user)
	if res, err := r.Run(ctx, fmt.Sprintf("install -d -o %s -g %s -m 700 %s", user, user, shQuote(sshDir)), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("create %s: %s", sshDir, res.Stderr)
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: authorizedKeysPath(user), Content: want,
		Owner: user, Group: user, Mode: 0o600, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s authorized_keys: %w", user, err)
	}
	return nil
}

// ensureDeployKey generates a deploy SSH key under the site user's ~/.ssh and
// scans the Git host into that user's known_hosts, only when the site has a
// repository.
func (accounts) ensureDeployKey(ctx context.Context, s *config.Server, site config.Site, r bssh.Runner) error {
	if site.Repository == "" {
		return nil
	}
	host, err := config.GitHost(site.Repository)
	if err != nil {
		return fmt.Errorf("parse git host from %q: %w", site.Repository, err)
	}
	user := s.SiteUser(site)
	keyPath := fmt.Sprintf("/home/%s/.ssh/id_ed25519", user)
	exists, err := fileExists(ctx, r, keyPath)
	if err != nil {
		return err
	}
	if !exists {
		gen := fmt.Sprintf("sudo -u %s ssh-keygen -t ed25519 -N '' -f %s -C %s",
			user, shQuote(keyPath), shQuote(user+"@"+host))
		if res, err := r.Run(ctx, gen, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("ssh-keygen for %s: %s", user, res.Stderr)
		}
	}
	knownHosts := fmt.Sprintf("/home/%s/.ssh/known_hosts", user)
	scan := fmt.Sprintf("sudo -u %s sh -c %s", user,
		shQuote(fmt.Sprintf("ssh-keygen -F %s -f %s >/dev/null 2>&1 || ssh-keyscan %s >> %s", host, knownHosts, host, knownHosts)))
	if res, err := r.Run(ctx, scan, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("ssh-keyscan %s: %s", host, res.Stderr)
	}
	return nil
}

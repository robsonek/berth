package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// acmeWebroot is the dedicated ACME challenge root for a domain. It is owned by
// www-data so certbot's --webroot mode can write challenge files, kept separate
// from the application's deploy_path (design §6.4).
func acmeWebroot(domain string) string {
	return "/var/www/berth-acme/" + domain
}

type appDirs struct{}

// AppDirs creates the per-site deployment directories and ACME webroot BEFORE any
// secret is persisted, so seeding shared/.env (the database step) has a place to
// write (design §6.4). Each site's directories are owned by that site's OS user
// for isolation: deploy_path is <user>:www-data mode 0710 (nginx/www-data may
// traverse to public/, other site users cannot), shared/ is <user>:<user> 0700.
// shared/tmp backs the site's FPM sys_temp_dir/upload_tmp_dir so PHP never
// stages uploads or temp files in the world-readable shared /tmp.
func AppDirs() provision.Step { return appDirs{} }

func (appDirs) Name() string       { return "appdirs" }
func (appDirs) Requires() []string { return []string{"accounts"} }

// noSymlinkInPath reports whether every EXISTING component of p — each prefix
// from the first component under / down to p itself — is a real directory:
// not a symlink and not any other file type. berth's root-run `install -d`
// follows a directory symlink to its target and applies ownership there, so a
// tenant who owns an ancestor of p (e.g. their own prior deploy_path after a
// migration) could plant a symlink to redirect the chown at /etc. A
// non-directory ancestor must be refused too: it would make the owner guard's
// stat fail with ENOTDIR and read as "absent" — fail-open. A non-existent
// component passes, so a fresh path is created normally. (`test -d` follows
// symlinks, but `test ! -L` short-circuits first.)
func noSymlinkInPath(ctx context.Context, r bssh.Runner, p string) (bool, error) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := ""
	var tests []string
	for _, part := range parts {
		cur += "/" + part
		q := shQuote(cur)
		tests = append(tests, "{ test ! -e "+q+" || { test ! -L "+q+" && test -d "+q+"; }; }")
	}
	res, err := r.Run(ctx, strings.Join(tests, " && "), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// assertNoSymlinkAt fails loudly if any existing component of p is a symlink
// or not a directory (see noSymlinkInPath).
func assertNoSymlinkAt(ctx context.Context, r bssh.Runner, domain, p string) error {
	ok, err := noSymlinkInPath(ctx, r, p)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("refusing to create directories for %s: a component of %s is a symlink or not a directory; a tenant may have planted a symlink so root's install -d chowns the target — remove the offending path before re-running", domain, p)
	}
	return nil
}

// assertNoSymlinkDeployTree covers a site's deploy tree: probing the deepest
// deploy target covers deploy_path, shared and shared/tmp and all their
// ancestors in one probe. The accounts step runs this too — its owner probe
// must never read inodes through a tenant-planted symlink, and --only
// accounts never reaches appdirs.
func assertNoSymlinkDeployTree(ctx context.Context, r bssh.Runner, site config.Site) error {
	return assertNoSymlinkAt(ctx, r, site.Domain, site.DeployPath+"/shared/tmp")
}

// assertNoSymlinkTargets is the appdirs-wide variant: the deploy tree plus
// the site's ACME webroot.
func assertNoSymlinkTargets(ctx context.Context, r bssh.Runner, s *config.Server, site config.Site) error {
	if err := assertNoSymlinkDeployTree(ctx, r, site); err != nil {
		return err
	}
	return assertNoSymlinkAt(ctx, r, site.Domain, acmeWebroot(site.Domain))
}

// assertSiteTreeOwners fails loudly when an EXISTING per-site directory
// (deploy_path, shared, shared/tmp) is owned by a different user than the
// configured/derived site user, or is not a directory at all. Adopting such
// a tree silently would be a lie: install -d -o re-owns only the directory
// itself, never its contents (the app would still 500 on an unreadable
// shared/.env), and the previous account, its deploy key and its sudoers
// entry would linger as orphans. Absent paths pass — a fresh provision
// creates them. Deliberately NOT bypassable with --force (like the symlink
// guard): after a deliberate migration the owner matches and the guard
// passes on its own. The probe is guard-specific (%U owner name, %u uid,
// %F type — type last, it contains spaces): GNU stat prints UNKNOWN for %U
// when the uid has no passwd entry, so the uid is captured too, and the pin
// suggestion is offered only for owners that are valid sites[].user
// candidates. %F is localized via gettext, so the probe pins LC_ALL=C.
func assertSiteTreeOwners(ctx context.Context, r bssh.Runner, s *config.Server, site config.Site) error {
	user := s.SiteUser(site)
	for _, p := range []string{site.DeployPath, site.DeployPath + "/shared", site.DeployPath + "/shared/tmp"} {
		res, err := r.Run(ctx, "LC_ALL=C stat -c '%U %u %F' "+shQuote(p), nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			// Absent. The path-chain assertion already proved every existing
			// component is a real directory, so a nonzero exit here means
			// ENOENT — barring a mid-run race or IO failure (consciously
			// accepted; tracked with the deferred TOCTOU item).
			continue
		}
		fields := strings.Fields(strings.TrimSpace(res.Stdout))
		if len(fields) < 3 {
			return fmt.Errorf("unexpected stat output probing %s: %q", p, strings.TrimSpace(res.Stdout))
		}
		owner, uid, ftype := fields[0], fields[1], strings.Join(fields[2:], " ")
		if ftype != "directory" {
			return fmt.Errorf("refusing to manage site %s: %s exists but is not a directory (%s) — inspect and remove it before re-running", site.Domain, p, ftype)
		}
		if owner != user {
			hint := "migrate the tree deliberately (create the target account first, chown the tree, move the deploy key, then run a full provision — see the site identity note in the README)"
			if config.IsValidSiteOSUser(owner) {
				hint = fmt.Sprintf("pin sites[].user: %q to keep the existing identity, or %s", owner, hint)
			}
			return fmt.Errorf("refusing to manage site %s: %s is owned by %s (uid %s) but the configured site user is %q; %s", site.Domain, p, owner, uid, user, hint)
		}
	}
	return nil
}

func (a appDirs) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	// Safety preflight over EVERY site before any drift verdict: the drift
	// loop below returns at the first unsatisfied entry, and a later site's
	// foreign-owned tree must fail the whole run loudly (also in dry-run).
	for _, site := range s.Sites {
		if err := assertNoSymlinkTargets(ctx, r, s, site); err != nil {
			return provision.CheckResult{}, err
		}
		if err := assertSiteTreeOwners(ctx, r, s, site); err != nil {
			return provision.CheckResult{}, err
		}
	}
	for _, site := range s.Sites {
		user := s.SiteUser(site)
		// Owner AND mode: deploy_path 0710 (<user>:www-data — nginx traverses,
		// sibling tenants cannot enter), shared/ and shared/tmp 0700 private,
		// ACME webroot 0755. A drifted mode silently breaks tenant isolation, so
		// it is probed exactly like ownership (stat prints modes without a
		// leading zero). Apply's install -d resets both on existing dirs.
		for _, d := range []struct{ path, meta string }{
			{site.DeployPath, user + ":www-data 710"},
			{site.DeployPath + "/shared", user + ":" + user + " 700"},
			{site.DeployPath + "/shared/tmp", user + ":" + user + " 700"},
			{acmeWebroot(site.Domain), "www-data:www-data 755"},
		} {
			meta, present, err := statOwnerMode(ctx, r, d.path)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if !present || meta != d.meta {
				return provision.CheckResult{Satisfied: false, Reason: d.path + " missing or not " + d.meta, Changes: a.changes()}, nil
			}
		}
	}
	return provision.CheckResult{Satisfied: true, Reason: "per-site application directories present with isolating owners"}, nil
}

func (appDirs) changes() []string {
	return []string{
		"install -d deploy_path (<user>:www-data 0710) + shared and shared/tmp (<user> 0700)",
		"install -d ACME webroot (owner www-data)",
	}
}

func (appDirs) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	// Same preflight as Check: no site may be mutated once ANY site's tree
	// is symlinked or foreign-owned.
	for _, site := range s.Sites {
		if err := assertNoSymlinkTargets(ctx, r, s, site); err != nil {
			return err
		}
		if err := assertSiteTreeOwners(ctx, r, s, site); err != nil {
			return err
		}
	}
	for _, site := range s.Sites {
		user := s.SiteUser(site)
		// deploy_path: site user owns it, group www-data + mode 0710 lets nginx
		// traverse to public/ while other site users cannot enter.
		cmds := []string{
			fmt.Sprintf("install -d -o %s -g www-data -m 0710 %s", user, shQuote(site.DeployPath)),
			// shared/ holds .env and is private to the site user.
			fmt.Sprintf("install -d -o %s -g %s -m 0700 %s", user, user, shQuote(site.DeployPath+"/shared")),
			// shared/tmp backs the pool's sys_temp_dir/upload_tmp_dir (no shared /tmp).
			fmt.Sprintf("install -d -o %s -g %s -m 0700 %s", user, user, shQuote(site.DeployPath+"/shared/tmp")),
			// ACME webroot for certbot --webroot.
			fmt.Sprintf("install -d -o www-data -g www-data -m 0755 %s", shQuote(acmeWebroot(site.Domain))),
		}
		for _, cmd := range cmds {
			if res, err := r.Run(ctx, cmd, nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("create directories for %s: %s", site.Domain, res.Stderr)
			}
		}
	}
	return nil
}

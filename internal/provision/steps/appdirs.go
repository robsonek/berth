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

// dirOwnedBy reports whether path exists and is owned by owner:group.
func dirOwnedBy(ctx context.Context, r bssh.Runner, path, owner, group string) (bool, error) {
	res, err := r.Run(ctx, "stat -c %U:%G "+shQuote(path), nil)
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, nil // absent
	}
	return strings.TrimSpace(res.Stdout) == owner+":"+group, nil
}

// noSymlinkInPath reports whether NEITHER path p NOR any of its ancestors is a
// symlink. berth's root-run `install -d` follows a directory symlink to its
// target and applies ownership there, so a tenant who owns an ancestor of p
// (e.g. their own prior deploy_path after a migration) could plant a symlink to
// redirect the chown at /etc. It checks every prefix from the first component
// under / down to p; a non-existent component is simply "not a symlink" and
// passes, so a fresh path is created normally.
func noSymlinkInPath(ctx context.Context, r bssh.Runner, p string) (bool, error) {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := ""
	var tests []string
	for _, part := range parts {
		cur += "/" + part
		tests = append(tests, "test ! -L "+shQuote(cur))
	}
	res, err := r.Run(ctx, strings.Join(tests, " && "), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// assertNoSymlinkTargets fails loudly if any component of a site's deploy tree
// or its ACME webroot is a symlink (see noSymlinkInPath). Checking the deepest
// deploy target covers deploy_path, shared and shared/tmp and all their
// ancestors in one probe.
func assertNoSymlinkTargets(ctx context.Context, r bssh.Runner, s *config.Server, site config.Site) error {
	for _, p := range []string{site.DeployPath + "/shared/tmp", acmeWebroot(site.Domain)} {
		ok, err := noSymlinkInPath(ctx, r, p)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("refusing to create directories for %s: a component of %s is a symlink; a tenant may have planted it so root's install -d chowns the target — remove the symlink (or the stale directory) before re-running", site.Domain, p)
		}
	}
	return nil
}

func (a appDirs) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	for _, site := range s.Sites {
		if err := assertNoSymlinkTargets(ctx, r, s, site); err != nil {
			return provision.CheckResult{}, err
		}
		user := s.SiteUser(site)
		// deploy_path owned by the site user, group www-data (so nginx can reach
		// public/); shared/ private to the site user.
		for _, d := range []struct{ path, owner, group string }{
			{site.DeployPath, user, "www-data"},
			{site.DeployPath + "/shared", user, user},
			{site.DeployPath + "/shared/tmp", user, user},
			{acmeWebroot(site.Domain), "www-data", "www-data"},
		} {
			ok, err := dirOwnedBy(ctx, r, d.path, d.owner, d.group)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if !ok {
				return provision.CheckResult{Satisfied: false, Reason: d.path + " missing or not owned by " + d.owner + ":" + d.group, Changes: a.changes()}, nil
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
	for _, site := range s.Sites {
		if err := assertNoSymlinkTargets(ctx, r, s, site); err != nil {
			return err
		}
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

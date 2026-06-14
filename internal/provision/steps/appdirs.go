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

func (a appDirs) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	for _, site := range s.Sites {
		user := s.SiteUser(site)
		// deploy_path owned by the site user, group www-data (so nginx can reach
		// public/); shared/ private to the site user.
		for _, d := range []struct{ path, owner, group string }{
			{site.DeployPath, user, "www-data"},
			{site.DeployPath + "/shared", user, user},
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
		"install -d deploy_path (<user>:www-data 0710) + shared (<user> 0700)",
		"install -d ACME webroot (owner www-data)",
	}
}

func (appDirs) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	for _, site := range s.Sites {
		user := s.SiteUser(site)
		// deploy_path: site user owns it, group www-data + mode 0710 lets nginx
		// traverse to public/ while other site users cannot enter.
		cmds := []string{
			fmt.Sprintf("install -d -o %s -g www-data -m 0710 %s", user, shQuote(site.DeployPath)),
			// shared/ holds .env and is private to the site user.
			fmt.Sprintf("install -d -o %s -g %s -m 0700 %s", user, user, shQuote(site.DeployPath+"/shared")),
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

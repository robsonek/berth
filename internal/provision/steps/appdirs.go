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

// AppDirs creates the deployment directories and the per-domain ACME webroot
// BEFORE any secret is persisted, so seeding shared/.env (the database step) has
// a place to write (design §6.4).
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
		// deploy_path and its shared/ subtree are owned by the deploy account.
		for _, dir := range []string{site.DeployPath, site.DeployPath + "/shared"} {
			ok, err := dirOwnedBy(ctx, r, dir, "deploy", "deploy")
			if err != nil {
				return provision.CheckResult{}, err
			}
			if !ok {
				return provision.CheckResult{Satisfied: false, Reason: dir + " missing or not owned by deploy", Changes: a.changes()}, nil
			}
		}
		// The ACME webroot is owned by www-data so certbot --webroot can write it.
		webroot := acmeWebroot(site.Domain)
		ok, err := dirOwnedBy(ctx, r, webroot, "www-data", "www-data")
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			return provision.CheckResult{Satisfied: false, Reason: webroot + " missing or not owned by www-data", Changes: a.changes()}, nil
		}
	}
	return provision.CheckResult{Satisfied: true, Reason: "application directories present with correct owners"}, nil
}

func (appDirs) changes() []string {
	return []string{
		"install -d deploy_path + shared (owner deploy)",
		"install -d ACME webroot (owner www-data)",
	}
}

func (appDirs) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	for _, site := range s.Sites {
		// deploy_path + shared/, owned by deploy.
		deployCmd := fmt.Sprintf("sudo install -d -o deploy -g deploy %s %s",
			shQuote(site.DeployPath), shQuote(site.DeployPath+"/shared"))
		if res, err := r.Run(ctx, deployCmd, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("create deploy directories for %s: %s", site.Domain, res.Stderr)
		}
		// ACME webroot, owned by www-data.
		webrootCmd := fmt.Sprintf("sudo install -d -o www-data -g www-data %s", shQuote(acmeWebroot(site.Domain)))
		if res, err := r.Run(ctx, webrootCmd, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("create ACME webroot for %s: %s", site.Domain, res.Stderr)
		}
	}
	return nil
}

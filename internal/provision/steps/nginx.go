package steps

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

type nginx struct{}

func Nginx() provision.Step { return nginx{} }

func (nginx) Name() string       { return "nginx" }
func (nginx) Requires() []string { return []string{"base"} }

// nginxOrgSourceList is the apt source file the nginx.org repo is written to; its
// presence is how Check knows the configured upstream source is in effect.
const nginxOrgSourceList = "/etc/apt/sources.list.d/nginx-org.list"

// Stock catch-all server blocks berth disables so they cannot answer unmatched
// :80 traffic: Debian ships sites-enabled/default, nginx.org ships
// conf.d/default.conf.
const (
	debianDefaultSite   = "/etc/nginx/sites-enabled/default"
	nginxOrgDefaultConf = "/etc/nginx/conf.d/default.conf"
)

func (nginx) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	installed, err := pkgInstalled(ctx, r, "nginx")
	if err != nil {
		return provision.CheckResult{}, err
	}
	up, err := serviceUp(ctx, r, "nginx")
	if err != nil {
		return provision.CheckResult{}, err
	}
	// When nginx.org is the configured source, its repo must be registered; this
	// makes a source switch (debian -> nginx) re-trigger Apply.
	sourceOK := true
	if s.Nginx.Source == "nginx" {
		sourceOK, err = fileExists(ctx, r, nginxOrgSourceList)
		if err != nil {
			return provision.CheckResult{}, err
		}
	}
	// The stock catch-all sites must be disabled.
	defaultsDisabled, err := stockDefaultsDisabled(ctx, r)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if installed && up && sourceOK && defaultsDisabled {
		return provision.CheckResult{Satisfied: true, Reason: "nginx installed and running from the " + s.Nginx.Source + " source; stock default sites disabled"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "nginx not installed, not running, not from the configured source, or stock default site still enabled",
		Changes:   []string{"install nginx (" + s.Nginx.Source + ")", "disable stock default site(s)", "systemctl enable --now nginx"},
	}, nil
}

// stockDefaultsDisabled reports whether neither stock catch-all server block is
// present.
func stockDefaultsDisabled(ctx context.Context, r bssh.Runner) (bool, error) {
	for _, p := range []string{debianDefaultSite, nginxOrgDefaultConf} {
		exists, err := fileExists(ctx, r, p)
		if err != nil {
			return false, err
		}
		if exists {
			return false, nil
		}
	}
	return true, nil
}

func (nginx) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	m := apt.New(r)
	if s.Nginx.Source == "nginx" {
		if err := m.EnsureRepo(ctx, apt.NginxOrg()); err != nil {
			return fmt.Errorf("add nginx.org repo: %w", err)
		}
	}
	if err := m.EnsurePackages(ctx, nil, "nginx"); err != nil {
		return fmt.Errorf("install nginx: %w", err)
	}
	if s.Nginx.Source == "nginx" {
		if err := bridgeNginxSitesLayout(ctx, r); err != nil {
			return err
		}
	}
	if err := disableStockDefaults(ctx, r); err != nil {
		return err
	}
	if res, err := r.Run(ctx, "systemctl enable --now nginx", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("enable nginx: %s", res.Stderr)
	}
	// Reload so a disabled default site stops answering on an already-running
	// nginx (enable --now is a no-op when nginx is already up). Validate first.
	if res, err := r.Run(ctx, "nginx -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("nginx -t failed after disabling stock defaults: %s", res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload nginx", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload nginx: %s", res.Stderr)
	}
	return nil
}

// disableStockDefaults idempotently removes the Debian default-site symlink and
// renames nginx.org's conf.d/default.conf (renamed, not deleted, so it is
// recoverable on a reused host).
func disableStockDefaults(ctx context.Context, r bssh.Runner) error {
	if res, err := r.Run(ctx, "rm -f "+shQuote(debianDefaultSite), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("disable %s: %s", debianDefaultSite, res.Stderr)
	}
	rename := fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(nginxOrgDefaultConf))
	if _, err := r.Run(ctx, rename, nil); err != nil {
		return err
	}
	return nil
}

// bridgeNginxSitesLayout reconciles the two nginx config layouts: nginx.org's
// nginx.conf includes /etc/nginx/conf.d/*.conf but not Debian's sites-enabled/,
// where berth's site step writes server blocks. It ensures the sites dirs exist
// and drops a managed conf.d include so those server blocks are loaded.
func bridgeNginxSitesLayout(ctx context.Context, r bssh.Runner) error {
	if res, err := r.Run(ctx, "install -d /etc/nginx/sites-available /etc/nginx/sites-enabled", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("create nginx sites dirs: %s", res.Stderr)
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path:    "/etc/nginx/conf.d/berth-sites.conf",
		Content: []byte(managedMarker + "\ninclude /etc/nginx/sites-enabled/*;\n"),
		Owner:   "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write nginx sites bridge: %w", err)
	}
	return nil
}

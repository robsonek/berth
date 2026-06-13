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

// poolName derives the FPM pool / cron app name from a site domain (filesystem
// safe: dots become underscores).
func poolName(domain string) string {
	return strings.ReplaceAll(domain, ".", "_")
}

func nginxAvailablePath(domain string) string { return "/etc/nginx/sites-available/" + domain }
func nginxEnabledPath(domain string) string   { return "/etc/nginx/sites-enabled/" + domain }
func fpmPoolPath(phpVersion, domain string) string {
	return fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", phpVersion, poolName(domain))
}
func supervisorProgramPath(s *config.Server) string {
	return "/etc/supervisor/conf.d/" + programName(s) + ".conf"
}
func cronPath(s *config.Server) string {
	return "/etc/cron.d/berth-" + poolName(s.Sites[0].Domain)
}

// siteFile pairs a desired managed file's path with its rendered content.
type siteFile struct {
	path    string
	content []byte
}

// managedSiteFiles returns every config file the site step owns, in render order.
// Both Check (content-hash drift) and Apply (WriteFile) use this list so they
// stay in lock-step.
func managedSiteFiles(s *config.Server) []siteFile {
	var files []siteFile
	for _, site := range s.Sites {
		http, _ := renderNginxHTTP(s, site)
		files = append(files, siteFile{nginxAvailablePath(site.Domain), http})
		pool, _ := renderFPMPool(s, site)
		files = append(files, siteFile{fpmPoolPath(s.PHP.Version, site.Domain), pool})
	}
	prog, _ := renderSupervisor(s)
	files = append(files, siteFile{supervisorProgramPath(s), prog})
	cron, _ := renderCron(s)
	files = append(files, siteFile{cronPath(s), cron})
	return files
}

func renderNginxHTTP(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("nginx_http.conf.tmpl", struct {
		Domain, DeployPath, ACMEWebroot, PHPVersion string
	}{
		Domain: site.Domain, DeployPath: site.DeployPath,
		ACMEWebroot: acmeWebroot(site.Domain), PHPVersion: s.PHP.Version,
	})
}

func renderFPMPool(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("fpm_pool.conf.tmpl", struct {
		PoolName, PHPVersion string
	}{PoolName: poolName(site.Domain), PHPVersion: s.PHP.Version})
}

func renderSupervisor(s *config.Server) ([]byte, error) {
	return templates.Render("supervisor.conf.tmpl", struct {
		ProgramName, DeployPath string
	}{ProgramName: programName(s), DeployPath: s.Sites[0].DeployPath})
}

func renderCron(s *config.Server) ([]byte, error) {
	return templates.Render("scheduler.cron.tmpl", struct {
		DeployPath string
	}{DeployPath: s.Sites[0].DeployPath})
}

type site struct{}

// Site renders and installs the per-site web server block (validated before any
// reload), the FPM pool, the dormant Supervisor worker, and the guarded
// scheduler cron (design §6.4).
func Site() provision.Step { return site{} }

func (site) Name() string       { return "site" }
func (site) Requires() []string { return []string{"php", "nginx", "appdirs", "database"} }

func (st site) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	for _, mf := range managedSiteFiles(s) {
		state, err := checkManagedFile(ctx, r, mf.path, mf.content)
		if err != nil {
			return provision.CheckResult{}, err
		}
		ok, err := managedFileSatisfied(state, mf.path, rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			return provision.CheckResult{Satisfied: false, Reason: mf.path + " not up to date", Changes: st.changes()}, nil
		}
	}
	// The active nginx configuration must validate.
	res, err := r.Run(ctx, "nginx -t", nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if res.ExitCode != 0 {
		return provision.CheckResult{Satisfied: false, Reason: "nginx -t fails", Changes: st.changes()}, nil
	}
	return provision.CheckResult{Satisfied: true, Reason: "site config in place and nginx valid"}, nil
}

func (site) changes() []string {
	return []string{
		"write nginx server block + enable it",
		"write FPM pool",
		"install dormant supervisor worker",
		"install scheduler cron",
	}
}

func (st site) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	// 1) Write each site's nginx server block and enable it.
	for _, site := range s.Sites {
		http, err := renderNginxHTTP(s, site)
		if err != nil {
			return fmt.Errorf("render nginx config for %s: %w", site.Domain, err)
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{
			Path: nginxAvailablePath(site.Domain), Content: http,
			Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
		}); err != nil {
			return fmt.Errorf("write nginx config for %s: %w", site.Domain, err)
		}
		link := fmt.Sprintf("ln -sfn %s %s", shQuote(nginxAvailablePath(site.Domain)), shQuote(nginxEnabledPath(site.Domain)))
		if res, err := r.Run(ctx, link, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("enable nginx site %s: %s", site.Domain, res.Stderr)
		}
	}

	// 2) Validate the whole nginx configuration BEFORE reloading. Abort on failure
	//    so a broken config never reaches a live reload.
	if res, err := r.Run(ctx, "nginx -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("nginx -t failed, refusing to reload: %s", res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload nginx", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload nginx: %s", res.Stderr)
	}

	// 3) FPM pool(s).
	for _, site := range s.Sites {
		pool, err := renderFPMPool(s, site)
		if err != nil {
			return fmt.Errorf("render FPM pool for %s: %w", site.Domain, err)
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{
			Path: fpmPoolPath(s.PHP.Version, site.Domain), Content: pool,
			Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
		}); err != nil {
			return fmt.Errorf("write FPM pool for %s: %w", site.Domain, err)
		}
	}

	// 4) Dormant Supervisor worker (autostart=false; started post-deploy).
	prog, err := renderSupervisor(s)
	if err != nil {
		return fmt.Errorf("render supervisor program: %w", err)
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: supervisorProgramPath(s), Content: prog,
		Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write supervisor program: %w", err)
	}

	// 5) Guarded scheduler cron (no-op until an app is deployed).
	cron, err := renderCron(s)
	if err != nil {
		return fmt.Errorf("render scheduler cron: %w", err)
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: cronPath(s), Content: cron,
		Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write scheduler cron: %w", err)
	}
	return nil
}

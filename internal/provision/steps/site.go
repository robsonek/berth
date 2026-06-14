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

// poolName derives the FPM pool / app slug from a site domain (filesystem safe:
// dots become underscores).
func poolName(domain string) string {
	return strings.ReplaceAll(domain, ".", "_")
}

// programName is the Supervisor program name for a site's queue worker.
func programName(domain string) string { return "berth-" + poolName(domain) }

// fpmSocket is the per-site PHP-FPM unix socket (one per site so sites do not
// share a socket and each runs under its own user).
func fpmSocket(domain string) string { return "/run/php/berth-" + poolName(domain) + ".sock" }

func nginxAvailablePath(domain string) string { return "/etc/nginx/sites-available/" + domain }
func nginxEnabledPath(domain string) string   { return "/etc/nginx/sites-enabled/" + domain }
func fpmPoolPath(phpVersion, domain string) string {
	return fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", phpVersion, poolName(domain))
}
func supervisorProgramPath(domain string) string {
	return "/etc/supervisor/conf.d/" + programName(domain) + ".conf"
}
func cronPath(domain string) string { return "/etc/cron.d/berth-" + poolName(domain) }

// logrotatePath is the single global logrotate fragment covering every site's
// FPM and supervisor logs via globs (rotation is host-global, not per-tenant).
const logrotatePath = "/etc/logrotate.d/berth"

func renderLogrotate() ([]byte, error) { return templates.Render("logrotate.conf.tmpl", nil) }

// fpmService is the systemd unit for the configured PHP-FPM version.
func fpmService(s *config.Server) string { return "php" + s.PHP.Version + "-fpm" }

// defaultFPMPoolPath is the distro's default pool; berth disables it so its own
// per-site pools own their sockets rather than colliding with the stock www pool.
func defaultFPMPoolPath(s *config.Server) string {
	return fmt.Sprintf("/etc/php/%s/fpm/pool.d/www.conf", s.PHP.Version)
}

// siteFile pairs a desired managed file's path with its rendered content.
type siteFile struct {
	path    string
	content []byte
}

// managedSiteFiles returns every config file the site step owns for every site,
// in render order. Both Check (content-hash drift) and Apply (WriteFile) use
// this list so they stay in lock-step. The nginx block is cert-aware (HTTPS once
// a certificate is installed) so a re-run does not revert the TLS 443 block.
func managedSiteFiles(ctx context.Context, r bssh.Runner, s *config.Server) ([]siteFile, error) {
	var files []siteFile
	for _, site := range s.Sites {
		conf, err := renderSiteNginx(ctx, r, s, site)
		if err != nil {
			return nil, err
		}
		files = append(files, siteFile{nginxAvailablePath(site.Domain), conf})
		pool, err := renderFPMPool(s, site)
		if err != nil {
			return nil, err
		}
		files = append(files, siteFile{fpmPoolPath(s.PHP.Version, site.Domain), pool})
		prog, err := renderSupervisor(s, site)
		if err != nil {
			return nil, err
		}
		files = append(files, siteFile{supervisorProgramPath(site.Domain), prog})
		cron, err := renderCron(s, site)
		if err != nil {
			return nil, err
		}
		files = append(files, siteFile{cronPath(site.Domain), cron})
	}
	lr, err := renderLogrotate()
	if err != nil {
		return nil, err
	}
	files = append(files, siteFile{path: logrotatePath, content: lr})
	return files, nil
}

// certDir is where a site's TLS certificate lives: Let's Encrypt's live dir, or
// a berth-managed dir for self-signed certs.
func certDir(site config.Site) string {
	if site.CertMode() == "selfsigned" {
		return "/etc/ssl/berth/" + site.Domain
	}
	return "/etc/letsencrypt/live/" + site.Domain
}

func certFullchainPath(site config.Site) string { return certDir(site) + "/fullchain.pem" }
func certKeyPath(site config.Site) string       { return certDir(site) + "/privkey.pem" }

// certInstalled reports whether the site's certificate file is present yet (used
// to decide whether the nginx block should be HTTPS).
func certInstalled(ctx context.Context, r bssh.Runner, site config.Site) (bool, error) {
	return fileExists(ctx, r, certFullchainPath(site))
}

// renderSiteNginx renders the HTTPS (443) server block when the site uses SSL and
// a certificate is already installed, otherwise the HTTP-only block — so the ACME
// webroot challenge can complete on the first issuance, and subsequent runs keep
// the HTTPS block in place rather than reverting it.
func renderSiteNginx(ctx context.Context, r bssh.Runner, s *config.Server, site config.Site) ([]byte, error) {
	if site.SSL {
		has, err := certInstalled(ctx, r, site)
		if err != nil {
			return nil, err
		}
		if has {
			return renderNginxHTTPS(s, site)
		}
	}
	return renderNginxHTTP(s, site)
}

// nginxData is the render input for both nginx server-block templates. Socket is
// the site's own PHP-FPM socket so each domain proxies to its own pool/user;
// CertPath/KeyPath point at the site's TLS material (LE or self-signed). HTTP3
// adds the QUIC listeners + Alt-Svc; QUICReuseport marks the one site that owns
// the `reuseport` flag on the shared :443 QUIC socket. HSTS is set only for
// real (non-self-signed) certificates to avoid bricking a domain in browsers.
type nginxData struct {
	Domain, DeployPath, ACMEWebroot, Socket, CertPath, KeyPath string
	HTTP3, QUICReuseport, HSTS                                 bool
}

func nginxRenderData(s *config.Server, site config.Site) nginxData {
	return nginxData{
		Domain: site.Domain, DeployPath: site.DeployPath,
		ACMEWebroot: acmeWebroot(site.Domain), Socket: fpmSocket(site.Domain),
		CertPath: certFullchainPath(site), KeyPath: certKeyPath(site),
		HTTP3:         site.HTTP3,
		QUICReuseport: site.HTTP3 && quicReuseportOwner(s) == site.Domain,
		// HSTS is derived purely from static config (SSL + cert mode), never cert
		// presence, so site re-render and tls swap stay byte-identical. Self-signed
		// is excluded: pinning a browser to an untrusted cert would brick the site.
		HSTS: site.SSL && site.CertMode() != "selfsigned",
	}
}

// quicReuseportOwner returns the HTTP/3 site domain that owns the `reuseport`
// flag on the shared :443 QUIC socket. nginx permits `reuseport` only once per
// address:port and must see it on the FIRST `listen` it parses for that socket.
// berth enables vhosts via `include /etc/nginx/sites-enabled/*;`, a wildcard
// nginx expands in LEXICOGRAPHIC order — so the owner must be the alphabetically
// smallest HTTP/3 domain (the block nginx parses first), independent of the order
// the sites appear in the config. Empty when none enable HTTP/3.
func quicReuseportOwner(s *config.Server) string {
	owner := ""
	for _, site := range s.Sites {
		if site.HTTP3 && (owner == "" || site.Domain < owner) {
			owner = site.Domain
		}
	}
	return owner
}

// anySiteHTTP3 reports whether any site enables HTTP/3, so the firewall must also
// open UDP/443 for QUIC.
func anySiteHTTP3(s *config.Server) bool { return quicReuseportOwner(s) != "" }

func renderNginxHTTP(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("nginx_http.conf.tmpl", nginxRenderData(s, site))
}

// renderNginxHTTPS renders the 443 server block (HTTP redirect + TLS); shared by
// the site step (idempotent re-render) and the tls step (first issuance).
func renderNginxHTTPS(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("nginx_https.conf.tmpl", nginxRenderData(s, site))
}

func renderFPMPool(s *config.Server, site config.Site) ([]byte, error) {
	// PHP-FPM pool files are INI; their parser rejects '#' comment lines, so the
	// managed marker must use ';' (RenderINI). The pool runs as the site user and
	// listens on the site's own socket (isolation).
	return templates.RenderINI("fpm_pool.conf.tmpl", struct {
		PoolName, User, Socket, DeployPath string
	}{
		PoolName: poolName(site.Domain), User: s.SiteUser(site),
		Socket: fpmSocket(site.Domain), DeployPath: site.DeployPath,
	})
}

func renderSupervisor(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("supervisor.conf.tmpl", struct {
		ProgramName, DeployPath, User string
	}{ProgramName: programName(site.Domain), DeployPath: site.DeployPath, User: s.SiteUser(site)})
}

func renderCron(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("scheduler.cron.tmpl", struct {
		DeployPath, User string
	}{DeployPath: site.DeployPath, User: s.SiteUser(site)})
}

type site struct{}

// Site renders and installs, per site, the web server block (validated before any
// reload), the FPM pool (own user + socket), the dormant Supervisor worker, and
// the guarded scheduler cron (design §6.4).
func Site() provision.Step { return site{} }

func (site) Name() string       { return "site" }
func (site) Requires() []string { return []string{"php", "nginx", "appdirs", "database"} }

func (st site) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	mfs, err := managedSiteFiles(ctx, r, s)
	if err != nil {
		return provision.CheckResult{}, err
	}
	for _, mf := range mfs {
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
	// The active nginx and PHP-FPM configurations must validate.
	if res, err := r.Run(ctx, "nginx -t", nil); err != nil {
		return provision.CheckResult{}, err
	} else if res.ExitCode != 0 {
		return provision.CheckResult{Satisfied: false, Reason: "nginx -t fails", Changes: st.changes()}, nil
	}
	if res, err := r.Run(ctx, "php-fpm"+s.PHP.Version+" -t", nil); err != nil {
		return provision.CheckResult{}, err
	} else if res.ExitCode != 0 {
		return provision.CheckResult{Satisfied: false, Reason: "php-fpm -t fails", Changes: st.changes()}, nil
	}
	return provision.CheckResult{Satisfied: true, Reason: "site config in place; nginx and php-fpm valid"}, nil
}

func (site) changes() []string {
	return []string{
		"write per-site nginx server block + enable it",
		"write per-site FPM pool (own user + socket)",
		"install per-site dormant supervisor worker",
		"install per-site scheduler cron",
	}
}

func (st site) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	// 1) Per-site nginx server block (cert-aware) + enable.
	for _, site := range s.Sites {
		conf, err := renderSiteNginx(ctx, r, s, site)
		if err != nil {
			return fmt.Errorf("render nginx config for %s: %w", site.Domain, err)
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{
			Path: nginxAvailablePath(site.Domain), Content: conf,
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

	// 2) Validate the whole nginx configuration BEFORE reloading.
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

	// 3) Per-site FPM pools (each its own user + socket). Disable the stock www
	//    pool first so it cannot answer on a shared socket.
	disableWWW := fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(defaultFPMPoolPath(s)))
	if _, err := r.Run(ctx, disableWWW, nil); err != nil {
		return err
	}
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
	if res, err := r.Run(ctx, "php-fpm"+s.PHP.Version+" -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("php-fpm%s -t failed, refusing to reload: %s", s.PHP.Version, res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload "+fpmService(s), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload %s: %s", fpmService(s), res.Stderr)
	}

	// 4) Per-site dormant Supervisor worker + 5) guarded scheduler cron.
	for _, site := range s.Sites {
		prog, err := renderSupervisor(s, site)
		if err != nil {
			return fmt.Errorf("render supervisor program for %s: %w", site.Domain, err)
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{
			Path: supervisorProgramPath(site.Domain), Content: prog,
			Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
		}); err != nil {
			return fmt.Errorf("write supervisor program for %s: %w", site.Domain, err)
		}
		cron, err := renderCron(s, site)
		if err != nil {
			return fmt.Errorf("render scheduler cron for %s: %w", site.Domain, err)
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{
			Path: cronPath(site.Domain), Content: cron,
			Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
		}); err != nil {
			return fmt.Errorf("write scheduler cron for %s: %w", site.Domain, err)
		}
	}

	// 6) Global logrotate fragment for FPM + supervisor logs (one file, globs).
	lr, err := renderLogrotate()
	if err != nil {
		return err
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: logrotatePath, Content: lr, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", logrotatePath, err)
	}
	if res, err := r.Run(ctx, "logrotate -d "+shQuote(logrotatePath), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("logrotate -d failed for %s: %s", logrotatePath, res.Stderr)
	}
	return nil
}

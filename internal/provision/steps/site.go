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

// poolName derives the FPM pool / supervisor program slug (dots -> underscores).
func poolName(domain string) string { return config.PoolName(domain) }

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

// siteFile pairs a desired managed file's path with its rendered content. When
// remove is true the file must be ABSENT (a disabled feature): Check flags a
// lingering berth-managed file as drift and Apply rm -f's it.
type siteFile struct {
	path    string
	content []byte
	remove  bool
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
		files = append(files, siteFile{path: nginxAvailablePath(site.Domain), content: conf})
		pool, err := renderFPMPool(s, site)
		if err != nil {
			return nil, err
		}
		files = append(files, siteFile{path: fpmPoolPath(s.PHP.Version, site.Domain), content: pool})
		if s.QueueEnabled(site) {
			worker, err := renderSupervisorProgram(programName(site.Domain), queueCommand(s, site), queueNumprocs(site), s.SiteUser(site), site.DeployPath)
			if err != nil {
				return nil, err
			}
			files = append(files, siteFile{path: supervisorProgramPath(site.Domain), content: worker})
		}
		for _, d := range site.Daemons {
			body, err := renderSupervisorProgram(daemonProgramName(site.Domain, d.Name), d.Command, daemonNumprocs(d), s.SiteUser(site), site.DeployPath)
			if err != nil {
				return nil, err
			}
			files = append(files, siteFile{path: daemonProgramPath(site.Domain, d.Name), content: body})
		}
		if s.SchedulerEnabled(site) {
			cron, err := renderCron(s, site)
			if err != nil {
				return nil, err
			}
			files = append(files, siteFile{path: cronPath(site.Domain), content: cron})
		} else {
			files = append(files, siteFile{path: cronPath(site.Domain), remove: true})
		}
	}
	// Global orphan drift-removal: any berth-*.conf program file no site desires
	// is flagged for removal. Global glob (never per-pool) because pool names can
	// be prefixes of one another, so a per-site glob could match a sibling's file.
	desired := desiredProgramPaths(s)
	progs, err := listSupervisorPrograms(ctx, r)
	if err != nil {
		return nil, err
	}
	for _, p := range progs {
		if !desired[p] {
			files = append(files, siteFile{path: p, remove: true})
		}
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
	HTTP3, QUICReuseport, HSTS, CloudflareOnly                 bool
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
		// CloudflareOnly is derived purely from static config (like HSTS), never
		// from cert presence, so the site re-render and the tls swap stay
		// byte-identical.
		CloudflareOnly: s.CloudflareOnlyEnabled(site),
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

// queueCommand builds the worker command line. The default (no queue block) is
// byte-identical to berth's historical worker; tuning appends flags in a stable
// order. Horizon replaces queue:work entirely.
func queueCommand(s *config.Server, site config.Site) string {
	base := "php " + site.DeployPath + "/current/artisan "
	q := site.Queue
	if q != nil && q.Driver == "horizon" {
		return base + "horizon"
	}
	sleep, tries := 3, 3
	cmd := base + "queue:work"
	if q != nil {
		if q.Connection != "" {
			cmd += " " + q.Connection
		}
		if q.Queue != "" {
			cmd += " --queue=" + q.Queue
		}
		if q.Sleep != 0 {
			sleep = q.Sleep
		}
		if q.Tries != 0 {
			tries = q.Tries
		}
	}
	cmd += fmt.Sprintf(" --sleep=%d --tries=%d --max-time=3600", sleep, tries)
	if q != nil {
		if q.Timeout != 0 {
			cmd += fmt.Sprintf(" --timeout=%d", q.Timeout)
		}
		if q.MaxMemory != 0 {
			cmd += fmt.Sprintf(" --memory=%d", q.MaxMemory)
		}
	}
	return cmd
}

// queueNumprocs is the worker process count (default 1; horizon forces 1).
func queueNumprocs(site config.Site) int {
	if q := site.Queue; q != nil && q.Driver != "horizon" && q.Processes > 0 {
		return q.Processes
	}
	return 1
}

func daemonNumprocs(d config.Daemon) int {
	if d.Processes > 0 {
		return d.Processes
	}
	return 1
}

// renderSupervisorProgram renders one Supervisor program (worker or daemon).
func renderSupervisorProgram(programName, command string, numprocs int, user, deployPath string) ([]byte, error) {
	return templates.Render("supervisor.conf.tmpl", struct {
		ProgramName, Command, DeployPath, User string
		Numprocs                               int
	}{ProgramName: programName, Command: command, DeployPath: deployPath, User: user, Numprocs: numprocs})
}

// daemonProgramName / daemonProgramPath name a site's daemon program file.
func daemonProgramName(domain, name string) string { return programName(domain) + "-" + name }
func daemonProgramPath(domain, name string) string {
	return "/etc/supervisor/conf.d/" + daemonProgramName(domain, name) + ".conf"
}

// desiredProgramPaths is the set of supervisor program file paths every site
// desires (worker iff QueueEnabled, plus each daemon) across the WHOLE server.
func desiredProgramPaths(s *config.Server) map[string]bool {
	desired := map[string]bool{}
	for _, site := range s.Sites {
		for _, name := range s.SiteProgramNames(site) {
			desired["/etc/supervisor/conf.d/"+name+".conf"] = true
		}
	}
	return desired
}

// listSupervisorPrograms lists berth's supervisor program files on the host.
func listSupervisorPrograms(ctx context.Context, r bssh.Runner) ([]string, error) {
	res, err := r.Run(ctx, "ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", nil)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		if p := strings.TrimSpace(line); p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// supervisorReload registers berth's program set with the running supervisord
// (reread then update). update does NOT start an autostart=false program, so
// workers stay STOPPED (dormant); this is what makes the deployer's
// `supervisorctl start/restart berth-<pool>:*` work — otherwise the conf is on
// disk but supervisord never loaded it ("no such process").
func supervisorReload(ctx context.Context, r bssh.Runner) error {
	for _, cmd := range []string{"supervisorctl reread", "supervisorctl update"} {
		if res, err := r.Run(ctx, cmd, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("%s: %s", cmd, res.Stderr)
		}
	}
	return nil
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
		if mf.remove {
			present, err := managedFilePresent(ctx, r, mf.path)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if present {
				return provision.CheckResult{Satisfied: false, Reason: mf.path + " should be removed (feature disabled)", Changes: st.changes()}, nil
			}
			continue
		}
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
	// Every desired supervisor program must be LOADED in supervisord (not just on
	// disk), or the deployer's start/restart fails. A box whose conf predates this
	// enforcement reports "no such" here -> unsatisfied -> Apply reread/updates it.
	if s.NeedsSupervisor() {
		for _, site := range s.Sites {
			for _, prog := range s.SiteProgramNames(site) {
				// Quote the group glob so the sudo `/bin/sh -c` wrapper passes
				// "<prog>:*" to supervisorctl literally instead of pathname-expanding it.
				res, err := r.Run(ctx, "supervisorctl status "+shQuote(prog+":*"), nil)
				if err != nil {
					return provision.CheckResult{}, err
				}
				if strings.Contains(res.Stdout+res.Stderr, "no such") {
					return provision.CheckResult{Satisfied: false, Reason: prog + " not loaded in supervisord", Changes: st.changes()}, nil
				}
			}
		}
	}
	return provision.CheckResult{Satisfied: true, Reason: "site config in place; nginx and php-fpm valid"}, nil
}

func (site) changes() []string {
	return []string{
		"write per-site nginx server block + enable it",
		"write per-site FPM pool (own user + socket)",
		"write per-site supervisor programs (worker + daemons) and remove orphans",
		"reconcile per-site scheduler cron (install or remove)",
		"write global logrotate fragment",
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

	// 4) Per-site Supervisor worker (iff queue enabled) + daemons, then
	//    5) guarded scheduler cron.
	for _, site := range s.Sites {
		if s.QueueEnabled(site) {
			worker, err := renderSupervisorProgram(programName(site.Domain), queueCommand(s, site), queueNumprocs(site), s.SiteUser(site), site.DeployPath)
			if err != nil {
				return fmt.Errorf("render supervisor worker for %s: %w", site.Domain, err)
			}
			if err := r.WriteFile(ctx, bssh.FileSpec{
				Path: supervisorProgramPath(site.Domain), Content: worker,
				Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
			}); err != nil {
				return fmt.Errorf("write supervisor worker for %s: %w", site.Domain, err)
			}
		}
		for _, d := range site.Daemons {
			body, err := renderSupervisorProgram(daemonProgramName(site.Domain, d.Name), d.Command, daemonNumprocs(d), s.SiteUser(site), site.DeployPath)
			if err != nil {
				return fmt.Errorf("render daemon %s for %s: %w", d.Name, site.Domain, err)
			}
			if err := r.WriteFile(ctx, bssh.FileSpec{
				Path: daemonProgramPath(site.Domain, d.Name), Content: body,
				Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
			}); err != nil {
				return fmt.Errorf("write daemon %s for %s: %w", d.Name, site.Domain, err)
			}
		}
		if s.SchedulerEnabled(site) {
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
		} else {
			// Scheduler disabled: drift-remove a berth-managed cron (never a foreign file).
			present, err := managedFilePresent(ctx, r, cronPath(site.Domain))
			if err != nil {
				return err
			}
			if present {
				if res, err := r.Run(ctx, "rm -f "+shQuote(cronPath(site.Domain)), nil); err != nil {
					return err
				} else if res.ExitCode != 0 {
					return fmt.Errorf("remove scheduler cron for %s: %s", site.Domain, res.Stderr)
				}
			}
		}
	}

	// Global orphan removal: rm berth-managed supervisor program files no site
	// desires (never a foreign/unmanaged file). removedOrphan is declared at
	// function scope so the reload below can see it after the block closes.
	removedOrphan := false
	{
		desired := desiredProgramPaths(s)
		progs, err := listSupervisorPrograms(ctx, r)
		if err != nil {
			return err
		}
		for _, p := range progs {
			if desired[p] {
				continue
			}
			present, err := managedFilePresent(ctx, r, p)
			if err != nil {
				return err
			}
			if present {
				if res, err := r.Run(ctx, "rm -f "+shQuote(p), nil); err != nil {
					return err
				} else if res.ExitCode != 0 {
					return fmt.Errorf("remove orphan supervisor program %s: %s", p, res.Stderr)
				}
				removedOrphan = true
			}
		}
	}

	// Register/refresh the program set with the running supervisord so the deployer
	// can drive it (start/restart). Without this the conf is on disk but supervisord
	// never loaded it; update leaves autostart=false workers STOPPED, never started.
	if s.NeedsSupervisor() {
		// No presence guard here (unlike the orphan branch below): when programs are
		// desired, the supervisor step runs before site on a full pipeline and has
		// already installed+enabled supervisord, so it is present. (`--only site` is
		// documented as not perfectly isolated; there a missing supervisord surfaces
		// as a loud Apply error, which is the correct signal for a partial run.)
		if err := supervisorReload(ctx, r); err != nil {
			return err
		}
	} else if removedOrphan {
		// No desired programs, but a stale one was removed: unload it from
		// supervisord too — only if supervisor is actually present (a server that
		// never needed it may not have it installed). A non-zero probe exit just
		// means absent (skip); a transport error propagates like any Apply command.
		up, err := serviceUp(ctx, r, "supervisor")
		if err != nil {
			return err
		}
		if up {
			if err := supervisorReload(ctx, r); err != nil {
				return err
			}
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

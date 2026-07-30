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
func programName(domain string) string { return config.SiteWorkerProgram(domain) }

// fpmSocket is the per-site PHP-FPM unix socket (one per site so sites do not
// share a socket and each runs under its own user).
func fpmSocket(domain string) string { return config.FPMSocketPath(poolName(domain)) }

// nginxEnabledDir / fpmPoolDir are the directories governing which vhosts and
// pools the units load. They join the reload-stamp probes as a whole: a
// directory's mtime changes on any create/remove/rename inside it, covering
// topology drift (an out-of-band link recreation, a recreated stock file) that
// the per-file probes cannot see.
const nginxEnabledDir = "/etc/nginx/sites-enabled"

func fpmPoolDir(phpVersion string) string { return "/etc/php/" + phpVersion + "/fpm/pool.d" }

func nginxAvailablePath(domain string) string { return "/etc/nginx/sites-available/" + domain }
func nginxEnabledPath(domain string) string   { return nginxEnabledDir + "/" + domain }
func fpmPoolPath(phpVersion, domain string) string {
	return fpmPoolDir(phpVersion) + "/" + poolName(domain) + ".conf"
}

// supervisorProgramConfPath is THE conf.d path for one Supervisor program
// name; every surface that paths a program (write, sweep, orphan removal)
// goes through it so path and name derivation can never disagree.
func supervisorProgramConfPath(prog string) string {
	return "/etc/supervisor/conf.d/" + prog + ".conf"
}

func supervisorProgramPath(domain string) string {
	return supervisorProgramConfPath(programName(domain))
}

// cronPath is the scheduler cron for a site. The "berth-site-" prefix keeps
// the namespace disjoint from the backups step's "berth-backup-" crons: a
// domain literally named backup-<x>.tld would otherwise produce
// /etc/cron.d/berth-backup-<x>_tld — colliding with the backups step's
// namespace. Scheduler crons live under berth-site-, backup crons under
// berth-backup-; any FUTURE berth cron family needs its own prefix.
func cronPath(domain string) string { return "/etc/cron.d/berth-site-" + poolName(domain) }

// anySchedulerEnabled reports whether at least one site wants the scheduler cron.
func anySchedulerEnabled(s *config.Server) bool {
	for _, site := range s.Sites {
		if s.SchedulerEnabled(site) {
			return true
		}
	}
	return false
}

// logrotatePath is the single global logrotate fragment covering every site's
// FPM and supervisor logs via globs (rotation is host-global, not per-tenant).
const logrotatePath = "/etc/logrotate.d/berth"

func renderLogrotate() ([]byte, error) { return templates.Render("logrotate.conf.tmpl", nil) }

// fpmService is the systemd unit for the configured PHP-FPM version.
func fpmService(s *config.Server) string { return config.FPMServiceName(s.PHP.Version) }

// defaultFPMPoolPath is the distro's default pool; berth disables it so its own
// per-site pools own their sockets rather than colliding with the stock www pool.
func defaultFPMPoolPath(s *config.Server) string {
	return fpmPoolDir(s.PHP.Version) + "/www.conf"
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
	orphans, err := orphanSiteFiles(ctx, r, s)
	if err != nil {
		return nil, err
	}
	files = append(files, orphans...)
	lr, err := renderLogrotate()
	if err != nil {
		return nil, err
	}
	files = append(files, siteFile{path: logrotatePath, content: lr})
	// Global http-context snippet defining the $berth_cloudflare geo flag +
	// real-IP restoration. Present when any site is cloudflare_only; otherwise a
	// remove entry drift-cleans a lingering berth-managed copy (guarded so a
	// foreign conf.d file is never clobbered).
	if s.AnyCloudflareOnly() {
		cf, err := renderCloudflareConf()
		if err != nil {
			return nil, err
		}
		files = append(files, siteFile{path: cloudflareConfPath, content: cf})
	} else {
		files = append(files, siteFile{path: cloudflareConfPath, remove: true})
	}
	return files, nil
}

// selfSignedCertBase is berth's own namespace for self-signed material; the
// TLS orphan sweep treats everything under it as berth-owned.
const selfSignedCertBase = "/etc/ssl/berth"

func selfSignedCertDir(domain string) string { return selfSignedCertBase + "/" + domain }

// certDir is where a site's TLS certificate lives: Let's Encrypt's live dir, or
// a berth-managed dir for self-signed certs.
func certDir(site config.Site) string {
	if site.CertMode() == "selfsigned" {
		return selfSignedCertDir(site.Domain)
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
// BodyMax becomes client_max_body_size; like HSTS it derives purely from static
// config (tuning.php_upload_max + headroom), so site re-render and tls swap stay
// byte-identical.
type nginxData struct {
	Domain, DeployPath, ACMEWebroot, Socket, CertPath, KeyPath, BodyMax string
	HTTP3, QUICReuseport, HSTS, CloudflareOnly                          bool
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
		// BodyMax mirrors the FPM drop-in's post_max_size (one derived cap for
		// the whole upload path); static config only, never remote state, so
		// the site↔tls byte-identical re-render invariant holds.
		BodyMax: s.Tuning.PHPPostBodyMaxEff(),
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
	// listens on the site's own socket (isolation). pm.max_children comes from
	// tuning.php_fpm_max_children (one global value, every pool; default 10);
	// the pm siblings stay static, so validation floors the knob at 4
	// (pm.max_spare_servers must not exceed pm.max_children).
	return templates.RenderINI("fpm_pool.conf.tmpl", struct {
		PoolName, User, Socket, DeployPath string
		MaxChildren                        int
	}{
		PoolName: poolName(site.Domain), User: s.SiteUser(site),
		Socket: fpmSocket(site.Domain), DeployPath: site.DeployPath,
		MaxChildren: s.Tuning.PHPFPMMaxChildrenEff(),
	})
}

// queueCommand builds the worker command line. The default (no queue block) is
// byte-identical to berth's historical worker; tuning appends flags in a stable
// order. Horizon replaces queue:work entirely.
func queueCommand(_ *config.Server, site config.Site) string {
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
func daemonProgramName(domain, name string) string { return config.SiteDaemonProgram(domain, name) }
func daemonProgramPath(domain, name string) string {
	return supervisorProgramConfPath(daemonProgramName(domain, name))
}

// desiredProgramPaths is the set of supervisor program file paths every site
// desires (worker iff QueueEnabled, plus each daemon) across the WHOLE server.
func desiredProgramPaths(s *config.Server) map[string]bool {
	desired := map[string]bool{}
	for _, site := range s.Sites {
		for _, name := range s.SiteProgramNames(site) {
			desired[supervisorProgramConfPath(name)] = true
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

// findRegularFiles lists the immediate REGULAR files of dir (optionally
// matching namePattern). find, not ls: a foreign subdirectory must not spill
// its contents into the listing, and symlinks/special files must never reach
// the marker probe (cat follows symlinks and can block on a FIFO) nor rm.
// A nonzero find exit (permission, I/O) is a loud error: empty output would
// otherwise read as "no candidates" and every orphan would be silently
// skipped forever. A MISSING directory is the one legitimate quiet case
// (guarded by [ -d ]: exit 0, no output): on a fresh minimal image
// /etc/cron.d does not exist until site.Apply's own ensureCron installs
// cron, and a Check error here would fail-fast the engine before that Apply
// ever ran. Filenames with embedded newlines or edge whitespace stay as-is:
// a mangled path fails safe through the marker re-probe (its cat finds no
// berth marker), never through rm.
func findRegularFiles(ctx context.Context, r bssh.Runner, dir, namePattern string) ([]string, error) {
	cmd := "find " + shQuote(dir) + " -maxdepth 1 -type f"
	if namePattern != "" {
		cmd += " -name " + shQuote(namePattern)
	}
	cmd = "if [ -d " + shQuote(dir) + " ]; then " + cmd + "; fi"
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("list %s for orphan discovery: find exited %d: %s", dir, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		if p := strings.TrimSpace(line); p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// findDirectories lists the immediate subdirectories of dir. A missing dir is
// simply an empty result (mirrors findRegularFiles); a failing find is an
// error — orphan discovery must never mistake "could not look" for "nothing
// there".
func findDirectories(ctx context.Context, r bssh.Runner, dir string) ([]string, error) {
	cmd := "if [ -d " + shQuote(dir) + " ]; then find " + shQuote(dir) + " -mindepth 1 -maxdepth 1 -type d; fi"
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("list %s for orphan discovery: find exited %d: %s", dir, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	var dirs []string
	for _, line := range strings.Split(res.Stdout, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			dirs = append(dirs, line)
		}
	}
	return dirs, nil
}

// orphanSiteFiles returns remove-entries for berth-managed vhosts, FPM pools
// and scheduler crons whose site is no longer in the config. Discovery is the
// proven sweep pattern (supervisor/backups/valkey): list candidates, skip the
// desired set, and remove ONLY files carrying the berth managed marker — a
// foreign vhost/pool/cron is never touched. Without this, removing a site from
// the YAML left its vhost publicly served, its pool running and its cron
// executing schedule:run of removed code, forever, with every run green.
// Only the CONFIGURED PHP version's pool dir is swept: cleaning up after a
// php.version change is a separate (documented) manual step.
func orphanSiteFiles(ctx context.Context, r bssh.Runner, s *config.Server) ([]siteFile, error) {
	desired := map[string]bool{}
	for _, site := range s.Sites {
		desired[nginxAvailablePath(site.Domain)] = true
		desired[fpmPoolPath(s.PHP.Version, site.Domain)] = true
		desired[cronPath(site.Domain)] = true
	}
	var files []siteFile
	for _, k := range []struct{ dir, pattern string }{
		{"/etc/nginx/sites-available", ""},
		{fpmPoolDir(s.PHP.Version), "*.conf"},
		{"/etc/cron.d", "berth-site-*"},
	} {
		paths, err := findRegularFiles(ctx, r, k.dir, k.pattern)
		if err != nil {
			return nil, err
		}
		for _, p := range paths {
			if desired[p] {
				continue
			}
			managed, err := managedFilePresent(ctx, r, p)
			if err != nil {
				return nil, err
			}
			if managed {
				files = append(files, siteFile{path: p, remove: true})
			}
		}
	}
	return files, nil
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
	// Enforce the managed-marker policy for the global Cloudflare snippet
	// regardless of loop position: an earlier drifted file (e.g. a vhost that just
	// gained the guard) would otherwise short-circuit Check before this entry's
	// unmanaged-conflict check ran, letting Apply overwrite a foreign
	// berth-cloudflare.conf without --force. (Mirrors systembase's unconditional pre-check.)
	if s.AnyCloudflareOnly() {
		cf, err := renderCloudflareConf()
		if err != nil {
			return provision.CheckResult{}, err
		}
		state, err := checkManagedFile(ctx, r, cloudflareConfPath, cf)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if _, err := managedFileSatisfied(state, cloudflareConfPath, rc.Force); err != nil {
			return provision.CheckResult{}, err
		}
	}
	for _, mf := range mfs {
		var reason string
		if mf.remove {
			present, err := managedFilePresent(ctx, r, mf.path)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if !present {
				continue
			}
			reason = mf.path + " should be removed (feature disabled or site removed)"
		} else {
			state, err := checkManagedFile(ctx, r, mf.path, mf.content)
			if err != nil {
				return provision.CheckResult{}, err
			}
			ok, err := managedFileSatisfied(state, mf.path, rc.Force)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if ok {
				continue
			}
			reason = mf.path + " not up to date"
		}
		// First unsatisfied hit, whatever tripped it: Apply will ALSO perform
		// every planned removal, so the destructive dry-run preview must ride
		// along on EVERY unsatisfied result of this loop — a content drift
		// used to short-circuit before the preview was computed, silently
		// omitting deletions from --dry-run. Computed lazily (read-only cat
		// probes) so a satisfied run never pays for it.
		removals, err := plannedRemovals(ctx, r, mfs)
		if err != nil {
			return provision.CheckResult{}, err
		}
		return provision.CheckResult{Satisfied: false, Reason: reason, Changes: append(removals, st.changes()...)}, nil
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
	// The RUNNING nginx/FPM must postdate every managed vhost/pool: a crash
	// between a write and its reload otherwise serves the old config forever
	// (e.g. a just-enabled cloudflare_only lockdown not actually enforced)
	// while the bytes on disk read converged. The enabled symlink and the
	// absence of the stock www pool are probed too — Apply converges both
	// every run, but nothing re-triggered it when only they drifted.
	var vhosts, pools []string
	if s.AnyCloudflareOnly() {
		vhosts = append(vhosts, cloudflareConfPath)
	}
	for _, site := range s.Sites {
		vhosts = append(vhosts, nginxAvailablePath(site.Domain))
		pools = append(pools, fpmPoolPath(s.PHP.Version, site.Domain))
		res, err := r.Run(ctx, "[ "+shQuote(nginxEnabledPath(site.Domain))+" -ef "+shQuote(nginxAvailablePath(site.Domain))+" ]", nil)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if res.ExitCode != 0 {
			return provision.CheckResult{Satisfied: false, Reason: "site " + site.Domain + " not enabled (sites-enabled link missing or wrong)", Changes: st.changes()}, nil
		}
	}
	// The governing directories join the probes: a directory newer than the
	// stamp means links/files were added or removed after the last reload
	// (out-of-band link recreation, a recreated stock file) — invisible to the
	// per-file probes above — so one reconciling reload is scheduled.
	vhosts = append(vhosts, nginxEnabledDir)
	pools = append(pools, fpmPoolDir(s.PHP.Version))
	stock, err := fileExists(ctx, r, defaultFPMPoolPath(s))
	if err != nil {
		return provision.CheckResult{}, err
	}
	if stock {
		return provision.CheckResult{Satisfied: false, Reason: "stock FPM pool present (must be disabled)", Changes: st.changes()}, nil
	}
	// Liveness for these units lives in the nginx and php steps (site's
	// Requires()), whose serviceUp/serviceActive probes satisfy the
	// reloadedSince pairing contract at pipeline level.
	nginxLoaded, err := reloadedSince(ctx, r, "nginx", vhosts...)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !nginxLoaded {
		return provision.CheckResult{Satisfied: false, Reason: "running nginx predates a managed vhost (reload pending)", Changes: st.changes()}, nil
	}
	fpmLoaded, err := reloadedSince(ctx, r, fpmService(s), pools...)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !fpmLoaded {
		return provision.CheckResult{Satisfied: false, Reason: "running php-fpm predates a managed pool (reload pending)", Changes: st.changes()}, nil
	}
	// /etc/cron.d drop-ins are inert without a running cron daemon; the
	// scheduler promise depends on it, so probe it (Apply heals via ensureCron).
	if anySchedulerEnabled(s) {
		cronUp, err := serviceUp(ctx, r, "cron")
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !cronUp {
			return provision.CheckResult{Satisfied: false, Reason: "cron daemon not active/enabled (scheduler crons are inert)", Changes: st.changes()}, nil
		}
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

// plannedRemovals probes every remove-entry in mfs and returns a
// "remove: <path>" line for each berth-managed file actually present — the
// deletions Apply will really perform (an absent or foreign file is skipped
// by Apply's guards, so previewing it would lie to the operator).
func plannedRemovals(ctx context.Context, r bssh.Runner, mfs []siteFile) ([]string, error) {
	var out []string
	for _, mf := range mfs {
		if !mf.remove {
			continue
		}
		present, err := managedFilePresent(ctx, r, mf.path)
		if err != nil {
			return nil, err
		}
		if present {
			out = append(out, "remove: "+mf.path)
		}
	}
	return out, nil
}

func (site) changes() []string {
	return []string{
		"write per-site nginx server block + enable it",
		"write per-site FPM pool (own user + socket)",
		"write per-site supervisor programs (worker + daemons) and remove orphans",
		"reconcile per-site scheduler cron (install or remove)",
		"remove orphan vhosts/pools/scheduler crons of sites no longer in the config",
		"write global logrotate fragment",
		"reconcile the global Cloudflare origin-lockdown snippet (write or remove)",
	}
}

func (st site) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	// Discover the removed-site orphans up front (read-only, so it may precede
	// the stamp invalidation) and classify them by owning unit: each class is
	// deleted inside its unit's invalidate→mutate→validate→reload→mark window.
	// The managedFilePresent guard already ran inside discovery this same call —
	// removal goes by the discovered absolute paths only.
	orphans, err := orphanSiteFiles(ctx, r, s)
	if err != nil {
		return err
	}
	var orphanVhosts, orphanPools, orphanCrons []string
	for _, o := range orphans {
		switch {
		case strings.HasPrefix(o.path, "/etc/nginx/sites-available/"):
			orphanVhosts = append(orphanVhosts, o.path)
		case strings.HasPrefix(o.path, fpmPoolDir(s.PHP.Version)+"/"):
			orphanPools = append(orphanPools, o.path)
		default:
			orphanCrons = append(orphanCrons, o.path)
		}
	}

	// Invalidate nginx's reload stamp before the first nginx-config mutation
	// (the cloudflare snippet or a vhost): from here until markReloaded after
	// the successful reload in step 3, a crash leaves no stamp and the next
	// run reconciles with one reload.
	if err := invalidateReloaded(ctx, r, "nginx"); err != nil {
		return err
	}

	// 0) When cloudflare_only is active, write the global geo/realip snippet BEFORE
	//    the per-site vhosts so $berth_cloudflare is defined when nginx -t validates a
	//    guarded vhost. (The disabled-state removal happens AFTER the vhosts are
	//    rewritten unguarded — step 2 below — so the geo outlives the last vhost
	//    that references it.)
	if s.AnyCloudflareOnly() {
		cf, err := renderCloudflareConf()
		if err != nil {
			return err
		}
		if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
			Path: cloudflareConfPath, Content: cf, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
		}); err != nil {
			return fmt.Errorf("write %s: %w", cloudflareConfPath, err)
		}
	}

	// 1) Per-site nginx server block (cert-aware) + enable.
	for _, site := range s.Sites {
		conf, err := renderSiteNginx(ctx, r, s, site)
		if err != nil {
			return fmt.Errorf("render nginx config for %s: %w", site.Domain, err)
		}
		if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
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

	// 2) cloudflare_only disabled: the vhosts above are already rewritten
	//    without the guard, so validation passes without the geo — drift-remove
	//    a lingering berth-managed snippet (guarded so a foreign conf.d file is
	//    never clobbered) BEFORE the validate+reload: under the transactional
	//    reload stamp no nginx-config mutation may follow the mark in step 3.
	//    The geo still outlives every vhost that referenced it — the removal
	//    runs only after step 1 rewrote them all unguarded.
	if !s.AnyCloudflareOnly() {
		present, err := managedFilePresent(ctx, r, cloudflareConfPath)
		if err != nil {
			return err
		}
		if present {
			if res, err := r.Run(ctx, "rm -f "+shQuote(cloudflareConfPath), nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("remove %s: %s", cloudflareConfPath, res.Stderr)
			}
		}
	}

	// Orphan vhosts: the site left the config. The disposition check runs
	// FIRST and deletes NOTHING when the enabled entry exists but is not
	// berth's symlink to this vhost (a foreign file, hardlink or repointed
	// link — exit 3): nginx -t is perfectly happy with such a leftover, so it
	// would keep serving the removed site silently forever. Because the
	// berth-marked available file SURVIVES that refusal, discovery re-finds
	// the orphan on every later run and both Check and Apply repeat the same
	// actionable error — a stable loud failure, not a one-shot one. When the
	// entry is ours (or absent/dangling), link and file are removed together.
	for _, p := range orphanVhosts {
		link := nginxEnabledPath(strings.TrimPrefix(p, "/etc/nginx/sites-available/"))
		cmd := "if [ -e " + shQuote(link) + " ] && ! { [ -L " + shQuote(link) + " ] && [ " + shQuote(link) + " -ef " + shQuote(p) + " ]; }; then exit 3; fi; if [ -L " + shQuote(link) + " ]; then rm -f " + shQuote(link) + "; fi; rm -f " + shQuote(p)
		if res, err := r.Run(ctx, cmd, nil); err != nil {
			return err
		} else if res.ExitCode == 3 {
			return fmt.Errorf("orphan vhost %s: enabled entry %s is a foreign file or hardlink, not berth's symlink — remove it manually; nginx keeps serving the removed site otherwise (the berth-marked vhost file is kept so every run repeats this error)", p, link)
		} else if res.ExitCode != 0 {
			return fmt.Errorf("remove orphan vhost %s: %s", p, res.Stderr)
		}
	}

	// 3) Validate the whole nginx configuration BEFORE reloading, then stamp:
	//    the running nginx now postdates every vhost written above.
	if res, err := r.Run(ctx, "nginx -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		// Terminal diagnosis: php/nginx defer unit-validation failures here
		// (P13), and this step just re-rendered every site-owned vhost — the
		// validator's path points at an unmanaged file, unit config owned by
		// an earlier berth step, certificate state, or a berth template bug.
		return fmt.Errorf("nginx -t failed, refusing to reload: %s — berth just re-rendered every site-owned vhost, so inspect the file the validator names (an unmanaged file, unit config owned by an earlier berth step, certificate state, or a berth template bug); fix or remove it", res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload nginx", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload nginx: %s", res.Stderr)
	}
	if err := markReloaded(ctx, r, "nginx"); err != nil {
		return err
	}

	// 4) Per-site FPM pools (each its own user + socket), a separate unit with
	//    its own invalidate/mark pair. Disable the stock www pool first so it
	//    cannot answer on a shared socket.
	if err := invalidateReloaded(ctx, r, fpmService(s)); err != nil {
		return err
	}
	disableWWW := fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(defaultFPMPoolPath(s)))
	if _, err := r.Run(ctx, disableWWW, nil); err != nil {
		return err
	}
	for _, site := range s.Sites {
		pool, err := renderFPMPool(s, site)
		if err != nil {
			return fmt.Errorf("render FPM pool for %s: %w", site.Domain, err)
		}
		if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
			Path: fpmPoolPath(s.PHP.Version, site.Domain), Content: pool,
			Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
		}); err != nil {
			return fmt.Errorf("write FPM pool for %s: %w", site.Domain, err)
		}
	}
	// Orphan pools (removed sites): deleted inside the FPM window so the
	// validate+reload below stop the orphan's workers in the same transaction.
	for _, p := range orphanPools {
		if res, err := r.Run(ctx, "rm -f "+shQuote(p), nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("remove orphan FPM pool %s: %s", p, res.Stderr)
		}
	}
	if res, err := r.Run(ctx, "php-fpm"+s.PHP.Version+" -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		// Terminal diagnosis — same contract as the nginx -t failure above.
		return fmt.Errorf("php-fpm%s -t failed, refusing to reload: %s — berth just re-rendered every site-owned pool, so inspect the file the validator names (an unmanaged file, unit config owned by an earlier berth step, or a berth template bug); fix or remove it", s.PHP.Version, res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload "+fpmService(s), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload %s: %s", fpmService(s), res.Stderr)
	}
	// No FPM-config mutation follows (supervisor/cron/logrotate below belong
	// to other units), so the stamp may bless the running pools.
	if err := markReloaded(ctx, r, fpmService(s)); err != nil {
		return err
	}

	// Scheduler crons are inert without the daemon; ensure it before writing them.
	if anySchedulerEnabled(s) {
		if err := ensureCron(ctx, r); err != nil {
			return err
		}
	}

	// 5) Per-site Supervisor worker (iff queue enabled) + daemons, then
	//    6) guarded scheduler cron.
	for _, site := range s.Sites {
		if s.QueueEnabled(site) {
			worker, err := renderSupervisorProgram(programName(site.Domain), queueCommand(s, site), queueNumprocs(site), s.SiteUser(site), site.DeployPath)
			if err != nil {
				return fmt.Errorf("render supervisor worker for %s: %w", site.Domain, err)
			}
			if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
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
			if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
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
			if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
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

	// Orphan scheduler crons (removed sites): no unit window — /etc/cron.d
	// drop-ins take effect on removal by themselves.
	for _, p := range orphanCrons {
		if res, err := r.Run(ctx, "rm -f "+shQuote(p), nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("remove orphan scheduler cron %s: %s", p, res.Stderr)
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
		// supervisord too — whenever supervisord is RUNNING (an active but
		// boot-disabled daemon would otherwise keep executing the removed
		// site's worker; enablement stays the supervisor step's business).
		// A non-zero probe exit just means absent (skip); a transport error
		// propagates like any Apply command.
		up, err := serviceActive(ctx, r, "supervisor")
		if err != nil {
			return err
		}
		if up {
			if err := supervisorReload(ctx, r); err != nil {
				return err
			}
		}
	}

	// 7) Global logrotate fragment for FPM + supervisor logs (one file, globs).
	lr, err := renderLogrotate()
	if err != nil {
		return err
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
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

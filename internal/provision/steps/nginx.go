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

// nginxConfPath is nginx's main config. The nginx.org package ships it with
// `user nginx;`, but berth's permission model (deploy_path group www-data, FPM
// socket owned by www-data) assumes nginx workers run as www-data — as Debian's
// package does. For the nginx.org source berth reconciles the worker user back
// to www-data so nginx can traverse deploy_path and connect to the FPM socket.
const nginxConfPath = "/etc/nginx/nginx.conf"

// Stock catch-all server blocks berth disables so they cannot answer unmatched
// :80 traffic: Debian ships sites-enabled/default, nginx.org ships
// conf.d/default.conf.
const (
	debianDefaultSite   = "/etc/nginx/sites-enabled/default"
	nginxOrgDefaultConf = "/etc/nginx/conf.d/default.conf"
)

// nginxBridgePath/nginxBridgeContent are the managed conf.d include bridging
// nginx.org's layout to Debian's sites-enabled/ (single source for Check's
// drift probe and Apply's write, so they can never disagree).
const nginxBridgePath = "/etc/nginx/conf.d/berth-sites.conf"

func nginxBridgeContent() []byte {
	return []byte(managedMarker + "\ninclude /etc/nginx/sites-enabled/*;\n")
}

// nginxOwnedConfigFiles are the config files this step's Apply lays down or
// rewrites, probed against the reload stamp: nginx.conf always (the package
// ships it; the worker-user sed rewrites it for source=nginx), plus the conf.d
// sites bridge for source=nginx. The stock-default removals need no entry —
// a removed path can never be newer than the stamp.
func nginxOwnedConfigFiles(s *config.Server) []string {
	files := []string{nginxConfPath}
	if s.Nginx.Source == "nginx" {
		files = append(files, nginxBridgePath)
	}
	return files
}

func (n nginx) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	installed, err := pkgInstalled(ctx, r, "nginx")
	if err != nil {
		return provision.CheckResult{}, err
	}
	up, err := serviceUp(ctx, r, "nginx")
	if err != nil {
		return provision.CheckResult{}, err
	}
	// When nginx.org is the configured source, its repo must be registered (so a
	// source switch re-triggers Apply) and its worker user must be reconciled to
	// www-data (so berth's www-data-based permission model holds).
	sourceOK, userOK, bridgeOK := true, true, true
	if s.Nginx.Source == "nginx" {
		sourceOK, err = fileExists(ctx, r, nginxOrgSourceList)
		if err != nil {
			return provision.CheckResult{}, err
		}
		userOK, err = nginxRunsAsWWWData(ctx, r)
		if err != nil {
			return provision.CheckResult{}, err
		}
		// The sites bridge must be the berth-managed one: without it nginx.org's
		// nginx never loads sites-enabled/, so a missing/drifted bridge is
		// unsatisfied drift and a foreign file aborts unless --force.
		state, err := checkManagedFile(ctx, r, nginxBridgePath, nginxBridgeContent())
		if err != nil {
			return provision.CheckResult{}, err
		}
		bridgeOK, err = managedFileSatisfied(state, nginxBridgePath, rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
	}
	// The stock catch-all sites must be disabled.
	defaultsDisabled, err := stockDefaultsDisabled(ctx, r)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !(installed && up && sourceOK && userOK && bridgeOK && defaultsDisabled) {
		return provision.CheckResult{
			Satisfied: false,
			Reason:    "nginx not installed, not running, not from the configured source, worker user not www-data, or stock default site still enabled",
			Changes:   n.changes(s),
		}, nil
	}
	// The RUNNING nginx must postdate the core config this step owns: a crash
	// between Apply's writes and its final reload leaves the daemon on the old
	// config forever while every byte-level probe above reads converged. Probed
	// only once everything else is satisfied — any drift above re-runs Apply,
	// which always ends with a reload + fresh stamp. serviceUp above is the
	// liveness probe reloadedSince requires.
	loaded, err := reloadedSince(ctx, r, "nginx", nginxOwnedConfigFiles(s)...)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !loaded {
		return provision.CheckResult{
			Satisfied: false,
			Reason:    "running nginx predates its managed core config (reload pending)",
			Changes:   n.changes(s),
		}, nil
	}
	return provision.CheckResult{Satisfied: true, Reason: "nginx installed and running from the " + s.Nginx.Source + " source (worker user www-data); stock default sites disabled"}, nil
}

func (nginx) changes(s *config.Server) []string {
	return []string{"install nginx (" + s.Nginx.Source + ")", "run workers as www-data", "disable stock default site(s)", "systemctl enable --now nginx"}
}

// nginxRunsAsWWWData reports whether nginx.conf sets the worker user to www-data.
func nginxRunsAsWWWData(ctx context.Context, r bssh.Runner) (bool, error) {
	res, err := r.Run(ctx, "grep -qE '^[[:space:]]*user[[:space:]]+www-data;' "+nginxConfPath, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
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

func (nginx) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	m := apt.New(r)
	if s.Nginx.Source == "nginx" {
		if err := m.EnsureRepo(ctx, apt.NginxOrg()); err != nil {
			return fmt.Errorf("add nginx.org repo: %w", err)
		}
	}
	// Invalidate nginx's reload stamp before the package transaction, not just
	// before the config mutations this step performs itself (bridge write /
	// worker-user sed / stock-default removal): apt can mutate the unit's
	// config too (conffiles, maintainer scripts). From here until markReloaded
	// after the successful reload below, a crash leaves no stamp and the next
	// run reconciles with one reload.
	if err := invalidateReloaded(ctx, r, "nginx"); err != nil {
		return err
	}
	if err := m.EnsurePackages(ctx, nil, "nginx"); err != nil {
		return fmt.Errorf("install nginx: %w", err)
	}
	if s.Nginx.Source == "nginx" {
		if err := bridgeNginxSitesLayout(ctx, r, rc.Force); err != nil {
			return err
		}
		if err := ensureNginxWorkerUser(ctx, r); err != nil {
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
		// -t validates the WHOLE unit, so the failure may live in a vhost
		// owned by the later site step; fail-fast stops the run before site
		// could heal it, so point the operator there.
		return fmt.Errorf("nginx -t failed after disabling stock defaults: %s — if the failure points at a vhost under /etc/nginx/sites-available/, fix or remove that file (berth's site step re-renders its vhosts on the next run)", res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload nginx", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload nginx: %s", res.Stderr)
	}
	// No nginx-config mutation follows (every write/removal above precedes the
	// validate+reload), so the stamp may bless the running config.
	return markReloaded(ctx, r, "nginx")
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
func bridgeNginxSitesLayout(ctx context.Context, r bssh.Runner, force bool) error {
	if res, err := r.Run(ctx, "install -d /etc/nginx/sites-available /etc/nginx/sites-enabled", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("create nginx sites dirs: %s", res.Stderr)
	}
	if err := writeManagedFile(ctx, r, force, bssh.FileSpec{
		Path: nginxBridgePath, Content: nginxBridgeContent(),
		Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write nginx sites bridge: %w", err)
	}
	return nil
}

// ensureNginxWorkerUser rewrites nginx.conf's `user` directive to www-data
// (idempotent). The nginx.org package defaults to `user nginx;`, which would
// leave workers unable to traverse deploy_path (group www-data) or connect to
// the FPM socket (owned by www-data). The subsequent nginx -t + reload applies
// the new worker credentials.
func ensureNginxWorkerUser(ctx context.Context, r bssh.Runner) error {
	cmd := `sed -ri 's|^[[:space:]]*user[[:space:]]+[^;]*;|user  www-data;|' ` + nginxConfPath
	if res, err := r.Run(ctx, cmd, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("set nginx worker user to www-data: %s", res.Stderr)
	}
	return nil
}

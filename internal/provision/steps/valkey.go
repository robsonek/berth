package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

// valkeyUnit is the systemd unit shipped by the Debian valkey-server package.
const valkeyUnit = "valkey-server.service"

const (
	valkeyUnitDir   = "/etc/systemd/system"
	valkeyRunBase   = "/run/berth-valkey"
	valkeyStateBase = "/var/lib/berth-valkey"
)

// Per-site instance identity. One Valkey per site, reachable only via a unix
// socket in a 0700 runtime dir owned by the site user — OS-level tenant
// isolation, no TCP listener, no credentials (same philosophy as the per-site
// FPM pool). systemd creates Runtime/StateDirectory owned by User=, so the
// step needs no mkdir/chown and does not depend on appdirs.
func valkeyInstanceUnit(domain string) string { return "berth-valkey-" + poolName(domain) + ".service" }
func valkeyUnitPath(domain string) string     { return valkeyUnitDir + "/" + valkeyInstanceUnit(domain) }
func valkeySocketPath(domain string) string {
	return valkeyRunBase + "/" + poolName(domain) + "/valkey.sock"
}
func valkeyDataDir(domain string) string { return valkeyStateBase + "/" + poolName(domain) }

// renderValkeyUnit renders one site's managed instance unit. All configuration
// travels as ExecStart args on purpose: nothing here is secret, and it keeps
// the unit the single managed artifact per site. The maxmemory knobs are the
// existing tuning.* config values — the cap is per instance.
func renderValkeyUnit(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("berth_valkey.service.tmpl", struct {
		Domain, User, Pool, Maxmemory, Policy string
	}{
		Domain:    site.Domain,
		User:      s.SiteUser(site),
		Pool:      poolName(site.Domain),
		Maxmemory: s.Tuning.ValkeyMaxmemoryEff(),
		Policy:    s.Tuning.ValkeyMaxmemoryPolicyEff(),
	})
}

type valkey struct{}

func Valkey() provision.Step { return valkey{} }

func (valkey) Name() string       { return "valkey" }
func (valkey) Requires() []string { return []string{"base", "accounts"} }

// valkeyListUnitsCmd lists berth-managed per-site instance units. Global glob
// (never per-pool): pool names can be prefixes of one another, so a per-site
// glob could match a sibling's unit — same rule as the supervisor sweep.
const valkeyListUnitsCmd = "ls -1 /etc/systemd/system/berth-valkey-*.service 2>/dev/null"

func listValkeyUnits(ctx context.Context, r bssh.Runner) ([]string, error) {
	res, err := r.Run(ctx, valkeyListUnitsCmd, nil)
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

func desiredValkeyUnitPaths(s *config.Server) map[string]bool {
	desired := map[string]bool{}
	for _, site := range s.Sites {
		desired[valkeyUnitPath(site.Domain)] = true
	}
	return desired
}

// valkeyPingCmd probes an instance AS THE SITE USER over its socket: a PONG
// proves both that the daemon answers and that the socket path admits the
// tenant (owner-only runtime dir + socket perms) — the step's whole point.
func valkeyPingCmd(user, domain string) string {
	return "runuser -u " + shQuote(user) + " -- valkey-cli -s " + shQuote(valkeySocketPath(domain)) + " ping"
}

// unitCacheFresh reports whether systemd's loaded copy of unit matches the
// file on disk (NeedDaemonReload=no). A write that crashed before
// daemon-reload leaves the manager serving stale ExecStart args — a state the
// mtime-vs-ActiveEnterTimestamp probe alone cannot always expose.
func unitCacheFresh(ctx context.Context, r bssh.Runner, unit string) (bool, error) {
	res, err := r.Run(ctx, "systemctl show -p NeedDaemonReload --value "+unit, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0 && strings.TrimSpace(res.Stdout) == "no", nil
}

func (valkey) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	ok := true
	installed, err := pkgInstalled(ctx, r, "valkey-server")
	if err != nil {
		return provision.CheckResult{}, err
	}
	ok = ok && installed

	// The stock shared service IS the vulnerability this step removes (an
	// unauthenticated listener on 127.0.0.1:6379): it must be disabled AND
	// inactive.
	stockEnabled, err := r.Run(ctx, "systemctl is-enabled "+valkeyUnit, nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	stockActive, err := r.Run(ctx, "systemctl is-active "+valkeyUnit, nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	ok = ok && stockEnabled.ExitCode != 0 && stockActive.ExitCode != 0

	// The legacy tuning drop-in targeted the stock unit; a berth-managed copy
	// left behind must be migrated away (foreign files are left alone).
	legacyDropIn, err := managedFilePresent(ctx, r, valkeyDropInPath)
	if err != nil {
		return provision.CheckResult{}, err
	}
	ok = ok && !legacyDropIn

	for _, site := range s.Sites {
		want, err := renderValkeyUnit(s, site)
		if err != nil {
			return provision.CheckResult{}, err
		}
		state, err := checkManagedFile(ctx, r, valkeyUnitPath(site.Domain), want)
		if err != nil {
			return provision.CheckResult{}, err
		}
		unitOK, err := managedFileSatisfied(state, valkeyUnitPath(site.Domain), rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		up, err := serviceUp(ctx, r, valkeyInstanceUnit(site.Domain))
		if err != nil {
			return provision.CheckResult{}, err
		}
		// Liveness beyond "active": the running process must actually use the
		// on-disk unit (crash between write and restart leaves stale ExecStart
		// args running — the same window checkTuned closes for MariaDB), and
		// the daemon must answer over the socket AS the site user.
		loaded, fresh, pong := false, false, false
		if unitOK && up {
			if loaded, err = serviceConfigLoaded(ctx, r, valkeyInstanceUnit(site.Domain), valkeyUnitPath(site.Domain)); err != nil {
				return provision.CheckResult{}, err
			}
			if fresh, err = unitCacheFresh(ctx, r, valkeyInstanceUnit(site.Domain)); err != nil {
				return provision.CheckResult{}, err
			}
			res, err := r.Run(ctx, valkeyPingCmd(s.SiteUser(site), site.Domain), nil)
			if err != nil {
				return provision.CheckResult{}, err
			}
			pong = res.ExitCode == 0 && strings.TrimSpace(res.Stdout) == "PONG"
		}
		ok = ok && unitOK && up && loaded && fresh && pong
	}

	// Orphans: only berth-MANAGED units count (mirror Apply's guard) — a
	// foreign file matching the glob is not ours to remove, so counting it
	// would make the step permanently unsatisfiable.
	units, err := listValkeyUnits(ctx, r)
	if err != nil {
		return provision.CheckResult{}, err
	}
	desired := desiredValkeyUnitPaths(s)
	for _, u := range units {
		if desired[u] {
			continue
		}
		present, err := managedFilePresent(ctx, r, u)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if present {
			ok = false
		}
	}

	if ok {
		return provision.CheckResult{Satisfied: true, Reason: "per-site valkey instances running, stock service off"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "per-site valkey fleet not converged",
		Changes: []string{
			"install valkey-server (valkey-cli comes via its valkey-tools dependency)",
			"disable the stock shared valkey-server.service",
			"remove the legacy valkey tuning drop-in (when berth-managed)",
			"per site: write berth-valkey-<pool>.service, enable --now, verify PONG over the socket",
			"remove orphan berth-valkey instances",
		},
	}, nil
}

func (valkey) Apply(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	if err := apt.New(r).EnsurePackages(ctx, nil, "valkey-server"); err != nil {
		return fmt.Errorf("install valkey-server: %w", err)
	}
	if res, err := r.Run(ctx, "systemctl enable --now "+valkeyUnit, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("enable valkey-server: %s", res.Stderr)
	}
	return nil
}

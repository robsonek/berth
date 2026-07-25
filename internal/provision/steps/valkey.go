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

// valkeyUnit is the systemd unit shipped by the Debian valkey-server package.
const valkeyUnit = "valkey-server.service"

// Legacy paths of the pre-per-site tuning drop-in that targeted the stock
// valkey-server.service; kept only so Apply can migrate them away.
const (
	valkeyDropInDir  = "/etc/systemd/system/valkey-server.service.d"
	valkeyDropInPath = valkeyDropInDir + "/berth.conf"
)

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

// valkeyBinary is the path the instance units exec; probed for staleness after
// unattended-upgrades replace the file under a running process.
const valkeyBinary = "/usr/bin/valkey-server"

// valkeyExecCmd probes whether unit's running process still executes the
// CURRENT valkey binary: it compares the inode the process's /proc/<pid>/exe
// resolves to (stat -L follows to the possibly-deleted inode) against the
// on-disk binary's inode. A mismatch means the binary was replaced (e.g. by
// unattended-upgrades) under a running process — the stock unit gets a
// postinst restart, ours do not, so Check must catch it.
func valkeyExecCmd(unit string) string {
	return `p="$(systemctl show -p MainPID --value ` + unit + `)"; [ "$(stat -Lc %i /proc/$p/exe 2>/dev/null)" = "$(stat -c %i ` + valkeyBinary + ` 2>/dev/null)" ]`
}

// valkeyExecCurrent reports whether unit's process runs the current binary.
func valkeyExecCurrent(ctx context.Context, r bssh.Runner, unit string) (bool, error) {
	res, err := r.Run(ctx, valkeyExecCmd(unit), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

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
		// args running — the same window checkTuned closes for MariaDB), it
		// must execute the CURRENT binary (unattended-upgrades replaces the
		// file under the running process; only the stock unit gets a postinst
		// restart), and the daemon must answer over the socket AS the site
		// user.
		loaded, fresh, pong := false, false, false
		execFresh := false
		if unitOK && up {
			if loaded, err = serviceConfigLoaded(ctx, r, valkeyInstanceUnit(site.Domain), valkeyUnitPath(site.Domain)); err != nil {
				return provision.CheckResult{}, err
			}
			if fresh, err = unitCacheFresh(ctx, r, valkeyInstanceUnit(site.Domain)); err != nil {
				return provision.CheckResult{}, err
			}
			if execFresh, err = valkeyExecCurrent(ctx, r, valkeyInstanceUnit(site.Domain)); err != nil {
				return provision.CheckResult{}, err
			}
			if pong, err = valkeyPong(ctx, r, s.SiteUser(site), site.Domain); err != nil {
				return provision.CheckResult{}, err
			}
		}
		ok = ok && unitOK && up && loaded && fresh && execFresh && pong
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

func (valkey) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if err := aptInstall(ctx, r, "valkey-server"); err != nil {
		return fmt.Errorf("install valkey-server: %w", err)
	}
	// The stock shared service is the unauthenticated 6379 listener this step
	// replaces. disable --now is idempotent, and a disabled unit is not
	// re-enabled by package upgrades (deb-systemd-helper respects the state).
	if res, err := r.Run(ctx, "systemctl disable --now "+valkeyUnit, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("disable stock %s: %s", valkeyUnit, res.Stderr)
	}

	needReload := false

	// Migrate the legacy tuning drop-in (targeted the stock unit) — guarded:
	// only a berth-managed file is removed.
	if present, err := managedFilePresent(ctx, r, valkeyDropInPath); err != nil {
		return err
	} else if present {
		if res, err := r.Run(ctx, "rm -f "+shQuote(valkeyDropInPath), nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("remove legacy %s: %s", valkeyDropInPath, res.Stderr)
		}
		if res, err := r.Run(ctx, "rmdir --ignore-fail-on-non-empty "+shQuote(valkeyDropInDir), nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("rmdir %s: %s", valkeyDropInDir, res.Stderr)
		}
		needReload = true
	}

	// Orphan sweep, modelled on the supervisor one in site.go: disable and
	// remove berth-managed instances no site desires; never a foreign file.
	desired := desiredValkeyUnitPaths(s)
	units, err := listValkeyUnits(ctx, r)
	if err != nil {
		return err
	}
	for _, u := range units {
		if desired[u] {
			continue
		}
		present, err := managedFilePresent(ctx, r, u)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		unit := strings.TrimPrefix(u, valkeyUnitDir+"/")
		if res, err := r.Run(ctx, "systemctl disable --now "+unit, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("disable orphan %s: %s", unit, res.Stderr)
		}
		if res, err := r.Run(ctx, "rm -f "+shQuote(u), nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("remove orphan %s: %s", u, res.Stderr)
		}
		needReload = true
	}

	// Per-site units: write when absent or drifted (writeManagedFile enforces
	// the foreign-file abort), remember which changed for a targeted restart.
	changed := map[string]bool{}
	for _, site := range s.Sites {
		want, err := renderValkeyUnit(s, site)
		if err != nil {
			return err
		}
		state, err := checkManagedFile(ctx, r, valkeyUnitPath(site.Domain), want)
		if err != nil {
			return err
		}
		if state == fileUpToDate {
			continue
		}
		if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
			Path: valkeyUnitPath(site.Domain), Content: want,
			Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
		}); err != nil {
			return fmt.Errorf("write %s: %w", valkeyUnitPath(site.Domain), err)
		}
		// A replaced unit needs a restart to load the new ExecStart; a FRESH
		// one does not — enable --now below starts it with current content.
		if state != fileAbsent {
			changed[site.Domain] = true
		}
		needReload = true
	}

	if needReload {
		if res, err := r.Run(ctx, "systemctl daemon-reload", nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("daemon-reload: %s", res.Stderr)
		}
	}

	for _, site := range s.Sites {
		unit := valkeyInstanceUnit(site.Domain)
		if res, err := r.Run(ctx, "systemctl enable --now "+unit, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("enable %s: %s", unit, res.Stderr)
		}
		// enable --now is a no-op on an already-running unit, so a REPLACED
		// unit needs an explicit restart to load the rewritten ExecStart; an
		// untouched one may still be running stale config after a crash
		// between a past write and its restart (the loaded/NeedDaemonReload
		// probes catch that).
		restarted := false
		if changed[site.Domain] {
			if err := restartValkey(ctx, r, unit); err != nil {
				return err
			}
			restarted = true
		} else {
			loaded, err := serviceConfigLoaded(ctx, r, unit, valkeyUnitPath(site.Domain))
			if err != nil {
				return err
			}
			fresh, err := unitCacheFresh(ctx, r, unit)
			if err != nil {
				return err
			}
			execFresh, err := valkeyExecCurrent(ctx, r, unit)
			if err != nil {
				return err
			}
			if !loaded || !fresh || !execFresh {
				// A stale manager cache needs a daemon-reload before the
				// restart (restart alone re-runs the cached definition); a
				// stale binary just needs the restart (unit file unchanged).
				if !loaded || !fresh {
					if res, err := r.Run(ctx, "systemctl daemon-reload", nil); err != nil {
						return err
					} else if res.ExitCode != 0 {
						return fmt.Errorf("daemon-reload before restarting stale %s: %s", unit, res.Stderr)
					}
				}
				if err := restartValkey(ctx, r, unit); err != nil {
					return err
				}
				restarted = true
			}
		}
		// Heal-and-verify: an up-to-date unit whose daemon is wedged (or whose
		// socket vanished) would otherwise never converge — Check unsatisfied,
		// Apply all-no-op, forever. One restart, then fail loud.
		pong, err := valkeyPong(ctx, r, s.SiteUser(site), site.Domain)
		if err != nil {
			return err
		}
		if !pong && !restarted {
			if err := restartValkey(ctx, r, unit); err != nil {
				return err
			}
			if pong, err = valkeyPong(ctx, r, s.SiteUser(site), site.Domain); err != nil {
				return err
			}
		}
		if !pong {
			return fmt.Errorf("%s does not answer PONG on %s as %s (restart did not heal it); check `journalctl -u %s`",
				unit, valkeySocketPath(site.Domain), s.SiteUser(site), unit)
		}
	}
	return nil
}

// valkeyPong runs the per-site PONG probe (see valkeyPingCmd).
func valkeyPong(ctx context.Context, r bssh.Runner, user, domain string) (bool, error) {
	res, err := r.Run(ctx, valkeyPingCmd(user, domain), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0 && strings.TrimSpace(res.Stdout) == "PONG", nil
}

func restartValkey(ctx context.Context, r bssh.Runner, unit string) error {
	if res, err := r.Run(ctx, "systemctl restart "+unit, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("restart %s: %s", unit, res.Stderr)
	}
	return nil
}

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

// The run/state bases live in config (the domain-length cap is computed from
// their byte lengths); the state alias keeps valkeyDataDir short.
const (
	valkeyUnitDir   = "/etc/systemd/system"
	valkeyStateBase = config.ValkeyStateBase
)

// Per-site instance identity. One Valkey per site, reachable only via a unix
// socket in a 0700 runtime dir owned by the site user — OS-level tenant
// isolation, no TCP listener, no credentials (same philosophy as the per-site
// FPM pool). systemd creates Runtime/StateDirectory owned by User=, so the
// step needs no mkdir/chown and does not depend on appdirs.
func valkeyInstanceUnit(domain string) string { return config.ValkeyInstanceUnit(domain) }
func valkeyUnitPath(domain string) string     { return valkeyUnitDir + "/" + valkeyInstanceUnit(domain) }
func valkeySocketPath(domain string) string {
	return config.ValkeySocketPath(poolName(domain))
}
func valkeyDataDir(domain string) string { return valkeyStateBase + "/" + poolName(domain) }

// The queue instance (valkey_queue: true): a second process per site for the
// application's job queue, in the SAME 0700 runtime dir (its own socket leaf)
// with its own state dir, unit and memory cap. Names come from config so the
// status probe and the domain-length budget see the same strings.
func valkeyQueueInstanceUnit(domain string) string { return config.ValkeyQueueInstanceUnit(domain) }
func valkeyQueueUnitPath(domain string) string {
	return valkeyUnitDir + "/" + valkeyQueueInstanceUnit(domain)
}
func valkeyQueueSocketPath(domain string) string {
	return config.ValkeyQueueSocketPath(poolName(domain))
}
func valkeyQueueDataDir(domain string) string { return config.ValkeyQueueDataDir(poolName(domain)) }

// valkeyInstance is one Valkey process the step manages: the cache instance
// every site has, and — with valkey_queue on — the site's queue instance.
// Check and Apply iterate instances, not sites, so both roles get the exact
// same probes, writes, restarts and heal path with different values.
type valkeyInstance struct {
	site    config.Site
	unit    string // berth-valkey-<pool>.service | berth-valkey-<pool>-queue.service
	path    string // /etc/systemd/system/<unit>
	socket  string // …/valkey.sock | …/queue.sock (same 0700 runtime dir)
	dataDir string // StateDirectory=: …/<pool> | …/<pool>-queue
	queue   bool
}

// valkeyInstances lists every desired instance in site order: a site's cache
// instance first, then its queue instance when the knob is on.
func valkeyInstances(s *config.Server) []valkeyInstance {
	var out []valkeyInstance
	for _, site := range s.Sites {
		out = append(out, valkeyInstance{
			site: site, unit: valkeyInstanceUnit(site.Domain), path: valkeyUnitPath(site.Domain),
			socket: valkeySocketPath(site.Domain), dataDir: valkeyDataDir(site.Domain),
		})
		if s.ValkeyQueue {
			out = append(out, valkeyInstance{
				site: site, unit: valkeyQueueInstanceUnit(site.Domain), path: valkeyQueueUnitPath(site.Domain),
				socket: valkeyQueueSocketPath(site.Domain), dataDir: valkeyQueueDataDir(site.Domain), queue: true,
			})
		}
	}
	return out
}

// renderValkeyInstanceUnit renders the unit for one instance of either role.
func renderValkeyInstanceUnit(s *config.Server, in valkeyInstance) ([]byte, error) {
	if in.queue {
		return renderValkeyQueueUnit(s, in.site)
	}
	return renderValkeyUnit(s, in.site)
}

// valkeyDataOwnerCmd is the data-owner guard's probe: the same shape as
// assertSiteTreeOwners (appdirs.go) — %U owner name, %u uid, %F type last
// (it contains spaces), LC_ALL=C because %F is localized.
func valkeyDataOwnerCmd(dir string) string {
	return "LC_ALL=C stat -c '%U %u %F' " + shQuote(dir)
}

// assertValkeyDataOwners refuses when an EXISTING instance data dir (cache
// or queue) is not a directory owned by the site user. A removed site keeps
// its data on purpose, and systemd's StateDirectory= chowns a pre-existing
// directory's contents recursively to User= on the next start — so a later
// site whose derived dir name coincides (a re-added domain under another
// sites[].user; app.example.com-queue's cache dir vs app.example.com's queue
// dir) would silently inherit a previous tenant's dataset. Absent dirs pass
// (a fresh provision creates them). Runs FIRST in Check and Apply, over every
// instance of every site, and is deliberately not bypassable with --force:
// after a deliberate migration the owner matches and the guard passes.
func assertValkeyDataOwners(ctx context.Context, r bssh.Runner, s *config.Server) error {
	for _, in := range valkeyInstances(s) {
		res, err := r.Run(ctx, valkeyDataOwnerCmd(in.dataDir), nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			continue // absent: nothing to adopt
		}
		fields := strings.Fields(strings.TrimSpace(res.Stdout))
		if len(fields) < 3 {
			return fmt.Errorf("unexpected stat output probing %s: %q", in.dataDir, strings.TrimSpace(res.Stdout))
		}
		owner, uid, ftype := fields[0], fields[1], strings.Join(fields[2:], " ")
		if ftype != "directory" {
			return fmt.Errorf("refusing to manage valkey for %s: %s exists but is not a directory (%s) — inspect and remove it before re-running; --force does not override this check", in.site.Domain, in.dataDir, ftype)
		}
		if user := s.SiteUser(in.site); owner != user {
			return fmt.Errorf("refusing to manage valkey for %s: %s is owned by %s (uid %s) but the site user is %q; move or remove that directory (a removed site's data is kept on purpose), or pin sites[].user to its owner — --force does not override this check", in.site.Domain, in.dataDir, owner, uid, user)
		}
	}
	return nil
}

// valkeyBinary is the path the instance units exec; probed for staleness after
// unattended-upgrades replace the file under a running process.
const valkeyBinary = "/usr/bin/valkey-server"

// valkeyExecCmd probes whether unit's running process still executes the
// CURRENT valkey binary: it compares the inode the process's /proc/<pid>/exe
// resolves to against the binary the unit would exec. A mismatch means the
// binary was replaced (e.g. by unattended-upgrades) under a running process —
// the stock unit gets a postinst restart, ours do not, so Check must catch it.
//
// BOTH sides use `stat -L` (follow symlinks): /usr/bin/valkey-server is a
// symlink to the multi-call binary valkey-check-rdb (one file, mode chosen by
// argv[0], busybox-style), so /proc/<pid>/exe resolves to that real file. A
// bare `stat` on the symlink would report the SYMLINK's inode, never matching
// the process's real executable inode — making the probe fire on every
// healthy instance and breaking idempotency (found only on a fresh box, since
// unit tests stub the command string and a `cp+mv` "upgrade" replaces the
// symlink with a plain file, both of which hide the mismatch).
func valkeyExecCmd(unit string) string {
	return `p="$(systemctl show -p MainPID --value ` + unit + `)"; [ "$(stat -Lc %i /proc/$p/exe 2>/dev/null)" = "$(stat -Lc %i ` + valkeyBinary + ` 2>/dev/null)" ]`
}

// valkeyExecCurrent reports whether unit's process runs the current binary.
func valkeyExecCurrent(ctx context.Context, r bssh.Runner, unit string) (bool, error) {
	res, err := r.Run(ctx, valkeyExecCmd(unit), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// valkeyUnitData is the render struct of berth_valkey.service.tmpl, shared by
// the cache and the queue instance (one template, two value sets). Mirror any
// field change in the test-local copy in internal/templates/templates_test.go.
type valkeyUnitData struct {
	Domain, User, Pool, Maxmemory, Policy string
	// Queue selects the queue role: "queue" in the description and the fixed
	// AOF arguments on ExecStart. Preserve adds RuntimeDirectoryPreserve=yes:
	// both instances share one RuntimeDirectory, which systemd removes when
	// EITHER unit stops unless preserved — so it is set on BOTH units while
	// valkey_queue is on, and on neither otherwise (byte-identical to the
	// pre-feature unit). StateSuffix/SocketName pick the per-role data dir
	// and socket leaf.
	Queue, Preserve         bool
	StateSuffix, SocketName string
}

// renderValkeyUnit renders one site's managed CACHE instance unit. All
// configuration travels as ExecStart args on purpose: nothing here is secret,
// and it keeps the unit the single managed artifact per instance. The
// maxmemory knobs are the existing tuning.* config values — the cap is per
// instance.
func renderValkeyUnit(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("berth_valkey.service.tmpl", valkeyUnitData{
		Domain:     site.Domain,
		User:       s.SiteUser(site),
		Pool:       poolName(site.Domain),
		Maxmemory:  s.Tuning.ValkeyMaxmemoryEff(),
		Policy:     s.Tuning.ValkeyMaxmemoryPolicyEff(),
		Preserve:   s.ValkeyQueue,
		SocketName: "valkey.sock",
	})
}

// renderValkeyQueueUnit renders one site's managed QUEUE instance unit: the
// same template with the queue's own cap (tuning.valkey_queue_maxmemory), a
// fixed noeviction policy (a queue must never drop jobs — a full instance
// refuses writes instead) and fixed AOF persistence (appendfsync everysec).
func renderValkeyQueueUnit(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("berth_valkey.service.tmpl", valkeyUnitData{
		Domain:      site.Domain,
		User:        s.SiteUser(site),
		Pool:        poolName(site.Domain),
		Maxmemory:   s.Tuning.ValkeyQueueMaxmemoryEff(),
		Policy:      "noeviction",
		Queue:       true,
		Preserve:    true,
		StateSuffix: "-queue",
		SocketName:  "queue.sock",
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
	for _, in := range valkeyInstances(s) {
		desired[in.path] = true
	}
	return desired
}

// valkeyPingOver probes an instance AS THE SITE USER over its socket
// (valkey.sock or queue.sock — the read-only classifier in cmdclass_test.go
// pins this exact shape and both leaves): a PONG proves both that the daemon
// answers and that the socket path admits the tenant (owner-only runtime dir
// + socket perms) — the step's whole point.
//
// setpriv, not runuser: runuser opens a PAM session, and pam_unix logs a
// session open/close pair to the journal on every invocation — so a
// read-only Check wrote to the host, per site, per run. setpriv changes
// credentials directly without PAM (verified on a provisioned Debian 13
// host: PONG on the tenant's own socket, Permission denied cross-tenant,
// zero journal lines). --init-groups is load-bearing: it grants the site
// user's supplementary groups, which socket access can depend on — do not
// "simplify" it away.
func valkeyPingOver(user, socket string) string {
	qu := shQuote(user)
	return "setpriv --reuid " + qu + " --regid " + qu + " --init-groups -- valkey-cli -s " +
		shQuote(socket) + " ping"
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

// sweepValkeyUnits disables and removes berth-managed instance units not in
// desired (marker-guarded: a foreign berth-valkey-* file is never touched).
// Reports whether anything was removed so the caller can daemon-reload once.
func sweepValkeyUnits(ctx context.Context, r bssh.Runner, desired map[string]bool) (bool, error) {
	units, err := listValkeyUnits(ctx, r)
	if err != nil {
		return false, err
	}
	removed := false
	for _, u := range units {
		if desired[u] {
			continue
		}
		present, err := managedFilePresent(ctx, r, u)
		if err != nil {
			return false, err
		}
		if !present {
			continue
		}
		unit := strings.TrimPrefix(u, valkeyUnitDir+"/")
		if res, err := r.Run(ctx, "systemctl disable --now "+unit, nil); err != nil {
			return false, err
		} else if res.ExitCode != 0 {
			return false, fmt.Errorf("disable orphan %s: %s", unit, res.Stderr)
		}
		if res, err := r.Run(ctx, "rm -f "+shQuote(u), nil); err != nil {
			return false, err
		} else if res.ExitCode != 0 {
			return false, fmt.Errorf("remove orphan %s: %s", u, res.Stderr)
		}
		removed = true
	}
	return removed, nil
}

// checkDisabled is valkey's Check when the config turns the feature off: the
// step still runs (P14 — always registered) so berth-valkey instances a
// previous valkey:true provision left behind are reconciled away instead of
// running forever. Only marker-owned units count — a foreign berth-valkey-*
// file must not keep this unsatisfied forever (Apply would never remove it).
// A clean valkey-less host pays exactly one ls probe. The package and the
// disabled stock service are deliberately left alone (clearing = stop
// managing), and instance data under /var/lib/berth-valkey stays, matching
// the orphan sweep's data-retention behavior for removed sites.
func (valkey) checkDisabled(ctx context.Context, r bssh.Runner) (provision.CheckResult, error) {
	units, err := listValkeyUnits(ctx, r)
	if err != nil {
		return provision.CheckResult{}, err
	}
	owned := 0
	for _, u := range units {
		present, err := managedFilePresent(ctx, r, u)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if present {
			owned++
		}
	}
	if owned == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "valkey disabled; no berth-valkey instances present"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    fmt.Sprintf("valkey disabled but %d berth-valkey instance(s) remain", owned),
		Changes:   []string{"disable, stop and remove every berth-managed valkey instance (data under /var/lib/berth-valkey is kept)"},
	}, nil
}

// applyDisabled sweeps every berth-managed instance (empty desired set) and
// reloads the manager once if anything was removed. A crash between the unit
// removal and daemon-reload leaves only stale manager cache (runtime is
// already stopped by disable --now); that cache is deliberately outside this
// mode's convergence contract.
func (valkey) applyDisabled(ctx context.Context, r bssh.Runner) error {
	removed, err := sweepValkeyUnits(ctx, r, map[string]bool{})
	if err != nil {
		return err
	}
	if !removed {
		return nil
	}
	if res, err := r.Run(ctx, "systemctl daemon-reload", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("daemon-reload after valkey sweep: %s", res.Stderr)
	}
	return nil
}

func (v valkey) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	if !s.Valkey {
		return v.checkDisabled(ctx, r)
	}
	// Safety preflight over every instance of every site before any drift
	// verdict (also in dry-run): a foreign-owned data dir must fail the whole
	// run loudly, never be adopted by systemd on the next start.
	if err := assertValkeyDataOwners(ctx, r, s); err != nil {
		return provision.CheckResult{}, err
	}
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

	for _, in := range valkeyInstances(s) {
		want, err := renderValkeyInstanceUnit(s, in)
		if err != nil {
			return provision.CheckResult{}, err
		}
		state, err := checkManagedFile(ctx, r, in.path, want)
		if err != nil {
			return provision.CheckResult{}, err
		}
		unitOK, err := managedFileSatisfied(state, in.path, rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		up, err := serviceUp(ctx, r, in.unit)
		if err != nil {
			return provision.CheckResult{}, err
		}
		// Liveness beyond "active": the running process must actually use the
		// on-disk unit (crash between write and restart leaves stale ExecStart
		// args running — the same window checkTuned closes for MariaDB), it
		// must execute the CURRENT binary (unattended-upgrades replaces the
		// file under the running process; only the stock unit gets a postinst
		// restart), and the daemon must answer over ITS socket AS the site
		// user.
		loaded, fresh, pong := false, false, false
		execFresh := false
		if unitOK && up {
			if loaded, err = serviceConfigLoaded(ctx, r, in.unit, in.path); err != nil {
				return provision.CheckResult{}, err
			}
			if fresh, err = unitCacheFresh(ctx, r, in.unit); err != nil {
				return provision.CheckResult{}, err
			}
			if execFresh, err = valkeyExecCurrent(ctx, r, in.unit); err != nil {
				return provision.CheckResult{}, err
			}
			if pong, err = valkeyPongOver(ctx, r, s.SiteUser(in.site), in.socket); err != nil {
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
	changes := []string{
		"install valkey-server (valkey-cli comes via its valkey-tools dependency)",
		"disable the stock shared valkey-server.service",
		"per site: write berth-valkey-<pool>.service, enable --now, verify PONG over the socket",
	}
	if s.ValkeyQueue {
		changes = append(changes, "per site: write berth-valkey-<pool>-queue.service (noeviction, AOF everysec), enable --now, verify PONG over queue.sock")
	}
	changes = append(changes, "remove orphan berth-valkey instances")
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "per-site valkey fleet not converged",
		Changes:   changes,
	}, nil
}

func (v valkey) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if !s.Valkey {
		return v.applyDisabled(ctx, r)
	}
	// Same preflight as Check, before the first mutation (--only valkey runs
	// Apply without a passing Check having run on this exact state).
	if err := assertValkeyDataOwners(ctx, r, s); err != nil {
		return err
	}
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

	// Orphan sweep, modelled on the supervisor one in site.go: disable and
	// remove berth-managed instances no site desires; never a foreign file.
	needReload, err := sweepValkeyUnits(ctx, r, desiredValkeyUnitPaths(s))
	if err != nil {
		return err
	}

	// Per-instance units: write when absent or drifted (writeManagedFile
	// enforces the foreign-file abort), remember which changed for a targeted
	// restart — keyed by unit, so a drifted queue unit never restarts the
	// cache instance beside it.
	changed := map[string]bool{}
	for _, in := range valkeyInstances(s) {
		want, err := renderValkeyInstanceUnit(s, in)
		if err != nil {
			return err
		}
		state, err := checkManagedFile(ctx, r, in.path, want)
		if err != nil {
			return err
		}
		if state == fileUpToDate {
			continue
		}
		if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
			Path: in.path, Content: want,
			Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
		}); err != nil {
			return fmt.Errorf("write %s: %w", in.path, err)
		}
		// A replaced unit needs a restart to load the new ExecStart; a FRESH
		// one does not — enable --now below starts it with current content.
		if state != fileAbsent {
			changed[in.unit] = true
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

	for _, in := range valkeyInstances(s) {
		unit := in.unit
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
		if changed[unit] {
			if err := restartValkey(ctx, r, unit); err != nil {
				return err
			}
			restarted = true
		} else {
			loaded, err := serviceConfigLoaded(ctx, r, unit, in.path)
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
		user := s.SiteUser(in.site)
		pong, err := valkeyPongOver(ctx, r, user, in.socket)
		if err != nil {
			return err
		}
		if !pong && !restarted {
			if err := restartValkey(ctx, r, unit); err != nil {
				return err
			}
			if pong, err = valkeyPongOver(ctx, r, user, in.socket); err != nil {
				return err
			}
		}
		if !pong {
			return fmt.Errorf("%s does not answer PONG on %s as %s (restart did not heal it); check `journalctl -u %s`",
				unit, in.socket, user, unit)
		}
	}
	return nil
}

// valkeyPongOver runs the PONG probe over one instance's socket (see
// valkeyPingOver).
func valkeyPongOver(ctx context.Context, r bssh.Runner, user, socket string) (bool, error) {
	res, err := r.Run(ctx, valkeyPingOver(user, socket), nil)
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

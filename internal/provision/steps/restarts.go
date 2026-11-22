package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// staleUnitsCmd lists the running services that still execute a library or a
// binary which has since been replaced on disk — the state a package upgrade
// leaves behind for every service the package itself does not restart (an
// OpenSSL or libc update, for one). One line per service, `<unit>\t<path>`,
// naming the first replaced file found, plus a final `reboot-required` line
// when the host flags a pending reboot.
//
// How: a replaced file stays mapped into the processes that loaded it and
// /proc/<pid>/maps marks the mapping `(deleted)`. Only EXECUTABLE mappings
// under the system library and binary directories count, which is what
// separates a replaced libcrypto from the deleted temp files, shared-memory
// segments and locale caches every long-running service also maps. The
// processes of a service are its cgroup's. Reads only; run as root (the maps
// of other users' processes are not readable otherwise).
const staleUnitsCmd = `for u in $(systemctl list-units --type=service --state=running --no-legend --plain | cut -d' ' -f1); do ` +
	`cg="$(systemctl show -p ControlGroup --value "$u")"; [ -n "$cg" ] || continue; ` +
	`for p in $(cat "/sys/fs/cgroup$cg/cgroup.procs" 2>/dev/null); do ` +
	`f="$(awk '$2 ~ /x/ && $7 == "(deleted)" && $6 ~ "^/(usr/)?(lib|lib64|bin|sbin|libexec)/" {print $6; exit}' "/proc/$p/maps" 2>/dev/null)"; ` +
	`if [ -n "$f" ]; then printf '%s\t%s\n' "$u" "$f"; break; fi; done; done; ` +
	`if [ -e /run/reboot-required ]; then echo reboot-required; fi`

// staleUnit is one service running a replaced file.
type staleUnit struct {
	unit string // with its .service suffix, as systemctl lists it
	path string // the first replaced library or binary found
}

// parseStaleUnits reads staleUnitsCmd's output. Per-user session managers
// (user@<uid>.service) are dropped: they hold login sessions, not services
// anyone restarts.
func parseStaleUnits(out string) (stale []staleUnit, reboot bool) {
	for _, line := range strings.Split(out, "\n") {
		if line == "reboot-required" {
			reboot = true
			continue
		}
		unit, path, ok := strings.Cut(line, "\t")
		if !ok || unit == "" || strings.HasPrefix(unit, "user@") {
			continue
		}
		stale = append(stale, staleUnit{unit: unit, path: path})
	}
	return stale, reboot
}

// probeStaleUnits runs staleUnitsCmd. A failed probe is an error, never a
// clean host.
func probeStaleUnits(ctx context.Context, r bssh.Runner) ([]staleUnit, bool, error) {
	res, err := r.Run(ctx, staleUnitsCmd, nil)
	if err != nil {
		return nil, false, err
	}
	if res.ExitCode != 0 {
		return nil, false, fmt.Errorf("probe services for replaced libraries: %s", res.Stderr)
	}
	stale, reboot := parseStaleUnits(res.Stdout)
	return stale, reboot, nil
}

// restartable is a service the restarts step may restart: one berth installed
// and configures.
type restartable struct {
	unit     string // with its .service suffix
	validate string // config check that must pass first; "" = none
}

const supervisorUnit = "supervisor.service"

// restartableUnits returns the services berth restarts when they run a
// replaced library, in restart order: the database and the caches first,
// then PHP-FPM, then nginx, then the workers, so nothing comes back into a
// dependency that is about to go away. sshd is deliberately absent — berth
// never restarts the daemon its own connection runs through; it is reported
// with the other unmanaged services instead.
func restartableUnits(s *config.Server) []restartable {
	out := []restartable{{unit: config.DatabaseUnit(s.Database.Engine)}}
	if s.Valkey {
		for _, in := range valkeyInstances(s) {
			out = append(out, restartable{unit: in.unit})
		}
	}
	out = append(out,
		restartable{unit: fpmService(s) + ".service", validate: "php-fpm" + s.PHP.Version + " -t"},
		restartable{unit: "nginx.service", validate: "nginx -t"},
		restartable{unit: supervisorUnit},
		restartable{unit: "cron.service"},
		restartable{unit: "fail2ban.service"},
	)
	return out
}

// splitStale sorts the probed services into the ones berth restarts (in
// restart order) and the names of the rest.
func splitStale(s *config.Server, stale []staleUnit) (managed []staleUnit, plan []restartable, others []string) {
	byUnit := make(map[string]staleUnit, len(stale))
	for _, st := range stale {
		byUnit[st.unit] = st
	}
	for _, ru := range restartableUnits(s) {
		if st, ok := byUnit[ru.unit]; ok {
			managed = append(managed, st)
			plan = append(plan, ru)
			delete(byUnit, ru.unit)
		}
	}
	for _, st := range stale {
		if _, left := byUnit[st.unit]; left {
			others = append(others, unitLabel(st.unit))
		}
	}
	return managed, plan, others
}

// unitLabel is a unit name as berth prints it: without the .service suffix.
func unitLabel(unit string) string { return strings.TrimSuffix(unit, ".service") }

type restarts struct{}

// Restarts returns the step that restarts berth-managed services still
// running a library or binary a package upgrade has replaced on disk. It
// never reboots the host: a pending reboot is reported, not acted on.
func Restarts() provision.Step { return restarts{} }

func (restarts) Name() string       { return "restarts" }
func (restarts) Requires() []string { return []string{"site"} }

func (restarts) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	stale, reboot, err := probeStaleUnits(ctx, r)
	if err != nil {
		return provision.CheckResult{}, err
	}
	managed, _, others := splitStale(s, stale)
	if len(managed) == 0 {
		reason := "no berth-managed service runs a replaced library"
		if len(others) > 0 {
			reason += "; not managed by berth and still on a replaced one: " + strings.Join(others, ", ")
		}
		if reboot {
			reason += "; a reboot is pending"
		}
		return provision.CheckResult{Satisfied: true, Reason: reason}, nil
	}
	changes := make([]string, 0, len(managed))
	for _, st := range managed {
		changes = append(changes, "restart "+unitLabel(st.unit)+" (still runs the replaced "+st.path+")")
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    fmt.Sprintf("%d service(s) still run a library or binary that a package upgrade replaced", len(managed)),
		Changes:   changes,
	}, nil
}

func (restarts) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	stale, reboot, err := probeStaleUnits(ctx, r)
	if err != nil {
		return err
	}
	_, plan, others := splitStale(s, stale)
	// Validate everything first: a service whose config does not load would
	// not come back, so nothing is restarted unless every check passes.
	for _, ru := range plan {
		if ru.validate == "" {
			continue
		}
		res, err := r.Run(ctx, ru.validate, nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("refusing to restart %s: %s fails, so it would not come back: %s", unitLabel(ru.unit), ru.validate, strings.TrimSpace(res.Stderr+res.Stdout))
		}
	}
	for _, ru := range plan {
		if err := restartUnit(ctx, r, ru.unit); err != nil {
			return err
		}
	}
	if len(others) > 0 {
		rc.Warnf("these services still run a library or binary that was replaced on disk and berth does not restart them: %s — restart them yourself or reboot", strings.Join(others, ", "))
	}
	if reboot {
		rc.Warnf("a reboot is pending (/run/reboot-required): a new kernel only takes effect after it; berth never reboots the host")
	}
	return nil
}

// restartUnit restarts one service. supervisord takes the long way round:
// restarting it stops every program it runs, and only the autostart ones
// come back by themselves.
func restartUnit(ctx context.Context, r bssh.Runner, unit string) error {
	if unit != supervisorUnit {
		return runOK(ctx, r, "systemctl restart "+unit)
	}
	// `supervisorctl status` exits 3 when any process is not running — the
	// output is the data, never the exit code.
	res, err := r.Run(ctx, "supervisorctl status", nil)
	if err != nil {
		return err
	}
	running := runningSupervisorProcesses(res.Stdout)
	if err := runOK(ctx, r, "systemctl restart "+unit); err != nil {
		return err
	}
	if len(running) == 0 {
		return nil
	}
	return runOK(ctx, r, supervisorStartAfterRestartCmd(running))
}

// runningSupervisorProcesses returns the `group:name` of every RUNNING line
// in `supervisorctl status` output.
func runningSupervisorProcesses(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "RUNNING" {
			names = append(names, f[0])
		}
	}
	return names
}

// supervisorStartAfterRestartCmd waits for the restarted supervisord to
// answer (its socket appears a moment after systemd reports it started) and
// starts the given processes. `supervisorctl start` reports "already
// started" for the autostart ones and exits non-zero for it, so the final
// verdict is each process's state, not that exit code.
func supervisorStartAfterRestartCmd(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = shQuote(n)
	}
	list := strings.Join(quoted, " ")
	return "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do supervisorctl pid >/dev/null 2>&1 && break; sleep 1; done; " +
		"supervisorctl start " + list + " >/dev/null 2>&1; " +
		"for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do " +
		"supervisorctl status " + list + " 2>&1 | grep -qvE ' (RUNNING|STARTING) ' || exit 0; sleep 1; done; " +
		"echo 'not running again after the supervisor restart:' >&2; supervisorctl status " + list + " >&2; exit 1"
}

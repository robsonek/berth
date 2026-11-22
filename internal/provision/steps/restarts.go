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
//
// Both systemctl queries are assigned before use and exit 3 on failure: a
// `for u in $(failing command)` loop would simply not run and the script
// would end 0 with no output — a systemd that cannot be reached must never
// read as a clean host.
const staleUnitsCmd = `units="$(systemctl list-units --type=service --state=running --no-legend --plain)" || exit 3; ` +
	`for u in $(printf '%s\n' "$units" | cut -d' ' -f1); do ` +
	`cg="$(systemctl show -p ControlGroup --value "$u")" || exit 3; [ -n "$cg" ] || continue; ` +
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
// and configures. Exactly one of unit and prefix is set.
type restartable struct {
	unit     string // exact name, with its .service suffix
	prefix   string // or: every running unit whose name starts with this
	validate string // config check that must pass first; "" = none
}

func (ru restartable) matches(unit string) bool {
	if ru.prefix != "" {
		return strings.HasPrefix(unit, ru.prefix)
	}
	return unit == ru.unit
}

const supervisorUnit = "supervisor.service"

// databaseRestartable is the unit that actually holds the database server's
// processes. For PostgreSQL that is NOT config.DatabaseUnit's umbrella
// postgresql.service (a oneshot with no processes of its own) but the
// cluster units postgresql@<ver>-<name>.service, however many there are.
func databaseRestartable(engine string) restartable {
	if engine == "postgres" {
		return restartable{prefix: "postgresql@"}
	}
	return restartable{unit: config.DatabaseUnit(engine)}
}

// restartableUnits returns the services berth restarts when they run a
// replaced library, in restart order: the database and the caches first,
// then PHP-FPM, then nginx, then the workers, so nothing comes back into a
// dependency that is about to go away. Only what this config makes berth
// manage is listed: a Supervisor on a host whose config has no worker or
// daemon is the operator's, and so is a Valkey without valkey: true. sshd is
// deliberately absent — berth never restarts the daemon its own connection
// runs through. Everything not listed is reported, never restarted.
func restartableUnits(s *config.Server) []restartable {
	out := []restartable{databaseRestartable(s.Database.Engine)}
	if s.Valkey {
		for _, in := range valkeyInstances(s) {
			out = append(out, restartable{unit: in.unit})
		}
	}
	out = append(out,
		restartable{unit: fpmService(s) + ".service", validate: "php-fpm" + s.PHP.Version + " -t"},
		restartable{unit: "nginx.service", validate: "nginx -t"},
	)
	if s.NeedsSupervisor() {
		out = append(out, restartable{unit: supervisorUnit})
	}
	return append(out, restartable{unit: "cron.service"}, restartable{unit: "fail2ban.service"})
}

// plannedRestart is one stale unit berth will restart.
type plannedRestart struct {
	staleUnit
	validate string
}

// splitStale sorts the probed services into the ones berth restarts (in
// restart order) and the names of the rest.
func splitStale(s *config.Server, stale []staleUnit) (plan []plannedRestart, others []string) {
	taken := make(map[string]bool, len(stale))
	for _, ru := range restartableUnits(s) {
		for _, st := range stale {
			if !taken[st.unit] && ru.matches(st.unit) {
				taken[st.unit] = true
				plan = append(plan, plannedRestart{staleUnit: st, validate: ru.validate})
			}
		}
	}
	for _, st := range stale {
		if !taken[st.unit] {
			others = append(others, unitLabel(st.unit))
		}
	}
	return plan, others
}

// restartNotes are the things the operator must hear that berth does not act
// on: services it does not manage, and a pending reboot. They are warnings
// in every outcome — satisfied, planned or applied — and never drift: a host
// waiting for a reboot would otherwise never converge.
func restartNotes(others []string, reboot bool) []string {
	var notes []string
	if len(others) > 0 {
		notes = append(notes, "these services still run a library or binary that was replaced on disk and berth does not restart them: "+strings.Join(others, ", ")+" — restart them yourself or reboot")
	}
	if reboot {
		notes = append(notes, "a reboot is pending (/run/reboot-required): a new kernel only takes effect after it; berth never reboots the host")
	}
	return notes
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
	plan, others := splitStale(s, stale)
	notes := restartNotes(others, reboot)
	if len(plan) == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "no berth-managed service runs a replaced library", Warnings: notes}, nil
	}
	changes := make([]string, 0, len(plan))
	for _, p := range plan {
		changes = append(changes, "restart "+unitLabel(p.unit)+" (still runs the replaced "+p.path+")")
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    fmt.Sprintf("%d service(s) still run a library or binary that a package upgrade replaced", len(plan)),
		Changes:   changes,
		Warnings:  notes,
	}, nil
}

func (restarts) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	stale, reboot, err := probeStaleUnits(ctx, r)
	if err != nil {
		return err
	}
	plan, others := splitStale(s, stale)
	// Validate everything first: a service whose config does not load would
	// not come back, so nothing is restarted unless every check passes.
	for _, p := range plan {
		if p.validate == "" {
			continue
		}
		res, err := r.Run(ctx, p.validate, nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("refusing to restart %s: %s fails, so it would not come back: %s", unitLabel(p.unit), p.validate, strings.TrimSpace(res.Stderr+res.Stdout))
		}
	}
	for _, p := range plan {
		if err := restartUnit(ctx, r, p.unit); err != nil {
			return err
		}
	}
	for _, note := range restartNotes(others, reboot) {
		rc.Warnf("%s", note)
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
	running, err := runningSupervisorProcesses(ctx, r)
	if err != nil {
		return err
	}
	if err := runOK(ctx, r, "systemctl restart "+unit); err != nil {
		return err
	}
	if len(running) == 0 {
		return nil
	}
	return startSupervisorProcesses(ctx, r, running)
}

// supervisorStates are the process states supervisorctl prints; a status
// line whose second column is none of them is not a status line.
var supervisorStates = map[string]bool{
	"STOPPED": true, "STARTING": true, "RUNNING": true, "BACKOFF": true,
	"STOPPING": true, "EXITED": true, "FATAL": true, "UNKNOWN": true,
}

// runningSupervisorProcesses returns the `group:name` of every RUNNING
// process — the snapshot the restart must restore. It has to be COMPLETE or
// refused: an unreadable snapshot would read as "nothing was running", the
// restart would stop the non-autostart workers and nothing would bring them
// back. `supervisorctl status` exits 0, or 3 when some process is not
// running; any other code (4 when supervisord cannot be reached), or a line
// that is not a status line, refuses the restart.
func runningSupervisorProcesses(ctx context.Context, r bssh.Runner) ([]string, error) {
	res, err := r.Run(ctx, "supervisorctl status", nil)
	if err != nil {
		return nil, err
	}
	refuse := func(why string) error {
		return fmt.Errorf("refusing to restart supervisor: cannot tell which programs are running (%s): %s", why, strings.TrimSpace(res.Stdout+res.Stderr))
	}
	if res.ExitCode != 0 && res.ExitCode != 3 {
		return nil, refuse(fmt.Sprintf("supervisorctl status exited %d", res.ExitCode))
	}
	var names []string
	for _, line := range strings.Split(res.Stdout, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 2 || !supervisorStates[f[1]] {
			return nil, refuse("unexpected supervisorctl status output")
		}
		if f[1] == "RUNNING" {
			names = append(names, f[0])
		}
	}
	return names, nil
}

// startSupervisorProcesses brings the given processes back after a
// supervisord restart and proves it: every one of them must reach RUNNING.
// The restarted supervisord answers a moment after systemd reports it
// started, so its socket is waited for first. `supervisorctl start` skips
// processes already STARTING (the autostart ones) and its exit code is not
// the verdict; the states are re-read until they leave STARTING/BACKOFF —
// a program that is still STARTING may yet end in FATAL (the same settle
// rule as site's ensureProgramRunning).
func startSupervisorProcesses(ctx context.Context, r bssh.Runner, names []string) error {
	for i := 0; ; i++ {
		res, err := r.Run(ctx, "supervisorctl pid", nil)
		if err != nil {
			return err
		}
		if res.ExitCode == 0 {
			break
		}
		if i >= programSettleAttempts {
			return fmt.Errorf("supervisor did not answer after its restart: %s", strings.TrimSpace(res.Stdout+res.Stderr))
		}
		programSettleSleep()
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = shQuote(n)
	}
	list := strings.Join(quoted, " ")
	if _, err := r.Run(ctx, "supervisorctl start "+list, nil); err != nil {
		return err
	}
	var out string
	for i := 0; ; i++ {
		res, err := r.Run(ctx, "supervisorctl status "+list, nil)
		if err != nil {
			return err
		}
		out = res.Stdout
		states := parseProgramStates(out)
		if len(states) == len(names) && allRunning(states) {
			return nil
		}
		if i >= programSettleAttempts || !inTransition(states) {
			break
		}
		programSettleSleep()
	}
	return fmt.Errorf("not running again after the supervisor restart: %s", strings.TrimSpace(out))
}

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
	// ready is set for the services the workers depend on (the database,
	// the valkey instances): a command that exits 0 once the restarted
	// service accepts connections. Restarting one of these is what makes
	// the step stop the workers first.
	ready string
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
		return restartable{prefix: "postgresql@", ready: "pg_isready -q"}
	}
	return restartable{unit: config.DatabaseUnit(engine), ready: "mariadb -e 'SELECT 1'"}
}

// restartableUnits returns the services berth restarts when they run a
// replaced library, in restart order: first what the workers depend on (the
// database, the caches), then supervisord, and only then the services the
// workers do not need (PHP-FPM, nginx, cron, fail2ban). The workers come
// back as soon as the first group is done (see Apply), so a failure further
// down the list never leaves them stopped. Only what this config makes berth
// manage is listed: a Supervisor on a host whose config has no worker or
// daemon is the operator's, and so is a Valkey without valkey: true. sshd is
// deliberately absent — berth never restarts the daemon its own connection
// runs through. Everything not listed is reported, never restarted.
func restartableUnits(s *config.Server) []restartable {
	out := []restartable{databaseRestartable(s.Database.Engine)}
	if s.Valkey {
		for _, in := range valkeyInstances(s) {
			out = append(out, restartable{unit: in.unit, ready: "test -S " + shQuote(in.socket)})
		}
	}
	if s.NeedsSupervisor() {
		out = append(out, restartable{unit: supervisorUnit})
	}
	return append(out,
		restartable{unit: fpmService(s) + ".service", validate: "php-fpm" + s.PHP.Version + " -t"},
		restartable{unit: "nginx.service", validate: "nginx -t"},
		restartable{unit: "cron.service"},
		restartable{unit: "fail2ban.service"},
	)
}

// plannedRestart is one stale unit berth will restart.
type plannedRestart struct {
	staleUnit
	validate string
	ready    string
}

// splitStale sorts the probed services into the ones berth restarts (in
// restart order) and the names of the rest.
func splitStale(s *config.Server, stale []staleUnit) (plan []plannedRestart, others []string) {
	taken := make(map[string]bool, len(stale))
	for _, ru := range restartableUnits(s) {
		for _, st := range stale {
			if !taken[st.unit] && ru.matches(st.unit) {
				taken[st.unit] = true
				plan = append(plan, plannedRestart{staleUnit: st, validate: ru.validate, ready: ru.ready})
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
	// Workers talk to the database and to Valkey: restarting those under a
	// running worker fails its job mid-flight. So when a dependency is about
	// to restart (or supervisord itself), the programs that are running are
	// recorded, stopped, and started again once everything is back. Only
	// when this config makes berth run Supervisor — otherwise it is the
	// operator's and is left alone. The scheduler cron is NOT covered: a
	// `schedule:run` that lands inside the window fails like an HTTP request
	// does, which a restart accepts.
	restartsDependency, restartsSupervisor := false, false
	for _, p := range plan {
		restartsDependency = restartsDependency || p.ready != ""
		restartsSupervisor = restartsSupervisor || p.unit == supervisorUnit
	}
	var workers []string
	if restartsSupervisor || (restartsDependency && s.NeedsSupervisor()) {
		if workers, err = runningSupervisorProcesses(ctx, r); err != nil {
			return err
		}
	}
	if restartsDependency && len(workers) > 0 {
		if err := stopSupervisorProcesses(ctx, rc, r, workers); err != nil {
			return err
		}
	}
	// The workers come back the moment everything they need is back: after
	// the last dependency and after supervisord itself, BEFORE the unrelated
	// restarts. Their names live only in this run — a later failure (nginx,
	// say) that returned with them still stopped would leave them down for
	// good, because a retry would no longer see them as running.
	restoreAfter := -1
	var workersErr error
	for i, p := range plan {
		if p.ready != "" || p.unit == supervisorUnit {
			restoreAfter = i
		}
	}
	for i, p := range plan {
		if err := runOK(ctx, r, "systemctl restart "+p.unit); err != nil {
			return err
		}
		if err := waitReady(ctx, r, p); err != nil {
			return err
		}
		if i == restoreAfter && len(workers) > 0 {
			// A worker that cannot be started again fails the step — at
			// the end. The restarts below have nothing to do with the
			// workers and must not wait for another run because of it.
			workersErr = startSupervisorProcesses(ctx, r, workers)
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
	for _, note := range restartNotes(others, reboot) {
		rc.Warnf("%s", note)
	}
	return workersErr
}

// waitReady waits until a restarted dependency accepts connections, so the
// workers are never started a moment too early (a worker started one second
// before the socket exists fails exactly like one that was never stopped).
// Bounded like every other settle wait; a dependency that does not come back
// is an error and nothing is started into it.
func waitReady(ctx context.Context, r bssh.Runner, p plannedRestart) error {
	if p.ready == "" {
		return nil
	}
	for i := 0; ; i++ {
		res, err := r.Run(ctx, p.ready, nil)
		if err != nil {
			return err
		}
		if res.ExitCode == 0 {
			return nil
		}
		if i >= programSettleAttempts {
			return fmt.Errorf("%s did not accept connections after its restart (%s): %s", unitLabel(p.unit), p.ready, strings.TrimSpace(res.Stderr+res.Stdout))
		}
		programSettleSleep()
	}
}

// workerStopSeconds bounds the wait for the workers to finish their current
// job and stop. berth's programs carry stopwaitsecs=3600, so an unbounded
// `supervisorctl stop` could hold a provision for an hour behind one long
// job. Past the bound the restarts go ahead anyway (the operator's decision,
// 2026-11-22): the job that was still running loses its connection — which
// is what happened to every job before workers were stopped at all — and
// the operator is told which program it was.
const workerStopSeconds = 300

// stopSupervisorProcesses asks the given processes to stop and waits up to
// workerStopSeconds. It never fails for a process that is merely slow: the
// ones still busy are named in a warning and the run continues.
func stopSupervisorProcesses(ctx context.Context, rc provision.RunCtx, r bssh.Runner, names []string) error {
	list := quoteAll(names)
	// supervisorctl's exit code is not the verdict (it is non-zero when a
	// process had already stopped, and 124 comes from timeout); the states
	// read back are.
	//
	// One `supervisorctl stop a b` stops its arguments ONE AFTER ANOTHER, so
	// a single worker deep in a job would keep every other one from even
	// being asked (seen live: the idle worker was still RUNNING when the
	// limit hit). Each process therefore gets its own client, all in the
	// background, and `wait` collects them; timeout kills the whole group.
	stop := fmt.Sprintf(`timeout %d sh -c 'for p in "$@"; do supervisorctl stop "$p" >/dev/null 2>&1 & done; wait' berth-stop %s`, workerStopSeconds, list)
	if _, err := r.Run(ctx, stop, nil); err != nil {
		return err
	}
	procs, err := supervisorStatusOf(ctx, r, names)
	if err != nil {
		return err
	}
	var busy []string
	for _, p := range procs {
		if p.state == "STOPPING" || p.state == "RUNNING" {
			busy = append(busy, p.name)
		}
	}
	if len(busy) > 0 {
		rc.Warnf("still finishing a job after %d minutes, so the restarts went ahead without waiting for: %s — that job may fail on the lost connection", workerStopSeconds/60, strings.Join(busy, ", "))
	}
	return nil
}

// quoteAll shell-quotes each name and joins them with spaces.
func quoteAll(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = shQuote(n)
	}
	return strings.Join(quoted, " ")
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
//
// A process in STARTING or BACKOFF is one supervisord is bringing up right
// now (a worker in its hourly --max-time restart, say): taking the snapshot
// at that instant would drop it. The status is therefore re-read until
// nothing is in transition, under the same bound the site step uses; a
// program that settles in FATAL was already broken and is not restored, and
// programs that never settle refuse the restart.
func runningSupervisorProcesses(ctx context.Context, r bssh.Runner) ([]string, error) {
	for i := 0; ; i++ {
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
		var names, states []string
		for _, line := range strings.Split(res.Stdout, "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			if len(f) < 2 || !supervisorStates[f[1]] {
				return nil, refuse("unexpected supervisorctl status output")
			}
			states = append(states, f[1])
			if f[1] == "RUNNING" {
				names = append(names, f[0])
			}
		}
		if !inTransition(states) {
			return names, nil
		}
		if i >= programSettleAttempts {
			return nil, refuse("programs are still starting")
		}
		programSettleSleep()
	}
}

// procState is one line of `supervisorctl status`.
type procState struct{ name, state string }

// supervisorStatusOf reads the state of exactly the given processes. The
// answer must be complete and readable or it is an error: exit 0, or 3 when
// some process is not running (any other code — 4 when supervisord cannot be
// reached — is a failure), every line a status line, one line per requested
// process. An unreadable answer must never read as "nothing is busy".
func supervisorStatusOf(ctx context.Context, r bssh.Runner, names []string) ([]procState, error) {
	res, err := r.Run(ctx, "supervisorctl status "+quoteAll(names), nil)
	if err != nil {
		return nil, err
	}
	out := strings.TrimSpace(res.Stdout + res.Stderr)
	if res.ExitCode != 0 && res.ExitCode != 3 {
		return nil, fmt.Errorf("supervisorctl status exited %d: %s", res.ExitCode, out)
	}
	var procs []procState
	for _, line := range strings.Split(res.Stdout, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 2 || !supervisorStates[f[1]] {
			return nil, fmt.Errorf("unexpected supervisorctl status output: %s", out)
		}
		procs = append(procs, procState{name: f[0], state: f[1]})
	}
	if len(procs) != len(names) {
		return nil, fmt.Errorf("supervisorctl status answered for %d of %d programs: %s", len(procs), len(names), out)
	}
	return procs, nil
}

// startSupervisorProcesses brings the given processes back and proves it.
//
//   - A just-restarted supervisord answers a moment after systemd reports it
//     started, so its socket is waited for first.
//   - A process still STOPPING (it outlived the stop limit and is finishing,
//     or failing, its job) cannot be started yet. It is waited for under the
//     usual bound — and then set aside: the processes that HAVE stopped are
//     started regardless, because one busy worker must not keep the idle
//     ones down. The ones left stopping are reported at the end, with the
//     command that starts them (berth's programs may take up to an hour).
//   - `supervisorctl start` skips processes already STARTING (the autostart
//     ones) and its exit code is not the verdict; the states are re-read
//     until they leave STARTING/BACKOFF — a program that is still STARTING
//     may yet end in FATAL (the same settle rule as site's
//     ensureProgramRunning). Every started process must reach RUNNING.
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
	var startable, stopping []string
	for i := 0; ; i++ {
		procs, err := supervisorStatusOf(ctx, r, names)
		if err != nil {
			return err
		}
		startable, stopping = nil, nil
		for _, p := range procs {
			if p.state == "STOPPING" {
				stopping = append(stopping, p.name)
			} else {
				startable = append(startable, p.name)
			}
		}
		if len(stopping) == 0 || i >= programSettleAttempts {
			break
		}
		programSettleSleep()
	}
	if len(startable) > 0 {
		if _, err := r.Run(ctx, "supervisorctl start "+quoteAll(startable), nil); err != nil {
			return err
		}
		for i := 0; ; i++ {
			procs, err := supervisorStatusOf(ctx, r, startable)
			if err != nil {
				return err
			}
			var notRunning []string
			settling := false
			for _, p := range procs {
				if p.state != "RUNNING" {
					notRunning = append(notRunning, p.name+" ("+p.state+")")
				}
				settling = settling || p.state == "STARTING" || p.state == "BACKOFF"
			}
			if len(notRunning) == 0 {
				break
			}
			if i >= programSettleAttempts || !settling {
				return fmt.Errorf("not running again after the restart: %s", strings.Join(notRunning, ", "))
			}
			programSettleSleep()
		}
	}
	if len(stopping) > 0 {
		list := quoteAll(stopping)
		return fmt.Errorf("still finishing their job, so berth could not start them again: %s — once they have stopped, run: supervisorctl start %s", strings.Join(stopping, ", "), list)
	}
	return nil
}

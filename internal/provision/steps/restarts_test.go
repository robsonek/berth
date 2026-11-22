package steps

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func restartsServer() *config.Server {
	return &config.Server{
		PHP:      config.PHP{Version: "8.5"},
		Database: config.Database{Engine: "mariadb"},
		Valkey:   true,
		Queue:    true,
		Sites:    []config.Site{{Domain: "app.example.com", DeployPath: "/var/www/app"}},
	}
}

const libcrypto = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"

func staleLine(unit string) string { return unit + "\t" + libcrypto + "\n" }

func TestParseStaleUnits(t *testing.T) {
	out := "nginx.service\t" + libcrypto + "\nssh.service\t/usr/lib/x86_64-linux-gnu/libc.so.6\n\nuser@1000.service\t/usr/bin/bash\nreboot-required\n"
	stale, reboot := parseStaleUnits(out)
	if !reboot {
		t.Error("reboot-required line must set the reboot flag")
	}
	if len(stale) != 2 || stale[0].unit != "nginx.service" || stale[0].path != libcrypto || stale[1].unit != "ssh.service" {
		t.Errorf("parseStaleUnits() = %+v; want nginx and ssh (user@ sessions are not services to restart)", stale)
	}
}

// Services berth does not manage and a pending reboot are never drift — a
// host waiting for a reboot would otherwise never converge — but the
// operator must still hear about them, so they ride on the result as
// warnings even though nothing is planned.
func TestRestartsCheckSatisfiedWhenNothingManagedIsStale(t *testing.T) {
	cases := []struct {
		name, out string
		wantWarn  []string
	}{
		{"clean host", "", nil},
		{"only an unmanaged service", staleLine("ssh.service"), []string{"ssh"}},
		{"an unmanaged service and a pending reboot", staleLine("ssh.service") + "reboot-required\n", []string{"ssh", "reboot is pending"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			f.On(staleUnitsCmd, bssh.Result{Stdout: c.out})
			cr, err := Restarts().Check(context.Background(), provision.RunCtx{}, restartsServer(), f)
			if err != nil {
				t.Fatal(err)
			}
			if !cr.Satisfied {
				t.Fatalf("want satisfied; got %+v", cr)
			}
			if len(cr.Warnings) != len(c.wantWarn) {
				t.Fatalf("want %d warning(s), got %q", len(c.wantWarn), cr.Warnings)
			}
			for i, w := range c.wantWarn {
				if !strings.Contains(cr.Warnings[i], w) {
					t.Errorf("warning %q must mention %q", cr.Warnings[i], w)
				}
			}
			if len(f.Calls()) != 1 {
				t.Errorf("Check must cost exactly one probe; ran %d", len(f.Calls()))
			}
		})
	}
}

func TestRestartsCheckPlansEveryStaleManagedUnit(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("nginx.service") + staleLine("mariadb.service") + staleLine("berth-valkey-app_example_com.service") + staleLine("ssh.service")})
	cr, err := Restarts().Check(context.Background(), provision.RunCtx{}, restartsServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("stale managed services must be unsatisfied")
	}
	got := strings.Join(cr.Changes, "\n")
	for _, want := range []string{"restart mariadb", "restart berth-valkey-app_example_com", "restart nginx", "libcrypto.so.3"} {
		if !strings.Contains(got, want) {
			t.Errorf("Changes must contain %q; got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "restart ssh") {
		t.Errorf("an unmanaged service must not be planned for a restart; got:\n%s", got)
	}
	if len(cr.Changes) != 3 {
		t.Errorf("want 3 planned restarts, got %d: %v", len(cr.Changes), cr.Changes)
	}
	if len(cr.Warnings) != 1 || !strings.Contains(cr.Warnings[0], "ssh") {
		t.Errorf("the unmanaged service must be reported as a warning in the plan too; got %q", cr.Warnings)
	}
}

// Every config is validated before anything is restarted. Then order matters:
// the database and the caches come back before PHP-FPM, PHP-FPM before nginx,
// and the workers last, so nothing restarts into a dependency that is about
// to go away.
func TestRestartsApplyRestartsInDependencyOrderAfterValidating(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("nginx.service") + staleLine("php8.5-fpm.service") + staleLine("mariadb.service") + staleLine("cron.service")})
	for _, cmd := range []string{"supervisorctl status", "systemctl restart mariadb.service", mariadbReady, "php-fpm8.5 -t", "systemctl restart php8.5-fpm.service", "nginx -t", "systemctl restart nginx.service", "systemctl restart cron.service"} {
		f.On(cmd, bssh.Result{})
	}
	if err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var ran []string
	for _, c := range f.Calls()[1:] {
		ran = append(ran, c.Cmd)
	}
	// No worker is running, so nothing is stopped or started around the
	// database restart — but the snapshot is still read to know that.
	want := "php-fpm8.5 -t|nginx -t|supervisorctl status|systemctl restart mariadb.service|" + mariadbReady + "|systemctl restart php8.5-fpm.service|systemctl restart nginx.service|systemctl restart cron.service"
	if got := strings.Join(ran, "|"); got != want {
		t.Errorf("commands:\n got %s\nwant %s", got, want)
	}
}

// A service whose config does not validate would not come back from a
// restart: refuse, and leave it running on the old library.
func TestRestartsApplyRefusesToRestartAnInvalidConfig(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("nginx.service")})
	f.On("nginx -t", bssh.Result{ExitCode: 1, Stderr: "nginx: [emerg] unknown directive"})
	err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f)
	if err == nil || !strings.Contains(err.Error(), "nginx") || !strings.Contains(err.Error(), "unknown directive") {
		t.Fatalf("want a refusal quoting the validation error; got %v", err)
	}
	if cmd := ranAny(f, "systemctl restart"); cmd != "" {
		t.Errorf("nothing may be restarted after a failed validation; ran %q", cmd)
	}
}

func TestRestartsApplyWarnsAboutUnmanagedServicesAndReboot(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("cron.service") + staleLine("ssh.service") + staleLine("systemd-journald.service") + "reboot-required\n"})
	f.On("systemctl restart cron.service", bssh.Result{})
	var warnings []string
	rc := provision.RunCtx{Warn: func(m string) { warnings = append(warnings, m) }}
	if err := Restarts().Apply(context.Background(), rc, restartsServer(), f); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"ssh", "systemd-journald", "reboot"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings must mention %q; got %q", want, warnings)
		}
	}
	if len(warnings) != 2 {
		t.Errorf("want one warning for the unmanaged services and one for the reboot; got %q", warnings)
	}
}

const (
	workerA    = "berth-app_example_com:berth-app_example_com_00"
	workerB    = "berth-other:berth-other_00"
	statusBoth = "supervisorctl status '" + workerA + "' '" + workerB + "'"
	startBoth  = "supervisorctl start '" + workerA + "' '" + workerB + "'"
)

// statusLines is `supervisorctl status` for the two workers: workerA in the
// given state, workerB running.
func statusLines(a string) string {
	return workerA + "   " + a + "   x\n" + workerB + "   RUNNING   x\n"
}

// Restarting supervisord stops every program; the ones that were running and
// do not autostart (a dormant-mode host whose deploy started them) must be
// started again, or a library update would silently stop the workers. The
// step waits for the restarted supervisord to answer and then for every
// saved process to reach RUNNING — STARTING is not success yet.
func TestRestartsApplyBringsRunningSupervisorProgramsBack(t *testing.T) {
	stubNoSettleSleep(t)
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("supervisor.service")})
	f.On("supervisorctl status", bssh.Result{ExitCode: 3, Stdout: workerA + "   RUNNING   pid 10, uptime 1:00:00\nberth-app_example_com:berth-app_example_com_01   STOPPED   Not started\n" + workerB + "   RUNNING   pid 11, uptime 0:10:00\n"})
	f.On("systemctl restart supervisor.service", bssh.Result{})
	f.OnSeq("supervisorctl pid", bssh.Result{ExitCode: 4, Stderr: "unix:///var/run/supervisor.sock no such file"}, bssh.Result{Stdout: "123\n"})
	f.On(startBoth, bssh.Result{ExitCode: 1, Stdout: workerB + ": ERROR (already started)\n"})
	f.OnSeq(statusBoth,
		bssh.Result{ExitCode: 3, Stdout: bothStopped}, // nothing is still stopping
		bssh.Result{ExitCode: 3, Stdout: statusLines("STARTING")},
		bssh.Result{Stdout: statusLines("RUNNING")})
	if err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var ran []string
	for _, c := range f.Calls()[1:] {
		ran = append(ran, c.Cmd)
	}
	want := strings.Join([]string{"supervisorctl status", "systemctl restart supervisor.service", "supervisorctl pid", "supervisorctl pid", statusBoth, startBoth, statusBoth, statusBoth}, "|")
	if got := strings.Join(ran, "|"); got != want {
		t.Errorf("commands:\n got %s\nwant %s", got, want)
	}
}

// A process that goes STARTING and then ends in FATAL has not come back: the
// step fails and quotes supervisorctl's own status.
func TestRestartsApplyFailsWhenASavedProcessDoesNotReachRunning(t *testing.T) {
	stubNoSettleSleep(t)
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("supervisor.service")})
	f.On("supervisorctl status", bssh.Result{Stdout: workerA + "   RUNNING   pid 10\n" + workerB + "   RUNNING   pid 11\n"})
	f.On("systemctl restart supervisor.service", bssh.Result{})
	f.On("supervisorctl pid", bssh.Result{Stdout: "123\n"})
	f.On(startBoth, bssh.Result{})
	f.OnSeq(statusBoth,
		bssh.Result{ExitCode: 3, Stdout: bothStopped},
		bssh.Result{ExitCode: 3, Stdout: statusLines("STARTING")},
		bssh.Result{ExitCode: 3, Stdout: statusLines("FATAL")})
	err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f)
	if err == nil || !strings.Contains(err.Error(), "FATAL") || !strings.Contains(err.Error(), workerA) {
		t.Fatalf("want a failure quoting the FATAL process; got %v", err)
	}
}

// An unreadable snapshot would read as "nothing was running": the restart
// would stop the workers and nothing would bring them back. Refuse instead.
func TestRestartsApplyRefusesSupervisorRestartWithoutASnapshot(t *testing.T) {
	cases := []struct {
		name string
		res  bssh.Result
	}{
		{"supervisord unreachable", bssh.Result{ExitCode: 4, Stdout: "unix:///var/run/supervisor.sock refused connection\n"}},
		{"output that is not a status table", bssh.Result{ExitCode: 3, Stdout: "error: something else entirely\n"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("supervisor.service")})
			f.On("supervisorctl status", c.res)
			err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f)
			if err == nil || !strings.Contains(err.Error(), "refusing to restart supervisor") {
				t.Fatalf("want a refusal; got %v", err)
			}
			if cmd := ranAny(f, "systemctl restart"); cmd != "" {
				t.Errorf("supervisor must not be restarted without a snapshot; ran %q", cmd)
			}
		})
	}
}

// A Supervisor on a host whose config gives berth no worker or daemon is the
// operator's: it is reported, never restarted.
func TestRestartsLeavesAnUnmanagedSupervisorAlone(t *testing.T) {
	s := restartsServer()
	s.Queue = false
	if s.NeedsSupervisor() {
		t.Fatal("fixture must not need supervisor")
	}
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("supervisor.service")})
	cr, err := Restarts().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied || len(cr.Warnings) != 1 || !strings.Contains(cr.Warnings[0], "supervisor") {
		t.Errorf("an unmanaged supervisor is a warning, not a planned restart; got %+v", cr)
	}
}

// PostgreSQL's processes live in the cluster units, not in the umbrella
// postgresql.service config.DatabaseUnit names.
func TestRestartsRestartsPostgresClusterUnits(t *testing.T) {
	s := restartsServer()
	s.Database.Engine = "postgres"
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("nginx.service") + staleLine("postgresql@18-main.service")})
	f.On("nginx -t", bssh.Result{})
	f.On("supervisorctl status", bssh.Result{})
	f.On("pg_isready -q", bssh.Result{})
	f.On("systemctl restart postgresql@18-main.service", bssh.Result{})
	f.On("systemctl restart nginx.service", bssh.Result{})
	cr, err := Restarts().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied || len(cr.Changes) != 2 || !strings.Contains(cr.Changes[0], "postgresql@18-main") || len(cr.Warnings) != 0 {
		t.Fatalf("the cluster unit must be planned first and not reported as unmanaged; got %+v", cr)
	}
	if err := Restarts().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	var ran []string
	for _, c := range f.Calls()[2:] {
		ran = append(ran, c.Cmd)
	}
	if got, want := strings.Join(ran, "|"), "nginx -t|supervisorctl status|systemctl restart postgresql@18-main.service|pg_isready -q|systemctl restart nginx.service"; got != want {
		t.Errorf("commands:\n got %s\nwant %s", got, want)
	}
}

// The probe's own shell must fail when systemd cannot be asked: a
// `for u in $(failing command)` loop simply does not run, and without the
// explicit exit the script would end 0 with no output — a clean host.
func TestStaleUnitsProbeFailsWhenSystemctlFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\necho 'Failed to connect to bus' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", staleUnitsCmd)
	cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH")}
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() == 0 {
		t.Fatalf("a failing systemctl must fail the probe; err=%v stdout=%q", err, out)
	}
	// And a systemd that lists nothing is a clean host, exit 0.
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("sh", "-c", staleUnitsCmd)
	cmd.Env = []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH")}
	if out, err := cmd.Output(); err != nil || strings.Contains(string(out), "\t") {
		t.Fatalf("an empty unit list must be a clean, successful probe; err=%v stdout=%q", err, out)
	}
}

func TestRestartsApplyDoesNothingOnACleanHost(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{})
	if err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f); err != nil {
		t.Fatal(err)
	}
	if len(f.Calls()) != 1 {
		t.Errorf("a clean host costs one probe; ran %d", len(f.Calls()))
	}
}

func TestRestartsProbeFailureIsAnError(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{ExitCode: 2, Stderr: "sh: systemctl: not found"})
	if _, err := Restarts().Check(context.Background(), provision.RunCtx{}, restartsServer(), f); err == nil {
		t.Fatal("a failed probe must not read as a clean host")
	}
}

// A worker caught mid-start (its hourly --max-time restart, say) is one
// supervisord is bringing up: the snapshot waits for it to settle instead of
// skipping it, or the restart would leave a non-autostart worker stopped.
func TestRestartsSnapshotWaitsForStartingProgramsToSettle(t *testing.T) {
	stubNoSettleSleep(t)
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("supervisor.service")})
	f.OnSeq("supervisorctl status",
		bssh.Result{ExitCode: 3, Stdout: statusLines("STARTING")},
		bssh.Result{ExitCode: 3, Stdout: statusLines("BACKOFF")},
		bssh.Result{Stdout: statusLines("RUNNING")})
	f.On("systemctl restart supervisor.service", bssh.Result{})
	f.On("supervisorctl pid", bssh.Result{Stdout: "123\n"})
	f.On(startBoth, bssh.Result{})
	f.On(statusBoth, bssh.Result{Stdout: statusLines("RUNNING")})
	if err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if ranAny(f, startBoth) == "" {
		t.Errorf("the worker that was starting must be restored with the running one; ran %v", f.Calls())
	}
}

// Programs that never leave STARTING/BACKOFF give no trustworthy snapshot:
// the restart is refused rather than guessed.
func TestRestartsRefusesSupervisorRestartWhileProgramsKeepStarting(t *testing.T) {
	stubNoSettleSleep(t)
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("supervisor.service")})
	f.On("supervisorctl status", bssh.Result{ExitCode: 3, Stdout: statusLines("BACKOFF")})
	err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f)
	if err == nil || !strings.Contains(err.Error(), "refusing to restart supervisor") || !strings.Contains(err.Error(), "BACKOFF") {
		t.Fatalf("want a refusal quoting the unsettled program; got %v", err)
	}
	if cmd := ranAny(f, "systemctl restart"); cmd != "" {
		t.Errorf("supervisor must not be restarted on an unsettled snapshot; ran %q", cmd)
	}
}

const (
	mariadbReady = "mariadb -e 'SELECT 1'"
	cacheUnit    = "berth-valkey-app_example_com.service"
	valkeyReady  = "test -S '/run/berth-valkey/app_example_com/valkey.sock'"
	// Every process gets its own `supervisorctl stop`, all at once: one
	// client stops its arguments one after another, so a single busy worker
	// would keep the others from being asked at all (seen live).
	stopBoth     = `timeout 300 sh -c 'for p in "$@"; do supervisorctl stop "$p" >/dev/null 2>&1 & done; wait' berth-stop '` + workerA + `' '` + workerB + `'`
	bothRunning  = workerA + "   RUNNING   pid 10\n" + workerB + "   RUNNING   pid 11\n"
	bothStopped  = workerA + "   STOPPED   x\n" + workerB + "   STOPPED   x\n"
	oneStillBusy = workerA + "   STOPPING   x\n" + workerB + "   STOPPED   x\n"
	restartMaria = "systemctl restart mariadb.service"
	restartCache = "systemctl restart " + cacheUnit
)

func ranCommands(f *bssh.FakeRunner) string {
	var ran []string
	for _, c := range f.Calls()[1:] {
		ran = append(ran, c.Cmd)
	}
	return strings.Join(ran, "|")
}

// Workers talk to the database and to Valkey: restarting those under a
// running worker fails its job mid-flight (production, 2026-11-22: 13
// RedisException "No such file or directory" in the minute of the restart).
// The running programs are stopped first, the dependencies restarted and
// probed for readiness, and only then are the same programs started again.
func TestRestartsApplyQuiescesWorkersAroundDependencyRestarts(t *testing.T) {
	stubNoSettleSleep(t)
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("mariadb.service") + staleLine(cacheUnit) + staleLine("nginx.service")})
	f.On("nginx -t", bssh.Result{})
	f.On("supervisorctl status", bssh.Result{Stdout: bothRunning})
	f.On(stopBoth, bssh.Result{})
	f.OnSeq(statusBoth, bssh.Result{ExitCode: 3, Stdout: bothStopped}, bssh.Result{ExitCode: 3, Stdout: bothStopped}, bssh.Result{Stdout: statusLines("RUNNING")})
	f.On(restartMaria, bssh.Result{})
	f.OnSeq(mariadbReady, bssh.Result{ExitCode: 1, Stderr: "ERROR 2002: Can't connect"}, bssh.Result{})
	f.On(restartCache, bssh.Result{})
	f.On(valkeyReady, bssh.Result{})
	f.On("systemctl restart nginx.service", bssh.Result{})
	f.On("supervisorctl pid", bssh.Result{Stdout: "1\n"})
	f.On(startBoth, bssh.Result{})
	var warnings []string
	rc := provision.RunCtx{Warn: func(m string) { warnings = append(warnings, m) }}
	if err := Restarts().Apply(context.Background(), rc, restartsServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	want := strings.Join([]string{
		"nginx -t", "supervisorctl status", stopBoth, statusBoth,
		restartMaria, mariadbReady, mariadbReady, restartCache, valkeyReady,
		"systemctl restart nginx.service",
		"supervisorctl pid", statusBoth, startBoth, statusBoth,
	}, "|")
	if got := ranCommands(f); got != want {
		t.Errorf("commands:\n got %s\nwant %s", got, want)
	}
	if len(warnings) != 0 {
		t.Errorf("a clean quiesce warns about nothing; got %q", warnings)
	}
}

// A worker deep in a long job may not stop in time (supervisor would wait an
// hour). After the limit the restarts go ahead anyway, the operator is told
// which program was still busy, and every worker is started again at the end.
func TestRestartsApplyGoesAheadWhenAWorkerDoesNotStopInTime(t *testing.T) {
	stubNoSettleSleep(t)
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("mariadb.service")})
	f.On("supervisorctl status", bssh.Result{Stdout: bothRunning})
	f.On(stopBoth, bssh.Result{ExitCode: 124})
	f.OnSeq(statusBoth,
		bssh.Result{ExitCode: 3, Stdout: oneStillBusy}, // after the stop timed out
		bssh.Result{ExitCode: 3, Stdout: oneStillBusy}, // before the start: still stopping
		bssh.Result{ExitCode: 3, Stdout: bothStopped},  // its job failed on the lost connection
		bssh.Result{Stdout: statusLines("RUNNING")})
	f.On(restartMaria, bssh.Result{})
	f.On(mariadbReady, bssh.Result{})
	f.On("supervisorctl pid", bssh.Result{Stdout: "1\n"})
	f.On(startBoth, bssh.Result{})
	var warnings []string
	rc := provision.RunCtx{Warn: func(m string) { warnings = append(warnings, m) }}
	if err := Restarts().Apply(context.Background(), rc, restartsServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !strings.Contains(ranCommands(f), restartMaria+"|"+mariadbReady) || !strings.HasSuffix(ranCommands(f), startBoth+"|"+statusBoth) {
		t.Errorf("the restart must go ahead and the workers be started at the end; ran %s", ranCommands(f))
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], workerA) || strings.Contains(warnings[0], workerB) || !strings.Contains(warnings[0], "5 minutes") {
		t.Errorf("want one warning naming only the program that was still busy; got %q", warnings)
	}
}

// Nothing a worker depends on is restarted: the workers are left alone.
func TestRestartsApplyDoesNotTouchWorkersForUnrelatedRestarts(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("nginx.service") + staleLine("cron.service")})
	f.On("nginx -t", bssh.Result{})
	f.On("systemctl restart nginx.service", bssh.Result{})
	f.On("systemctl restart cron.service", bssh.Result{})
	if err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f); err != nil {
		t.Fatal(err)
	}
	if cmd := ranAny(f, "supervisorctl", "timeout"); cmd != "" {
		t.Errorf("workers must not be touched when no dependency restarts; ran %q", cmd)
	}
}

// A dependency that does not come back is an error, and the workers are not
// started into it.
func TestRestartsApplyFailsWhenADependencyDoesNotBecomeReady(t *testing.T) {
	stubNoSettleSleep(t)
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("mariadb.service")})
	f.On("supervisorctl status", bssh.Result{Stdout: bothRunning})
	f.On(stopBoth, bssh.Result{})
	f.On(statusBoth, bssh.Result{ExitCode: 3, Stdout: bothStopped})
	f.On(restartMaria, bssh.Result{})
	f.On(mariadbReady, bssh.Result{ExitCode: 1, Stderr: "ERROR 2002 (HY000): Can't connect to local server"})
	err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f)
	if err == nil || !strings.Contains(err.Error(), "mariadb") || !strings.Contains(err.Error(), "ERROR 2002") {
		t.Fatalf("want an error naming the dependency and its probe output; got %v", err)
	}
	if cmd := ranAny(f, "supervisorctl start"); cmd != "" {
		t.Errorf("workers must not be started into a dependency that is not ready; ran %q", cmd)
	}
}

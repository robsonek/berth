package steps

import (
	"context"
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

func TestRestartsCheckSatisfiedWhenNothingManagedIsStale(t *testing.T) {
	cases := []struct {
		name, out  string
		wantReason []string
	}{
		{"clean host", "", nil},
		{"only an unmanaged service and a pending reboot", staleLine("ssh.service") + "reboot-required\n", []string{"ssh", "reboot"}},
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
			for _, w := range c.wantReason {
				if !strings.Contains(cr.Reason, w) {
					t.Errorf("Reason %q must mention %q", cr.Reason, w)
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
}

// Every config is validated before anything is restarted. Then order matters:
// the database and the caches come back before PHP-FPM, PHP-FPM before nginx,
// and the workers last, so nothing restarts into a dependency that is about
// to go away.
func TestRestartsApplyRestartsInDependencyOrderAfterValidating(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("nginx.service") + staleLine("php8.5-fpm.service") + staleLine("mariadb.service") + staleLine("cron.service")})
	for _, cmd := range []string{"systemctl restart mariadb.service", "php-fpm8.5 -t", "systemctl restart php8.5-fpm.service", "nginx -t", "systemctl restart nginx.service", "systemctl restart cron.service"} {
		f.On(cmd, bssh.Result{})
	}
	if err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var ran []string
	for _, c := range f.Calls()[1:] {
		ran = append(ran, c.Cmd)
	}
	want := "php-fpm8.5 -t|nginx -t|systemctl restart mariadb.service|systemctl restart php8.5-fpm.service|systemctl restart nginx.service|systemctl restart cron.service"
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

// Restarting supervisord stops every program; the ones that were running and
// do not autostart (a dormant-mode host whose deploy started them) must be
// started again, or a library update would silently stop the workers.
func TestRestartsApplyBringsRunningSupervisorProgramsBack(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(staleUnitsCmd, bssh.Result{Stdout: staleLine("supervisor.service")})
	f.On("supervisorctl status", bssh.Result{ExitCode: 3, Stdout: "berth-app_example_com:berth-app_example_com_00   RUNNING   pid 10, uptime 1:00:00\nberth-app_example_com:berth-app_example_com_01   STOPPED   Not started\nberth-other:berth-other_00   RUNNING   pid 11, uptime 0:10:00\n"})
	f.On("systemctl restart supervisor.service", bssh.Result{})
	start := supervisorStartAfterRestartCmd([]string{"berth-app_example_com:berth-app_example_com_00", "berth-other:berth-other_00"})
	f.On(start, bssh.Result{})
	if err := Restarts().Apply(context.Background(), provision.RunCtx{}, restartsServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var ran []string
	for _, c := range f.Calls()[1:] {
		ran = append(ran, c.Cmd)
	}
	if got, want := strings.Join(ran, "|"), "supervisorctl status|systemctl restart supervisor.service|"+start; got != want {
		t.Errorf("commands:\n got %s\nwant %s", got, want)
	}
	if !strings.Contains(start, "'berth-app_example_com:berth-app_example_com_00'") || strings.Contains(start, "_01") {
		t.Errorf("only the previously RUNNING programs are started again; got %q", start)
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

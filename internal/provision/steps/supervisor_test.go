package steps

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestSupervisorRequiresBase(t *testing.T) {
	if got := Supervisor().Requires(); len(got) != 1 || got[0] != "base" {
		t.Fatalf("Requires() = %v, want [base]", got)
	}
}

func TestSupervisorCheckSatisfiedWhenInstalledAndUp(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s supervisor", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active supervisor", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled supervisor", bssh.Result{ExitCode: 0})
	f.On(supervisorOrderRead, bssh.Result{ExitCode: 1}) // dormant: no drop-in
	cr, err := Supervisor().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when supervisor installed and running; got %+v", cr)
	}
}

func TestSupervisorCheckUnsatisfiedWhenNotRunning(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s supervisor", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active supervisor", bssh.Result{ExitCode: 3}) // inactive
	f.On("systemctl is-enabled supervisor", bssh.Result{ExitCode: 0})
	f.On(supervisorOrderRead, bssh.Result{ExitCode: 1})
	cr, err := Supervisor().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when supervisor is not active")
	}
}

func TestSupervisorApplyInstallsAndEnables(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y supervisor", bssh.Result{})
	f.On("systemctl enable --now supervisor", bssh.Result{})
	f.On(supervisorOrderRead, bssh.Result{ExitCode: 1})
	if err := Supervisor().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"apt-get install -y supervisor", "systemctl enable --now supervisor"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

// supervisorOrderRead is the one read-only probe of the ordering drop-in
// (managed-file classify in running mode, managedFilePresent in dormant).
const supervisorOrderRead = "cat '/etc/systemd/system/supervisor.service.d/berth-after.conf'"

const (
	supervisorOrderMkdir  = "install -d -o root -g root -m 0755 '/etc/systemd/system/supervisor.service.d'"
	supervisorOrderRemove = "rm -f '/etc/systemd/system/supervisor.service.d/berth-after.conf'"
	daemonReloadCmd       = "systemctl daemon-reload"
)

// supervisorOrderServer is a two-site mariadb + Valkey server with queue
// workers, the sites deliberately listed out of order; workers sets the
// server-wide knob.
func supervisorOrderServer(workers string) *config.Server {
	return &config.Server{
		Database: config.Database{Engine: "mariadb"},
		Valkey:   true,
		Queue:    true,
		Workers:  workers,
		Sites: []config.Site{
			{Domain: "www.example.com", DeployPath: "/var/www/www"},
			{Domain: "app.example.com", DeployPath: "/var/www/app"},
		},
	}
}

// stubSupervisorUp stubs an installed, running and enabled supervisor.
func stubSupervisorUp(f *bssh.FakeRunner) {
	f.On("dpkg -s supervisor", bssh.Result{Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active supervisor", bssh.Result{})
	f.On("systemctl is-enabled supervisor", bssh.Result{})
}

// TestSupervisorAfterUnits: the database unit first, then one Valkey
// instance per site (Valkey is server-wide), sorted whatever the site order.
func TestSupervisorAfterUnits(t *testing.T) {
	s := supervisorOrderServer("running")
	want := []string{"mariadb.service", "berth-valkey-app_example_com.service", "berth-valkey-www_example_com.service"}
	if got := supervisorAfterUnits(s); !reflect.DeepEqual(got, want) {
		t.Errorf("supervisorAfterUnits = %v, want %v", got, want)
	}
	s.Database.Engine = "postgres"
	s.Valkey = false
	if got := supervisorAfterUnits(s); !reflect.DeepEqual(got, []string{"postgresql.service"}) {
		t.Errorf("postgres without valkey = %v, want [postgresql.service]", got)
	}
}

// TestSupervisorRenderOrderIsTheGolden: the step renders the drop-in from
// the template the golden pins, with the units above.
func TestSupervisorRenderOrderIsTheGolden(t *testing.T) {
	got, err := renderSupervisorOrder(supervisorOrderServer("running"))
	if err != nil {
		t.Fatal(err)
	}
	want := "# managed by berth\n" +
		"# Ordering only: supervisord (and the workers: running programs it starts)\n" +
		"# comes up after the database and each site's Valkey at boot, so a worker\n" +
		"# never races a backend that is still starting and goes FATAL.\n" +
		"[Unit]\n" +
		"After=mariadb.service\n" +
		"After=berth-valkey-app_example_com.service\n" +
		"After=berth-valkey-www_example_com.service\n"
	if string(got) != want {
		t.Errorf("drop-in bytes:\n got %q\nwant %q", got, want)
	}
}

// TestSupervisorDormantCheckReadsDropInOnce (ruling R17): with no site
// running, Check adds exactly ONE read-only probe — the drop-in classify —
// and a clean host is satisfied.
func TestSupervisorDormantCheckReadsDropInOnce(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubSupervisorUp(f)
	f.On(supervisorOrderRead, bssh.Result{ExitCode: 1})
	cr, err := Supervisor().Check(context.Background(), provision.RunCtx{}, supervisorOrderServer(""), f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied || cr.Reason != "supervisor installed and running" {
		t.Errorf("Check = (%v, %q), want satisfied with the unchanged reason", cr.Satisfied, cr.Reason)
	}
	want := []string{"dpkg -s supervisor", "systemctl is-active supervisor", "systemctl is-enabled supervisor", supervisorOrderRead}
	if got := callCmds(f); !reflect.DeepEqual(got, want) {
		t.Errorf("dormant Check commands = %q, want %q", got, want)
	}
}

// TestSupervisorDormantApplyCleanHostWritesNothing (ruling R17): a dormant
// Apply on a host without the drop-in issues today's commands plus the one
// read — no file, no write, no daemon-reload.
func TestSupervisorDormantApplyCleanHostWritesNothing(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y supervisor", bssh.Result{})
	f.On("systemctl enable --now supervisor", bssh.Result{})
	f.On(supervisorOrderRead, bssh.Result{ExitCode: 1})
	if err := Supervisor().Apply(context.Background(), provision.RunCtx{}, supervisorOrderServer("dormant"), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(f.Writes()) != 0 {
		t.Errorf("a dormant Apply must not write; wrote %v", f.Writes())
	}
	for _, c := range callCmds(f) {
		if c == daemonReloadCmd || c == supervisorOrderRemove || c == supervisorOrderMkdir {
			t.Errorf("a dormant Apply on a clean host must not run %q", c)
		}
	}
}

// TestSupervisorRunningWritesDropInAndReloads: any running site orders
// supervisord after the database and every Valkey instance — the drop-in is
// written (directory first) and systemd reloads its unit files.
func TestSupervisorRunningWritesDropInAndReloads(t *testing.T) {
	s := supervisorOrderServer("")
	s.Sites[1].Workers = "running" // one site is enough
	want, err := renderSupervisorOrder(s)
	if err != nil {
		t.Fatal(err)
	}

	f := bssh.NewFakeRunner()
	stubSupervisorUp(f)
	f.On(supervisorOrderRead, bssh.Result{ExitCode: 1})
	cr, err := Supervisor().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied || !strings.Contains(cr.Reason, "berth-after.conf") {
		t.Errorf("Check = (%v, %q), want unsatisfied naming the drop-in", cr.Satisfied, cr.Reason)
	}

	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y supervisor", bssh.Result{})
	f.On("systemctl enable --now supervisor", bssh.Result{})
	f.On(supervisorOrderMkdir, bssh.Result{})
	f.On(daemonReloadCmd, bssh.Result{})
	if err := Supervisor().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	w := f.Writes()
	if len(w) != 1 || w[0].Path != "/etc/systemd/system/supervisor.service.d/berth-after.conf" || string(w[0].Content) != string(want) {
		t.Fatalf("writes = %+v, want the rendered drop-in once", w)
	}
	if w[0].Owner != "root" || w[0].Group != "root" || w[0].Mode != 0o644 {
		t.Errorf("drop-in meta = %s:%s %#o, want root:root 0644", w[0].Owner, w[0].Group, w[0].Mode)
	}
	cmds := callCmds(f)
	mkdir, reload := slices.Index(cmds, supervisorOrderMkdir), slices.Index(cmds, daemonReloadCmd)
	if mkdir < 0 || reload < 0 || reload < mkdir {
		t.Errorf("want the directory created and then daemon-reload; calls %q", cmds)
	}
}

// TestSupervisorRunningConvergedIsSatisfied: the up-to-date drop-in is
// converged, and an Apply that runs anyway (supervisor stopped) rewrites
// nothing and reloads nothing.
func TestSupervisorRunningConvergedIsSatisfied(t *testing.T) {
	s := supervisorOrderServer("running")
	want, err := renderSupervisorOrder(s)
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubSupervisorUp(f)
	f.On(supervisorOrderRead, bssh.Result{Stdout: string(want)})
	cr, err := Supervisor().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("Check = %q, want satisfied", cr.Reason)
	}

	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y supervisor", bssh.Result{})
	f.On("systemctl enable --now supervisor", bssh.Result{})
	if err := Supervisor().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v (an unstubbed mkdir/daemon-reload would surface here)", err)
	}
	if len(f.Writes()) != 0 {
		t.Errorf("an up-to-date drop-in must not be rewritten; wrote %v", f.Writes())
	}
}

// TestSupervisorFlipToDormantRemovesDropIn: after the last site stops
// running, berth's drop-in is drift: Check reports it, Apply removes it and
// reloads systemd.
func TestSupervisorFlipToDormantRemovesDropIn(t *testing.T) {
	stale, err := renderSupervisorOrder(supervisorOrderServer("running"))
	if err != nil {
		t.Fatal(err)
	}
	s := supervisorOrderServer("dormant")
	f := bssh.NewFakeRunner()
	stubSupervisorUp(f)
	f.On(supervisorOrderRead, bssh.Result{Stdout: string(stale)})
	cr, err := Supervisor().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied || !strings.Contains(cr.Reason, "should be removed") {
		t.Errorf("Check = (%v, %q), want unsatisfied: the drop-in should be removed", cr.Satisfied, cr.Reason)
	}

	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y supervisor", bssh.Result{})
	f.On("systemctl enable --now supervisor", bssh.Result{})
	f.On(supervisorOrderRemove, bssh.Result{})
	f.On(daemonReloadCmd, bssh.Result{})
	if err := Supervisor().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	cmds := callCmds(f)
	rm, reload := slices.Index(cmds, supervisorOrderRemove), slices.Index(cmds, daemonReloadCmd)
	if rm < 0 || reload < rm {
		t.Errorf("want rm then daemon-reload; calls %q", cmds)
	}
}

// TestSupervisorDormantLeavesForeignDropIn: a file at that path berth did
// not write is never touched — not reported, not removed, even with --force.
func TestSupervisorDormantLeavesForeignDropIn(t *testing.T) {
	for _, force := range []bool{false, true} {
		f := bssh.NewFakeRunner()
		stubSupervisorUp(f)
		f.On(supervisorOrderRead, bssh.Result{Stdout: "[Unit]\nAfter=postgresql.service\n"})
		rc := provision.RunCtx{Force: force}
		cr, err := Supervisor().Check(context.Background(), rc, supervisorOrderServer(""), f)
		if err != nil {
			t.Fatal(err)
		}
		if !cr.Satisfied {
			t.Errorf("force=%v: a foreign drop-in must not be drift; Check = %q", force, cr.Reason)
		}
		f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y supervisor", bssh.Result{})
		f.On("systemctl enable --now supervisor", bssh.Result{})
		if err := Supervisor().Apply(context.Background(), rc, supervisorOrderServer(""), f); err != nil {
			t.Fatalf("force=%v: Apply() error = %v (an unstubbed rm/daemon-reload would surface here)", force, err)
		}
	}
}

// TestSupervisorRunningForeignDropInNeedsForce: under running the path is
// berth's to write, so a foreign file there follows the managed-file policy —
// refused without --force, overwritten with it.
func TestSupervisorRunningForeignDropInNeedsForce(t *testing.T) {
	s := supervisorOrderServer("running")
	f := bssh.NewFakeRunner()
	stubSupervisorUp(f)
	f.On(supervisorOrderRead, bssh.Result{Stdout: "[Unit]\nAfter=postgresql.service\n"})
	if _, err := Supervisor().Check(context.Background(), provision.RunCtx{}, s, f); err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("Check error = %v, want the not-managed refusal", err)
	}
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y supervisor", bssh.Result{})
	f.On("systemctl enable --now supervisor", bssh.Result{})
	if err := Supervisor().Apply(context.Background(), provision.RunCtx{}, s, f); err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("Apply error = %v, want the not-managed refusal without --force", err)
	}
	if len(f.Writes()) != 0 {
		t.Errorf("a refused Apply must not write; wrote %v", f.Writes())
	}

	f = bssh.NewFakeRunner()
	stubSupervisorUp(f)
	f.On(supervisorOrderRead, bssh.Result{Stdout: "[Unit]\nAfter=postgresql.service\n"})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y supervisor", bssh.Result{})
	f.On("systemctl enable --now supervisor", bssh.Result{})
	f.On(supervisorOrderMkdir, bssh.Result{})
	f.On(daemonReloadCmd, bssh.Result{})
	if err := Supervisor().Apply(context.Background(), provision.RunCtx{Force: true}, s, f); err != nil {
		t.Fatalf("Apply(--force) error = %v", err)
	}
	if len(f.Writes()) != 1 {
		t.Errorf("--force must overwrite the foreign drop-in; writes %v", f.Writes())
	}
}

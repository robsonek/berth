package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

const (
	valkeyLiveness = `[ "$(stat -c %Y '/etc/systemd/system/valkey-server.service.d/berth.conf' 2>/dev/null)" -le "$(date -d "$(systemctl show -p ActiveEnterTimestamp --value valkey-server.service)" +%s 2>/dev/null)" ]`
)

func valkeyOnlyServer() *config.Server {
	return &config.Server{Valkey: true, Database: config.Database{Engine: "postgres"}}
}

func TestTuningRequires(t *testing.T) {
	if got := Tuning(false).Requires(); len(got) != 1 || got[0] != "database" {
		t.Fatalf("Tuning(false).Requires() = %v, want [database]", got)
	}
	if got := Tuning(true).Requires(); len(got) != 2 || got[0] != "database" || got[1] != "valkey" {
		t.Fatalf("Tuning(true).Requires() = %v, want [database valkey]", got)
	}
}

func TestTuningCheckValkeySatisfiedWhenLoaded(t *testing.T) {
	srv := valkeyOnlyServer()
	want, err := renderValkeyDropIn(srv)
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, valkeyUnit)
	f.On(valkeyLiveness, bssh.Result{ExitCode: 0})
	cr, err := Tuning(true).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

// stubServiceActive stubs the single command serviceActive issues so the unit
// reads as active (running). Check requires the service to be active before
// consulting liveness; enablement is the service's own step's responsibility, so
// tuning never consults systemctl is-enabled.
func stubServiceActive(f *bssh.FakeRunner, unit string) {
	f.On("systemctl is-active "+unit, bssh.Result{ExitCode: 0})
}

func TestTuningCheckValkeyUnsatisfiedWhenDropInAbsent(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 1})
	cr, err := Tuning(true).Check(context.Background(), provision.RunCtx{}, valkeyOnlyServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when drop-in absent")
	}
}

func TestTuningCheckValkeyUnsatisfiedWhenNotLoaded(t *testing.T) {
	srv := valkeyOnlyServer()
	want, _ := renderValkeyDropIn(srv)
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, valkeyUnit)
	f.On(valkeyLiveness, bssh.Result{ExitCode: 1}) // file newer than last restart
	cr, err := Tuning(true).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when drop-in present but not yet loaded")
	}
}

func TestTuningCheckValkeyUnsatisfiedWhenServiceDown(t *testing.T) {
	srv := valkeyOnlyServer()
	want, _ := renderValkeyDropIn(srv)
	f := bssh.NewFakeRunner()
	// File is up-to-date, but the unit is stopped: serviceActive fails before liveness.
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On("systemctl is-active "+valkeyUnit, bssh.Result{ExitCode: 1})
	cr, err := Tuning(true).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when up-to-date drop-in but service is down")
	}
}

func TestTuningCheckValkeyActiveButDisabledStillSatisfied(t *testing.T) {
	srv := valkeyOnlyServer()
	want, _ := renderValkeyDropIn(srv)
	f := bssh.NewFakeRunner()
	// Up-to-date file, active but DISABLED unit, loaded config. tuning must NOT
	// require enabled — enablement is the valkey step's job. Requiring it here would
	// never converge (Apply restarts but never enables). The is-enabled stub is
	// present only to prove it is never consulted (asserted via Calls below).
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On("systemctl is-active "+valkeyUnit, bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled "+valkeyUnit, bssh.Result{ExitCode: 1}) // disabled
	f.On(valkeyLiveness, bssh.Result{ExitCode: 0})
	cr, err := Tuning(true).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied for active-but-disabled service; got %+v", cr)
	}
	// Prove checkTuned never asks about enablement (else it would loop forever).
	if calledCmd(f, "systemctl is-enabled "+valkeyUnit) {
		t.Error("checkTuned must not consult systemctl is-enabled (enablement is the service step's job)")
	}
}

func TestTuningApplyValkeyWritesDropInReloadsRestarts(t *testing.T) {
	srv := valkeyOnlyServer()
	f := bssh.NewFakeRunner()
	// Pre-check: drop-in absent ⇒ block unsatisfied ⇒ Apply acts on it.
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 1})
	f.On("mkdir -p /etc/systemd/system/valkey-server.service.d", bssh.Result{})
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl restart valkey-server.service", bssh.Result{})
	if err := Tuning(true).Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	// drop-in written with the rendered content, root:root 0644.
	var found bool
	want, _ := renderValkeyDropIn(srv)
	for _, w := range f.Writes() {
		if w.Path == "/etc/systemd/system/valkey-server.service.d/berth.conf" {
			found = true
			if string(w.Content) != string(want) {
				t.Errorf("drop-in content mismatch:\n got: %q\nwant: %q", w.Content, want)
			}
			if w.Owner != "root" || w.Group != "root" || w.Mode != 0o644 {
				t.Errorf("drop-in perms = %s:%s %o, want root:root 644", w.Owner, w.Group, w.Mode)
			}
		}
	}
	if !found {
		t.Fatal("drop-in not written")
	}
	// Exact order: mkdir < daemon-reload < restart.
	mkdirIdx := cmdIndex(f, "mkdir -p /etc/systemd/system/valkey-server.service.d")
	reloadIdx := cmdIndex(f, "systemctl daemon-reload")
	restartIdx := cmdIndex(f, "systemctl restart valkey-server.service")
	if mkdirIdx < 0 || reloadIdx < 0 || restartIdx < 0 {
		t.Fatalf("missing expected call(s): mkdir=%d reload=%d restart=%d", mkdirIdx, reloadIdx, restartIdx)
	}
	if !(mkdirIdx < reloadIdx && reloadIdx < restartIdx) {
		t.Errorf("wrong call order: mkdir=%d daemon-reload=%d restart=%d (want mkdir < reload < restart)", mkdirIdx, reloadIdx, restartIdx)
	}
}

// cmdIndex returns the index of the first call whose Cmd equals want, or -1.
func cmdIndex(f *bssh.FakeRunner, want string) int {
	for i, c := range f.Calls() {
		if c.Cmd == want {
			return i
		}
	}
	return -1
}

const mariadbLiveness = `[ "$(stat -c %Y '/etc/mysql/mariadb.conf.d/99-berth.cnf' 2>/dev/null)" -le "$(date -d "$(systemctl show -p ActiveEnterTimestamp --value mariadb.service)" +%s 2>/dev/null)" ]`

func mariadbOnlyServer() *config.Server {
	return &config.Server{Valkey: false, Database: config.Database{Engine: "mariadb"}}
}

func TestTuningCheckMariaDBSatisfiedWhenLoaded(t *testing.T) {
	srv := mariadbOnlyServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	cr, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestTuningApplyMariaDBWritesDropInRestarts(t *testing.T) {
	srv := mariadbOnlyServer()
	f := bssh.NewFakeRunner()
	// Pre-check: cnf absent ⇒ block unsatisfied ⇒ Apply acts on it.
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 1})
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("systemctl restart mariadb.service", bssh.Result{})
	if err := Tuning(false).Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var found bool
	want, _ := renderMariaDBTuning(srv)
	for _, w := range f.Writes() {
		if w.Path == "/etc/mysql/mariadb.conf.d/99-berth.cnf" {
			found = true
			if string(w.Content) != string(want) {
				t.Errorf("cnf content mismatch:\n got: %q\nwant: %q", w.Content, want)
			}
		}
	}
	if !found {
		t.Fatal("mariadb tuning cnf not written")
	}
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "systemctl restart mariadb.service") {
		t.Errorf("Apply did not restart mariadb; calls: %v", cmds)
	}
}

func TestTuningGatingSkipsAbsentServices(t *testing.T) {
	// Postgres + no Valkey: Apply must touch nothing (no writes, no calls).
	srv := &config.Server{Valkey: false, Database: config.Database{Engine: "postgres"}}
	f := bssh.NewFakeRunner()
	if err := Tuning(false).Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(f.Writes()) != 0 || len(f.Calls()) != 0 {
		t.Errorf("expected no-op; got writes=%v calls=%v", f.Writes(), f.Calls())
	}
	// And Check is trivially satisfied.
	cr, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied no-op; got %+v", cr)
	}
}

func TestTuningCheckValkeyUnmanagedAbortsWithoutForce(t *testing.T) {
	srv := valkeyOnlyServer()
	// A pre-existing, foreign drop-in lacking the "# managed by berth" marker.
	unmanaged := "[Service]\nExecStart=/usr/bin/valkey-server\n"
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 0, Stdout: unmanaged})

	// Without --force: unmanaged file must abort (unsatisfied + non-nil error).
	cr, err := Tuning(true).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err == nil {
		t.Error("expected error aborting on unmanaged drop-in without --force")
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied on unmanaged drop-in")
	}

	// With --force: unsatisfied (will be overwritten), but no error.
	cr, err = Tuning(true).Check(context.Background(), provision.RunCtx{Force: true}, srv, f)
	if err != nil {
		t.Errorf("unexpected error with --force: %v", err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied (overwrite pending) on unmanaged drop-in with --force")
	}
}

func TestTuningCheckValkeyDriftedUnsatisfied(t *testing.T) {
	srv := valkeyOnlyServer()
	want, err := renderValkeyDropIn(srv)
	if err != nil {
		t.Fatal(err)
	}
	// Managed (keeps the marker) but content differs from desired.
	drifted := strings.Replace(string(want), "256mb", "999mb", 1)
	if drifted == string(want) {
		t.Fatal("test setup: expected drifted content to differ from desired")
	}
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 0, Stdout: drifted})
	cr, err := Tuning(true).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when managed drop-in content has drifted")
	}
}

func TestTuningCheckMariaDBUnsatisfiedWhenNotLoaded(t *testing.T) {
	srv := mariadbOnlyServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 1}) // file newer than last restart
	cr, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when mariadb cnf present but not yet loaded")
	}
}

func TestTuningCheckMariaDBUnsatisfiedWhenAbsent(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 1})
	cr, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, mariadbOnlyServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when mariadb cnf absent")
	}
}

func valkeyAndMariaDBServer() *config.Server {
	return &config.Server{Valkey: true, Database: config.Database{Engine: "mariadb"}}
}

func TestTuningCheckCombinedSatisfiedWhenBothLoaded(t *testing.T) {
	srv := valkeyAndMariaDBServer()
	vWant, err := renderValkeyDropIn(srv)
	if err != nil {
		t.Fatal(err)
	}
	mWant, err := renderMariaDBTuning(srv)
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 0, Stdout: string(vWant)})
	stubServiceActive(f, valkeyUnit)
	f.On(valkeyLiveness, bssh.Result{ExitCode: 0})
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(mWant)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	cr, err := Tuning(true).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when both drop-ins loaded; got %+v", cr)
	}
}

func TestTuningApplyCombinedWritesBothRestartsBoth(t *testing.T) {
	srv := valkeyAndMariaDBServer()
	f := bssh.NewFakeRunner()
	// Pre-check: both files absent ⇒ both blocks unsatisfied ⇒ Apply acts on both.
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 1})
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("mkdir -p /etc/systemd/system/valkey-server.service.d", bssh.Result{})
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl restart valkey-server.service", bssh.Result{})
	f.On("systemctl restart mariadb.service", bssh.Result{})
	if err := Tuning(true).Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	vWant, _ := renderValkeyDropIn(srv)
	mWant, _ := renderMariaDBTuning(srv)
	var vFound, mFound bool
	for _, w := range f.Writes() {
		switch w.Path {
		case "/etc/systemd/system/valkey-server.service.d/berth.conf":
			vFound = true
			if string(w.Content) != string(vWant) {
				t.Errorf("valkey drop-in content mismatch:\n got: %q\nwant: %q", w.Content, vWant)
			}
		case "/etc/mysql/mariadb.conf.d/99-berth.cnf":
			mFound = true
			if string(w.Content) != string(mWant) {
				t.Errorf("mariadb cnf content mismatch:\n got: %q\nwant: %q", w.Content, mWant)
			}
		}
	}
	if !vFound {
		t.Error("valkey drop-in not written")
	}
	if !mFound {
		t.Error("mariadb tuning cnf not written")
	}

	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	for _, w := range []string{
		"mkdir -p /etc/systemd/system/valkey-server.service.d",
		"systemctl daemon-reload",
		"systemctl restart valkey-server.service",
		"systemctl restart mariadb.service",
	} {
		if !strings.Contains(joined, w) {
			t.Errorf("Apply did not run %q; calls:\n%s", w, joined)
		}
	}
}

func TestTuningApplyValkeyRestartErrorPropagates(t *testing.T) {
	srv := valkeyOnlyServer()
	f := bssh.NewFakeRunner()
	// Pre-check: drop-in absent ⇒ block unsatisfied ⇒ Apply acts and reaches restart.
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 1})
	f.On("mkdir -p /etc/systemd/system/valkey-server.service.d", bssh.Result{})
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl restart valkey-server.service", bssh.Result{ExitCode: 1, Stderr: "boom"})
	if err := Tuning(true).Apply(context.Background(), provision.RunCtx{}, srv, f); err == nil {
		t.Fatal("expected error when systemctl restart fails")
	}
}

func calledCmd(f *bssh.FakeRunner, want string) bool { return cmdIndex(f, want) >= 0 }

func wrotePath(f *bssh.FakeRunner, path string) bool {
	for _, w := range f.Writes() {
		if w.Path == path {
			return true
		}
	}
	return false
}

func TestTuningApplyCombinedOnlyValkeyDriftedRestartsOnlyValkey(t *testing.T) {
	srv := valkeyAndMariaDBServer()
	mWant, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	// Valkey block unsatisfied (drop-in absent).
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 1})
	f.On("mkdir -p /etc/systemd/system/valkey-server.service.d", bssh.Result{})
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl restart valkey-server.service", bssh.Result{})
	// MariaDB block satisfied (file up-to-date, service up, loaded).
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(mWant)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})

	if err := Tuning(true).Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if !wrotePath(f, valkeyDropInPath) {
		t.Error("expected valkey drop-in written")
	}
	if !calledCmd(f, "systemctl restart "+valkeyUnit) {
		t.Error("expected valkey restarted")
	}
	if wrotePath(f, mariadbTuningPath) {
		t.Error("did not expect mariadb cnf written (block satisfied)")
	}
	if calledCmd(f, "systemctl restart "+mariadbUnit) {
		t.Error("did not expect mariadb restarted (block satisfied)")
	}
}

func TestTuningApplyCombinedOnlyMariaDBDriftedRestartsOnlyMariaDB(t *testing.T) {
	srv := valkeyAndMariaDBServer()
	vWant, _ := renderValkeyDropIn(srv)
	f := bssh.NewFakeRunner()
	// Valkey block satisfied (file up-to-date, service up, loaded).
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 0, Stdout: string(vWant)})
	stubServiceActive(f, valkeyUnit)
	f.On(valkeyLiveness, bssh.Result{ExitCode: 0})
	// MariaDB block unsatisfied (cnf absent).
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 1})
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("systemctl restart mariadb.service", bssh.Result{})

	if err := Tuning(true).Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if !wrotePath(f, mariadbTuningPath) {
		t.Error("expected mariadb cnf written")
	}
	if !calledCmd(f, "systemctl restart "+mariadbUnit) {
		t.Error("expected mariadb restarted")
	}
	if wrotePath(f, valkeyDropInPath) {
		t.Error("did not expect valkey drop-in written (block satisfied)")
	}
	if calledCmd(f, "systemctl restart "+valkeyUnit) {
		t.Error("did not expect valkey restarted (block satisfied)")
	}
}

// gateStub is a minimal provision.Step for exercising the --only dependency
// gate against the REAL tuning step: only Name and a fixed Check verdict matter.
type gateStub struct {
	name      string
	satisfied bool
}

func (s gateStub) Name() string       { return s.name }
func (s gateStub) Requires() []string { return nil }
func (s gateStub) Check(context.Context, provision.RunCtx, *config.Server, bssh.Runner) (provision.CheckResult, error) {
	return provision.CheckResult{Satisfied: s.satisfied, Reason: "stub"}, nil
}
func (s gateStub) Apply(context.Context, provision.RunCtx, *config.Server, bssh.Runner) error {
	return nil
}

func TestOnlyTuningRefusesWhenValkeyUnsatisfied(t *testing.T) {
	// valkey: true in config, but the valkey step is unsatisfied (never
	// provisioned): --only tuning must refuse pre-flight, not fail mid-Apply.
	eng := provision.New(
		gateStub{name: "database", satisfied: true},
		gateStub{name: "valkey", satisfied: false},
		Tuning(true),
	)
	_, err := eng.Run(context.Background(), valkeyOnlyServer(), bssh.NewFakeRunner(), provision.Options{Only: "tuning"})
	if err == nil || !strings.Contains(err.Error(), "valkey") {
		t.Fatalf("expected pre-flight refusal naming valkey; got %v", err)
	}
}

func TestOnlyTuningPassesWhenValkeySatisfied(t *testing.T) {
	eng := provision.New(
		gateStub{name: "database", satisfied: true},
		gateStub{name: "valkey", satisfied: true},
		Tuning(true),
	)
	f := bssh.NewFakeRunner()
	// Dry-run stops at Planned, so only tuning's own Check runs: valkey block,
	// drop-in absent -> unsatisfied -> Planned.
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 1})
	events, err := eng.Run(context.Background(), valkeyOnlyServer(), f, provision.Options{Only: "tuning", DryRun: true})
	if err != nil {
		t.Fatalf("gate must pass when valkey is satisfied: %v", err)
	}
	// Per-step failures travel on the event channel, not Run's returned error:
	// drain fully and pin tuning's terminal event to Planned.
	planned := false
	for ev := range events {
		if ev.Step == "tuning" && ev.Kind == provision.EventPlanned {
			planned = true
		}
	}
	if !planned {
		t.Fatal("expected tuning to reach Planned (dry-run, drop-in absent)")
	}
}

func TestParseMariaDBSize(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"268435456", 268435456, true}, // bare bytes
		{"64K", 64 << 10, true},
		{"256M", 256 << 20, true},
		{"2G", 2 << 30, true},
		// MariaDB accepts lowercase suffixes; literal-Server callers bypass
		// reMariaDBSize validation entirely, so the parser must not false-reject.
		{"1k", 1 << 10, true},
		{"256m", 256 << 20, true},
		{"1g", 1 << 30, true},
		{"99999999999G", 0, false}, // overflows uint64
		{"", 0, false},
		{"G", 0, false},   // suffix without digits
		{"12Q", 0, false}, // unknown suffix
		{"12.5M", 0, false},
	} {
		got, err := parseMariaDBSize(tc.in)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("parseMariaDBSize(%q) = %d, %v; want %d, nil", tc.in, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Errorf("parseMariaDBSize(%q) = %d, nil; want error", tc.in, got)
		}
	}
}

func TestTuningMariaDBBufferPoolGuardBoundaries(t *testing.T) {
	// MemTotal 1000000 kB = 1024000000 bytes; limit = 1024000000/100*80 =
	// 819200000. Exactly the limit passes; one byte over errors.
	for _, tc := range []struct {
		pool string
		ok   bool
	}{
		{"819200000", true},
		{"819200001", false},
	} {
		srv := mariadbOnlyServer()
		srv.Tuning.MariaDBBufferPool = tc.pool
		f := bssh.NewFakeRunner()
		f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1000000\n"})
		if tc.ok {
			// Fitting value: Check proceeds to the normal file probe.
			f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 1})
		}
		cr, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f)
		if tc.ok {
			if err != nil {
				t.Fatalf("pool %s: unexpected error: %v", tc.pool, err)
			}
			if cr.Satisfied {
				t.Errorf("pool %s: expected unsatisfied (file absent)", tc.pool)
			}
		} else if err == nil {
			t.Errorf("pool %s: expected guard error", tc.pool)
		} else if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("pool %s: expected the buffer-pool guard error, got: %v", tc.pool, err)
		}
	}
}

func TestTuningMariaDBGuardBadMemTotal(t *testing.T) {
	for _, out := range []string{"", "banana"} {
		srv := mariadbOnlyServer()
		f := bssh.NewFakeRunner()
		f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: out})
		if _, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f); err == nil {
			t.Errorf("MemTotal output %q: expected error, got nil", out)
		}
	}
}

func TestTuningCheckMariaDBOverLimitErrorsEvenWhenDeployed(t *testing.T) {
	// Accepted behavior change pinned: a host already running with an
	// over-limit drop-in fails Check on every run until the value is lowered.
	// The guard fires before the file is even consulted.
	srv := mariadbOnlyServer()
	srv.Tuning.MariaDBBufferPool = "2G"
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"}) // 1 GiB
	if _, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f); err == nil {
		t.Fatal("expected guard error for 2G pool on a 1 GiB host")
	}
	if calledCmd(f, "cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'") {
		t.Error("guard must fire before the managed-file probe")
	}
}

func TestTuningApplyMariaDBOverLimitNoWriteNoRestart(t *testing.T) {
	// Config raised above the limit while an old, fitting managed drop-in is
	// on disk: Apply must error BEFORE any write or restart.
	srv := mariadbOnlyServer()
	srv.Tuning.MariaDBBufferPool = "2G"
	old, err := renderMariaDBTuning(mariadbOnlyServer()) // default 256M content
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(old)})
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"}) // 1 GiB
	if err := Tuning(false).Apply(context.Background(), provision.RunCtx{}, srv, f); err == nil {
		t.Fatal("expected guard error from Apply")
	}
	if len(f.Writes()) != 0 {
		t.Errorf("Apply must not write anything past a failing guard: %+v", f.Writes())
	}
	if calledCmd(f, "systemctl restart mariadb.service") {
		t.Error("Apply must not restart mariadb past a failing guard")
	}
}

func TestRenderMariaDBTuningSlowLog(t *testing.T) {
	s := &config.Server{Tuning: config.Tuning{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: 5}}
	b, err := renderMariaDBTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"slow_query_log = 1",
		"slow_query_log_file = /var/log/mysql/mariadb-slow.log",
		"long_query_time = 5",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("enabled slow log render missing %q:\n%s", want, b)
		}
	}
	off, err := renderMariaDBTuning(&config.Server{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(off), "slow_query_log") {
		t.Errorf("disabled slow log must render nothing slow-log related:\n%s", off)
	}
}

func TestRenderMariaDBTuningSlowLogDefaultThreshold(t *testing.T) {
	s := &config.Server{Tuning: config.Tuning{MariaDBSlowQueryLog: true}}
	b, err := renderMariaDBTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "long_query_time = 2") {
		t.Errorf("default threshold must render as 2 s:\n%s", b)
	}
}

func mariadbSlowLogServer() *config.Server {
	return &config.Server{Database: config.Database{Engine: "mariadb"}, Tuning: config.Tuning{MariaDBSlowQueryLog: true}}
}

func TestTuningCheckSlowLogDirMissingUnsatisfied(t *testing.T) {
	// Debian 13's mariadb logs to the journal and ships no /var/log/mysql; a
	// loaded drop-in with the directory missing means mariadbd silently turned
	// slow logging OFF for its whole lifetime — Check must not read Satisfied.
	srv := mariadbSlowLogServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	f.On("test -d /var/log/mysql", bssh.Result{ExitCode: 1}) // dir absent
	cr, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while /var/log/mysql is missing with the slow log enabled")
	}
}

func TestTuningCheckSlowLogDirPresentSatisfied(t *testing.T) {
	srv := mariadbSlowLogServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	f.On("test -d /var/log/mysql", bssh.Result{ExitCode: 0})
	cr, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestTuningApplySlowLogCreatesDirAndRestarts(t *testing.T) {
	// The drop-in itself is loaded (checkTuned satisfied) but the directory is
	// missing: Apply must create it AND restart — mariadbd disabled slow
	// logging for the process duration, so a dir alone changes nothing.
	srv := mariadbSlowLogServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	f.On("test -d /var/log/mysql", bssh.Result{ExitCode: 1})
	f.On("install -d -m 2750 -o mysql -g adm /var/log/mysql", bssh.Result{})
	f.On("systemctl restart mariadb.service", bssh.Result{})
	if err := Tuning(false).Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, "install -d -m 2750 -o mysql -g adm /var/log/mysql") {
		t.Error("expected the slow-log directory created")
	}
	if !calledCmd(f, "systemctl restart mariadb.service") {
		t.Error("expected a mariadb restart to re-enable the in-process-disabled slow log")
	}
	for _, w := range f.Writes() {
		if w.Path == mariadbTuningPath {
			t.Error("an up-to-date drop-in must not be rewritten")
		}
	}
}

func TestTuningSlowLogOffNeverProbesDir(t *testing.T) {
	srv := mariadbOnlyServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	if _, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatal(err)
	}
	if err := Tuning(false).Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "test -d /var/log/mysql") {
			t.Errorf("slow log off must not probe the log dir; ran %q", c.Cmd)
		}
	}
}

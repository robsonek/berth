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

func TestTuningRequiresDatabase(t *testing.T) {
	if got := Tuning().Requires(); len(got) != 1 || got[0] != "database" {
		t.Fatalf("Requires() = %v, want [database]", got)
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
	f.On(valkeyLiveness, bssh.Result{ExitCode: 0})
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestTuningCheckValkeyUnsatisfiedWhenDropInAbsent(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 1})
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, valkeyOnlyServer(), f)
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
	f.On(valkeyLiveness, bssh.Result{ExitCode: 1}) // file newer than last restart
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when drop-in present but not yet loaded")
	}
}

func TestTuningApplyValkeyWritesDropInReloadsRestarts(t *testing.T) {
	srv := valkeyOnlyServer()
	f := bssh.NewFakeRunner()
	f.On("mkdir -p /etc/systemd/system/valkey-server.service.d", bssh.Result{})
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl restart valkey-server.service", bssh.Result{})
	if err := Tuning().Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
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
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	for _, w := range []string{"mkdir -p /etc/systemd/system/valkey-server.service.d", "systemctl daemon-reload", "systemctl restart valkey-server.service"} {
		if !strings.Contains(joined, w) {
			t.Errorf("Apply did not run %q; calls:\n%s", w, joined)
		}
	}
}

const mariadbLiveness = `[ "$(stat -c %Y '/etc/mysql/mariadb.conf.d/99-berth.cnf' 2>/dev/null)" -le "$(date -d "$(systemctl show -p ActiveEnterTimestamp --value mariadb.service)" +%s 2>/dev/null)" ]`

func mariadbOnlyServer() *config.Server {
	return &config.Server{Valkey: false, Database: config.Database{Engine: "mariadb"}}
}

func TestTuningCheckMariaDBSatisfiedWhenLoaded(t *testing.T) {
	srv := mariadbOnlyServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
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
	f.On("systemctl restart mariadb.service", bssh.Result{})
	if err := Tuning().Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
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
	if err := Tuning().Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(f.Writes()) != 0 || len(f.Calls()) != 0 {
		t.Errorf("expected no-op; got writes=%v calls=%v", f.Writes(), f.Calls())
	}
	// And Check is trivially satisfied.
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied no-op; got %+v", cr)
	}
}

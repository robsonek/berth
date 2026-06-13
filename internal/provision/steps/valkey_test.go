package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestValkeyRequiresBase(t *testing.T) {
	if got := Valkey().Requires(); len(got) != 1 || got[0] != "base" {
		t.Fatalf("Requires() = %v, want [base]", got)
	}
}

func TestValkeyCheckSatisfiedWhenInstalledAndUp(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s valkey-server", bssh.Result{ExitCode: 0})
	f.On("systemctl is-active valkey-server.service", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled valkey-server.service", bssh.Result{ExitCode: 0})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when valkey-server installed and running; got %+v", cr)
	}
}

func TestValkeyCheckUnsatisfiedWhenNotInstalled(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s valkey-server", bssh.Result{ExitCode: 1})
	f.On("systemctl is-active valkey-server.service", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled valkey-server.service", bssh.Result{ExitCode: 0})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when valkey-server is not installed")
	}
}

func TestValkeyApplyInstallsAndEnables(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl enable --now valkey-server.service", bssh.Result{})
	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"apt-get install -y valkey-server", "systemctl enable --now valkey-server.service"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

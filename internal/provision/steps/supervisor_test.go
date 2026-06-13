package steps

import (
	"context"
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
	f.On("dpkg -s supervisor", bssh.Result{ExitCode: 0})
	f.On("systemctl is-active supervisor", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled supervisor", bssh.Result{ExitCode: 0})
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
	f.On("dpkg -s supervisor", bssh.Result{ExitCode: 0})
	f.On("systemctl is-active supervisor", bssh.Result{ExitCode: 3}) // inactive
	f.On("systemctl is-enabled supervisor", bssh.Result{ExitCode: 0})
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

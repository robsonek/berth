package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestSystemBaseRequiresPreflight(t *testing.T) {
	if got := SystemBase().Requires(); len(got) != 1 || got[0] != "preflight" {
		t.Fatalf("Requires() = %v, want [preflight]", got)
	}
}

func TestSystemBaseCheckSatisfiedWhenAllInstalled(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0})
	}
	cr, err := SystemBase().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when all base packages present; got %+v", cr)
	}
}

func TestSystemBaseCheckUnsatisfiedWhenMissing(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0})
	}
	f.On("dpkg -s git", bssh.Result{ExitCode: 1}) // git missing
	cr, err := SystemBase().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when a base package is missing")
	}
}

func TestBasePackagesIncludeDeployerTools(t *testing.T) {
	// The deployer clones over git and uploads built assets over rsync; both must
	// be provisioned because a minimal Debian 13 ships neither.
	for _, want := range []string{"git", "rsync"} {
		found := false
		for _, p := range basePackages {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("basePackages must include %q (required by the deployer)", want)
		}
	}
}

func TestSystemBaseApplyInstallsAndConfigures(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(basePackages, " "), bssh.Result{})
	f.On("timedatectl set-timezone UTC", bssh.Result{})
	f.On("systemctl enable --now unattended-upgrades", bssh.Result{})
	if err := SystemBase().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var saw []string
	for _, c := range f.Calls() {
		saw = append(saw, c.Cmd)
	}
	joined := strings.Join(saw, "\n")
	for _, want := range []string{"apt-get install -y", "timedatectl set-timezone UTC", "systemctl enable --now unattended-upgrades"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

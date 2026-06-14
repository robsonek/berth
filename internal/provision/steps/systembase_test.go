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
	want, err := renderAutoUpgrades()
	if err != nil {
		t.Fatal(err)
	}
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{Stdout: string(want), ExitCode: 0})
	var cr provision.CheckResult
	cr, err = SystemBase().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when all base packages present; got %+v", cr)
	}
}

func TestSystemBaseCheckAbortsOnUnmanagedAutoUpgrades(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0})
	}
	f.On("dpkg -s git", bssh.Result{ExitCode: 1}) // a base package is missing
	// An unmanaged 20auto-upgrades already exists (no berth marker).
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{Stdout: "APT::Periodic::Unattended-Upgrade \"1\";\n", ExitCode: 0})
	// Without --force: must abort (drift policy) EVEN THOUGH a package is missing.
	if _, err := SystemBase().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f); err == nil {
		t.Error("expected abort on an unmanaged 20auto-upgrades even when a base package is missing")
	}
	// With --force: reconciles instead (no error, unsatisfied).
	cr, err := SystemBase().Check(context.Background(), provision.RunCtx{Force: true}, &config.Server{}, f)
	if err != nil {
		t.Fatalf("with --force expected no error; got %v", err)
	}
	if cr.Satisfied {
		t.Error("with --force on an unmanaged file, expected unsatisfied (will reconcile)")
	}
}

func TestSystemBaseCheckUnsatisfiedWhenMissing(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0})
	}
	f.On("dpkg -s git", bssh.Result{ExitCode: 1})                    // git missing
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{ExitCode: 1}) // file absent (cat now runs even when a package is missing)
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

func TestSystemBaseCheckUnsatisfiedWhenAutoUpgradesMissing(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, pkg := range basePackages {
		f.On("dpkg -s "+pkg, bssh.Result{ExitCode: 0})
	}
	f.On("cat "+shQuote(autoUpgradesPath), bssh.Result{ExitCode: 1}) // periodic file absent
	cr, err := SystemBase().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the 20auto-upgrades periodic file is absent")
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
	var auto *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == autoUpgradesPath {
			auto = &f.Writes()[i]
		}
	}
	if auto == nil {
		t.Fatalf("Apply must write the managed %s periodic config", autoUpgradesPath)
	}
	if !strings.HasPrefix(string(auto.Content), "# managed by berth") {
		t.Errorf("%s content must start with the managed marker", autoUpgradesPath)
	}
	if auto.Owner != "root" || auto.Group != "root" || auto.Mode != 0o644 || !auto.Sudo {
		t.Errorf("unexpected FileSpec for %s: %+v", autoUpgradesPath, *auto)
	}
}

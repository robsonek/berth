package steps

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

// basePackages are the foundational packages every berth-managed server needs.
// git and rsync are required by the deployer: Deployer PHP clones the repo over
// git and uploads built assets over rsync, and a minimal Debian 13 ships neither.
var basePackages = []string{"curl", "git", "rsync", "unzip", "ca-certificates", "gnupg", "unattended-upgrades"}

// autoUpgradesPath is the APT Periodic config that actually makes
// unattended-upgrades run. Without it the apt-daily-upgrade timer applies
// nothing, so the enabled service is inert. Debian's unattended-upgrades package
// may ship an unmanaged file here (via debconf); that is reported as unmanaged
// and aborts unless --force, per the drift policy.
const autoUpgradesPath = "/etc/apt/apt.conf.d/20auto-upgrades"

// renderAutoUpgrades renders the APT Periodic config (static; '#' marker).
func renderAutoUpgrades() ([]byte, error) {
	return templates.Render("apt_auto_upgrades.conf.tmpl", nil)
}

type systembase struct{}

func SystemBase() provision.Step { return systembase{} }

func (systembase) Name() string       { return "base" }
func (systembase) Requires() []string { return []string{"preflight"} }

func (systembase) Check(ctx context.Context, rc provision.RunCtx, _ *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	var missing []string
	for _, pkg := range basePackages {
		ok, err := pkgInstalled(ctx, r, pkg)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			missing = append(missing, pkg)
		}
	}
	changes := []string{"timedatectl set-timezone UTC", "enable unattended-upgrades", "write 20auto-upgrades periodic config"}
	if len(missing) > 0 {
		return provision.CheckResult{
			Satisfied: false,
			Reason:    "missing base packages",
			Changes:   append([]string{"install: " + fmt.Sprint(missing)}, changes...),
		}, nil
	}
	// unattended-upgrades only does anything if the APT Periodic config is present.
	want, err := renderAutoUpgrades()
	if err != nil {
		return provision.CheckResult{}, err
	}
	state, err := checkManagedFile(ctx, r, autoUpgradesPath, want)
	if err != nil {
		return provision.CheckResult{}, err
	}
	ok, err := managedFileSatisfied(state, autoUpgradesPath, rc.Force)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !ok {
		return provision.CheckResult{Satisfied: false, Reason: "auto-upgrades periodic config not up to date", Changes: changes}, nil
	}
	return provision.CheckResult{Satisfied: true, Reason: "base packages installed; auto-upgrades enabled"}, nil
}

func (systembase) Apply(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	m := apt.New(r)
	if err := m.EnsurePackages(ctx, nil, basePackages...); err != nil {
		return fmt.Errorf("install base packages: %w", err)
	}
	cfg, err := renderAutoUpgrades()
	if err != nil {
		return err
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: autoUpgradesPath, Content: cfg, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", autoUpgradesPath, err)
	}
	for _, cmd := range []string{
		"timedatectl set-timezone UTC",
		"systemctl enable --now unattended-upgrades",
	} {
		res, err := r.Run(ctx, cmd, nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("base %q: %s", cmd, res.Stderr)
		}
	}
	return nil
}

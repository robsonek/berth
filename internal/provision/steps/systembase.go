package steps

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// basePackages are the foundational packages every berth-managed server needs.
var basePackages = []string{"curl", "git", "unzip", "ca-certificates", "gnupg", "unattended-upgrades"}

type systembase struct{}

func SystemBase() provision.Step { return systembase{} }

func (systembase) Name() string       { return "base" }
func (systembase) Requires() []string { return []string{"preflight"} }

func (systembase) Check(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) (provision.CheckResult, error) {
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
	if len(missing) == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "base packages installed"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "missing base packages",
		Changes:   append([]string{"install: " + fmt.Sprint(missing)}, "timedatectl set-timezone UTC", "enable unattended-upgrades"),
	}, nil
}

func (systembase) Apply(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	m := apt.New(r)
	if err := m.EnsurePackages(ctx, nil, basePackages...); err != nil {
		return fmt.Errorf("install base packages: %w", err)
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

package steps

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// valkeyUnit is the systemd unit shipped by the Debian valkey-server package.
const valkeyUnit = "valkey-server.service"

type valkey struct{}

func Valkey() provision.Step { return valkey{} }

func (valkey) Name() string       { return "valkey" }
func (valkey) Requires() []string { return []string{"base"} }

func (valkey) Check(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	installed, err := pkgInstalled(ctx, r, "valkey-server")
	if err != nil {
		return provision.CheckResult{}, err
	}
	up, err := serviceUp(ctx, r, valkeyUnit)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if installed && up {
		return provision.CheckResult{Satisfied: true, Reason: "valkey-server installed and running"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "valkey-server not installed or not running",
		Changes:   []string{"install valkey-server", "systemctl enable --now " + valkeyUnit},
	}, nil
}

func (valkey) Apply(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	if err := apt.New(r).EnsurePackages(ctx, nil, "valkey-server"); err != nil {
		return fmt.Errorf("install valkey-server: %w", err)
	}
	if res, err := r.Run(ctx, "systemctl enable --now "+valkeyUnit, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("enable valkey-server: %s", res.Stderr)
	}
	return nil
}

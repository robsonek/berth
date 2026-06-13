package steps

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

type supervisor struct{}

func Supervisor() provision.Step { return supervisor{} }

func (supervisor) Name() string       { return "supervisor" }
func (supervisor) Requires() []string { return []string{"base"} }

func (supervisor) Check(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	installed, err := pkgInstalled(ctx, r, "supervisor")
	if err != nil {
		return provision.CheckResult{}, err
	}
	up, err := serviceUp(ctx, r, "supervisor")
	if err != nil {
		return provision.CheckResult{}, err
	}
	if installed && up {
		return provision.CheckResult{Satisfied: true, Reason: "supervisor installed and running"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "supervisor not installed or not running",
		Changes:   []string{"install supervisor", "systemctl enable --now supervisor"},
	}, nil
}

func (supervisor) Apply(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	if err := apt.New(r).EnsurePackages(ctx, nil, "supervisor"); err != nil {
		return fmt.Errorf("install supervisor: %w", err)
	}
	if res, err := r.Run(ctx, "systemctl enable --now supervisor", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("enable supervisor: %s", res.Stderr)
	}
	return nil
}

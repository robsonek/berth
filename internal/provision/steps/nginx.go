package steps

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

type nginx struct{}

func Nginx() provision.Step { return nginx{} }

func (nginx) Name() string       { return "nginx" }
func (nginx) Requires() []string { return []string{"base"} }

func (nginx) Check(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	installed, err := pkgInstalled(ctx, r, "nginx")
	if err != nil {
		return provision.CheckResult{}, err
	}
	up, err := serviceUp(ctx, r, "nginx")
	if err != nil {
		return provision.CheckResult{}, err
	}
	if installed && up {
		return provision.CheckResult{Satisfied: true, Reason: "nginx installed and running"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "nginx not installed or not running",
		Changes:   []string{"install nginx", "systemctl enable --now nginx"},
	}, nil
}

func (nginx) Apply(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	if err := apt.New(r).EnsurePackages(ctx, nil, "nginx"); err != nil {
		return fmt.Errorf("install nginx: %w", err)
	}
	if res, err := r.Run(ctx, "systemctl enable --now nginx", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("enable nginx: %s", res.Stderr)
	}
	return nil
}

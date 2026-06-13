package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

type preflight struct{}

func Preflight() provision.Step { return preflight{} }

func (preflight) Name() string       { return "preflight" }
func (preflight) Requires() []string { return nil }

func (preflight) Check(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	res, err := r.Run(ctx, ". /etc/os-release && echo $VERSION_CODENAME", nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	codename := strings.TrimSpace(res.Stdout)
	if codename != "trixie" {
		return provision.CheckResult{}, fmt.Errorf("unsupported OS: VERSION_CODENAME=%q, berth requires Debian 13 (trixie)", codename)
	}
	// Preflight always "acts" (apt update) but reports satisfied=false so Apply runs once per run.
	return provision.CheckResult{Satisfied: false, Reason: "Debian 13 detected", Changes: []string{"apt-get update"}}, nil
}

func (preflight) Apply(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	for _, cmd := range []string{
		"sudo -n true",
		"sudo DEBIAN_FRONTEND=noninteractive apt-get update -y",
	} {
		res, err := r.Run(ctx, cmd, nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("preflight %q: %s", cmd, res.Stderr)
		}
	}
	return nil
}

package steps

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

const debianStockPHP = "8.4" // Debian 13 (trixie) ships PHP 8.4

type php struct{}

func PHP() provision.Step { return php{} }

func (php) Name() string       { return "php" }
func (php) Requires() []string { return []string{"base"} }

// useSury decides whether the requested version needs the Surý repo.
func useSury(p config.PHP) (bool, error) {
	switch p.Source {
	case "sury":
		return true, nil
	case "debian":
		if p.Version != debianStockPHP {
			return false, fmt.Errorf("php.source=debian cannot provide %s (Debian 13 ships %s); use auto or sury", p.Version, debianStockPHP)
		}
		return false, nil
	case "auto", "":
		return p.Version != debianStockPHP, nil
	default:
		return false, fmt.Errorf("invalid php.source %q", p.Source)
	}
}

func (php) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	res, err := r.Run(ctx, "dpkg -s php"+s.PHP.Version+"-fpm", nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if res.ExitCode == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "php" + s.PHP.Version + "-fpm installed"}, nil
	}
	return provision.CheckResult{Satisfied: false, Changes: []string{"install php" + s.PHP.Version + " + extensions"}}, nil
}

func (php) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	sury, err := useSury(s.PHP)
	if err != nil {
		return err
	}
	m := apt.New(r)
	if sury {
		if err := m.EnsureRepo(ctx, apt.Sury()); err != nil {
			return err
		}
	}
	v := s.PHP.Version
	pkgs := []string{}
	for _, ext := range []string{"fpm", "cli", "mbstring", "xml", "bcmath", "curl", "intl", "zip", "gd", "redis", "mysql"} {
		pkgs = append(pkgs, fmt.Sprintf("php%s-%s", v, ext))
	}
	return m.EnsurePackages(ctx, nil, pkgs...)
}

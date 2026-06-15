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

const debianStockPHP = "8.4" // Debian 13 (trixie) ships PHP 8.4

// phpLogDir holds the per-site FPM error logs (/var/log/php/<pool>-fpm.error.log).
// PHP-FPM does not create this directory, and no other step did — so the per-site
// error log was silently lost. The php step owns the FPM runtime, so it ensures it.
const phpLogDir = "/var/log/php"

// opcacheDropInPath is the FPM-only OPcache tuning drop-in. It is FPM-only on
// purpose: the CLI SAPI keeps Debian's stock opcache.enable_cli=0, so long-lived
// queue workers and repeated artisan runs never serve stale bytecode.
func opcacheDropInPath(ver string) string {
	return "/etc/php/" + ver + "/fpm/conf.d/99-berth-opcache.ini"
}

// renderOpcache renders the production OPcache settings (INI, ';' marker).
func renderOpcache() ([]byte, error) { return templates.RenderINI("php_opcache.ini.tmpl", nil) }

// phpPDOExt is the PHP PDO extension for a database engine: pgsql for postgres,
// else mysql. A Postgres app needs pdo_pgsql; installing the wrong one leaves the
// box unable to connect.
func phpPDOExt(engine string) string {
	if engine == "postgres" {
		return "pgsql"
	}
	return "mysql"
}

// phpPackages returns the php<ver>-<ext> packages to install, including the
// engine-appropriate PDO driver.
func phpPackages(version, engine string) []string {
	exts := []string{"fpm", "cli", "mbstring", "xml", "bcmath", "curl", "intl", "zip", "gd", "redis", phpPDOExt(engine)}
	pkgs := make([]string, len(exts))
	for i, ext := range exts {
		pkgs[i] = fmt.Sprintf("php%s-%s", version, ext)
	}
	return pkgs
}

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

func (php) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	changes := []string{"install php" + s.PHP.Version + " + extensions", "write production OPcache drop-in", "ensure " + phpLogDir}
	res, err := r.Run(ctx, "dpkg -s php"+s.PHP.Version+"-fpm", nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if res.ExitCode != 0 {
		return provision.CheckResult{Satisfied: false, Changes: changes}, nil
	}
	// The production OPcache drop-in must be the berth-managed one and up to date.
	want, err := renderOpcache()
	if err != nil {
		return provision.CheckResult{}, err
	}
	state, err := checkManagedFile(ctx, r, opcacheDropInPath(s.PHP.Version), want)
	if err != nil {
		return provision.CheckResult{}, err
	}
	ok, err := managedFileSatisfied(state, opcacheDropInPath(s.PHP.Version), rc.Force)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !ok {
		return provision.CheckResult{Satisfied: false, Reason: "OPcache drop-in not up to date", Changes: changes}, nil
	}
	// PHP-FPM does not create the parent dir of the per-site error_log
	// (/var/log/php/<pool>-fpm.error.log); ensure it exists.
	dir, err := r.Run(ctx, "test -d "+shQuote(phpLogDir), nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if dir.ExitCode != 0 {
		return provision.CheckResult{Satisfied: false, Reason: phpLogDir + " missing", Changes: changes}, nil
	}
	// The engine PDO driver must be installed too (a Postgres box with only pdo_mysql
	// can't run a DB_CONNECTION=pgsql app even though fpm is present).
	pdoPkg := "php" + s.PHP.Version + "-" + phpPDOExt(s.Database.Engine)
	pdo, err := r.Run(ctx, "dpkg -s "+pdoPkg, nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if pdo.ExitCode != 0 {
		return provision.CheckResult{Satisfied: false, Reason: pdoPkg + " not installed", Changes: changes}, nil
	}
	return provision.CheckResult{Satisfied: true, Reason: "php" + s.PHP.Version + "-fpm installed; OPcache tuned for production"}, nil
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
	pkgs := phpPackages(v, s.Database.Engine)
	if err := m.EnsurePackages(ctx, nil, pkgs...); err != nil {
		return err
	}
	if res, err := r.Run(ctx, "install -d -o root -g root -m 0755 "+shQuote(phpLogDir), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("create %s: %s", phpLogDir, res.Stderr)
	}
	// Production OPcache tuning (FPM SAPI only). validate_timestamps=0 means new
	// code is picked up only after an FPM reload — the deployer does that
	// post-deploy via its narrow `sudo systemctl reload php<ver>-fpm` grant.
	ini, err := renderOpcache()
	if err != nil {
		return err
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: opcacheDropInPath(v), Content: ini, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write OPcache drop-in: %w", err)
	}
	if res, err := r.Run(ctx, "php-fpm"+v+" -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("php-fpm%s -t failed after writing OPcache drop-in: %s", v, res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload php"+v+"-fpm", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload php%s-fpm: %s", v, res.Stderr)
	}
	return nil
}

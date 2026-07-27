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

// phpTuningDropInPath is the FPM-only berth tuning drop-in (memory_limit,
// upload sizing, execution limits). FPM-only on purpose: the CLI SAPI keeps
// Debian's stock php.ini (memory_limit=-1, max_execution_time=0), so
// long-lived queue workers and artisan runs are never capped.
func phpTuningDropInPath(ver string) string {
	return "/etc/php/" + ver + "/fpm/conf.d/99-berth-tuning.ini"
}

// renderPHPTuning renders the FPM tuning drop-in (INI, ';' marker). Values are
// read only through the Tuning *Eff accessors so literal-Server callers that
// bypass config.Load still render valid directives. PostMax is the derived
// request-body cap (upload + multipart headroom, exact bytes) that the site
// step also renders as nginx client_max_body_size.
func renderPHPTuning(s *config.Server) ([]byte, error) {
	return templates.RenderINI("php_tuning.ini.tmpl", struct {
		MemoryLimit, UploadMax, PostMax string
		MaxExecutionTime, MaxInputVars  int
	}{
		MemoryLimit:      s.Tuning.PHPMemoryLimitEff(),
		UploadMax:        s.Tuning.PHPUploadMaxEff(),
		PostMax:          s.Tuning.PHPPostBodyMaxEff(),
		MaxExecutionTime: s.Tuning.PHPMaxExecutionTimeEff(),
		MaxInputVars:     s.Tuning.PHPMaxInputVarsEff(),
	})
}

// removePHPDropIns best-effort removes both managed FPM drop-ins after a
// failed validate/reload. The files were written but never loaded; leaving
// them would make the next run's Check falsely Satisfied (bytes match) while
// the running master still serves the old config. Removing them keeps disk
// state honest so the next run re-applies write -> -t -> reload. The result
// is deliberately ignored: the original failure is what the operator must
// see, and a box where even rm fails needs attention anyway.
func removePHPDropIns(ctx context.Context, r bssh.Runner, ver string) {
	_, _ = r.Run(ctx, "rm -f "+shQuote(opcacheDropInPath(ver))+" "+shQuote(phpTuningDropInPath(ver)), nil)
}

// phpBlameValidateFailure assigns blame for a failed unit-wide php-fpm -t by
// difference, without parsing validator output: remove berth's two drop-ins
// (strictly — the differential is an experiment and its intervention must be
// certain, unlike the best-effort removePHPDropIns cleanup) and run -t again.
//   - Passes now  → the fault is berth's own rendered files: keep them removed
//     and fail loudly (the next run re-applies them).
//   - Still fails → the fault lives outside the drop-ins (a pool under
//     pool.d/ owned by the later site step, or a foreign file): restore the
//     drop-ins, skip start/reload/stamp and — on a full run — warn and let
//     the pipeline reach site, which re-renders its pools, validates and
//     reloads; site's markReloaded on the shared per-unit stamp blesses the
//     restored drop-ins in the same run. Under --only there is no later site
//     execution, so deferring would report Applied with no reload ever
//     happening: fail hard instead.
//
// Drop-in ini files have no include mechanism, so removing them cannot mask
// a pool-file fault (unlike nginx's sites bridge — see nginx.Apply).
func phpBlameValidateFailure(ctx context.Context, rc provision.RunCtx, r bssh.Runner, v, firstStderr string, ini, tini []byte) error {
	rm := "rm -f " + shQuote(opcacheDropInPath(v)) + " " + shQuote(phpTuningDropInPath(v))
	rmRes, err := r.Run(ctx, rm, nil)
	if err != nil {
		return err
	}
	if rmRes.ExitCode != 0 {
		return fmt.Errorf("php-fpm%s -t failed after writing drop-ins (%s) and removing them for fault isolation failed too (%s); fix the removal failure and re-run", v, firstStderr, rmRes.Stderr)
	}
	second, err := r.Run(ctx, "php-fpm"+v+" -t", nil)
	if err != nil {
		return err
	}
	if second.ExitCode == 0 {
		// The unit validates WITHOUT berth's drop-ins, so the fault is proven
		// to be berth's own rendered files — say so instead of the pool.d
		// hint, which on this path is demonstrably wrong.
		return fmt.Errorf("php-fpm%s -t failed after writing drop-ins and passes without them, so berth's own drop-ins are at fault (likely a berth bug — please report it): %s — removed them so the next run re-applies", v, firstStderr)
	}
	// The verdict quotes the SECOND run's stderr: the validator's view without
	// berth's files is what proves the fault is external.
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
		Path: opcacheDropInPath(v), Content: ini, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("restore OPcache drop-in after fault isolation: %w", err)
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
		Path: phpTuningDropInPath(v), Content: tini, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("restore PHP tuning drop-in after fault isolation: %w", err)
	}
	if !rc.FullRun {
		return fmt.Errorf("php-fpm%s -t fails even without berth's drop-ins (%s); the failing file likely lives under /etc/php/%s/fpm/pool.d/ — run a full provision (no --only) so the site step can re-render its pool files", v, second.Stderr, v)
	}
	rc.Warnf("php-fpm%s -t fails outside berth's drop-ins (validator says: %s); skipping the FPM reload — the site step will re-render its pool files, validate and reload; if the offending file is not berth-managed the run will fail there with details", v, second.Stderr)
	return nil
}

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
	changes := []string{
		"install php" + s.PHP.Version + " + extensions",
		"write production OPcache drop-in",
		"write PHP tuning drop-in (memory_limit, upload, limits)",
		"ensure " + phpLogDir,
	}
	installed, err := pkgInstalled(ctx, r, "php"+s.PHP.Version+"-fpm")
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !installed {
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
	// The FPM tuning drop-in (memory_limit, upload sizing, execution limits)
	// must be the berth-managed one and up to date.
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		return provision.CheckResult{}, err
	}
	tstate, err := checkManagedFile(ctx, r, phpTuningDropInPath(s.PHP.Version), wantTuning)
	if err != nil {
		return provision.CheckResult{}, err
	}
	tok, err := managedFileSatisfied(tstate, phpTuningDropInPath(s.PHP.Version), rc.Force)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !tok {
		return provision.CheckResult{Satisfied: false, Reason: "PHP tuning drop-in not up to date", Changes: changes}, nil
	}
	// The FPM daemon must be RUNNING: php-fpm -t validates syntax even when
	// the daemon is dead, so without this probe every step reports green
	// while the host serves 502s. Active only (not enabled) — apt enables
	// the unit at install; requiring enabled here would never converge for
	// an operator who deliberately disabled boot-start (checkTuned precedent).
	active, err := serviceActive(ctx, r, fpmService(s))
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !active {
		return provision.CheckResult{Satisfied: false, Reason: fpmService(s) + " not running", Changes: changes}, nil
	}
	// And the running master must postdate the drop-ins (write→reload crash window).
	loaded, err := reloadedSince(ctx, r, fpmService(s), opcacheDropInPath(s.PHP.Version), phpTuningDropInPath(s.PHP.Version))
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !loaded {
		return provision.CheckResult{Satisfied: false, Reason: "running " + fpmService(s) + " predates the managed drop-ins (reload pending)", Changes: changes}, nil
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
	pdo, err := pkgInstalled(ctx, r, pdoPkg)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !pdo {
		return provision.CheckResult{Satisfied: false, Reason: pdoPkg + " not installed", Changes: changes}, nil
	}
	return provision.CheckResult{Satisfied: true, Reason: "php" + s.PHP.Version + "-fpm installed; OPcache and FPM tuning in place"}, nil
}

func (php) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
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
	// Invalidate the FPM reload stamp before the package transaction, not just
	// before the drop-in writes below: apt can mutate the unit's config too
	// (conffiles, conf.d links, maintainer scripts). From here until
	// markReloaded after the successful reload/start below, a crash leaves no
	// stamp and the next run reconciles with one reload.
	if err := invalidateReloaded(ctx, r, fpmService(s)); err != nil {
		return err
	}
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
	// post-deploy via its `sudo systemctl reload php<ver>-fpm` grant (the shared
	// per-version master: a reload gracefully recycles every site's pool).
	ini, err := renderOpcache()
	if err != nil {
		return err
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
		Path: opcacheDropInPath(v), Content: ini, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write OPcache drop-in: %w", err)
	}
	// FPM tuning (memory_limit, upload sizing, execution limits; FPM SAPI only —
	// CLI keeps stock unlimited values for workers and artisan).
	tini, err := renderPHPTuning(s)
	if err != nil {
		return err
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
		Path: phpTuningDropInPath(v), Content: tini, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write PHP tuning drop-in: %w", err)
	}
	if res, err := r.Run(ctx, "php-fpm"+v+" -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		// -t validates the WHOLE unit, so the failure may live in a pool file
		// owned by the later site step; fail-fast would stop the run before
		// site could heal it. Assign blame by difference: retest without
		// berth's drop-ins, and either fail on our own files or defer the
		// reload to site (which re-renders its pools, validates and reloads —
		// its shared unit stamp then blesses the restored drop-ins too).
		return phpBlameValidateFailure(ctx, rc, r, v, res.Stderr, ini, tini)
	}
	active, err := serviceActive(ctx, r, fpmService(s))
	if err != nil {
		return err
	}
	if !active {
		// A dead FPM cannot be reloaded; start it so the drop-ins load and
		// the host stops serving 502s. `start`, NOT `enable --now`: Check is
		// active-only (enablement is apt's at install), so silently changing
		// the boot policy of a deliberately disabled unit is not this step's
		// call.
		if res, err := r.Run(ctx, "systemctl start "+fpmService(s), nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			removePHPDropIns(ctx, r, v)
			return fmt.Errorf("start %s failed (removed the drop-ins so the next run re-applies): %s", fpmService(s), res.Stderr)
		}
	} else if res, err := r.Run(ctx, "systemctl reload "+fpmService(s), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		removePHPDropIns(ctx, r, v)
		return fmt.Errorf("reload php%s-fpm failed (removed the drop-ins so the next run re-applies): %s", v, res.Stderr)
	}
	return markReloaded(ctx, r, fpmService(s))
}

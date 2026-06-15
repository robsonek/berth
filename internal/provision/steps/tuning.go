package steps

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

const (
	valkeyDropInDir   = "/etc/systemd/system/valkey-server.service.d"
	valkeyDropInPath  = valkeyDropInDir + "/berth.conf"
	mariadbUnit       = "mariadb.service"
	mariadbTuningPath = "/etc/mysql/mariadb.conf.d/99-berth.cnf"
)

type tuning struct{}

// Tuning writes managed performance-tuning drop-ins for Valkey (systemd drop-in)
// and MariaDB (mariadb.conf.d), each gated on whether that service is provisioned.
// It runs after database so both services are installed.
func Tuning() provision.Step { return tuning{} }

func (tuning) Name() string       { return "tuning" }
func (tuning) Requires() []string { return []string{"database"} }

func renderValkeyDropIn(s *config.Server) ([]byte, error) {
	return templates.Render("valkey_dropin.conf.tmpl", struct{ Maxmemory, Policy string }{
		Maxmemory: s.Tuning.ValkeyMaxmemoryEff(),
		Policy:    s.Tuning.ValkeyMaxmemoryPolicyEff(),
	})
}

func renderMariaDBTuning(s *config.Server) ([]byte, error) {
	return templates.Render("mariadb_tuning.cnf.tmpl", struct{ BufferPool string }{
		BufferPool: s.Tuning.MariaDBBufferPoolEff(),
	})
}

// serviceConfigLoaded reports whether a managed unit-affecting file at path was
// already in place at the unit's last (re)start: loaded iff the file's mtime is not
// newer than the unit's ActiveEnterTimestamp. A file newer than the last start means
// Apply wrote it but the restart has not happened yet (e.g. a crash mid-Apply), so
// the running config is stale. Read-only; an inactive unit (empty timestamp) yields
// a non-zero exit, i.e. "not loaded". Liveness keys on the file's MTIME, not its
// content, so a benign out-of-band `touch` of an otherwise up-to-date drop-in
// triggers one reconciling restart — intentional, conservative behavior.
func serviceConfigLoaded(ctx context.Context, r bssh.Runner, unit, path string) (bool, error) {
	cmd := `[ "$(stat -c %Y ` + shQuote(path) + ` 2>/dev/null)" -le "$(date -d "$(systemctl show -p ActiveEnterTimestamp --value ` + unit + `)" +%s 2>/dev/null)" ]`
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// checkTuned reports whether a managed tuning file is up to date AND loaded by its
// unit. It returns a human-readable change list when not satisfied.
func checkTuned(ctx context.Context, rc provision.RunCtx, r bssh.Runner, unit, path string, want []byte, what string) (bool, []string, error) {
	state, err := checkManagedFile(ctx, r, path, want)
	if err != nil {
		return false, nil, err
	}
	fileOK, err := managedFileSatisfied(state, path, rc.Force)
	if err != nil {
		return false, nil, err
	}
	if !fileOK {
		return false, []string{"write " + path + " (" + what + "), restart " + unit}, nil
	}
	loaded, err := serviceConfigLoaded(ctx, r, unit, path)
	if err != nil {
		return false, nil, err
	}
	if !loaded {
		return false, []string{"restart " + unit + " to load " + path}, nil
	}
	return true, nil, nil
}

func (tuning) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	var changes []string
	if s.Valkey {
		want, err := renderValkeyDropIn(s)
		if err != nil {
			return provision.CheckResult{}, err
		}
		ok, ch, err := checkTuned(ctx, rc, r, valkeyUnit, valkeyDropInPath, want, "valkey maxmemory/eviction")
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	}
	if s.Database.Engine == "mariadb" {
		want, err := renderMariaDBTuning(s)
		if err != nil {
			return provision.CheckResult{}, err
		}
		ok, ch, err := checkTuned(ctx, rc, r, mariadbUnit, mariadbTuningPath, want, "mariadb innodb_buffer_pool_size")
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	}
	if len(changes) == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "service tuning drop-ins in place and loaded"}, nil
	}
	return provision.CheckResult{Satisfied: false, Reason: "service tuning not applied", Changes: changes}, nil
}

func (tuning) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if s.Valkey {
		cfg, err := renderValkeyDropIn(s)
		if err != nil {
			return err
		}
		if res, err := r.Run(ctx, "mkdir -p "+valkeyDropInDir, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("mkdir %s: %s", valkeyDropInDir, res.Stderr)
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{Path: valkeyDropInPath, Content: cfg, Owner: "root", Group: "root", Mode: 0o644, Sudo: true}); err != nil {
			return fmt.Errorf("write %s: %w", valkeyDropInPath, err)
		}
		for _, cmd := range []string{"systemctl daemon-reload", "systemctl restart " + valkeyUnit} {
			if res, err := r.Run(ctx, cmd, nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("tuning %q: %s", cmd, res.Stderr)
			}
		}
	}
	if s.Database.Engine == "mariadb" {
		cfg, err := renderMariaDBTuning(s)
		if err != nil {
			return err
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{Path: mariadbTuningPath, Content: cfg, Owner: "root", Group: "root", Mode: 0o644, Sudo: true}); err != nil {
			return fmt.Errorf("write %s: %w", mariadbTuningPath, err)
		}
		if res, err := r.Run(ctx, "systemctl restart "+mariadbUnit, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("restart %s: %s", mariadbUnit, res.Stderr)
		}
	}
	return nil
}

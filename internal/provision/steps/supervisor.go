package steps

import (
	"context"
	"fmt"
	"sort"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

// supervisorDropInDir / supervisorOrderPath: the systemd drop-in that orders
// supervisor.service after the database and every per-site Valkey instance.
// Without it all three are only After=network.target and start in parallel
// at boot, so a workers: running program that dies within a second while
// its backend is still starting (worst after an unclean shutdown, during
// InnoDB recovery) exhausts supervisord's startretries and stays FATAL.
const (
	supervisorDropInDir = "/etc/systemd/system/supervisor.service.d"
	supervisorOrderPath = supervisorDropInDir + "/berth-after.conf"
)

// supervisorAfterUnits is the ordering the drop-in declares: the database
// unit first, then each site's Valkey instance when Valkey is on (it is
// server-wide, so every site has one), sorted so the bytes never depend on
// the order of sites in the config. Ordering only — no Wants=/Requires=, so
// a database or Valkey that fails to start never keeps supervisord down.
func supervisorAfterUnits(s *config.Server) []string {
	units := []string{config.DatabaseUnit(s.Database.Engine)}
	if s.Valkey {
		var valkeys []string
		for _, site := range s.Sites {
			valkeys = append(valkeys, valkeyInstanceUnit(site.Domain))
		}
		sort.Strings(valkeys)
		units = append(units, valkeys...)
	}
	return units
}

func renderSupervisorOrder(s *config.Server) ([]byte, error) {
	return templates.Render("supervisor_after.conf.tmpl", struct{ After []string }{supervisorAfterUnits(s)})
}

type supervisor struct{}

func Supervisor() provision.Step { return supervisor{} }

func (supervisor) Name() string       { return "supervisor" }
func (supervisor) Requires() []string { return []string{"base"} }

func (supervisor) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	installed, err := pkgInstalled(ctx, r, "supervisor")
	if err != nil {
		return provision.CheckResult{}, err
	}
	up, err := serviceUp(ctx, r, "supervisor")
	if err != nil {
		return provision.CheckResult{}, err
	}
	orderReason, orderChange, err := checkSupervisorOrder(ctx, rc, s, r)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if installed && up && orderReason == "" {
		return provision.CheckResult{Satisfied: true, Reason: "supervisor installed and running"}, nil
	}
	reason := orderReason
	var changes []string
	if !installed || !up {
		reason = "supervisor not installed or not running"
		changes = append(changes, "install supervisor", "systemctl enable --now supervisor")
	}
	if orderChange != "" {
		changes = append(changes, orderChange)
	}
	return provision.CheckResult{Satisfied: false, Reason: reason, Changes: changes}, nil
}

// checkSupervisorOrder classifies the ordering drop-in: "" when converged,
// otherwise the reason and the planned change. It is ONE read-only probe of
// the path either way (ruling R17). With a site running workers the path is
// berth's to write, under the managed-file policy (a foreign file refuses
// unless --force). With none, only a berth-managed drop-in is drift — a file
// there that berth did not write is never touched, not even with --force.
func checkSupervisorOrder(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (reason, change string, err error) {
	if !s.AnyWorkersRunning() {
		present, err := managedFilePresent(ctx, r, supervisorOrderPath)
		if err != nil || !present {
			return "", "", err
		}
		return supervisorOrderPath + " should be removed (no site runs workers)",
			"remove " + supervisorOrderPath + " + systemctl daemon-reload", nil
	}
	want, err := renderSupervisorOrder(s)
	if err != nil {
		return "", "", err
	}
	state, err := checkManagedFile(ctx, r, supervisorOrderPath, want)
	if err != nil {
		return "", "", err
	}
	ok, err := managedFileSatisfied(state, supervisorOrderPath, rc.Force)
	if err != nil || ok {
		return "", "", err
	}
	return supervisorOrderPath + " not up to date",
		"write " + supervisorOrderPath + " (start supervisord after the database and Valkey) + systemctl daemon-reload", nil
}

func (supervisor) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if err := apt.New(r).EnsurePackages(ctx, nil, "supervisor"); err != nil {
		return fmt.Errorf("install supervisor: %w", err)
	}
	// Before enable --now, so the unit systemd starts already carries the
	// final ordering (and systemctl has no changed-on-disk unit to warn about).
	if err := applySupervisorOrder(ctx, rc, s, r); err != nil {
		return err
	}
	if res, err := r.Run(ctx, "systemctl enable --now supervisor", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("enable supervisor: %s", res.Stderr)
	}
	return nil
}

// applySupervisorOrder converges the ordering drop-in: written (and systemd
// reloaded) only when its bytes change, removed (and reloaded) when no site
// runs workers and the file is berth's. A crash between the write and the
// daemon-reload is harmless for the property the file exists for: systemd
// reads every unit file from disk at boot, which is when the ordering acts.
// The drop-in directory is left in place after a removal — an empty
// supervisor.service.d is inert, and another drop-in may live there.
func applySupervisorOrder(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if !s.AnyWorkersRunning() {
		present, err := managedFilePresent(ctx, r, supervisorOrderPath)
		if err != nil || !present {
			return err
		}
		if err := runOK(ctx, r, "rm -f "+shQuote(supervisorOrderPath)); err != nil {
			return err
		}
		return supervisorDaemonReload(ctx, r)
	}
	want, err := renderSupervisorOrder(s)
	if err != nil {
		return err
	}
	prior, exists, err := readManagedForWrite(ctx, r, rc.Force, supervisorOrderPath)
	if err != nil {
		return err
	}
	if exists && prior == string(want) {
		return nil
	}
	if err := runOK(ctx, r, "install -d -o root -g root -m 0755 "+shQuote(supervisorDropInDir)); err != nil {
		return err
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: supervisorOrderPath, Content: want, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", supervisorOrderPath, err)
	}
	return supervisorDaemonReload(ctx, r)
}

func supervisorDaemonReload(ctx context.Context, r bssh.Runner) error {
	if res, err := r.Run(ctx, "systemctl daemon-reload", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("daemon-reload after %s: %s", supervisorOrderPath, res.Stderr)
	}
	return nil
}

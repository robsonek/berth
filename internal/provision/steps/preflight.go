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

// AlwaysRun marks preflight as a re-apply-every-run step (it refreshes apt and
// re-checks the OS), so it reports Satisfied:false by design and the `--only`
// dependency gate does not treat that as a missing prerequisite.
func (preflight) AlwaysRun() bool { return true }

func (preflight) Check(ctx context.Context, rc provision.RunCtx, _ *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	res, err := r.Run(ctx, ". /etc/os-release && echo $VERSION_CODENAME", nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	codename := strings.TrimSpace(res.Stdout)
	if codename != "trixie" {
		return provision.CheckResult{}, fmt.Errorf("unsupported OS: VERSION_CODENAME=%q, berth requires Debian 13 (trixie)", codename)
	}
	// The lock-timeout drop-in carries the managed marker, so it obeys the
	// standard drift policy like every other managed file: a FOREIGN file at
	// its path aborts unless --force (preflight is always-run, so without this
	// gate even `--only identity` would clobber it), drift/absence is part of
	// this step's always-unsatisfied plan.
	state, err := checkManagedFile(ctx, r, aptLockTimeoutPath, []byte(aptLockTimeoutBody))
	if err != nil {
		return provision.CheckResult{}, err
	}
	if _, err := managedFileSatisfied(state, aptLockTimeoutPath, rc.Force); err != nil {
		return provision.CheckResult{}, err
	}
	changes := []string{"apt-get update"}
	if state != fileUpToDate {
		changes = append(changes, "write "+aptLockTimeoutPath)
	}
	// Preflight always "acts" (apt update) but reports satisfied=false so Apply runs once per run.
	return provision.CheckResult{Satisfied: false, Reason: "Debian 13 detected", Changes: changes}, nil
}

// aptLockTimeoutPath/Body make every apt operation wait for the dpkg lock (up to
// 10 min) instead of failing immediately. A freshly booted VPS runs apt-daily /
// unattended-upgrades, which holds the lock and would otherwise race berth's
// installs ("Could not get lock /var/lib/dpkg/lock-frontend"). The leading
// managed marker is safe in apt.conf: a line starting with `#` is a comment
// unless it is the `#include`/`#clear` directive.
const (
	aptLockTimeoutPath = "/etc/apt/apt.conf.d/99-berth-lock-timeout"
	aptLockTimeoutBody = managedMarker + "\n" + `DPkg::Lock::Timeout "600";` + "\n"
)

func (preflight) Apply(ctx context.Context, rc provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	// Confirm sudo works before anything else.
	if res, err := r.Run(ctx, "sudo -n true", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("preflight \"sudo -n true\": %s", res.Stderr)
	}
	// Install the dpkg-lock-wait config BEFORE the first apt call, so even this
	// apt-get update (and every later install) tolerates a boot-time apt-daily
	// run. Written via the managed-file path: a foreign file here is refused
	// unless Force (which the engine scopes to the --only target).
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
		Path: aptLockTimeoutPath, Content: []byte(aptLockTimeoutBody),
		Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write apt lock-timeout config: %w", err)
	}
	if res, err := r.Run(ctx, "sudo DEBIAN_FRONTEND=noninteractive apt-get update -y", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("preflight \"apt-get update\": %s", res.Stderr)
	}
	return nil
}

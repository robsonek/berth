package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// stubTrixie stubs the OS-release probe every preflight Check starts with.
func stubTrixie(f *bssh.FakeRunner) {
	f.On(". /etc/os-release && echo $VERSION_CODENAME", bssh.Result{Stdout: "trixie\n"})
}

// lockTimeoutCatCmd is the managed-file read probe for the apt lock-timeout
// drop-in (both checkManagedFile and writeManagedFile's guard issue it).
func lockTimeoutCatCmd() string { return "cat " + shQuote(aptLockTimeoutPath) }

func TestPreflightRejectsNonTrixie(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(". /etc/os-release && echo $VERSION_CODENAME", bssh.Result{Stdout: "bookworm\n"})
	_, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil {
		t.Fatal("expected rejection of non-trixie")
	}
}

func TestPreflightAcceptsTrixie(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubTrixie(f)
	f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1}) // drop-in absent (fresh host)
	cr, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("trixie should pass and report not-yet-satisfied; got cr=%+v err=%v", cr, err)
	}
	// The absent drop-in is part of the plan (what dry-run prints).
	if !strings.Contains(strings.Join(cr.Changes, "\n"), aptLockTimeoutPath) {
		t.Errorf("Changes = %q, want the lock-timeout write planned", cr.Changes)
	}
	if len(f.Writes()) != 0 {
		t.Error("Check must not write anything (dry-run runs Check only)")
	}
}

func TestPreflightCheckRefusesForeignLockTimeout(t *testing.T) {
	// The drop-in carries the managed marker, so it obeys the standard drift
	// policy: a FOREIGN file at its path aborts unless --force. Preflight is
	// always-run, so without this gate even `--only identity` would clobber
	// an operator's own apt tuning.
	f := bssh.NewFakeRunner()
	stubTrixie(f)
	f.On(lockTimeoutCatCmd(), bssh.Result{Stdout: `DPkg::Lock::Timeout "60";` + "\n"})
	_, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("foreign drop-in must abort without --force; got %v", err)
	}
}

func TestPreflightCheckForceOverwritesForeignLockTimeout(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubTrixie(f)
	f.On(lockTimeoutCatCmd(), bssh.Result{Stdout: `DPkg::Lock::Timeout "60";` + "\n"})
	cr, err := Preflight().Check(context.Background(), provision.RunCtx{Force: true}, &config.Server{}, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("forced Check = %+v err=%v, want unsatisfied without error", cr, err)
	}
	if !strings.Contains(strings.Join(cr.Changes, "\n"), aptLockTimeoutPath) {
		t.Errorf("Changes = %q, want the forced overwrite planned", cr.Changes)
	}
}

func TestPreflightCheckPlansDriftRewrite(t *testing.T) {
	// A berth-managed drop-in with stale content (e.g. an older timeout value)
	// is drift: rewritten without --force, and visible in the plan.
	f := bssh.NewFakeRunner()
	stubTrixie(f)
	f.On(lockTimeoutCatCmd(), bssh.Result{Stdout: managedMarker + "\n" + `DPkg::Lock::Timeout "120";` + "\n"})
	cr, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("Check = %+v err=%v, want unsatisfied without error", cr, err)
	}
	if !strings.Contains(strings.Join(cr.Changes, "\n"), aptLockTimeoutPath) {
		t.Errorf("Changes = %q, want the drift rewrite planned", cr.Changes)
	}
}

func TestPreflightCheckUpToDateOmitsWriteFromPlan(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubTrixie(f)
	f.On(lockTimeoutCatCmd(), bssh.Result{Stdout: aptLockTimeoutBody})
	cr, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("Check = %+v err=%v, want unsatisfied (always-run) without error", cr, err)
	}
	if strings.Contains(strings.Join(cr.Changes, "\n"), aptLockTimeoutPath) {
		t.Errorf("Changes = %q, an up-to-date drop-in must not be re-planned", cr.Changes)
	}
}

func TestPreflightApplyRunsAptUpdate(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("sudo -n true", bssh.Result{})
	f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1}) // write-guard read: absent
	f.On("sudo DEBIAN_FRONTEND=noninteractive apt-get update -y", bssh.Result{})
	if err := Preflight().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	calls := f.Calls()
	if len(calls) != 3 || calls[0].Cmd != "sudo -n true" ||
		calls[1].Cmd != lockTimeoutCatCmd() ||
		calls[2].Cmd != "sudo DEBIAN_FRONTEND=noninteractive apt-get update -y" {
		t.Errorf("unexpected command sequence: %+v", calls)
	}
	// The dpkg-lock-wait config must be written before the apt-get update so a
	// boot-time apt-daily run cannot make the install steps fail on the lock.
	var wroteLockCfg bool
	for _, w := range f.Writes() {
		if w.Path == aptLockTimeoutPath {
			wroteLockCfg = true
			if string(w.Content) != aptLockTimeoutBody {
				t.Errorf("lock-timeout config body = %q, want %q", w.Content, aptLockTimeoutBody)
			}
			if w.Owner != "root" || w.Group != "root" || w.Mode != 0o644 {
				t.Errorf("lock-timeout config metadata = %s:%s %o, want root:root 644", w.Owner, w.Group, w.Mode)
			}
		}
	}
	if !wroteLockCfg {
		t.Errorf("expected %s to be written", aptLockTimeoutPath)
	}
}

func TestPreflightApplyRefusesForeignLockTimeoutWithoutForce(t *testing.T) {
	// Check's per-run classification is not enough on its own: the write path
	// must enforce the same policy (writeManagedFile), so a foreign file that
	// appears between Check and Apply is still refused — and apt-get update
	// never runs after the refusal.
	f := bssh.NewFakeRunner()
	f.On("sudo -n true", bssh.Result{})
	f.On(lockTimeoutCatCmd(), bssh.Result{Stdout: `DPkg::Lock::Timeout "60";` + "\n"})
	err := Preflight().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("Apply must refuse a foreign drop-in without --force; got %v", err)
	}
	if len(f.Writes()) != 0 {
		t.Error("the refused Apply must not write the drop-in")
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "apt-get update") {
			t.Error("apt-get update must not run after the refusal")
		}
	}
}

func TestPreflightApplyForceOverwritesForeignLockTimeout(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("sudo -n true", bssh.Result{})
	f.On(lockTimeoutCatCmd(), bssh.Result{Stdout: `DPkg::Lock::Timeout "60";` + "\n"})
	f.On("sudo DEBIAN_FRONTEND=noninteractive apt-get update -y", bssh.Result{})
	if err := Preflight().Apply(context.Background(), provision.RunCtx{Force: true}, &config.Server{}, f); err != nil {
		t.Fatalf("forced Apply error = %v", err)
	}
	if len(f.Writes()) != 1 || f.Writes()[0].Path != aptLockTimeoutPath {
		t.Errorf("forced Apply must overwrite the drop-in; writes = %+v", f.Writes())
	}
}

package steps

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/version/versiontest"
)

// stubTrixie stubs the OS-release probe every preflight Check starts with.
func stubTrixie(f *bssh.FakeRunner) {
	f.On(osReleaseCodenameCmd, bssh.Result{Stdout: "VERSION_CODENAME=trixie\n"})
}

// lockTimeoutCatCmd is the managed-file read probe for the apt lock-timeout
// drop-in (both checkManagedFile and writeManagedFile's guard issue it).
func lockTimeoutCatCmd() string { return "cat " + shQuote(aptLockTimeoutPath) }

func TestPreflightRejectsNonTrixie(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(osReleaseCodenameCmd, bssh.Result{Stdout: "VERSION_CODENAME=bookworm\n"})
	_, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	// Match the message, not just non-nil: a bare err check once passed
	// vacuously on FakeRunner's unstubbed-command error.
	if err == nil || !strings.Contains(err.Error(), "unsupported OS") {
		t.Fatalf("expected the unsupported-OS rejection of bookworm; got %v", err)
	}
}

// A missing VERSION_CODENAME line (grep exit 1, empty stdout) must land in the
// same unsupported-OS rejection the sourcing form gave for an unset variable,
// not a new error path.
func TestPreflightRejectsMissingCodenameLine(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(osReleaseCodenameCmd, bssh.Result{ExitCode: 1})
	_, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), "unsupported OS") {
		t.Fatalf("expected the unsupported-OS rejection on a missing codename line; got %v", err)
	}
}

// os-release permits a quoted value (VERSION_CODENAME="trixie"); the parser
// must strip that layer itself now that no shell evaluates the assignment.
func TestPreflightAcceptsQuotedCodename(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(osReleaseCodenameCmd, bssh.Result{Stdout: "VERSION_CODENAME=\"trixie\"\n"})
	f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
	cr, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("quoted trixie should pass; got cr=%+v err=%v", cr, err)
	}
}

// A tampered os-release must be read as DATA. The old form sourced the file, so
// a substitution in it executed as root during a read-only check.
func TestPreflightReadsOSReleaseAsData(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubTrixie(f)
	f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
	if _, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Check: %v", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, ". ") || strings.Contains(c.Cmd, "&& echo $") {
			t.Errorf("preflight still sources a file: %q", c.Cmd)
		}
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

// aptUpdateCmd is the apt-get update preflight.Apply runs last.
const aptUpdateCmd = "sudo DEBIAN_FRONTEND=noninteractive apt-get update -y"

// floorInstallDirCmd creates /var/lib/berth before the floor is written.
const floorInstallDirCmd = "install -d -o root -g root -m 0755 /var/lib/berth"

// touchedFloor reports whether any recorded command mentions the floor file.
func touchedFloor(f *bssh.FakeRunner) bool {
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "version-floor") {
			return true
		}
	}
	return false
}

func TestPreflightCheckPlansFloorRecord(t *testing.T) {
	versiontest.Set(t, "0.37.0")
	f := bssh.NewFakeRunner()
	stubTrixie(f)
	f.On(versionFloorTestCmd, bssh.Result{ExitCode: 1})
	f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
	cr, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("Check = %+v err=%v, want unsatisfied without error", cr, err)
	}
	want := "record version floor v0.37.0 in /var/lib/berth/version-floor"
	if len(cr.Changes) == 0 || cr.Changes[0] != want {
		t.Errorf("Changes = %q, want %q first", cr.Changes, want)
	}
	if len(f.Writes()) != 0 {
		t.Error("Check must not write the floor (dry-run and status run Check only)")
	}
}

func TestPreflightCheckRefusesDowngradeEvenWithForce(t *testing.T) {
	versiontest.Set(t, "0.37.0")
	stub := func() *bssh.FakeRunner {
		f := bssh.NewFakeRunner()
		stubTrixie(f)
		f.On(versionFloorTestCmd, bssh.Result{})
		f.On(versionFloorCatCmd, bssh.Result{Stdout: "VERSION=v0.38.0\n"})
		f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
		return f
	}
	want := "host was last changed by berth v0.38.0, this binary is v0.37.0 — use v0.38.0 or newer; to roll back deliberately, re-run `berth provision` with --allow-downgrade"
	for _, rc := range []provision.RunCtx{{}, {Force: true}} {
		f := stub()
		_, err := Preflight().Check(context.Background(), rc, &config.Server{}, f)
		if err == nil || err.Error() != want {
			t.Errorf("Check(Force=%v) err = %v, want %q", rc.Force, err, want)
		}
		// The downgrade stop wins over every other refusal: the apt drop-in
		// is never even classified.
		if callIndex(f, lockTimeoutCatCmd()) >= 0 {
			t.Errorf("Check(Force=%v) classified the apt drop-in; the downgrade stop must come first", rc.Force)
		}
	}
	f := stub()
	cr, err := Preflight().Check(context.Background(), provision.RunCtx{AllowDowngrade: true}, &config.Server{}, f)
	if err != nil {
		t.Fatalf("Check(AllowDowngrade) err = %v", err)
	}
	if !slices.Contains(cr.Changes, "lower version floor v0.38.0 → v0.37.0 (--allow-downgrade)") {
		t.Errorf("Changes = %q, want the lowered floor planned", cr.Changes)
	}
}

func TestPreflightCheckFloorReadFailureIsNotAbsence(t *testing.T) {
	versiontest.Set(t, "0.37.0")
	f := bssh.NewFakeRunner()
	stubTrixie(f)
	f.On(versionFloorTestCmd, bssh.Result{})
	f.On(versionFloorCatCmd, bssh.Result{ExitCode: 1, Stderr: "Permission denied"})
	f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
	_, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), "unreadable or malformed") {
		t.Fatalf("a present but unreadable floor must refuse, never read as absent; got %v", err)
	}
}

func TestPreflightCheckDevBuildSkipsFloor(t *testing.T) {
	versiontest.Set(t, "dev")
	f := bssh.NewFakeRunner()
	stubTrixie(f)
	f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
	if _, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if touchedFloor(f) {
		t.Errorf("a development build probed the floor: %+v", f.Calls())
	}
}

func TestPreflightApplyWritesFloorFirst(t *testing.T) {
	versiontest.Set(t, "0.37.0")
	f := bssh.NewFakeRunner()
	f.On("sudo -n true", bssh.Result{})
	f.On(versionFloorTestCmd, bssh.Result{ExitCode: 1})
	f.On(floorInstallDirCmd, bssh.Result{})
	f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
	f.On(aptUpdateCmd, bssh.Result{})
	if err := Preflight().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	w := f.Writes()
	if len(w) != 2 {
		t.Fatalf("writes = %+v, want the floor then the apt drop-in", w)
	}
	if w[0].Path != versionFloorPath || string(w[0].Content) != "# managed by berth\nVERSION=v0.37.0\n" ||
		w[0].Owner != "root" || w[0].Group != "root" || w[0].Mode != 0o644 {
		t.Errorf("first write = %s %q %s:%s %o, want %s root:root 644", w[0].Path, w[0].Content, w[0].Owner, w[0].Group, w[0].Mode, versionFloorPath)
	}
	if w[1].Path != aptLockTimeoutPath {
		t.Errorf("second write = %s, want %s", w[1].Path, aptLockTimeoutPath)
	}
	// The floor is the host's first change: after sudo is proven, before apt.
	if sudo, dir, apt := callIndex(f, "sudo -n true"), callIndex(f, floorInstallDirCmd), callIndex(f, aptUpdateCmd); sudo != 0 || dir < 0 || apt < 0 || dir > apt {
		t.Errorf("call order sudo=%d install-dir=%d apt-get=%d, want sudo first and the floor dir before apt-get update: %+v", sudo, dir, apt, f.Calls())
	}
}

func TestPreflightApplyEqualFloorWritesNothing(t *testing.T) {
	versiontest.Set(t, "v0.37.0")
	f := bssh.NewFakeRunner()
	f.On("sudo -n true", bssh.Result{})
	f.On(versionFloorTestCmd, bssh.Result{})
	f.On(versionFloorCatCmd, bssh.Result{Stdout: "VERSION=0.37.0\n"})
	f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
	f.On(aptUpdateCmd, bssh.Result{})
	if err := Preflight().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if w := f.Writes(); len(w) != 1 || w[0].Path != aptLockTimeoutPath {
		t.Errorf("writes = %+v, want only the apt drop-in (an equal floor is never rewritten)", w)
	}
}

func TestPreflightApplyRefusesDowngradeEvenWithForce(t *testing.T) {
	versiontest.Set(t, "0.37.0")
	for _, rc := range []provision.RunCtx{{}, {Force: true}} {
		f := bssh.NewFakeRunner()
		f.On("sudo -n true", bssh.Result{})
		f.On(versionFloorTestCmd, bssh.Result{})
		f.On(versionFloorCatCmd, bssh.Result{Stdout: "VERSION=v0.38.0\n"})
		f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
		f.On(aptUpdateCmd, bssh.Result{})
		err := Preflight().Apply(context.Background(), rc, &config.Server{}, f)
		if err == nil || !strings.Contains(err.Error(), "host was last changed by berth v0.38.0, this binary is v0.37.0") {
			t.Errorf("Apply(Force=%v) must refuse the downgrade itself, not trust Check; got %v", rc.Force, err)
		}
		if len(f.Writes()) != 0 {
			t.Errorf("the refused Apply(Force=%v) wrote %+v", rc.Force, f.Writes())
		}
		if callIndex(f, aptUpdateCmd) >= 0 {
			t.Errorf("apt-get update ran after the refusal (Force=%v)", rc.Force)
		}
	}
}

func TestPreflightApplyDevBuildWarns(t *testing.T) {
	versiontest.Set(t, "dev")
	var warns []string
	rc := provision.RunCtx{Warn: func(m string) { warns = append(warns, m) }}
	f := bssh.NewFakeRunner()
	f.On("sudo -n true", bssh.Result{})
	f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
	f.On(aptUpdateCmd, bssh.Result{})
	if err := Preflight().Apply(context.Background(), rc, &config.Server{}, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "development build (dev): host version floor neither checked nor recorded") {
		t.Errorf("warnings = %q, want exactly the development-build notice", warns)
	}
	if touchedFloor(f) {
		t.Errorf("a development build touched the floor: %+v", f.Calls())
	}
}

// Every row of the verdict table through BOTH Check and Apply: Apply re-reads
// the floor itself, so it must reach Check's verdict without Check's help.
func TestPreflightFloorVerdictInCheckAndApply(t *testing.T) {
	versiontest.Set(t, "0.37.0")
	present, absent := bssh.Result{}, bssh.Result{ExitCode: 1}
	newer := bssh.Result{Stdout: "VERSION=v0.38.0\n"}
	junk := bssh.Result{Stdout: "junk\n"}
	denied := bssh.Result{ExitCode: 1, Stderr: "Permission denied"}
	cases := []struct {
		name      string
		test, cat bssh.Result
		allow     bool
		change    string // the floor line Check plans first; "" = none
		errSub    string // the refusal Check AND Apply give
		writes    bool   // Apply writes the floor
	}{
		{"absent", absent, bssh.Result{}, false, "record version floor v0.37.0 in /var/lib/berth/version-floor", "", true},
		{"older", present, bssh.Result{Stdout: managedMarker + "\nVERSION=v0.36.0\n"}, false, "raise version floor v0.36.0 → v0.37.0", "", true},
		{"equal", present, bssh.Result{Stdout: managedMarker + "\nVERSION=v0.37.0\n"}, false, "", "", false},
		{"newer", present, newer, false, "", "host was last changed by berth v0.38.0", false},
		{"newer-allowed", present, newer, true, "lower version floor v0.38.0 → v0.37.0 (--allow-downgrade)", "", true},
		{"malformed", present, junk, false, "", "unreadable or malformed", false},
		{"malformed-allowed", present, junk, true, "rewrite version floor as v0.37.0 (--allow-downgrade)", "", true},
		{"unreadable", present, denied, false, "", "unreadable or malformed (Permission denied", false},
		{"unreadable-allowed", present, denied, true, "rewrite version floor as v0.37.0 (--allow-downgrade)", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := func() *bssh.FakeRunner {
				f := bssh.NewFakeRunner()
				stubTrixie(f)
				f.On("sudo -n true", bssh.Result{})
				f.On(versionFloorTestCmd, c.test)
				f.On(versionFloorCatCmd, c.cat)
				f.On(floorInstallDirCmd, bssh.Result{})
				f.On(lockTimeoutCatCmd(), bssh.Result{ExitCode: 1})
				f.On(aptUpdateCmd, bssh.Result{})
				return f
			}
			rc := provision.RunCtx{AllowDowngrade: c.allow}

			cr, err := Preflight().Check(context.Background(), rc, &config.Server{}, stub())
			switch {
			case c.errSub != "":
				if err == nil || !strings.Contains(err.Error(), c.errSub) {
					t.Errorf("Check err = %v, want %q", err, c.errSub)
				}
			case err != nil:
				t.Errorf("Check err = %v", err)
			case c.change != "" && (len(cr.Changes) == 0 || cr.Changes[0] != c.change):
				t.Errorf("Check Changes = %q, want %q first", cr.Changes, c.change)
			case c.change == "" && strings.Contains(strings.Join(cr.Changes, "\n"), "version floor"):
				t.Errorf("Check Changes = %q, want no floor change", cr.Changes)
			}

			f := stub()
			err = Preflight().Apply(context.Background(), rc, &config.Server{}, f)
			if c.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), c.errSub) {
					t.Errorf("Apply err = %v, want %q", err, c.errSub)
				}
			} else if err != nil {
				t.Errorf("Apply err = %v", err)
			}
			w := f.Writes()
			wrote := len(w) > 0 && w[0].Path == versionFloorPath
			if wrote != c.writes {
				t.Errorf("Apply wrote the floor = %v, want %v (writes %+v)", wrote, c.writes, w)
			}
			if wrote && string(w[0].Content) != managedMarker+"\nVERSION=v0.37.0\n" {
				t.Errorf("floor content = %q, want this binary's version", w[0].Content)
			}
		})
	}
}

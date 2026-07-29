package steps

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestParseSwapBytes(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"2G", 2 * 1024 * 1024 * 1024, false},
		{"512M", 512 * 1024 * 1024, false},
		{"1G", 1024 * 1024 * 1024, false},
		{"2g", 2 * 1024 * 1024 * 1024, false},
		{"512m", 512 * 1024 * 1024, false},
		{"0G", 0, true},
		{"2", 0, true},
		{"2GB", 0, true},
		{"", 0, true},
		{"G", 0, true},
	}
	for _, tc := range cases {
		got, err := parseSwapBytes(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseSwapBytes(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("parseSwapBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestFstabSwapState(t *testing.T) {
	const fstab = "UUID=abc / ext4 defaults 0 1\n" +
		"/swapfile none swap sw 0 0 # managed by berth\n"
	marked, foreign := fstabSwapState(fstab)
	if !marked || foreign {
		t.Errorf("marked line: marked=%v foreign=%v, want true,false", marked, foreign)
	}

	const foreignFstab = "UUID=abc / ext4 defaults 0 1\n" +
		"/swapfile none swap sw 0 0\n"
	marked, foreign = fstabSwapState(foreignFstab)
	if marked || !foreign {
		t.Errorf("foreign line: marked=%v foreign=%v, want false,true", marked, foreign)
	}

	const none = "UUID=abc / ext4 defaults 0 1\n# /swapfile none swap sw 0 0\n"
	marked, foreign = fstabSwapState(none)
	if marked || foreign {
		t.Errorf("no/commented line: marked=%v foreign=%v, want false,false", marked, foreign)
	}

	// Marker present but NOT at end-of-line -> foreign (the removal sed anchors at $,
	// so ownership must require the marker at EOL, not merely contained).
	const markerMidLine = "/swapfile none swap sw 0 0 # managed by berth tail\n"
	marked, foreign = fstabSwapState(markerMidLine)
	if marked || !foreign {
		t.Errorf("marker mid-line: marked=%v foreign=%v, want false,true", marked, foreign)
	}

	// Leading whitespace before a properly-marked line -> still owned (trimmed).
	const indented = "  /swapfile none swap sw 0 0 # managed by berth\n"
	marked, foreign = fstabSwapState(indented)
	if !marked || foreign {
		t.Errorf("indented marked line: marked=%v foreign=%v, want true,false", marked, foreign)
	}

	// Trailing whitespace AFTER the marker -> still owned (the classifier trims, and the
	// removal sed tolerates trailing whitespace before EOL so the two stay in lockstep).
	const trailingWS = "/swapfile none swap sw 0 0 # managed by berth   \n"
	marked, foreign = fstabSwapState(trailingWS)
	if !marked || foreign {
		t.Errorf("trailing-whitespace marked line: marked=%v foreign=%v, want true,false", marked, foreign)
	}
}

func TestSwapActiveErrorsOnNonZeroExit(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 1, Stderr: "swapon: not available"})
	if _, err := swapActive(context.Background(), f); err == nil {
		t.Error("expected swapActive to error when swapon --show exits non-zero")
	}
}

func TestSysctlKeysMatchTemplate(t *testing.T) {
	out, err := renderSysctl()
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range sysctlKeys {
		want := kv.Key + " = " + kv.Value
		if !strings.Contains(string(out), want) {
			t.Errorf("sysctl_berth.conf.tmpl missing %q (keep sysctlKeys in sync with the template)", want)
		}
	}
}

// swapServer builds a Server with a 2G swap enabled (the size every swap test
// pins) and sysctl off.
func swapServer() *config.Server {
	return &config.Server{System: config.System{Swap: "2G"}}
}

// stubSwapSatisfied stubs every command checkSwap issues for a converged 2G swap.
func stubSwapSatisfied(t *testing.T, f *bssh.FakeRunner, size string) {
	t.Helper()
	want, err := renderSwapSysctl()
	if err != nil {
		t.Fatal(err)
	}
	bytes := func() int64 { b, _ := parseSwapBytes(size); return b }()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(bytes, 10) + "\n"})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "10\n"})
	// sysctl is off in these swap-only tests, so the step's Check/Apply also reach the
	// sysctl-removal predicate, which reads the general drop-in. Stub it absent.
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
}

func TestSystemCheckSwapSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	stubSwapSatisfied(t, f, "2G")
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestSystemCheckSwapAbsentUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 1})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "60\n"})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when swap absent")
	}
}

func TestSystemCheckSwapSizeMismatchUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	stubSwapSatisfied(t, f, "2G")
	// Re-stub stat to report a 1G file while config wants 2G.
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(1024*1024*1024, 10) + "\n"})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when swap file size differs from config")
	}
}

func TestSystemCheckForeignSwapAbortsWithoutForce(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	// A foreign /swapfile: fstab line without the berth marker, file present.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(1024*1024*1024, 10) + "\n"})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // reached only on the --force pass (sysctl off)
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer(), f)
	if err == nil {
		t.Error("expected abort error on foreign /swapfile without --force")
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied on foreign /swapfile")
	}
	// With --force: unsatisfied (overwrite pending) but no error.
	cr, err = System().Check(context.Background(), provision.RunCtx{Force: true}, swapServer(), f)
	if err != nil {
		t.Errorf("unexpected error with --force: %v", err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied (overwrite pending) with --force")
	}
}

func TestSystemCheckSwapDisabledNoArtifactsSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied no-op when nothing enabled and no artifacts; got %+v", cr)
	}
}

func TestSystemCheckSwapDisabledButPresentUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied: a berth-marked swap lingers while swap is off")
	}
}

func TestSystemCheckSysctlSatisfied(t *testing.T) {
	want, _ := renderSysctl()
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	for _, kv := range sysctlKeys {
		f.On("sysctl -n "+kv.Key, bssh.Result{ExitCode: 0, Stdout: kv.Value + "\n"})
	}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{System: config.System{Sysctl: true}}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestSystemCheckSysctlStaleValueUnsatisfied(t *testing.T) {
	want, _ := renderSysctl()
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	// File up-to-date but the first key's running value is stale.
	f.On("sysctl -n net.core.somaxconn", bssh.Result{ExitCode: 0, Stdout: "128\n"})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{System: config.System{Sysctl: true}}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when running sysctl value is stale")
	}
}

// captureSwappinessCmd is the no-clobber pre-berth state write applySwap
// issues before its first drop-in write.
func captureSwappinessCmd(val string) string {
	return "install -d -o root -g root -m 0755 /var/lib/berth && { set -C; printf '%s\n' " + val + " > " + swappinessStatePath + "; } 2>/dev/null || [ -s " + swappinessStatePath + " ]"
}

func TestSystemApplySwapCreates(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	// checkSwap pre-check sees nothing present (fresh box).
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 1})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "60\n"})
	f.On(captureSwappinessCmd("60"), bssh.Result{})
	// create path commands.
	f.On("fallocate -l 2G /swapfile", bssh.Result{})
	f.On("chmod 600 /swapfile", bssh.Result{})
	f.On("mkswap /swapfile", bssh.Result{})
	f.On("swapon /swapfile", bssh.Result{})
	f.On("printf '\\n%s\\n' '/swapfile none swap sw 0 0 # managed by berth' >> /etc/fstab", bssh.Result{})
	f.On("sed -i '\\|^[[:space:]]*/swapfile[[:space:]]|d' /etc/fstab", bssh.Result{})
	f.On("sysctl -p /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)

	if err := System().Apply(context.Background(), provision.RunCtx{}, swapServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, want := range []string{"fallocate -l 2G /swapfile", "mkswap /swapfile", "swapon /swapfile",
		"printf '\\n%s\\n' '/swapfile none swap sw 0 0 # managed by berth' >> /etc/fstab",
		"sysctl -p /etc/sysctl.d/99-berth-swap.conf"} {
		if !calledCmd(f, want) {
			t.Errorf("Apply did not run %q", want)
		}
	}
	if !wrotePath(f, swapSysctlPath) {
		t.Error("swappiness drop-in not written")
	}
	// Order: fallocate < mkswap < swapon.
	if !(cmdIndex(f, "fallocate -l 2G /swapfile") < cmdIndex(f, "mkswap /swapfile") &&
		cmdIndex(f, "mkswap /swapfile") < cmdIndex(f, "swapon /swapfile")) {
		t.Error("wrong create order; want fallocate < mkswap < swapon")
	}
}

func TestSystemApplySwapNoopWhenSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	stubSwapSatisfied(t, f, "2G")
	if err := System().Apply(context.Background(), provision.RunCtx{}, swapServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if calledCmd(f, "fallocate -l 2G /swapfile") || len(f.Writes()) != 0 {
		t.Errorf("expected no mutation when already satisfied; calls=%v writes=%v", f.Calls(), f.Writes())
	}
}

func TestSystemApplySwapResizeRecreates(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	// Marked + active + correct fstab + swappiness loaded, but the file is 1G vs 2G.
	want, _ := renderSwapSysctl()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(1024*1024*1024, 10) + "\n"})
	// Active in checkSwap and again in swapoffIfActive, then empty after the rebuild so
	// swapon re-enables — proves the resized swap is actually turned back on.
	f.OnSeq("swapon --show=NAME --noheadings",
		bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"},
		bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"},
		bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "10\n"})
	// resize path.
	f.On("swapoff /swapfile", bssh.Result{})
	f.On("rm -f /swapfile", bssh.Result{})
	f.On("fallocate -l 2G /swapfile", bssh.Result{})
	f.On("chmod 600 /swapfile", bssh.Result{})
	f.On("mkswap /swapfile", bssh.Result{})
	f.On("swapon /swapfile", bssh.Result{})
	f.On("sysctl -p /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})   // applySwap always rewrites the swappiness drop-in
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)

	if err := System().Apply(context.Background(), provision.RunCtx{}, swapServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !(cmdIndex(f, "swapoff /swapfile") < cmdIndex(f, "rm -f /swapfile") &&
		cmdIndex(f, "rm -f /swapfile") < cmdIndex(f, "fallocate -l 2G /swapfile")) {
		t.Error("resize must swapoff + rm before recreating at the new size")
	}
	if !calledCmd(f, "swapon /swapfile") {
		t.Error("resize must re-enable the swap (swapon) after rebuilding")
	}
}

func TestSystemApplySwapRemovalTargetsMarkedLineOnly(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	// Swap off, but a berth-marked swap lingers.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 0, Stdout: "# managed by berth\nvm.swappiness = 10\n"})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"}) // swapoffIfActive sees it active
	f.On("swapoff /swapfile", bssh.Result{})
	f.On("sed -i '\\|^[[:space:]]*/swapfile[[:space:]].*# managed by berth[[:space:]]*$|d' /etc/fstab", bssh.Result{})
	f.On("rm -f /swapfile", bssh.Result{})
	f.On("rm -f /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)

	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, want := range []string{"swapoff /swapfile",
		"sed -i '\\|^[[:space:]]*/swapfile[[:space:]].*# managed by berth[[:space:]]*$|d' /etc/fstab",
		"rm -f /swapfile", "rm -f /etc/sysctl.d/99-berth-swap.conf"} {
		if !calledCmd(f, want) {
			t.Errorf("removal did not run %q", want)
		}
	}
}

func TestSystemApplySwapRemovalSkipsForeign(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	// Swap off; a FOREIGN /swapfile line (no marker) and no berth drop-in: leave it.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if calledCmd(f, "rm -f /swapfile") || calledCmd(f, "swapoff /swapfile") {
		t.Error("must not touch a foreign /swapfile on removal")
	}
}

func TestSystemApplySwapoffFailureAborts(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	// swap off; a berth-marked ACTIVE swap, but swapoff fails (e.g. ENOMEM). Apply must
	// abort BEFORE rm -f, never removing a file backing a still-active swap.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"})
	f.On("swapoff /swapfile", bssh.Result{ExitCode: 1, Stderr: "swapoff: Cannot allocate memory"})
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err == nil {
		t.Fatal("expected Apply to abort when an active swapoff fails")
	}
	if calledCmd(f, "rm -f /swapfile") {
		t.Error("must NOT rm /swapfile after a failed active swapoff")
	}
}

func TestSystemApplySwapForceTakeoverSameSize(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	// A foreign 2G /swapfile (no marker). --force must REBUILD it (mkswap) and normalize
	// fstab, not merely swapon a possibly-non-swap file.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(2*1024*1024*1024, 10) + "\n"})
	// checkSwap returns at the conflict guard (no swapActive there), so only 2 reads:
	// swapoffIfActive (active) then post-rebuild (empty).
	f.OnSeq("swapon --show=NAME --noheadings",
		bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"},
		bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("swapoff /swapfile", bssh.Result{})
	f.On("rm -f /swapfile", bssh.Result{})
	f.On("fallocate -l 2G /swapfile", bssh.Result{})
	f.On("chmod 600 /swapfile", bssh.Result{})
	f.On("mkswap /swapfile", bssh.Result{})
	f.On("swapon /swapfile", bssh.Result{})
	f.On("sed -i '\\|^[[:space:]]*/swapfile[[:space:]]|d' /etc/fstab", bssh.Result{})
	f.On("printf '\\n%s\\n' '/swapfile none swap sw 0 0 # managed by berth' >> /etc/fstab", bssh.Result{})
	// pre-berth capture window: drop-in not yet managed, state absent -> record live 60.
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "60\n"})
	f.On(captureSwappinessCmd("60"), bssh.Result{})
	f.On("sysctl -p /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)
	srv := &config.Server{System: config.System{Swap: "2G"}}
	if err := System().Apply(context.Background(), provision.RunCtx{Force: true}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, "mkswap /swapfile") {
		t.Error("--force takeover must rebuild the swap (mkswap), not trust the existing file")
	}
	if !calledCmd(f, "sed -i '\\|^[[:space:]]*/swapfile[[:space:]]|d' /etc/fstab") {
		t.Error("--force takeover must normalize fstab (delete the foreign line)")
	}
}

func TestSystemApplySysctlEnables(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	// swap is off, so Apply first runs the swap-removal predicate (a no-op here).
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // absent
	f.On("sysctl --system", bssh.Result{})
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{System: config.System{Sysctl: true}}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !wrotePath(f, sysctlPath) {
		t.Error("general sysctl drop-in not written")
	}
	if !calledCmd(f, "sysctl --system") {
		t.Error("sysctl --system not run")
	}
}

func TestSystemApplySysctlRemoval(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	// sysctl off; the general drop-in is berth-managed -> remove.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 0, Stdout: "# managed by berth\nnet.core.somaxconn = 4096\n"})
	f.On("rm -f /etc/sysctl.d/99-berth.conf", bssh.Result{})
	f.On("sysctl --system", bssh.Result{})
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, "rm -f /etc/sysctl.d/99-berth.conf") {
		t.Error("expected the general drop-in removed")
	}
}

func TestSystemCheckTimezoneMismatchUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Etc/UTC\n"})
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the host zone differs from system.timezone")
	}
}

func TestSystemCheckTimezoneMatchSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Europe/Warsaw\n"}) // trailing \n trimmed
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when the host zone matches; got %+v", cr)
	}
}

func TestSystemTimezoneUnsetNeverProbed(t *testing.T) {
	// Empty knob = berth never touches (or even reads) the zone on EITHER
	// path: an unstubbed timedatectl would error the FakeRunner, so Check
	// succeeding AND Apply succeeding proves neither made the call.
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied no-op; got %+v", cr)
	}
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "timedatectl") {
			t.Errorf("unset timezone must not run timedatectl; ran %q", c.Cmd)
		}
	}
}

func TestSystemApplyTimezoneSetsAndRestartsCron(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Etc/UTC\n"})
	f.On("timedatectl set-timezone 'Europe/Warsaw'", bssh.Result{})
	// ensureCron pre-check: cron already active+enabled -> no install.
	f.On("systemctl is-active cron", bssh.Result{})
	f.On("systemctl is-enabled cron", bssh.Result{})
	f.On("systemctl restart cron", bssh.Result{})
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	// Exactly ONE set and ONE cron restart, in that order (counts, not just
	// presence — duplicate calls must fail this).
	var set, cron int
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "timedatectl set-timezone 'Europe/Warsaw'":
			set++
		case "systemctl restart cron":
			if set == 0 {
				t.Error("cron restart must come AFTER set-timezone")
			}
			cron++
		}
	}
	if set != 1 || cron != 1 {
		t.Errorf("want exactly one set-timezone and one cron restart; got %d and %d", set, cron)
	}
}

func TestSystemApplyTimezoneInstallsCronWhenAbsent(t *testing.T) {
	// The system step runs early in the pipeline (backups — berth's only other
	// cron installer — runs near the end), so on a cron-less image applyTimezone
	// must install+enable cron itself before restarting it, or the step fails on
	// every run even when the same config would install cron later.
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Etc/UTC\n"})
	f.On("timedatectl set-timezone 'Europe/Warsaw'", bssh.Result{})
	// ensureCron pre-check: the unit does not exist -> install + enable.
	f.On("systemctl is-active cron", bssh.Result{ExitCode: 4, Stderr: "inactive"})
	f.On("systemctl is-enabled cron", bssh.Result{ExitCode: 1})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y cron", bssh.Result{})
	f.On("systemctl enable --now cron", bssh.Result{})
	f.On("systemctl restart cron", bssh.Result{})
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	install := cmdIndex(f, "DEBIAN_FRONTEND=noninteractive apt-get install -y cron")
	enable := cmdIndex(f, "systemctl enable --now cron")
	restart := cmdIndex(f, "systemctl restart cron")
	if install < 0 || enable < 0 || restart < 0 {
		t.Fatalf("missing cron install/enable/restart; calls=%v", f.Calls())
	}
	if !(install < restart && enable < restart) {
		t.Errorf("cron must be installed (idx %d) and enabled (idx %d) BEFORE the restart (idx %d)", install, enable, restart)
	}
}

func TestSystemApplyTimezoneSetFailureAborts(t *testing.T) {
	// A failed set-timezone surfaces as the step error with NO cron restart
	// and NO revert (nothing changed): both commands are unstubbed, so any
	// attempt to run them errors the FakeRunner with a different message.
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Etc/UTC\n"})
	f.On("timedatectl set-timezone 'Europe/Warsaw'", bssh.Result{ExitCode: 1, Stderr: "Failed to set time zone"})
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	err := System().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "set-timezone") {
		t.Fatalf("err = %v, want the set-timezone failure", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl restart cron" || c.Cmd == "timedatectl set-timezone 'Etc/UTC'" {
			t.Errorf("failed set must not restart cron or revert; ran %q", c.Cmd)
		}
	}
}

func TestSystemApplyTimezoneNoopWhenSatisfied(t *testing.T) {
	// Re-entrant like applySwap/applySysctl: a matching zone must neither
	// set-timezone nor restart cron (unstubbed commands would error).
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Europe/Warsaw\n"})
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl restart cron" || strings.Contains(c.Cmd, "set-timezone") {
			t.Errorf("satisfied timezone must be a no-op; ran %q", c.Cmd)
		}
	}
}

func TestSystemApplyTimezoneCronFailureRevertsZone(t *testing.T) {
	// A failed cron restart must surface as the step error AND best-effort
	// revert the zone: leaving the new zone in place would make the next
	// run's Check falsely Satisfied while cron still fires on the old
	// zone's schedule (the php step's compensation precedent).
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Etc/UTC\n"})
	f.On("timedatectl set-timezone 'Europe/Warsaw'", bssh.Result{})
	// ensureCron pre-check: cron already active+enabled -> no install.
	f.On("systemctl is-active cron", bssh.Result{})
	f.On("systemctl is-enabled cron", bssh.Result{})
	f.On("systemctl restart cron", bssh.Result{ExitCode: 1, Stderr: "boom"})
	f.On("timedatectl set-timezone 'Etc/UTC'", bssh.Result{}) // the revert
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	err := System().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "reverted") {
		t.Fatalf("err = %v, want the cron failure naming the revert", err)
	}
	var reverted bool
	for _, c := range f.Calls() {
		if c.Cmd == "timedatectl set-timezone 'Etc/UTC'" {
			reverted = true
		}
	}
	if !reverted {
		t.Error("Apply must revert to the previous zone after a failed cron restart")
	}
}

func TestSystemApplyTimezoneCronAndRevertFailureIsHonest(t *testing.T) {
	// When the revert ALSO fails, the error must say so — never claim a
	// revert that didn't happen (the residual falsely-Satisfied state is
	// spec-accepted, but only with an honest message pointing at cron).
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Etc/UTC\n"})
	f.On("timedatectl set-timezone 'Europe/Warsaw'", bssh.Result{})
	// ensureCron pre-check: cron already active+enabled -> no install.
	f.On("systemctl is-active cron", bssh.Result{})
	f.On("systemctl is-enabled cron", bssh.Result{})
	f.On("systemctl restart cron", bssh.Result{ExitCode: 1, Stderr: "boom"})
	f.On("timedatectl set-timezone 'Etc/UTC'", bssh.Result{ExitCode: 1, Stderr: "busy"})
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	err := System().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "revert to Etc/UTC failed") {
		t.Fatalf("err = %v, want the double-failure message naming the failed revert", err)
	}
	if !strings.Contains(err.Error(), "busy") {
		t.Errorf("double-failure error must carry the revert's own stderr detail: %v", err)
	}
	if strings.Contains(err.Error(), "(reverted") {
		t.Errorf("double-failure error must not claim a successful revert: %v", err)
	}
}

func TestSystemCheckHostnameMismatchUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "debian\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.0.1 localhost\n127.0.1.1 debian\n"})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the static hostname differs from system.hostname")
	}
}

func TestSystemCheckHostnameSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "web-1.example.com\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.0.1 localhost\n127.0.1.1 web-1.example.com web-1 # managed by berth\n"})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when hostname and hosts alias match; got %+v", cr)
	}
}

func TestSystemCheckHostnameHostsLineMissingUnsatisfied(t *testing.T) {
	// Hostname already set but berth's marked alias line absent -> still work to do.
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "web-1.example.com\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.0.1 localhost\n127.0.1.1 debian\n"})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while the marked 127.0.1.1 alias line is missing")
	}
}

func TestSystemHostnameUnsetNeverProbed(t *testing.T) {
	// Empty knob = berth never reads or writes the hostname on either path.
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	if _, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatal(err)
	}
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "hostnamectl") {
			t.Errorf("unset hostname must not run hostnamectl; ran %q", c.Cmd)
		}
	}
}

func TestSystemApplyHostnameSetsAndRewritesHosts(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "debian\n"})
	f.On("hostnamectl set-hostname 'web-1.example.com'", bssh.Result{})
	// A foreign 127.0.1.1 line (the image's default alias) is replaced WITHOUT --force.
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.0.1 localhost\n127.0.1.1 debian\n"})
	f.On(`sed -i '\|^[[:space:]]*127\.0\.1\.1[[:space:]]|d' /etc/hosts`, bssh.Result{})
	f.On("printf '\\n%s\\n' '127.0.1.1 web-1.example.com web-1 # managed by berth' >> /etc/hosts", bssh.Result{})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, "hostnamectl set-hostname 'web-1.example.com'") {
		t.Error("expected hostnamectl set-hostname")
	}
	if !calledCmd(f, "printf '\\n%s\\n' '127.0.1.1 web-1.example.com web-1 # managed by berth' >> /etc/hosts") {
		t.Error("expected the marked 127.0.1.1 alias appended")
	}
}

func TestSystemApplyHostnameNoopWhenSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "web-1.example.com\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.1.1 web-1.example.com web-1 # managed by berth\n"})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "set-hostname") || strings.Contains(c.Cmd, `127\.0\.1\.1`) {
			t.Errorf("satisfied hostname must not mutate; ran %q", c.Cmd)
		}
	}
}

func TestSystemApplyHostnameShortNameNoDot(t *testing.T) {
	// A single-label hostname gets no short alias (no duplicate token).
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "debian\n"})
	f.On("hostnamectl set-hostname 'web1'", bssh.Result{})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.0.1 localhost\n"})
	f.On(`sed -i '\|^[[:space:]]*127\.0\.1\.1[[:space:]]|d' /etc/hosts`, bssh.Result{})
	f.On("printf '\\n%s\\n' '127.0.1.1 web1 # managed by berth' >> /etc/hosts", bssh.Result{})
	s := &config.Server{System: config.System{Hostname: "web1"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, "printf '\\n%s\\n' '127.0.1.1 web1 # managed by berth' >> /etc/hosts") {
		t.Error("expected the single-label alias line appended without a short duplicate")
	}
}

func TestSystemCheckHostnameForeignAliasBesideMarkedUnsatisfied(t *testing.T) {
	// The marked line alone is not enough: a stale foreign 127.0.1.1 alias
	// (e.g. re-added by another tool) would keep resolving the image's old
	// name forever if Check accepted it — the takeover must re-trigger.
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "web-1.example.com\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.1.1 debian\n127.0.1.1 web-1.example.com web-1 # managed by berth\n"})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while a foreign 127.0.1.1 alias sits beside the marked line")
	}
}

func TestSystemApplyHostnameNormalizesForeignAliasBesideMarked(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "web-1.example.com\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.1.1 debian\n127.0.1.1 web-1.example.com web-1 # managed by berth\n"})
	f.On(`sed -i '\|^[[:space:]]*127\.0\.1\.1[[:space:]]|d' /etc/hosts`, bssh.Result{})
	f.On("printf '\\n%s\\n' '127.0.1.1 web-1.example.com web-1 # managed by berth' >> /etc/hosts", bssh.Result{})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, `sed -i '\|^[[:space:]]*127\.0\.1\.1[[:space:]]|d' /etc/hosts`) {
		t.Error("expected the normalization sed when a foreign alias sits beside the marked line")
	}
}

func TestSystemCheckHostnameDuplicateMarkedLinesUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1}) // pre-berth state absent by default
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "web-1.example.com\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.1.1 web-1.example.com web-1 # managed by berth\n127.0.1.1 web-1.example.com web-1 # managed by berth\n"})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied on duplicated marked lines (Apply promises exactly one)")
	}
}

// cmdIdx returns the index of the first Call matching cmd, or -1.
func cmdIdx(f *bssh.FakeRunner, cmd string) int {
	for i, c := range f.Calls() {
		if c.Cmd == cmd {
			return i
		}
	}
	return -1
}

func TestSystemApplySwapCaptureSkippedWhenDropInAlreadyManaged(t *testing.T) {
	// Re-applies must NEVER rewrite the pre-berth state: with the drop-in
	// already berth-managed the live value is berth's own — recording it
	// would fabricate a false baseline.
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1})
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 1})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: ""})
	managed, err := renderSwapSysctl()
	if err != nil {
		t.Fatal(err)
	}
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 0, Stdout: string(managed)})
	// checkSwap's swappinessLive legitimately reads the live value; the
	// capture's distinguishing feature is the no-clobber `set -C` write.
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "10\n"})
	f.On("fallocate -l 2G /swapfile", bssh.Result{})
	f.On("chmod 600 /swapfile", bssh.Result{})
	f.On("mkswap /swapfile", bssh.Result{})
	f.On("swapon /swapfile", bssh.Result{})
	f.On("printf '\\n%s\\n' '/swapfile none swap sw 0 0 # managed by berth' >> /etc/fstab", bssh.Result{})
	f.On("sed -i '\\|^[[:space:]]*/swapfile[[:space:]]|d' /etc/fstab", bssh.Result{})
	f.On("sysctl -p /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})

	if err := System().Apply(context.Background(), provision.RunCtx{}, swapServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "set -C") {
			t.Errorf("no capture may happen when the drop-in is already managed: %q", c.Cmd)
		}
	}
}

// stubSwapRemovalArtifacts stubs a swap-off Apply where the marked fstab line
// and the managed drop-in exist; state file content is the caller's choice.
func stubSwapRemovalArtifacts(f *bssh.FakeRunner) {
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0 # managed by berth\n"})
	managed, _ := renderSwapSysctl()
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 0, Stdout: string(managed)})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("sed -i "+shQuote(fstabSedMarked)+" "+fstabPath, bssh.Result{})
	f.On("rm -f /swapfile", bssh.Result{})
	f.On("rm -f /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // general sysctl off, nothing to remove
}

func TestSystemApplySwapRemovalRestoresPreBerthSwappinessLast(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 0, Stdout: "35\n"})
	stubSwapRemovalArtifacts(f)
	f.On("sysctl --system", bssh.Result{})
	f.On("sysctl -w vm.swappiness=35", bssh.Result{})
	f.On("rm -f "+swappinessStatePath, bssh.Result{})

	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	system, restore, drop := cmdIdx(f, "sysctl --system"), cmdIdx(f, "sysctl -w vm.swappiness=35"), cmdIdx(f, "rm -f "+swappinessStatePath)
	if system < 0 || restore < 0 || drop < 0 {
		t.Fatalf("missing finalization commands: --system=%d -w=%d rm=%d\n%v", system, restore, drop, f.Calls())
	}
	// Commit order: reload persistent config FIRST (a later --system would
	// overwrite the restore), exact restore next, state dropped LAST.
	if !(system < restore && restore < drop) {
		t.Errorf("finalization order wrong: --system=%d -w=%d rm=%d", system, restore, drop)
	}
}

func TestSystemApplySwapRemovalStateOnlyConverges(t *testing.T) {
	// Interrupted removal (artifacts gone, state left): the lone state file
	// must still be restored and dropped.
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 0, Stdout: "35\n"})
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("sysctl --system", bssh.Result{})
	f.On("sysctl -w vm.swappiness=35", bssh.Result{})
	f.On("rm -f "+swappinessStatePath, bssh.Result{})

	// Check must be unsatisfied on the lone state file.
	ok, _, err := checkSwapRemoval(context.Background(), f)
	if err != nil || ok {
		t.Fatalf("checkSwapRemoval = %v, %v; want unsatisfied on a lone state file", ok, err)
	}
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if cmdIdx(f, "rm -f "+swappinessStatePath) < 0 {
		t.Error("state file must be restored and dropped")
	}
}

func TestSystemSwappinessStateInvalidIsHardErrorBeforeMutation(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 0, Stdout: "banana\n"})
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0 # managed by berth\n"})
	if _, _, err := checkSwapRemoval(context.Background(), f); err == nil {
		t.Fatal("Check must hard-error on an invalid state file")
	}
	f2 := bssh.NewFakeRunner()
	f2.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 0, Stdout: "banana\n"})
	err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f2)
	if err == nil || !strings.Contains(err.Error(), "banana") {
		t.Fatalf("Apply must hard-error naming the bad value; got %v", err)
	}
	for _, c := range f2.Calls() {
		if strings.HasPrefix(c.Cmd, "sysctl -w") || strings.HasPrefix(c.Cmd, "rm -f") || strings.HasPrefix(c.Cmd, "sed -i") {
			t.Errorf("no mutation may run with an invalid state file: %q", c.Cmd)
		}
	}
}

func TestSystemApplySwapRemovalFailuresKeepState(t *testing.T) {
	// A failed --system or a failed restore must leave the state file so the
	// next run retries the finalization.
	for _, failing := range []string{"sysctl --system", "sysctl -w vm.swappiness=35"} {
		f := bssh.NewFakeRunner()
		f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 0, Stdout: "35\n"})
		stubSwapRemovalArtifacts(f)
		f.On("sysctl --system", bssh.Result{})
		f.On("sysctl -w vm.swappiness=35", bssh.Result{})
		f.On(failing, bssh.Result{ExitCode: 1, Stderr: "boom"})
		if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err == nil {
			t.Fatalf("Apply must fail when %q fails", failing)
		}
		if cmdIdx(f, "rm -f "+swappinessStatePath) >= 0 {
			t.Errorf("state file must survive a failed %q", failing)
		}
	}
}

func TestSystemApplySwapRemovalLegacyNoStateWarns(t *testing.T) {
	// Pre-P15 install: managed drop-in removed but no recorded baseline —
	// warn (normal output), never fabricate a value.
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 1})
	stubSwapRemovalArtifacts(f)

	var warned []string
	rc := provision.RunCtx{FullRun: true, Warn: func(m string) { warned = append(warned, m) }}
	if err := System().Apply(context.Background(), rc, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "swappiness") {
		t.Fatalf("want one swappiness warning, got %q", warned)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "sysctl -w vm.swappiness=") {
			t.Errorf("no restore may run without recorded state: %q", c.Cmd)
		}
	}
}

func TestSystemApplyRestoreRunsAfterGeneralSysctlBranch(t *testing.T) {
	// Combined swap-off + general sysctl drift: the pre-berth restore must be
	// the FINAL sysctl mutation — after the general branch's own reload.
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(swappinessStatePath), bssh.Result{ExitCode: 0, Stdout: "35\n"})
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0 # managed by berth\n"})
	managed, _ := renderSwapSysctl()
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 0, Stdout: string(managed)})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("sed -i "+shQuote(fstabSedMarked)+" "+fstabPath, bssh.Result{})
	f.On("rm -f /swapfile", bssh.Result{})
	f.On("rm -f /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	// General sysctl branch ON with a drifted (absent) drop-in -> write + --system.
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("sysctl --system", bssh.Result{})
	f.On("sysctl -w vm.swappiness=35", bssh.Result{})
	f.On("rm -f "+swappinessStatePath, bssh.Result{})

	srv := &config.Server{System: config.System{Sysctl: true}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	restore := cmdIdx(f, "sysctl -w vm.swappiness=35")
	lastSystem := -1
	for i, c := range f.Calls() {
		if c.Cmd == "sysctl --system" {
			lastSystem = i
		}
	}
	if restore < 0 || lastSystem < 0 || restore < lastSystem {
		t.Errorf("restore must follow EVERY sysctl --system; restore=%d lastSystem=%d", restore, lastSystem)
	}
}

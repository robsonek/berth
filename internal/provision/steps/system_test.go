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

// swapServer builds a Server with swap enabled at the given size and sysctl off.
func swapServer(size string) *config.Server {
	return &config.Server{System: config.System{Swap: size}}
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
	stubSwapSatisfied(t, f, "2G")
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer("2G"), f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestSystemCheckSwapAbsentUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 1})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "60\n"})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer("2G"), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when swap absent")
	}
}

func TestSystemCheckSwapSizeMismatchUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubSwapSatisfied(t, f, "2G")
	// Re-stub stat to report a 1G file while config wants 2G.
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(1024*1024*1024, 10) + "\n"})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer("2G"), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when swap file size differs from config")
	}
}

func TestSystemCheckForeignSwapAbortsWithoutForce(t *testing.T) {
	f := bssh.NewFakeRunner()
	// A foreign /swapfile: fstab line without the berth marker, file present.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(1024*1024*1024, 10) + "\n"})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // reached only on the --force pass (sysctl off)
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer("2G"), f)
	if err == nil {
		t.Error("expected abort error on foreign /swapfile without --force")
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied on foreign /swapfile")
	}
	// With --force: unsatisfied (overwrite pending) but no error.
	cr, err = System().Check(context.Background(), provision.RunCtx{Force: true}, swapServer("2G"), f)
	if err != nil {
		t.Errorf("unexpected error with --force: %v", err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied (overwrite pending) with --force")
	}
}

func TestSystemCheckSwapDisabledNoArtifactsSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
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

func TestSystemApplySwapCreates(t *testing.T) {
	f := bssh.NewFakeRunner()
	// checkSwap pre-check sees nothing present (fresh box).
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 1})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "60\n"})
	// create path commands.
	f.On("fallocate -l 2G /swapfile", bssh.Result{})
	f.On("chmod 600 /swapfile", bssh.Result{})
	f.On("mkswap /swapfile", bssh.Result{})
	f.On("swapon /swapfile", bssh.Result{})
	f.On("printf '\\n%s\\n' '/swapfile none swap sw 0 0 # managed by berth' >> /etc/fstab", bssh.Result{})
	f.On("sed -i '\\|^[[:space:]]*/swapfile[[:space:]]|d' /etc/fstab", bssh.Result{})
	f.On("sysctl -p /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)

	if err := System().Apply(context.Background(), provision.RunCtx{}, swapServer("2G"), f); err != nil {
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
	stubSwapSatisfied(t, f, "2G")
	if err := System().Apply(context.Background(), provision.RunCtx{}, swapServer("2G"), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if calledCmd(f, "fallocate -l 2G /swapfile") || len(f.Writes()) != 0 {
		t.Errorf("expected no mutation when already satisfied; calls=%v writes=%v", f.Calls(), f.Writes())
	}
}

func TestSystemApplySwapResizeRecreates(t *testing.T) {
	f := bssh.NewFakeRunner()
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

	if err := System().Apply(context.Background(), provision.RunCtx{}, swapServer("2G"), f); err != nil {
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
	// Swap off, but a berth-marked swap lingers.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 0, Stdout: "# managed by berth\nvm.swappiness = 10\n"})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"}) // swapoffIfActive sees it active
	f.On("swapoff /swapfile", bssh.Result{})
	f.On("sed -i '\\|^[[:space:]]*/swapfile[[:space:]].*# managed by berth$|d' /etc/fstab", bssh.Result{})
	f.On("rm -f /swapfile", bssh.Result{})
	f.On("rm -f /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)

	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, want := range []string{"swapoff /swapfile",
		"sed -i '\\|^[[:space:]]*/swapfile[[:space:]].*# managed by berth$|d' /etc/fstab",
		"rm -f /swapfile", "rm -f /etc/sysctl.d/99-berth-swap.conf"} {
		if !calledCmd(f, want) {
			t.Errorf("removal did not run %q", want)
		}
	}
}

func TestSystemApplySwapRemovalSkipsForeign(t *testing.T) {
	f := bssh.NewFakeRunner()
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

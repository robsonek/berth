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

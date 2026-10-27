package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// stubGzipFresh makes the gzip drop-in read back absent and nginx.conf read
// back WITHOUT an active `gzip on;` (nginx.org's stock form): Check reports
// the drop-in missing, Apply's write guard passes and the render switches
// gzip on itself.
func stubGzipFresh(f *bssh.FakeRunner) {
	f.On(nginxGzipOnProbeCmd, bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(nginxGzipPath), bssh.Result{ExitCode: 1})
}

// stubGzipConverged makes the gzip drop-in read back as berth's rendered
// content for the given nginx.conf state (stockOn = nginx.conf already
// carries `gzip on;`, Debian's stock form).
func stubGzipConverged(t *testing.T, f *bssh.FakeRunner, stockOn bool) {
	t.Helper()
	want, err := renderNginxGzip(stockOn)
	if err != nil {
		t.Fatal(err)
	}
	code := 1
	if stockOn {
		code = 0
	}
	f.On(nginxGzipOnProbeCmd, bssh.Result{ExitCode: code})
	f.On("cat "+shQuote(nginxGzipPath), bssh.Result{ExitCode: 0, Stdout: string(want)})
}

func gzipOff() *config.Server {
	off := false
	return &config.Server{Nginx: config.Nginx{Gzip: &off}}
}

// stubNginxCheckConverged stubs everything nginx.Check probes on a converged
// debian-source host EXCEPT the gzip drop-in and the reload stamp.
func stubNginxCheckConverged(f *bssh.FakeRunner) {
	f.On("dpkg -s nginx", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active nginx", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled nginx", bssh.Result{ExitCode: 0})
	stubDefaultsAbsent(f)
	stubNginxRepoAbsent(f)
}

func TestNginxCheckUnsatisfiedWhenGzipDropInAbsent(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubNginxCheckConverged(f)
	stubGzipFresh(f)
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatalf("expected unsatisfied with the gzip drop-in absent; got %+v", cr)
	}
	if !strings.Contains(cr.Reason, "gzip") {
		t.Errorf("Reason must name the gzip drop-in; got %q", cr.Reason)
	}
	if !strings.Contains(strings.Join(cr.Changes, "\n"), nginxGzipPath) {
		t.Errorf("Changes must plan the gzip drop-in write; got %v", cr.Changes)
	}
}

func TestNginxCheckSatisfiedWithGzipDropIn(t *testing.T) {
	for _, stockOn := range []bool{false, true} {
		f := bssh.NewFakeRunner()
		stubNginxCheckConverged(f)
		stubGzipConverged(t, f, stockOn)
		// The drop-in joins the core config under the reload stamp.
		f.On(reloadedSinceCmd("nginx", nginxConfPath, nginxGzipPath), bssh.Result{})
		cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
		if err != nil {
			t.Fatalf("stockOn=%v: %v", stockOn, err)
		}
		if !cr.Satisfied {
			t.Errorf("stockOn=%v: expected satisfied with the rendered drop-in present; got %+v", stockOn, cr)
		}
	}
}

// The rendered drop-in depends on nginx.conf: with Debian's `gzip on;`
// already active, a drop-in that repeats the directive is a duplicate nginx
// -t rejects, so the shape WITH `gzip on;` is drift there (and vice versa).
func TestNginxCheckGzipDropInShapeFollowsStockNginxConf(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubNginxCheckConverged(f)
	withOn, err := renderNginxGzip(false) // the shape that switches gzip on itself
	if err != nil {
		t.Fatal(err)
	}
	f.On(nginxGzipOnProbeCmd, bssh.Result{ExitCode: 0}) // but nginx.conf already has it
	f.On("cat "+shQuote(nginxGzipPath), bssh.Result{ExitCode: 0, Stdout: string(withOn)})
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Errorf("a drop-in duplicating nginx.conf's gzip on; must be drift; got %+v", cr)
	}
}

// A foreign file at the drop-in path aborts unless --force, and it is the
// FIRST guard Check reaches: nothing else is stubbed, so a later placement
// would surface as an unstubbed-command error instead of the refusal.
func TestNginxCheckRefusesForeignGzipDropInFirst(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(nginxGzipOnProbeCmd, bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(nginxGzipPath), bssh.Result{ExitCode: 0, Stdout: "gzip on;\n"})
	_, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("expected the foreign-file refusal, got %v", err)
	}
	// --force downgrades the refusal to plain drift.
	f = bssh.NewFakeRunner()
	stubNginxCheckConverged(f)
	f.On(nginxGzipOnProbeCmd, bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(nginxGzipPath), bssh.Result{ExitCode: 0, Stdout: "gzip on;\n"})
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{Force: true}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Errorf("forced foreign drop-in must be unsatisfied drift; got %+v", cr)
	}
}

// gzip: false — a berth-managed drop-in is drift (Apply removes it), a
// foreign file or no file at all is converged, and nginx.conf is never
// probed (nothing to render).
func TestNginxCheckGzipOffSweepsOnlyManagedDropIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		cat  bssh.Result
		want bool
	}{
		{"managed lingers", bssh.Result{ExitCode: 0, Stdout: managedMarker + "\ngzip on;\n"}, false},
		{"foreign left alone", bssh.Result{ExitCode: 0, Stdout: "gzip on;\n"}, true},
		{"absent", bssh.Result{ExitCode: 1}, true},
	} {
		f := bssh.NewFakeRunner()
		stubNginxCheckConverged(f)
		f.On("cat "+shQuote(nginxGzipPath), tc.cat)
		f.On(reloadedSinceCmd("nginx", nginxConfPath), bssh.Result{})
		cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, gzipOff(), f)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if cr.Satisfied != tc.want {
			t.Errorf("%s: Satisfied = %v, want %v (%+v)", tc.name, cr.Satisfied, tc.want, cr)
		}
		for _, c := range f.Calls() {
			if c.Cmd == nginxGzipOnProbeCmd {
				t.Errorf("%s: gzip: false must not probe nginx.conf", tc.name)
			}
		}
	}
}

func TestNginxOwnedConfigFilesTrackGzipKnob(t *testing.T) {
	on := strings.Join(nginxOwnedConfigFiles(&config.Server{}), "\n")
	if !strings.Contains(on, nginxGzipPath) {
		t.Errorf("gzip on: the drop-in must be under the reload stamp; got %q", on)
	}
	off := strings.Join(nginxOwnedConfigFiles(gzipOff()), "\n")
	if strings.Contains(off, nginxGzipPath) {
		t.Errorf("gzip off: a removed path must not be stamp-probed; got %q", off)
	}
}

func TestNginxApplyWritesGzipDropIn(t *testing.T) {
	for _, stockOn := range []bool{false, true} {
		f := bssh.NewFakeRunner()
		f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
		f.On("systemctl enable nginx", bssh.Result{})
		stubNginxApplyTail(f)
		code := 1
		if stockOn {
			code = 0
		}
		f.On(nginxGzipOnProbeCmd, bssh.Result{ExitCode: code})
		if err := Nginx().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
			t.Fatalf("stockOn=%v: Apply() error = %v", stockOn, err)
		}
		want, err := renderNginxGzip(stockOn)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, w := range f.Writes() {
			if w.Path != nginxGzipPath {
				continue
			}
			found = true
			if string(w.Content) != string(want) {
				t.Errorf("stockOn=%v: drop-in content:\n%s\nwant:\n%s", stockOn, w.Content, want)
			}
			if w.Owner != "root" || w.Group != "root" || w.Mode != 0o644 || !w.Sudo {
				t.Errorf("stockOn=%v: drop-in must be root:root 0644 via sudo; got %+v", stockOn, w)
			}
		}
		if !found {
			t.Errorf("stockOn=%v: Apply must write %s", stockOn, nginxGzipPath)
		}
		// The nginx.conf probe must run AFTER the package install: on a fresh
		// host nginx.conf exists only once the package is unpacked.
		install, probe := -1, -1
		for i, c := range f.Calls() {
			switch c.Cmd {
			case "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx":
				install = i
			case nginxGzipOnProbeCmd:
				probe = i
			}
		}
		if install < 0 || probe < install {
			t.Errorf("stockOn=%v: the gzip probe (%d) must follow the install (%d)", stockOn, probe, install)
		}
	}
}

func TestNginxApplyGzipOffRemovesOnlyManagedDropIn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cat    bssh.Result
		wantRm bool
	}{
		{"managed", bssh.Result{ExitCode: 0, Stdout: managedMarker + "\ngzip on;\n"}, true},
		{"foreign", bssh.Result{ExitCode: 0, Stdout: "gzip on;\n"}, false},
		{"absent", bssh.Result{ExitCode: 1}, false},
	} {
		f := bssh.NewFakeRunner()
		f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
		f.On("systemctl enable nginx", bssh.Result{})
		stubNginxApplyTail(f)
		f.On("cat "+shQuote(nginxGzipPath), tc.cat)
		f.On("rm -f "+shQuote(nginxGzipPath), bssh.Result{})
		if err := Nginx().Apply(context.Background(), provision.RunCtx{Force: true}, gzipOff(), f); err != nil {
			t.Fatalf("%s: Apply() error = %v", tc.name, err)
		}
		var sawRm, sawWrite bool
		for _, c := range f.Calls() {
			if c.Cmd == "rm -f "+shQuote(nginxGzipPath) {
				sawRm = true
			}
		}
		for _, w := range f.Writes() {
			if w.Path == nginxGzipPath {
				sawWrite = true
			}
		}
		if sawRm != tc.wantRm {
			t.Errorf("%s: rm issued = %v, want %v", tc.name, sawRm, tc.wantRm)
		}
		if sawWrite {
			t.Errorf("%s: gzip: false must never write the drop-in", tc.name)
		}
	}
}

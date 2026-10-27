package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// The two stock nginx.conf shapes the drop-in adapts to: nginx.org's keeps
// gzip commented out, Debian's switches it on (tuning commented out).
const (
	nginxConfOrg    = "user  nginx;\nhttp {\n    #gzip  on;\n    include /etc/nginx/conf.d/*.conf;\n}\n"
	nginxConfDebian = "user www-data;\nhttp {\n\tgzip on;\n\n\t# gzip_vary on;\n\t# gzip_comp_level 6;\n\tinclude /etc/nginx/conf.d/*.conf;\n}\n"
)

// stubNginxConf makes nginx.conf read back with the given content.
func stubNginxConf(f *bssh.FakeRunner, conf string) {
	f.On("cat "+shQuote(nginxConfPath), bssh.Result{ExitCode: 0, Stdout: conf})
}

// stubGzipFresh makes the gzip drop-in read back absent and nginx.conf read
// back as nginx.org's stock (no active gzip directive): Check reports the
// drop-in missing, Apply's write guard passes and the render switches gzip
// on itself.
func stubGzipFresh(f *bssh.FakeRunner) {
	stubNginxConf(f, nginxConfOrg)
	f.On("cat "+shQuote(nginxGzipPath), bssh.Result{ExitCode: 1})
}

// stubGzipConverged makes the gzip drop-in read back as berth's rendered
// content for the given nginx.conf state (stockOn = Debian's stock form,
// which already carries `gzip on;`).
func stubGzipConverged(t *testing.T, f *bssh.FakeRunner, stockOn bool) {
	t.Helper()
	conf := nginxConfOrg
	if stockOn {
		conf = nginxConfDebian
	}
	shape, err := nginxGzipShapeFor(nginxHTTPDirectives(conf))
	if err != nil {
		t.Fatal(err)
	}
	want, err := renderNginxGzip(shape)
	if err != nil {
		t.Fatal(err)
	}
	stubNginxConf(f, conf)
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
	withOn, err := renderNginxGzip(nginxGzipShape{Gzip: true, Vary: true, Proxied: true, CompLevel: true, MinLength: true}) // the shape that switches gzip on itself
	if err != nil {
		t.Fatal(err)
	}
	stubNginxConf(f, nginxConfDebian) // but nginx.conf already has it
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
	stubNginxConf(f, nginxConfOrg)
	f.On("cat "+shQuote(nginxGzipPath), bssh.Result{ExitCode: 0, Stdout: "gzip on;\n"})
	_, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("expected the foreign-file refusal, got %v", err)
	}
	// --force downgrades the refusal to plain drift.
	f = bssh.NewFakeRunner()
	stubNginxCheckConverged(f)
	stubNginxConf(f, nginxConfOrg)
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
			if c.Cmd == "cat "+shQuote(nginxConfPath) {
				t.Errorf("%s: gzip: false must not read nginx.conf", tc.name)
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
		if stockOn {
			stubNginxConf(f, nginxConfDebian)
		}
		if err := Nginx().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
			t.Fatalf("stockOn=%v: Apply() error = %v", stockOn, err)
		}
		shape := nginxGzipShape{Gzip: !stockOn, Vary: true, Proxied: true, CompLevel: true, MinLength: true}
		want, err := renderNginxGzip(shape)
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
		// The nginx.conf read must run AFTER the package install: on a fresh
		// host nginx.conf exists only once the package is unpacked.
		install, probe := -1, -1
		for i, c := range f.Calls() {
			switch c.Cmd {
			case "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx":
				install = i
			case "cat " + shQuote(nginxConfPath):
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

// An operator's `gzip off;` in nginx.conf is intent berth cannot honour
// with the knob on: the drop-in could only duplicate the directive (nginx
// rejects a second `gzip` in one context whatever its value), so Check AND
// Apply refuse outright with the two ways out — not bypassable by --force.
func TestNginxCheckRefusesGzipOffInNginxConf(t *testing.T) {
	for _, force := range []bool{false, true} {
		f := bssh.NewFakeRunner()
		stubNginxConf(f, "http {\n    gzip off;\n}\n")
		_, err := Nginx().Check(context.Background(), provision.RunCtx{Force: force}, &config.Server{}, f)
		if err == nil || !strings.Contains(err.Error(), "gzip off") || !strings.Contains(err.Error(), "nginx.gzip: false") {
			t.Errorf("force=%v: want the gzip-off refusal naming nginx.gzip: false, got %v", force, err)
		}
	}
}

func TestNginxApplyRefusesGzipOffInNginxConf(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("systemctl enable nginx", bssh.Result{})
	stubNginxApplyTail(f)
	stubNginxConf(f, "http {\n\tgzip off;\n}\n")
	err := Nginx().Apply(context.Background(), provision.RunCtx{Force: true}, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), "gzip off") {
		t.Fatalf("want the gzip-off refusal, got %v", err)
	}
	for _, w := range f.Writes() {
		if w.Path == nginxGzipPath {
			t.Error("the drop-in must not be written when nginx.conf sets gzip off")
		}
	}
	for _, c := range f.Calls() {
		if c.Cmd == "nginx -t" {
			t.Error("Apply must refuse before validating — the refusal is the diagnosis, not a -t failure")
		}
	}
}

// Greptile P1 (PR #103): nginx's duplicate rule is per context, so a
// `gzip off;` inside a server block nested in nginx.conf is no conflict —
// the drop-in still switches gzip on at http level, and nothing is refused.
// Likewise nginx's permissive `gzip on ;` counts as the http-level flag.
func TestNginxGzipIgnoresNestedBlocksAndAcceptsSpacing(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubNginxCheckConverged(f)
	conf := "http {\n    server {\n        listen 80;\n        gzip off;\n    }\n}\n"
	shape, err := nginxGzipShapeFor(nginxHTTPDirectives(conf))
	if err != nil {
		t.Fatalf("nested gzip off must not refuse: %v", err)
	}
	if !shape.Gzip {
		t.Fatalf("nested gzip off must not suppress the http-level gzip on; shape %+v", shape)
	}
	want, err := renderNginxGzip(shape)
	if err != nil {
		t.Fatal(err)
	}
	stubNginxConf(f, conf)
	f.On("cat "+shQuote(nginxGzipPath), bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On(reloadedSinceCmd("nginx", nginxConfPath, nginxGzipPath), bssh.Result{})
	cr, err := Nginx().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied with a nested gzip off; got %+v", cr)
	}
	spaced, err := nginxGzipShapeFor(nginxHTTPDirectives("http {\n\tgzip on ;\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if spaced.Gzip {
		t.Errorf("`gzip on ;` must count as the http-level flag; shape %+v", spaced)
	}
}

// Greptile P1 (PR #103): tuning an operator uncommented in nginx.conf's http
// block (Debian ships `# gzip_vary on;` etc. as suggestions) must not be
// repeated by the drop-in — nginx rejects each as a duplicate — so Apply
// writes only what nginx.conf leaves unset.
func TestNginxApplyGzipDropInOmitsTuningNginxConfSets(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	f.On("systemctl enable nginx", bssh.Result{})
	stubNginxApplyTail(f)
	stubNginxConf(f, "http {\n\tgzip on;\n\tgzip_vary on;\n\tgzip_comp_level 6;\n\tgzip_types text/css;\n}\n")
	if err := Nginx().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, w := range f.Writes() {
		if w.Path != nginxGzipPath {
			continue
		}
		body := string(w.Content)
		for _, dup := range []string{"gzip on;", "gzip_vary", "gzip_comp_level"} {
			if strings.Contains(body, dup) {
				t.Errorf("drop-in repeats %q that nginx.conf already sets:\n%s", dup, body)
			}
		}
		for _, keep := range []string{"gzip_proxied any;", "gzip_min_length 256;", "gzip_types "} {
			if !strings.Contains(body, keep) {
				t.Errorf("drop-in must still carry %q:\n%s", keep, body)
			}
		}
		return
	}
	t.Fatal("Apply must write the drop-in")
}

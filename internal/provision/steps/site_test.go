package steps

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func siteServer() *config.Server {
	return &config.Server{
		Host:      "app.example.com",
		PHP:       config.PHP{Version: "8.4", Source: "auto"},
		Scheduler: true,
		Sites: []config.Site{{
			Domain:     "app.example.com",
			DeployPath: "/home/deploy/myapp",
		}},
	}
}

func TestSiteRequires(t *testing.T) {
	got := Site().Requires()
	want := []string{"php", "nginx", "appdirs", "database"}
	if len(got) != len(want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Requires() = %v, want %v", got, want)
		}
	}
}

func TestSiteApplyValidatesNginxBeforeReload(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// nginx -t must run before systemctl reload nginx.
	var idxTest, idxReload = -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "nginx -t":
			idxTest = i
		case "systemctl reload nginx":
			idxReload = i
		}
	}
	if idxTest < 0 || idxReload < 0 {
		t.Fatalf("expected both nginx -t and reload; calls=%v", f.Calls())
	}
	if idxTest > idxReload {
		t.Error("nginx -t must run before systemctl reload nginx")
	}
}

func TestSiteApplyAbortsOnNginxTestFailure(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 1, Stderr: "invalid config"})
	// systemctl reload is intentionally NOT stubbed: it must never be called.

	err := Site().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("expected Apply to abort when nginx -t fails")
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl reload nginx" {
			t.Error("reload must not run after a failed nginx -t")
		}
	}
}

func TestSiteApplyWritesManagedFiles(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	wantPaths := map[string]bool{
		"/etc/nginx/sites-available/app.example.com": false,
	}
	var supervisorBody string
	for _, w := range f.Writes() {
		if _, ok := wantPaths[w.Path]; ok {
			wantPaths[w.Path] = true
		}
		if strings.Contains(w.Path, "/etc/supervisor/conf.d/") {
			supervisorBody = string(w.Content)
		}
		if strings.HasPrefix(w.Path, "/etc/cron.d/berth-") {
			wantPaths["cron"] = true
		}
		if strings.Contains(w.Path, "fpm/pool.d/") {
			wantPaths["fpm"] = true
		}
	}
	for path, seen := range wantPaths {
		if !seen {
			t.Errorf("expected a write for %q", path)
		}
	}
	if !strings.Contains(supervisorBody, "autostart=false") {
		t.Error("supervisor program must be installed dormant (autostart=false)")
	}
}

func TestSiteCheckSatisfiedWhenFilesManagedAndNginxValid(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when managed files match and nginx -t passes; got %+v", cr)
	}
}

func TestSiteCheckUnsatisfiedWhenNginxInvalid(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 1})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when nginx -t fails")
	}
}

func TestSiteNginxIsCertAware(t *testing.T) {
	s := siteServer()
	s.Sites[0].SSL = true
	certPath := "/etc/letsencrypt/live/" + s.Sites[0].Domain + "/fullchain.pem"

	// No certificate yet: the nginx block must be HTTP-only so the ACME webroot
	// challenge can complete (never reference a cert that does not exist).
	noCert := bssh.NewFakeRunner()
	noCert.On("test -e "+shQuote(certPath), bssh.Result{ExitCode: 1})
	mfs, err := managedSiteFiles(context.Background(), noCert, s)
	if err != nil {
		t.Fatal(err)
	}
	if c := string(mfs[0].content); !strings.Contains(c, "listen 80;") || strings.Contains(c, "listen 443") {
		t.Errorf("without a cert, expected HTTP-only block; got:\n%s", c)
	}

	// Certificate present: the nginx block must be the HTTPS (443) one, so a
	// re-run does not revert the TLS step's 443 block back to HTTP.
	withCert := bssh.NewFakeRunner()
	withCert.On("test -e "+shQuote(certPath), bssh.Result{ExitCode: 0})
	mfs, err = managedSiteFiles(context.Background(), withCert, s)
	if err != nil {
		t.Fatal(err)
	}
	if c := string(mfs[0].content); !strings.Contains(c, "listen 443") {
		t.Errorf("with a cert, expected the HTTPS 443 block; got:\n%s", c)
	}
}

func TestSiteRenderHTTP3(t *testing.T) {
	// Sites are listed REVERSE-alphabetically on purpose: nginx loads
	// sites-enabled/* in lexicographic order, so reuseport must land on the
	// alphabetically-first domain (a.example.com), NOT the config-first one (b).
	s := &config.Server{
		Host:  "b.example.com",
		Nginx: config.Nginx{Source: "nginx"},
		PHP:   config.PHP{Version: "8.4"},
		Sites: []config.Site{
			{Domain: "b.example.com", DeployPath: "/var/www/b", SSL: true, HTTP3: true}, // config-first, alphabetically last
			{Domain: "a.example.com", DeployPath: "/var/www/a", SSL: true, HTTP3: true}, // config-last, alphabetically first
		},
	}
	b, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	a, err := renderNginxHTTPS(s, s.Sites[1])
	if err != nil {
		t.Fatal(err)
	}
	as, bs := string(a), string(b)
	// nginx parses a.example.com first (sorted glob), so it must own reuseport.
	if !strings.Contains(as, "listen 443 quic reuseport;") || !strings.Contains(as, "listen [::]:443 quic reuseport;") {
		t.Errorf("the alphabetically-first http3 site must own reuseport:\n%s", as)
	}
	if !strings.Contains(as, "http3 on;") || !strings.Contains(as, `add_header Alt-Svc 'h3=":443"; ma=86400' always;`) {
		t.Errorf("http3 site must enable http3 and advertise Alt-Svc:\n%s", as)
	}
	// b is config-first but alphabetically later -> plain quic, NO reuseport
	// (a later `listen 443 quic reuseport;` would make nginx -t fail).
	if !strings.Contains(bs, "listen 443 quic;") {
		t.Errorf("the later (alphabetically) http3 site must use a plain quic listener:\n%s", bs)
	}
	if strings.Contains(bs, "reuseport") {
		t.Errorf("only the alphabetically-first http3 site may use reuseport:\n%s", bs)
	}
}

func TestQUICReuseportOwner(t *testing.T) {
	// Reverse-alphabetical config order: the owner must still be the
	// alphabetically-smallest HTTP/3 domain (the block nginx parses first).
	s := &config.Server{Sites: []config.Site{
		{Domain: "z.example.com", HTTP3: true},
		{Domain: "x.example.com"}, // no http3
		{Domain: "y.example.com", HTTP3: true},
	}}
	if got := quicReuseportOwner(s); got != "y.example.com" {
		t.Errorf("quicReuseportOwner = %q, want y.example.com (alphabetically-smallest http3 domain)", got)
	}
	if !anySiteHTTP3(s) {
		t.Error("anySiteHTTP3 should be true when a site enables http3")
	}
	none := &config.Server{Sites: []config.Site{{Domain: "x.example.com"}}}
	if quicReuseportOwner(none) != "" || anySiteHTTP3(none) {
		t.Error("no http3 site -> owner empty and anySiteHTTP3 false")
	}
}

func TestNginxHTTPListensIPv6(t *testing.T) {
	s := siteServer()
	got, err := renderNginxHTTP(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "listen [::]:80;") {
		t.Errorf("nginx HTTP block must listen on IPv6 :80;\n%s", got)
	}
}

func TestNginxHTTPSRedirectListensIPv6(t *testing.T) {
	s := siteServer()
	got, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "listen [::]:80;") {
		t.Errorf("nginx HTTPS redirect block must listen on IPv6 :80;\n%s", got)
	}
}

func TestNginxHTTPSHSTSForRealCert(t *testing.T) {
	s := siteServer()
	s.Sites[0].SSL = true // CertMode() defaults to letsencrypt -> real cert -> HSTS on
	got, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `add_header Strict-Transport-Security "max-age=31536000" always;`) {
		t.Errorf("a real-cert HTTPS vhost must send HSTS;\n%s", got)
	}
}

func TestNginxHTTPSNoHSTSForSelfSigned(t *testing.T) {
	s := siteServer()
	s.Sites[0].SSL = true
	s.Sites[0].SSLMode = "selfsigned" // self-signed must NOT pin browsers via HSTS
	got, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "Strict-Transport-Security") {
		t.Errorf("a self-signed HTTPS vhost must NOT send HSTS;\n%s", got)
	}
}

func TestNginxHTTPSHasTLSTuning(t *testing.T) {
	s := siteServer()
	s.Sites[0].SSL = true
	got, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "ssl_protocols TLSv1.2 TLSv1.3;") {
		t.Errorf("HTTPS vhost must pin modern TLS protocols;\n%s", got)
	}
	if !strings.Contains(string(got), "ssl_session_tickets off;") {
		t.Errorf("HTTPS vhost must disable TLS session tickets;\n%s", got)
	}
}

func TestSiteHTTPSRenderMatchesTLSSwap(t *testing.T) {
	// site's cert-aware HTTPS render and the tls step's swap share renderNginxHTTPS,
	// so they must be byte-identical or `site` re-runs detect endless drift.
	s := siteServer()
	s.Sites[0].SSL = true
	withCert := bssh.NewFakeRunner()
	withCert.On("test -e "+shQuote(certFullchainPath(s.Sites[0])), bssh.Result{ExitCode: 0})
	siteRender, err := renderSiteNginx(context.Background(), withCert, s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	swapRender, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(siteRender) != string(swapRender) {
		t.Errorf("site cert-aware HTTPS render must equal tls swap render (byte-identical)")
	}
}

func TestSiteApplyWritesLogrotate(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var lr *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == logrotatePath {
			lr = &f.Writes()[i]
		}
	}
	if lr == nil {
		t.Fatal("logrotate fragment was not written")
	}
	if !strings.Contains(string(lr.Content), "managed by berth") || !strings.Contains(string(lr.Content), "copytruncate") {
		t.Errorf("logrotate fragment must carry the marker and use copytruncate;\n%s", lr.Content)
	}
	var validated bool
	for _, c := range f.Calls() {
		if c.Cmd == "logrotate -d "+shQuote(logrotatePath) {
			validated = true
		}
	}
	if !validated {
		t.Error("Apply must validate the logrotate fragment with `logrotate -d`")
	}
}

func TestSiteCheckUnsatisfiedWhenLogrotateMissing(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	// Override: the global logrotate fragment is absent on the host.
	f.On("cat "+shQuote(logrotatePath), bssh.Result{ExitCode: 1})
	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the global logrotate fragment is absent")
	}
}

func TestSiteApplyRemovesCronWhenSchedulerDisabled(t *testing.T) {
	s := siteServer()
	off := false
	s.Sites[0].Scheduler = &off
	cp := cronPath(s.Sites[0].Domain)

	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	// A berth-managed cron currently exists -> Apply must remove it.
	f.On("cat "+shQuote(cp), bssh.Result{Stdout: managedMarker + "\n* * * * * deploy ...\n", ExitCode: 0})
	f.On("rm -f "+shQuote(cp), bssh.Result{})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var rmSeen bool
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote(cp) {
			rmSeen = true
		}
	}
	if !rmSeen {
		t.Error("expected the disabled scheduler cron to be removed")
	}
	for _, w := range f.Writes() {
		if w.Path == cp {
			t.Error("must not write a cron when the scheduler is disabled")
		}
	}
}

func TestSiteCheckUnsatisfiedWhenDisabledCronLingers(t *testing.T) {
	s := siteServer()
	off := false
	s.Sites[0].Scheduler = &off
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	// Override: a berth-managed cron still exists at the path that should be empty.
	cp := cronPath(s.Sites[0].Domain)
	f.On("cat "+shQuote(cp), bssh.Result{Stdout: managedMarker + "\n* * * * * deploy ...\n", ExitCode: 0})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied: a disabled scheduler's cron still lingers")
	}
}

// stubManagedSiteFiles makes every managed site file read back as up-to-date so
// the Check's content-hash comparison is satisfied.
func stubManagedSiteFiles(t *testing.T, s *config.Server, f *bssh.FakeRunner) {
	t.Helper()
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatalf("managedSiteFiles: %v", err)
	}
	for _, mf := range mfs {
		f.On("cat "+shQuote(mf.path), bssh.Result{Stdout: string(mf.content)})
	}
}

// stubFPMApply stubs the commands the Apply path runs after writing the pool:
// disabling the stock www pool, validating + reloading php-fpm, and validating
// the global logrotate fragment.
func stubFPMApply(s *config.Server, f *bssh.FakeRunner) {
	f.On(fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(defaultFPMPoolPath(s))), bssh.Result{})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload "+fpmService(s), bssh.Result{})
	f.On("logrotate -d "+shQuote(logrotatePath), bssh.Result{})
}

// replayWritesAsReads seeds dst with `cat '<path>'` stubs for every file written
// during an Apply phase, last-write-wins: a Go map dedupes by path, so a later
// overwrite (e.g. the tls step swapping the vhost to the 443 block) wins. This
// models a real host where the files an earlier step wrote are what a later
// Check reads back via `cat`.
func replayWritesAsReads(dst *bssh.FakeRunner, writes []bssh.FileSpec) {
	latest := map[string][]byte{}
	for _, w := range writes {
		latest[w.Path] = w.Content
	}
	for path, content := range latest {
		dst.On("cat "+shQuote(path), bssh.Result{Stdout: string(content), ExitCode: 0})
	}
}

// TestSiteCheckSatisfiedAfterTLSSwap proves the cross-step contract end to end:
// after `site` writes the HTTP block (no cert yet) and `tls` issues a self-signed
// cert + swaps the vhost to the 443 block, a subsequent `site.Check` is satisfied
// with no further write — so the engine never re-applies `site` and never reverts
// TLS back to HTTP. Self-signed avoids any DNS/certbot dependency.
func TestSiteCheckSatisfiedAfterTLSSwap(t *testing.T) {
	s := siteServer()
	s.Sites[0].SSL = true
	s.Sites[0].SSLMode = "selfsigned"
	site := s.Sites[0]
	ctx := context.Background()

	// --- Apply phase: site.Apply then tls.Apply over one runner; cert absent. ---
	fApply := bssh.NewFakeRunner()
	fApply.On("test -e "+shQuote(certFullchainPath(site)), bssh.Result{ExitCode: 1}) // no cert yet
	// site.Apply commands:
	fApply.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	fApply.On("nginx -t", bssh.Result{ExitCode: 0})
	fApply.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, fApply)
	// tls.Apply (self-signed) commands:
	fApply.On("DEBIAN_FRONTEND=noninteractive apt-get install -y openssl", bssh.Result{})
	fApply.On("install -d -m 0755 "+shQuote(certDir(site)), bssh.Result{})
	openssl := fmt.Sprintf("openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout %s -out %s -subj %s -addext %s",
		shQuote(certKeyPath(site)), shQuote(certFullchainPath(site)),
		shQuote("/CN="+site.Domain), shQuote("subjectAltName=DNS:"+site.Domain))
	fApply.On(openssl, bssh.Result{})
	fApply.On("chmod 600 "+shQuote(certKeyPath(site)), bssh.Result{})

	if err := Site().Apply(ctx, provision.RunCtx{}, s, fApply); err != nil {
		t.Fatalf("site.Apply: %v", err)
	}
	if err := TLS().Apply(ctx, provision.RunCtx{}, s, fApply); err != nil {
		t.Fatalf("tls.Apply: %v", err)
	}

	// --- Check phase: fresh runner seeded from what Apply wrote; cert now present. ---
	fCheck := bssh.NewFakeRunner()
	replayWritesAsReads(fCheck, fApply.Writes())
	fCheck.On("test -e "+shQuote(certFullchainPath(site)), bssh.Result{ExitCode: 0})
	fCheck.On("nginx -t", bssh.Result{ExitCode: 0})
	fCheck.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})

	cr, err := Site().Check(ctx, provision.RunCtx{}, s, fCheck)
	if err != nil {
		t.Fatalf("site.Check after tls swap: %v", err)
	}
	if !cr.Satisfied {
		t.Errorf("site.Check must be satisfied after the tls swap (no drift); got %+v", cr)
	}
	if n := len(fCheck.Writes()); n != 0 {
		t.Errorf("site.Check must be side-effect-free; got %d writes", n)
	}
}

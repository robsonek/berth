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
	f.On("cat "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 1}) // step-0 cloudflare snippet absent
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
	s.Queue = true // queue enabled so a worker program (autostart=false) is written
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
	noCert.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
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
	withCert.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
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

func TestNginxGuardWhenCloudflareOnly(t *testing.T) {
	s := siteServer()
	tru := true
	s.Sites[0].CloudflareOnly = &tru
	s.Sites[0].SSL = true
	guard := "if ($berth_cloudflare = 0) { return 444; }"

	http, err := renderNginxHTTP(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(http), guard) != 2 {
		t.Errorf("HTTP block must guard location / and the php location:\n%s", http)
	}

	https, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	hs := string(https)
	if strings.Count(hs, guard) != 3 {
		t.Errorf("HTTPS must guard the 80 redirect /, the 443 /, and the php location:\n%s", hs)
	}
	// ACME must stay reachable so Let's Encrypt HTTP-01 still works: NO ACME block
	// (port-80 OR 443) may contain the guard. Scan every occurrence, panic-safe.
	const acmeLoc = "location /.well-known/acme-challenge/"
	for rest := hs; ; {
		i := strings.Index(rest, acmeLoc)
		if i == -1 {
			break
		}
		block := rest[i:]
		if end := strings.Index(block, "}"); end != -1 {
			block = block[:end]
		}
		if strings.Contains(block, "$berth_cloudflare") {
			t.Error("the ACME challenge location must NOT be guarded")
		}
		rest = rest[i+len(acmeLoc):]
	}
}

func TestNginxNoGuardWhenNotCloudflareOnly(t *testing.T) {
	s := siteServer() // cloudflare_only unset -> false
	http, err := renderNginxHTTP(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(http), "$berth_cloudflare") {
		t.Errorf("no guard expected when cloudflare_only is off:\n%s", http)
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
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatalf("managedSiteFiles: %v", err)
	}
	for _, mf := range mfs {
		f.On("cat "+shQuote(mf.path), bssh.Result{Stdout: string(mf.content)})
	}
}

// stubFPMApply stubs the commands the Apply path runs after writing the pool:
// disabling the stock www pool, validating + reloading php-fpm, validating the
// global logrotate fragment, and refreshing supervisord (reread/update) so a
// queue/daemon site's programs load. The supervisor verbs are stubbed
// unconditionally; they fire only when NeedsSupervisor (or an orphan was removed
// on a host that has supervisor), so non-supervisor Apply tests leave them unused.
// It also stubs the step-0 Cloudflare-snippet probe (cat -> absent), which every
// Apply success path now hits via managedFilePresent when cloudflare_only is off.
func stubFPMApply(s *config.Server, f *bssh.FakeRunner) {
	f.On(fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(defaultFPMPoolPath(s))), bssh.Result{})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload "+fpmService(s), bssh.Result{})
	f.On("logrotate -d "+shQuote(logrotatePath), bssh.Result{})
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
	f.On("supervisorctl reread", bssh.Result{})
	f.On("supervisorctl update", bssh.Result{})
	f.On("cat "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 1}) // step-0 cloudflare snippet absent
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
	fCheck.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
	fCheck.On("cat "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 1}) // cloudflare snippet absent (off), remove-entry satisfied

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

func TestManagedSiteFilesEnumeratesWorkerAndDaemons(t *testing.T) {
	s := siteServer()
	s.Queue = true
	s.Sites[0].Daemons = []config.Daemon{{Name: "reverb", Command: "php artisan reverb:start"}}
	f := bssh.NewFakeRunner()
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: ""})
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	var sawWorker, sawDaemon bool
	for _, mf := range mfs {
		if mf.path == "/etc/supervisor/conf.d/berth-app_example_com.conf" && !mf.remove {
			sawWorker = true
		}
		if mf.path == "/etc/supervisor/conf.d/berth-app_example_com-reverb.conf" && !mf.remove {
			sawDaemon = true
		}
	}
	if !sawWorker || !sawDaemon {
		t.Errorf("expected worker + daemon program files; worker=%v daemon=%v", sawWorker, sawDaemon)
	}
}

func TestManagedSiteFilesNoWorkerWhenQueueDisabled(t *testing.T) {
	s := siteServer() // Server.Queue false, no site.Queue -> QueueEnabled false
	s.Queue = false
	f := bssh.NewFakeRunner()
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: ""})
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.path == "/etc/supervisor/conf.d/berth-app_example_com.conf" && !mf.remove {
			t.Error("no worker program expected when queue disabled")
		}
	}
}

func TestManagedSiteFilesFlagsOrphanProgram(t *testing.T) {
	s := siteServer()
	s.Queue = true // worker berth-app_example_com is desired; berth-app_example_com-old is NOT
	f := bssh.NewFakeRunner()
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{ExitCode: 0,
		Stdout: "/etc/supervisor/conf.d/berth-app_example_com.conf\n/etc/supervisor/conf.d/berth-app_example_com-old.conf\n"})
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	var sawOrphanRemove bool
	for _, mf := range mfs {
		if mf.path == "/etc/supervisor/conf.d/berth-app_example_com-old.conf" && mf.remove {
			sawOrphanRemove = true
		}
		if mf.path == "/etc/supervisor/conf.d/berth-app_example_com.conf" && mf.remove {
			t.Error("the desired worker must NOT be flagged for removal")
		}
	}
	if !sawOrphanRemove {
		t.Error("an undesired berth-*.conf program file must be flagged for removal")
	}
}

func TestManagedSiteFilesIncludesCloudflareConf(t *testing.T) {
	s := siteServer()
	tru := true
	s.Sites[0].CloudflareOnly = &tru
	f := bssh.NewFakeRunner()
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, mf := range mfs {
		if mf.path == cloudflareConfPath {
			found = true
			if mf.remove {
				t.Error("cloudflare conf should be present (content), not marked for removal")
			}
			if !strings.Contains(string(mf.content), "geo $realip_remote_addr $berth_cloudflare {") {
				t.Errorf("cloudflare conf content missing geo block:\n%s", mf.content)
			}
		}
	}
	if !found {
		t.Errorf("managedSiteFiles must include %s when a site is cloudflare_only", cloudflareConfPath)
	}
}

func TestManagedSiteFilesRemovesCloudflareConfWhenDisabled(t *testing.T) {
	s := siteServer() // cloudflare_only off
	f := bssh.NewFakeRunner()
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.path == cloudflareConfPath {
			if !mf.remove {
				t.Error("cloudflare conf should be marked for removal when no site is cloudflare_only")
			}
			return
		}
	}
	t.Errorf("managedSiteFiles must include a remove entry for %s when disabled", cloudflareConfPath)
}

func TestSiteApplyWritesCloudflareConfWhenEnabled(t *testing.T) {
	s := siteServer()
	tru := true
	s.Sites[0].CloudflareOnly = &tru
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var wrote bool
	for _, w := range f.Writes() {
		if w.Path == cloudflareConfPath {
			wrote = true
			if !strings.Contains(string(w.Content), "geo $realip_remote_addr $berth_cloudflare {") {
				t.Errorf("cloudflare conf write missing geo block:\n%s", w.Content)
			}
		}
	}
	if !wrote {
		t.Errorf("Apply must write %s when a site is cloudflare_only", cloudflareConfPath)
	}
	// NOTE: FakeRunner records WriteFile (Writes) and Run (Calls) in separate logs,
	// so the "snippet written before the first nginx -t" ordering cannot be asserted
	// here — it is guaranteed structurally by step 0 being the first action in Apply
	// (see Task 4 Step 7) and is covered by code review, not this test.
}

func TestSiteApplyRemovesCloudflareConfWhenDisabled(t *testing.T) {
	s := siteServer() // cloudflare_only off
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	// A lingering berth-managed snippet is present -> Apply must rm it.
	f.On("cat "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 0, Stdout: "# managed by berth\nold\n"})
	f.On("rm -f "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 0})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	// The rm must run AFTER the vhosts are rewritten (unguarded) and nginx reloaded,
	// so the $berth_cloudflare geo always outlives the last vhost that referenced it
	// — a partial failure mid-Apply must never leave a guarded vhost without its geo.
	idxReload, idxRemove := -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "systemctl reload nginx":
			idxReload = i
		case "rm -f " + shQuote(cloudflareConfPath):
			idxRemove = i
		}
	}
	if idxRemove < 0 {
		t.Fatal("Apply must rm the lingering berth-managed cloudflare conf when disabled")
	}
	if idxReload < 0 || idxRemove < idxReload {
		t.Errorf("rm of the cloudflare snippet (idx %d) must run AFTER systemctl reload nginx (idx %d)", idxRemove, idxReload)
	}
}

// An unmanaged (foreign) berth-cloudflare.conf must abort Check without --force,
// even when an earlier-drifting guarded vhost would otherwise short-circuit the
// managed-site-files loop before the snippet's unmanaged-conflict check ran. We
// force that short-circuit by making the per-site vhost read back as drifted
// (managed marker, different content) — the realistic case on a disable->enable
// transition where the vhost just gained the guard.
func TestSiteCheckAbortsOnUnmanagedCloudflareConf(t *testing.T) {
	s := siteServer()
	tru := true
	s.Sites[0].CloudflareOnly = &tru
	vhost := nginxAvailablePath(s.Sites[0].Domain)
	drifted := bssh.Result{ExitCode: 0, Stdout: "# managed by berth\nserver { listen 80; } # stale\n"}
	foreign := bssh.Result{ExitCode: 0, Stdout: "server { listen 80; }\n"} // no berth marker

	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f) // stubs cat for all managed files (incl. cloudflare, with the marker)
	// The vhost drifts FIRST in the loop; the snippet is the LAST entry. Without the
	// unconditional pre-check, the loop returns at the vhost and never reaches the
	// snippet's unmanaged-conflict check.
	f.On("cat "+shQuote(vhost), drifted)
	// Override: the snippet exists but is FOREIGN (no berth marker).
	f.On("cat "+shQuote(cloudflareConfPath), foreign)
	_, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("Check must error on an unmanaged berth-cloudflare.conf (no --force)")
	}
	// And with Force it must NOT error on that account.
	f2 := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f2)
	f2.On("cat "+shQuote(vhost), drifted)
	f2.On("cat "+shQuote(cloudflareConfPath), foreign)
	f2.On("nginx -t", bssh.Result{ExitCode: 0})
	f2.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	cr, err := Site().Check(context.Background(), provision.RunCtx{Force: true}, s, f2)
	if err != nil {
		t.Fatalf("with --force, Check must not abort on the unmanaged snippet: %v", err)
	}
	// With force, the unmanaged snippet no longer aborts; the drifted vhost still
	// makes Check unsatisfied (it will be reconciled by Apply).
	if cr.Satisfied {
		t.Error("a drifted vhost must leave Check unsatisfied (reconciled by Apply)")
	}
}

func TestSiteApplyWritesDaemonAndRemovesOrphan(t *testing.T) {
	s := siteServer()
	s.Queue = true
	s.Sites[0].Daemons = []config.Daemon{{Name: "reverb", Command: "php artisan reverb:start"}}
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	// One orphan program file exists on the host and must be removed.
	orphan := "/etc/supervisor/conf.d/berth-app_example_com-old.conf"
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{ExitCode: 0,
		Stdout: "/etc/supervisor/conf.d/berth-app_example_com.conf\n/etc/supervisor/conf.d/berth-app_example_com-reverb.conf\n" + orphan + "\n"})
	f.On("cat "+shQuote(orphan), bssh.Result{ExitCode: 0, Stdout: managedMarker + "\n[program:berth-app_example_com-old]\n"})
	f.On("rm -f "+shQuote(orphan), bssh.Result{})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var wroteDaemon, removedOrphan bool
	for _, w := range f.Writes() {
		if w.Path == "/etc/supervisor/conf.d/berth-app_example_com-reverb.conf" && strings.Contains(string(w.Content), "reverb:start") {
			wroteDaemon = true
		}
	}
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote(orphan) {
			removedOrphan = true
		}
	}
	if !wroteDaemon {
		t.Error("expected the reverb daemon program file to be written")
	}
	if !removedOrphan {
		t.Error("expected the orphan program file to be removed")
	}
}

func TestQueueCommandDefaultByteIdentical(t *testing.T) {
	s := siteServer()
	s.Queue = true
	got := queueCommand(s, s.Sites[0])
	want := "php /home/deploy/myapp/current/artisan queue:work --sleep=3 --tries=3 --max-time=3600"
	if got != want {
		t.Errorf("default queue command must be byte-identical to today\n got: %s\nwant: %s", got, want)
	}
}

func TestQueueCommandTuned(t *testing.T) {
	s := siteServer()
	s.Sites[0].Queue = &config.QueueConfig{Processes: 2, Connection: "redis", Queue: "emails", Tries: 5, Timeout: 90, MaxMemory: 128}
	got := queueCommand(s, s.Sites[0])
	want := "php /home/deploy/myapp/current/artisan queue:work redis --queue=emails --sleep=3 --tries=5 --max-time=3600 --timeout=90 --memory=128"
	if got != want {
		t.Errorf("tuned queue command wrong\n got: %s\nwant: %s", got, want)
	}
}

func TestQueueCommandHorizon(t *testing.T) {
	s := siteServer()
	s.Sites[0].Queue = &config.QueueConfig{Driver: "horizon"}
	got := queueCommand(s, s.Sites[0])
	want := "php /home/deploy/myapp/current/artisan horizon"
	if got != want {
		t.Errorf("horizon command wrong: %s", got)
	}
}

// TestSiteApplyRereadsAndUpdatesSupervisor proves a queue site's Apply registers
// its program set with the running supervisord (reread THEN update) — otherwise
// the conf is on disk but never loaded and the deployer's restart hits "no such
// process". update does not start an autostart=false program, so it stays dormant.
func TestSiteApplyRereadsAndUpdatesSupervisor(t *testing.T) {
	s := siteServer()
	s.Queue = true // a worker program exists -> supervisord must be told to load it
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idxReread, idxUpdate := -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "supervisorctl reread":
			idxReread = i
		case "supervisorctl update":
			idxUpdate = i
		}
	}
	if idxReread < 0 || idxUpdate < 0 {
		t.Fatalf("expected supervisorctl reread + update; calls=%v", f.Calls())
	}
	if idxReread > idxUpdate {
		t.Error("supervisorctl reread must run before supervisorctl update")
	}
}

// TestSiteApplyReloadsSupervisorAfterOrphanRemovalWithoutQueue covers the
// disabled-queue path: NeedsSupervisor is false, but a stale berth-managed
// program lingers from a prior config. Removing the conf is not enough —
// supervisord still has it loaded — so Apply must reread/update to unload it,
// gated on supervisor actually being present.
func TestSiteApplyReloadsSupervisorAfterOrphanRemovalWithoutQueue(t *testing.T) {
	s := siteServer() // no queue, no daemons -> NeedsSupervisor false
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	// A stale managed program lingers from a prior queue config and must be unloaded.
	orphan := "/etc/supervisor/conf.d/berth-app_example_com.conf"
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{Stdout: orphan + "\n"})
	f.On("cat "+shQuote(orphan), bssh.Result{ExitCode: 0, Stdout: managedMarker + "\n[program:berth-app_example_com]\n"})
	f.On("rm -f "+shQuote(orphan), bssh.Result{})
	// supervisord is present, so the orphan removal must be followed by reread/update.
	f.On("systemctl is-active supervisor", bssh.Result{ExitCode: 0, Stdout: "active\n"})
	f.On("systemctl is-enabled supervisor", bssh.Result{ExitCode: 0, Stdout: "enabled\n"})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var sawReread, sawUpdate bool
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "supervisorctl reread":
			sawReread = true
		case "supervisorctl update":
			sawUpdate = true
		}
	}
	if !sawReread || !sawUpdate {
		t.Errorf("orphan removal on a supervisor host must refresh supervisord; reread=%v update=%v", sawReread, sawUpdate)
	}
}

// TestSiteApplyNoSupervisorReloadWhenNotNeeded pins the negative gate: a site
// with no queue/daemons and no orphan to remove must NOT touch supervisord, so a
// regression that always reloaded would be caught (the stubs make reread/update
// available but they must stay uncalled).
func TestSiteApplyNoSupervisorReloadWhenNotNeeded(t *testing.T) {
	s := siteServer() // no queue, no daemons -> NeedsSupervisor false
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f) // ls returns empty -> no orphan removed

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "supervisorctl reread" || c.Cmd == "supervisorctl update" {
			t.Errorf("must not refresh supervisord when no program is desired and none removed; saw %q", c.Cmd)
		}
	}
}

// TestSiteApplyOrphanReloadSkippedWhenSupervisorAbsent pins the safety guard on
// the orphan-unload path: when supervisord is not present (serviceUp false), the
// stale conf is still removed but supervisorctl is NOT invoked.
func TestSiteApplyOrphanReloadSkippedWhenSupervisorAbsent(t *testing.T) {
	s := siteServer() // no queue -> NeedsSupervisor false; reload only via removedOrphan
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	orphan := "/etc/supervisor/conf.d/berth-app_example_com.conf"
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{Stdout: orphan + "\n"})
	f.On("cat "+shQuote(orphan), bssh.Result{ExitCode: 0, Stdout: managedMarker + "\n[program:berth-app_example_com]\n"})
	f.On("rm -f "+shQuote(orphan), bssh.Result{})
	// supervisord is absent: both probes report non-zero (serviceUp => false).
	f.On("systemctl is-active supervisor", bssh.Result{ExitCode: 3, Stdout: "inactive\n"})
	f.On("systemctl is-enabled supervisor", bssh.Result{ExitCode: 1, Stdout: "disabled\n"})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var rmSeen bool
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote(orphan) {
			rmSeen = true
		}
		if c.Cmd == "supervisorctl reread" || c.Cmd == "supervisorctl update" {
			t.Errorf("must not invoke supervisorctl when supervisord is absent; saw %q", c.Cmd)
		}
	}
	if !rmSeen {
		t.Error("the stale orphan conf must still be removed even when supervisord is absent")
	}
}

// TestSiteApplyOrphanReloadPropagatesServiceUpError proves the orphan-unload
// path surfaces a transport failure from the supervisor probe rather than
// swallowing it (a non-zero exit means "absent" and is fine; a Go error is not).
func TestSiteApplyOrphanReloadPropagatesServiceUpError(t *testing.T) {
	s := siteServer() // no queue -> reload only via removedOrphan
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	orphan := "/etc/supervisor/conf.d/berth-app_example_com.conf"
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{Stdout: orphan + "\n"})
	f.On("cat "+shQuote(orphan), bssh.Result{ExitCode: 0, Stdout: managedMarker + "\n[program:berth-app_example_com]\n"})
	f.On("rm -f "+shQuote(orphan), bssh.Result{})
	// The probe itself fails at the transport layer -> Apply must not hide it.
	f.OnError("systemctl is-active supervisor", fmt.Errorf("ssh: connection lost"))

	err := Site().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("expected Apply to propagate the serviceUp transport error, got nil")
	}
	if !strings.Contains(err.Error(), "connection lost") {
		t.Errorf("expected the transport error to surface; got %v", err)
	}
}

// TestSiteCheckUnsatisfiedWhenSupervisorProgramNotLoaded proves Check is
// convergent for a box whose worker conf is on disk but was never loaded into
// supervisord (the real bug the live run found): status reports "no such group",
// so Check must flag drift -> Apply reread/updates it.
func TestSiteCheckUnsatisfiedWhenSupervisorProgramNotLoaded(t *testing.T) {
	s := siteServer()
	s.Queue = true
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	// The worker conf is on disk but supervisord never loaded it. The glob is
	// shell-quoted (so /bin/sh -c never pathname-expands it), matching the step.
	f.On("supervisorctl status "+shQuote("berth-app_example_com:*"), bssh.Result{ExitCode: 4, Stdout: "berth-app_example_com: ERROR (no such group)\n"})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the supervisor program is on disk but not loaded")
	}
}

// TestSiteCheckSatisfiedWhenSupervisorProgramLoaded guards the convergence
// endpoint: once the program is loaded (dormant STOPPED, no "no such"), Check is
// satisfied so the engine stops re-applying. Inverting the load condition would
// trip this.
func TestSiteCheckSatisfiedWhenSupervisorProgramLoaded(t *testing.T) {
	s := siteServer()
	s.Queue = true
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	// supervisord has the program loaded (dormant); status lists it, no "no such".
	f.On("supervisorctl status "+shQuote("berth-app_example_com:*"), bssh.Result{ExitCode: 3, Stdout: "berth-app_example_com:berth-app_example_com_00   STOPPED   Not started\n"})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when the supervisor program is loaded; got %+v", cr)
	}
}

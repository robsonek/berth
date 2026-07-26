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
	f.On("cat "+shQuote(legacyCronPath("app.example.com")), bssh.Result{ExitCode: 1})     // legacy-cron migration probe: absent
	stubEmptyDiscovery(f, s)                                                              // Apply's read-only orphan discovery runs first
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})                // stamp invalidation up front
	f.On("cat "+shQuote(nginxAvailablePath("app.example.com")), bssh.Result{ExitCode: 1}) // vhost write-guard: absent
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 1, Stderr: "invalid config"})
	f.On("cat "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 1}) // disabled cloudflare snippet absent
	// systemctl reload is intentionally NOT stubbed: it must never be called.

	err := Site().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("expected Apply to abort when nginx -t fails")
	}
	var ranNginxT bool
	for _, c := range f.Calls() {
		if c.Cmd == "nginx -t" {
			ranNginxT = true
		}
		if c.Cmd == "systemctl reload nginx" {
			t.Error("reload must not run after a failed nginx -t")
		}
	}
	if !ranNginxT {
		t.Fatal("Apply must reach and fail at nginx -t (not abort earlier)")
	}
}

func TestSiteApplyRefusesForeignVhost(t *testing.T) {
	// Check's managed-file loop returns unsatisfied at the FIRST conflict, so a
	// foreign vhost later in the list can reach Apply unclassified; the write
	// path itself must refuse to clobber a config berth does not manage.
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(legacyCronPath("app.example.com")), bssh.Result{ExitCode: 1}) // legacy-cron migration probe: absent
	stubEmptyDiscovery(f, s)                                                          // Apply's read-only orphan discovery runs first
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})            // stamp invalidation up front
	f.On("cat "+shQuote(nginxAvailablePath("app.example.com")), bssh.Result{ExitCode: 0, Stdout: "server { listen 80; } # hand-written\n"})

	err := Site().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	for _, w := range f.Writes() {
		if w.Path == nginxAvailablePath("app.example.com") {
			t.Error("a foreign vhost must not be overwritten without --force")
		}
	}
}

func TestSiteApplyOverwritesForeignVhostWithForce(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	// AFTER stubFPMApply (On overwrites map entries): the vhost is foreign.
	f.On("cat "+shQuote(nginxAvailablePath("app.example.com")), bssh.Result{ExitCode: 0, Stdout: "server { listen 80; } # hand-written\n"})

	if err := Site().Apply(context.Background(), provision.RunCtx{Force: true}, s, f); err != nil {
		t.Fatalf("Apply() with --force error = %v", err)
	}
	var overwritten bool
	for _, w := range f.Writes() {
		if w.Path == nginxAvailablePath("app.example.com") {
			overwritten = true
		}
	}
	if !overwritten {
		t.Error("--force must overwrite the foreign vhost")
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
	stubSiteConvergedProbes(s, f)

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
	stubEmptyDiscovery(noCert, s)
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
	stubEmptyDiscovery(withCert, s)
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

func TestSiteVhostHonorsUploadMax(t *testing.T) {
	// The derived request-body cap must reach client_max_body_size in BOTH
	// vhost renders, so nginx never rejects an upload PHP would accept.
	s := &config.Server{
		Tuning: config.Tuning{PHPUploadMax: "64M"},
		Sites: []config.Site{{
			Domain: "app.example.com", DeployPath: "/home/deploy/myapp", SSL: true,
		}},
	}
	want := "client_max_body_size " + s.Tuning.PHPPostBodyMaxEff() + ";" // 64M + 5% (floored) = 70464307
	httpBody, err := renderNginxHTTP(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(httpBody), want) {
		t.Errorf("HTTP vhost missing %q; got:\n%s", want, httpBody)
	}
	httpsBody, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(httpsBody), want) {
		t.Errorf("HTTPS vhost missing %q; got:\n%s", want, httpsBody)
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

// assertCloudflareGuards checks that every named content location carries the
// cloudflare guard as its first directive exactly `want[loc]` times, that no
// guards exist beyond those, and that no ACME challenge location is guarded.
func assertCloudflareGuards(t *testing.T, render, label string, want map[string]int) {
	t.Helper()
	const guard = "if ($berth_cloudflare = 0) { return 444; }"
	total := 0
	for loc, n := range want {
		if got := strings.Count(render, loc+"\n        "+guard); got != n {
			t.Errorf("%s: location %q must carry the guard as its first directive %d time(s), got %d:\n%s", label, loc, n, got, render)
		}
		total += n
	}
	if got := strings.Count(render, guard); got != total {
		t.Errorf("%s: expected %d guards in total, got %d:\n%s", label, total, got, render)
	}
	// ACME must stay reachable so Let's Encrypt HTTP-01 still works: NO ACME block
	// (port-80 OR 443) may contain the guard. Scan every occurrence, panic-safe.
	const acmeLoc = "location /.well-known/acme-challenge/"
	for rest := render; ; {
		i := strings.Index(rest, acmeLoc)
		if i == -1 {
			break
		}
		block := rest[i:]
		if end := strings.Index(block, "}"); end != -1 {
			block = block[:end]
		}
		if strings.Contains(block, "$berth_cloudflare") {
			t.Errorf("%s: the ACME challenge location must NOT be guarded", label)
		}
		rest = rest[i+len(acmeLoc):]
	}
}

func TestNginxGuardWhenCloudflareOnly(t *testing.T) {
	s := siteServer()
	tru := true
	s.Sites[0].CloudflareOnly = &tru
	s.Sites[0].SSL = true

	http, err := renderNginxHTTP(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	assertCloudflareGuards(t, string(http), "HTTP", map[string]int{
		"location / {":                 1,
		`location ~ \.php$ {`:          1,
		"location = /favicon.ico {":    1,
		"location = /robots.txt {":     1,
		"location ^~ /build/assets/ {": 1,
	})

	https, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	// location / appears twice on the HTTPS side: the port-80 redirect block
	// and the 443 content block — both must be guarded.
	assertCloudflareGuards(t, string(https), "HTTPS", map[string]int{
		"location / {":                 2,
		`location ~ \.php$ {`:          1,
		"location = /favicon.ico {":    1,
		"location = /robots.txt {":     1,
		"location ^~ /build/assets/ {": 1,
	})
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

// TestSiteCheckUnsatisfiedWhenCronDownWithScheduler proves the scheduler
// promise is probed end to end: /etc/cron.d drop-ins are inert without a
// running cron daemon, so an otherwise converged host with cron down must
// report drift (Apply heals it via ensureCron).
func TestSiteCheckUnsatisfiedWhenCronDownWithScheduler(t *testing.T) {
	s := siteServer() // Scheduler: true
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	stubSiteConvergedProbes(s, f)
	// Override the helper's converged cron probes: the daemon is down.
	f.On("systemctl is-active cron", bssh.Result{ExitCode: 3})
	f.On("systemctl is-enabled cron", bssh.Result{ExitCode: 1})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the cron daemon is down and a scheduler cron is desired")
	}
	if !strings.Contains(cr.Reason, "cron") {
		t.Errorf("Reason must mention cron; got %q", cr.Reason)
	}
}

// TestSiteApplyEnsuresCronWhenSchedulerEnabled proves Apply ensures the cron
// daemon BEFORE writing the scheduler crons that depend on it (here cron is
// already active+enabled, so ensureCron probes and installs nothing). The cron
// file's write-guard cat is the closest observable proxy for its write (Run
// and WriteFile orders cannot be correlated on the FakeRunner).
func TestSiteApplyEnsuresCronWhenSchedulerEnabled(t *testing.T) {
	s := siteServer() // Scheduler: true
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	// ensureCron pre-check: cron already active+enabled -> no install.
	f.On("systemctl is-active cron", bssh.Result{})
	f.On("systemctl is-enabled cron", bssh.Result{})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idxProbe, idxCronGuard := -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "systemctl is-active cron":
			idxProbe = i
		case "cat " + shQuote(cronPath(s.Sites[0].Domain)):
			idxCronGuard = i
		}
	}
	if idxProbe < 0 {
		t.Fatal("Apply must ensure the cron daemon (ensureCron probe) when a scheduler cron is desired")
	}
	if idxCronGuard < 0 || idxProbe > idxCronGuard {
		t.Errorf("ensureCron (idx %d) must run BEFORE the scheduler cron write (write-guard idx %d)", idxProbe, idxCronGuard)
	}
}

// siteStampFileLists mirrors Check's stamp-probe list construction: the
// cloudflare snippet FIRST when any site is cloudflare_only, then every site's
// vhost / pool in config order, then the governing directory (sites-enabled /
// pool.d) whose mtime covers link/file creation and removal. Kept in lock-step
// with site.Check by the tests that use it.
func siteStampFileLists(s *config.Server) (vhosts, pools []string) {
	if s.AnyCloudflareOnly() {
		vhosts = append(vhosts, cloudflareConfPath)
	}
	for _, site := range s.Sites {
		vhosts = append(vhosts, nginxAvailablePath(site.Domain))
		pools = append(pools, fpmPoolPath(s.PHP.Version, site.Domain))
	}
	vhosts = append(vhosts, nginxEnabledDir)
	pools = append(pools, fpmPoolDir(s.PHP.Version))
	return vhosts, pools
}

// stubSiteConvergedProbes stubs Check's enabled-symlink, stock-pool,
// reload-stamp and cron-daemon probes the way a converged host answers: every
// sites-enabled link resolves to its vhost, the stock www pool is absent, the
// running nginx/php-fpm postdate every managed vhost/pool, and the cron daemon
// is active+enabled (probed only when a site wants the scheduler; unused
// stubs are harmless otherwise).
func stubSiteConvergedProbes(s *config.Server, f *bssh.FakeRunner) {
	for _, site := range s.Sites {
		f.On("[ "+shQuote(nginxEnabledPath(site.Domain))+" -ef "+shQuote(nginxAvailablePath(site.Domain))+" ]", bssh.Result{})
	}
	f.On("test -e "+shQuote(defaultFPMPoolPath(s)), bssh.Result{ExitCode: 1})
	vhosts, pools := siteStampFileLists(s)
	f.On(reloadedSinceCmd("nginx", vhosts...), bssh.Result{})
	f.On(reloadedSinceCmd(fpmService(s), pools...), bssh.Result{})
	f.On("systemctl is-active cron", bssh.Result{})
	f.On("systemctl is-enabled cron", bssh.Result{})
}

// findFilesCmd mirrors findRegularFiles' command shape (orphan discovery).
func findFilesCmd(dir, pattern string) string {
	cmd := "find " + shQuote(dir) + " -maxdepth 1 -type f"
	if pattern != "" {
		cmd += " -name " + shQuote(pattern)
	}
	return "if [ -d " + shQuote(dir) + " ]; then " + cmd + "; fi"
}

// rmVhostPairCmd mirrors Apply's guarded orphan-vhost pair removal: the
// disposition check runs FIRST (exit 3, nothing deleted, when the enabled
// entry exists but is not berth's symlink to this vhost), then link and file go.
func rmVhostPairCmd(link, file string) string {
	return "if [ -e " + shQuote(link) + " ] && ! { [ -L " + shQuote(link) + " ] && [ " + shQuote(link) + " -ef " + shQuote(file) + " ]; }; then exit 3; fi; if [ -L " + shQuote(link) + " ]; then rm -f " + shQuote(link) + "; fi; rm -f " + shQuote(file)
}

// stubEmptyDiscovery stubs the three orphan-discovery listings as empty.
// Apply it in every satisfied-shaped fixture (and every direct
// managedSiteFiles caller); orphan tests OVERRIDE single listings AFTER it
// (FakeRunner.On is last-wins).
func stubEmptyDiscovery(f *bssh.FakeRunner, s *config.Server) {
	f.On(findFilesCmd("/etc/nginx/sites-available", ""), bssh.Result{})
	f.On(findFilesCmd(fpmPoolDir(s.PHP.Version), "*.conf"), bssh.Result{})
	f.On(findFilesCmd("/etc/cron.d", "berth-*"), bssh.Result{})
}

// stubManagedSiteFiles makes every managed site file read back as up-to-date so
// the Check's content-hash comparison is satisfied.
func stubManagedSiteFiles(t *testing.T, s *config.Server, f *bssh.FakeRunner) {
	t.Helper()
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
	stubEmptyDiscovery(f, s)
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
	// Reload-stamp bookkeeping: both units are invalidated up front and
	// re-stamped after their successful reloads.
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/"+fpmService(s)+".reloaded"), bssh.Result{})
	f.On(markReloadedCmd("nginx"), bssh.Result{})
	f.On(markReloadedCmd(fpmService(s)), bssh.Result{})
	f.On(fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(defaultFPMPoolPath(s))), bssh.Result{})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload "+fpmService(s), bssh.Result{})
	f.On("logrotate -d "+shQuote(logrotatePath), bssh.Result{})
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
	stubEmptyDiscovery(f, s)
	f.On("supervisorctl reread", bssh.Result{})
	f.On("supervisorctl update", bssh.Result{})
	// ensureCron pre-check (runs only when a site wants the scheduler): cron is
	// already active+enabled -> no install.
	f.On("systemctl is-active cron", bssh.Result{})
	f.On("systemctl is-enabled cron", bssh.Result{})
	f.On("cat "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 1}) // step-0 cloudflare snippet absent
	// Write-guard reads: every managed file Apply may write is absent by default.
	// Tests that model a pre-existing file re-stub the specific path AFTER this.
	f.On("cat "+shQuote(logrotatePath), bssh.Result{ExitCode: 1})
	for _, site := range s.Sites {
		f.On("cat "+shQuote(nginxAvailablePath(site.Domain)), bssh.Result{ExitCode: 1})
		f.On("cat "+shQuote(fpmPoolPath(s.PHP.Version, site.Domain)), bssh.Result{ExitCode: 1})
		f.On("cat "+shQuote(supervisorProgramPath(site.Domain)), bssh.Result{ExitCode: 1})
		f.On("cat "+shQuote(cronPath(site.Domain)), bssh.Result{ExitCode: 1})
		// Legacy-cron migration probe (Apply's pre-write phase): absent by
		// default; migration tests re-stub it with berth-managed content.
		f.On("cat "+shQuote(legacyCronPath(site.Domain)), bssh.Result{ExitCode: 1})
		for _, d := range site.Daemons {
			f.On("cat "+shQuote(daemonProgramPath(site.Domain, d.Name)), bssh.Result{ExitCode: 1})
		}
	}
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
	fApply.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // no lingering hook

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
	stubSiteConvergedProbes(s, fCheck)
	fCheck.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
	stubEmptyDiscovery(fCheck, s)
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
	stubEmptyDiscovery(f, s)
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
	stubEmptyDiscovery(f, s)
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
	stubEmptyDiscovery(f, s)
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
	stubEmptyDiscovery(f, s)
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
	stubEmptyDiscovery(f, s)
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

func TestSiteApplyRemovesDisabledCloudflareBeforeReload(t *testing.T) {
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
	// The rm must run AFTER the vhosts are rewritten unguarded (so validation
	// passes without the geo) but BEFORE nginx -t + reload: under the
	// transactional reload stamp nothing may mutate nginx config after the
	// mark, and the mark directly follows the reload. The vhost's write-guard
	// cat is the closest observable proxy for its rewrite (Run and WriteFile
	// orders cannot be correlated on the FakeRunner).
	idxVhostGuard, idxTest, idxReload, idxRemove := -1, -1, -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "cat " + shQuote(nginxAvailablePath(s.Sites[0].Domain)):
			idxVhostGuard = i
		case "nginx -t":
			idxTest = i
		case "systemctl reload nginx":
			idxReload = i
		case "rm -f " + shQuote(cloudflareConfPath):
			idxRemove = i
		}
	}
	if idxRemove < 0 {
		t.Fatal("Apply must rm the lingering berth-managed cloudflare conf when disabled")
	}
	if idxVhostGuard < 0 || idxRemove < idxVhostGuard {
		t.Errorf("rm of the cloudflare snippet (idx %d) must run AFTER the vhost rewrite (write-guard idx %d) so a guarded vhost never outlives its geo", idxRemove, idxVhostGuard)
	}
	if idxTest < 0 || idxRemove > idxTest {
		t.Errorf("rm of the cloudflare snippet (idx %d) must run BEFORE nginx -t (idx %d)", idxRemove, idxTest)
	}
	if idxReload < 0 || idxRemove > idxReload {
		t.Errorf("rm of the cloudflare snippet (idx %d) must run BEFORE systemctl reload nginx (idx %d)", idxRemove, idxReload)
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
	stubSiteConvergedProbes(s, f)
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
	stubSiteConvergedProbes(s, f)
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

func TestSiteCheckUnsatisfiedWhenVhostNewerThanNginxStamp(t *testing.T) {
	// A crash between writing a vhost and reloading nginx leaves the daemon
	// serving the old server block forever while the on-disk bytes read
	// converged — only the reload stamp catches it.
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	stubSiteConvergedProbes(s, f)
	vhosts, _ := siteStampFileLists(s)
	f.On(reloadedSinceCmd("nginx", vhosts...), bssh.Result{ExitCode: 1})
	// (FPM stamp probe not reached — Check returns at the first failed probe.)

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a vhost newer than the nginx reload stamp must be unsatisfied (written but not reloaded)")
	}
}

func TestSiteCheckUnsatisfiedWhenPoolNewerThanFPMStamp(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	stubSiteConvergedProbes(s, f)
	_, pools := siteStampFileLists(s)
	f.On(reloadedSinceCmd(fpmService(s), pools...), bssh.Result{ExitCode: 1})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a pool newer than the php-fpm reload stamp must be unsatisfied (written but not reloaded)")
	}
}

func TestSiteCheckUnsatisfiedWhenEnabledLinkMissing(t *testing.T) {
	// Apply converges the sites-enabled symlink every run, but nothing
	// re-triggered it when only the link drifted (deleted or repointed).
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	stubSiteConvergedProbes(s, f)
	f.On("[ "+shQuote(nginxEnabledPath(s.Sites[0].Domain))+" -ef "+shQuote(nginxAvailablePath(s.Sites[0].Domain))+" ]", bssh.Result{ExitCode: 1})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a missing/wrong sites-enabled link must be unsatisfied (the vhost is not actually served)")
	}
}

func TestSiteCheckUnsatisfiedWhenStockPoolPresent(t *testing.T) {
	// Apply disables the stock www pool every run; a pool that reappeared
	// (e.g. a php-fpm package upgrade restoring www.conf) must re-trigger it.
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	stubSiteConvergedProbes(s, f)
	f.On("test -e "+shQuote(defaultFPMPoolPath(s)), bssh.Result{})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a present stock FPM pool must be unsatisfied (it must stay disabled)")
	}
}

func TestSiteApplyStampsNginxAndFPMAfterReloads(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idx := func(want string) int {
		for i, c := range f.Calls() {
			if c.Cmd == want {
				return i
			}
		}
		return -1
	}
	reloadNginx := idx("systemctl reload nginx")
	markNginx := idx(markReloadedCmd("nginx"))
	reloadFPM := idx("systemctl reload " + fpmService(s))
	markFPM := idx(markReloadedCmd(fpmService(s)))
	if markNginx < 0 || markFPM < 0 {
		t.Fatalf("both reload stamps must be recorded; markNginx=%d markFPM=%d", markNginx, markFPM)
	}
	if reloadNginx < 0 || reloadNginx > markNginx {
		t.Errorf("nginx stamp must be recorded AFTER systemctl reload nginx; reload=%d mark=%d", reloadNginx, markNginx)
	}
	if reloadFPM < 0 || reloadFPM > markFPM {
		t.Errorf("FPM stamp must be recorded AFTER systemctl reload %s; reload=%d mark=%d", fpmService(s), reloadFPM, markFPM)
	}
	// Invalidate-before-mutation: the write-guard cat is issued by
	// writeManagedFile immediately before each WriteFile — the closest
	// observable proxy for the write itself (Run and WriteFile orders cannot
	// be correlated on the FakeRunner). The FPM phase's first mutation is the
	// stock-pool disable.
	rmNginx := idx("rm -f " + shQuote("/var/lib/berth/nginx.reloaded"))
	guardVhost := idx("cat " + shQuote(nginxAvailablePath(s.Sites[0].Domain)))
	if rmNginx < 0 || guardVhost < 0 || rmNginx > guardVhost {
		t.Errorf("nginx stamp must be invalidated BEFORE the vhost write; rm=%d write-guard=%d", rmNginx, guardVhost)
	}
	rmFPM := idx("rm -f " + shQuote("/var/lib/berth/"+fpmService(s)+".reloaded"))
	disableWWW := idx(fmt.Sprintf("test -f %[1]s && mv -f %[1]s %[1]s.disabled || true", shQuote(defaultFPMPoolPath(s))))
	if rmFPM < 0 || disableWWW < 0 || rmFPM > disableWWW {
		t.Errorf("FPM stamp must be invalidated BEFORE the stock-pool disable; rm=%d disable=%d", rmFPM, disableWWW)
	}
}

func TestSiteApplyNoNginxStampWhenValidationFails(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(legacyCronPath("app.example.com")), bssh.Result{ExitCode: 1}) // legacy-cron migration probe: absent
	stubEmptyDiscovery(f, s)                                                          // Apply's read-only orphan discovery runs first
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})
	f.On("cat "+shQuote(nginxAvailablePath("app.example.com")), bssh.Result{ExitCode: 1}) // vhost write-guard: absent
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("cat "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 1}) // disabled-snippet probe: absent
	f.On("nginx -t", bssh.Result{ExitCode: 1, Stderr: "broken"})

	err := Site().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("expected Apply to abort when nginx -t fails")
	}
	var invalidated bool
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote("/var/lib/berth/nginx.reloaded") {
			invalidated = true
		}
		if c.Cmd == markReloadedCmd("nginx") {
			t.Error("the nginx reload stamp must not be recorded after a failed nginx -t")
		}
		if c.Cmd == "systemctl reload nginx" {
			t.Error("reload must not run after a failed nginx -t")
		}
	}
	if !invalidated {
		t.Error("the nginx stamp must be invalidated before the vhost writes (crash-safe window)")
	}
}

func TestSiteCronPathUsesDisjointNamespace(t *testing.T) {
	if got := cronPath("backup-shop.example.com"); got != "/etc/cron.d/berth-site-backup-shop_example_com" {
		t.Fatalf("cronPath() = %q; the berth-site- prefix keeps a backup-*.tld domain out of the backups sweep glob", got)
	}
	if strings.HasPrefix(cronPath("shop.example.com"), backupCronPrefix) {
		t.Fatal("a scheduler cron must never fall inside the backups namespace")
	}
}

func TestSiteCheckFlagsOrphanVhostAndAggregatesRemovals(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	// Overrides AFTER the empty-discovery stubs (On is last-wins): the vhost
	// listing also holds a berth-managed leftover of a removed site, and the
	// cron listing a berth-managed leftover scheduler cron.
	goneVhost := "/etc/nginx/sites-available/gone.example.com"
	goneCron := "/etc/cron.d/berth-gone_example_com"
	f.On(findFilesCmd("/etc/nginx/sites-available", ""), bssh.Result{Stdout: nginxAvailablePath(s.Sites[0].Domain) + "\n" + goneVhost + "\n"})
	f.On("cat "+shQuote(goneVhost), bssh.Result{Stdout: managedMarker + "\nserver {}\n"})
	f.On(findFilesCmd("/etc/cron.d", "berth-*"), bssh.Result{Stdout: goneCron + "\n"})
	f.On("cat "+shQuote(goneCron), bssh.Result{Stdout: managedMarker + "\n* * * * * gone ...\n"})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("expected unsatisfied when a removed site's berth-managed vhost lingers")
	}
	if !strings.Contains(cr.Reason, "removed") {
		t.Errorf("Reason must mention removal; got %q", cr.Reason)
	}
	// Dry-run must preview EVERY planned removal, not just the first one found.
	for _, want := range []string{"remove: " + goneVhost, "remove: " + goneCron} {
		var seen bool
		for _, c := range cr.Changes {
			if c == want {
				seen = true
			}
		}
		if !seen {
			t.Errorf("Changes must list the planned removal %q; got %v", want, cr.Changes)
		}
	}
}

// TestSiteCheckPreviewsRemovalsOnEarlierContentDrift pins the dry-run
// contract on an upgraded-host shape: the NEW berth-site- cron path is absent
// (a content drift that trips the managed-file loop BEFORE any remove entry)
// while the legacy berth-<pool> cron lingers berth-managed. The destructive
// preview must ride along on THAT result too — Apply will delete (here:
// migrate away) the legacy file regardless of which entry tripped Check first.
func TestSiteCheckPreviewsRemovalsOnEarlierContentDrift(t *testing.T) {
	s := siteServer() // Scheduler: true
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	legacy := "/etc/cron.d/berth-" + poolName(s.Sites[0].Domain)
	f.On("cat "+shQuote(cronPath(s.Sites[0].Domain)), bssh.Result{ExitCode: 1}) // new cron absent -> content drift
	f.On(findFilesCmd("/etc/cron.d", "berth-*"), bssh.Result{Stdout: legacy + "\n"})
	f.On("cat "+shQuote(legacy), bssh.Result{Stdout: managedMarker + "\n* * * * * deploy ...\n"})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("expected unsatisfied: the new cron path is absent and a legacy cron lingers")
	}
	want := "remove: " + legacy
	var seen bool
	for _, c := range cr.Changes {
		if c == want {
			seen = true
		}
	}
	if !seen {
		t.Errorf("Changes must preview the legacy cron's removal even when a content drift tripped the loop first; got %v", cr.Changes)
	}
}

// TestSiteCheckTreatsMissingSweepDirAsEmpty pins the fresh-provision shape: on
// a minimal image /etc/cron.d does not exist until site.Apply's own ensureCron
// installs cron, so the discovery command must guard the listing with [ -d ]
// (missing dir -> exit 0, no output, no orphans) instead of erroring — a Check
// error here fail-fasts the engine and Apply never gets to install cron.
func TestSiteCheckTreatsMissingSweepDirAsEmpty(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	stubSiteConvergedProbes(s, f)
	// Missing /etc/cron.d: the guarded listing returns exit 0 with no output.
	f.On(findFilesCmd("/etc/cron.d", "berth-*"), bssh.Result{})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatalf("a missing sweep dir must read as \"no candidates\", not a Check error: %v", err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
	// Pin the property that makes the above true on a REAL host: the issued
	// command short-circuits on a missing directory.
	var issued string
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "-maxdepth 1 -type f") && strings.Contains(c.Cmd, "/etc/cron.d") {
			issued = c.Cmd
		}
	}
	if !strings.HasPrefix(issued, "if [ -d "+shQuote("/etc/cron.d")+" ]; then ") {
		t.Errorf("the discovery command must guard the listing with [ -d ]; issued %q", issued)
	}
}

// TestSiteCheckErrorsWhenOrphanDiscoveryFindFails pins fail-loud discovery: a
// find failure (permission, I/O) yields empty output + nonzero exit, which
// used to read as "no orphans" and silently skip every removal forever. All
// three swept directories exist by the time the site step runs (their owning
// steps precede it), so a nonzero exit is never a quiet "missing dir" case.
func TestSiteCheckErrorsWhenOrphanDiscoveryFindFails(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	stubSiteConvergedProbes(s, f)
	// Override AFTER the empty-discovery stubs: the cron listing fails.
	f.On(findFilesCmd("/etc/cron.d", "berth-*"), bssh.Result{ExitCode: 2, Stderr: "find: '/etc/cron.d': Permission denied"})

	_, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("Check must fail loud when an orphan-discovery find exits nonzero")
	}
	if !strings.Contains(err.Error(), "/etc/cron.d") || !strings.Contains(err.Error(), "Permission denied") {
		t.Errorf("the error must name the directory and carry find's stderr; got %v", err)
	}
}

func TestSiteCheckIgnoresForeignVhost(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})
	stubSiteConvergedProbes(s, f)
	// The listing returns a stray file WITHOUT the berth marker: an operator's
	// hand-written vhost must never be flagged (let alone removed).
	foreign := "/etc/nginx/sites-available/foreign.example.com"
	f.On(findFilesCmd("/etc/nginx/sites-available", ""), bssh.Result{Stdout: nginxAvailablePath(s.Sites[0].Domain) + "\n" + foreign + "\n"})
	f.On("cat "+shQuote(foreign), bssh.Result{Stdout: "server {}\n"})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("a foreign (unmarked) vhost must not make Check unsatisfied; got %+v", cr)
	}
}

func TestSiteApplyRemovesOrphanVhostPairBeforeReload(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	// Discovery override AFTER stubFPMApply's empty stubs.
	goneVhost := "/etc/nginx/sites-available/gone.example.com"
	goneLink := nginxEnabledPath("gone.example.com")
	f.On(findFilesCmd("/etc/nginx/sites-available", ""), bssh.Result{Stdout: nginxAvailablePath(s.Sites[0].Domain) + "\n" + goneVhost + "\n"})
	f.On("cat "+shQuote(goneVhost), bssh.Result{Stdout: managedMarker + "\nserver {}\n"})
	// The GUARDED pair removal: the enabled entry goes only when it is a
	// symlink resolving to exactly this vhost.
	rmPair := rmVhostPairCmd(goneLink, goneVhost)
	f.On(rmPair, bssh.Result{})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idx := func(want string) int {
		last := -1
		for i, c := range f.Calls() {
			if c.Cmd == want {
				last = i
			}
		}
		return last
	}
	idxRm := idx(rmPair)
	idxVhostGuard := idx("cat " + shQuote(nginxAvailablePath(s.Sites[0].Domain)))
	idxTest := idx("nginx -t")
	idxReload := idx("systemctl reload nginx")
	idxMark := idx(markReloadedCmd("nginx"))
	if idxRm < 0 {
		t.Fatalf("Apply must remove the orphan vhost pair; calls=%v", f.Calls())
	}
	if idxVhostGuard < 0 || idxRm < idxVhostGuard {
		t.Errorf("the orphan removal (idx %d) must run AFTER the desired vhost writes (write-guard idx %d)", idxRm, idxVhostGuard)
	}
	if idxTest < 0 || idxRm > idxTest {
		t.Errorf("the orphan removal (idx %d) must run BEFORE nginx -t (idx %d)", idxRm, idxTest)
	}
	if idxReload < 0 || idxTest > idxReload || idxMark < 0 || idxReload > idxMark {
		t.Errorf("expected nginx -t (%d) < reload (%d) < mark (%d)", idxTest, idxReload, idxMark)
	}
}

// TestSiteApplyForeignEnabledEntryFailsLoudAndStable pins the reworked pair
// removal: when the enabled entry is a foreign file, hardlink or repointed
// link, the disposition check fires BEFORE anything is deleted (exit 3), so
// the berth-marked sites-available anchor SURVIVES, discovery re-finds the
// orphan on every later run, and both Check and Apply repeat the same
// actionable signal — not a one-shot error after which the host goes green
// while nginx keeps serving the leftover.
func TestSiteApplyForeignEnabledEntryFailsLoudAndStable(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	stubFPMApply(s, f)
	goneVhost := "/etc/nginx/sites-available/gone.example.com"
	goneLink := nginxEnabledPath("gone.example.com")
	f.On(findFilesCmd("/etc/nginx/sites-available", ""), bssh.Result{Stdout: nginxAvailablePath(s.Sites[0].Domain) + "\n" + goneVhost + "\n"})
	f.On("cat "+shQuote(goneVhost), bssh.Result{Stdout: managedMarker + "\nserver {}\n"})
	f.On(rmVhostPairCmd(goneLink, goneVhost), bssh.Result{ExitCode: 3}) // foreign leftover: nothing deleted

	err1 := Site().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err1 == nil || !strings.Contains(err1.Error(), goneLink) || !strings.Contains(err1.Error(), "foreign file or hardlink") {
		t.Fatalf("Apply must fail loud pointing at the foreign enabled entry; got %v", err1)
	}
	// SECOND cycle on the same host state: identical failure, nothing forgotten.
	err2 := Site().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err2 == nil || err2.Error() != err1.Error() {
		t.Fatalf("the failure must be stable across runs; first %v, second %v", err1, err2)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote(goneVhost) || c.Cmd == "rm -f "+shQuote(goneLink) {
			t.Errorf("nothing may be deleted when the enabled entry is not berth's; saw %q", c.Cmd)
		}
		if c.Cmd == "systemctl reload nginx" {
			t.Error("nginx must not be reloaded after the removal failed loudly")
		}
	}

	// Check stays unsatisfied with the same removal preview on every run: the
	// surviving anchor keeps the orphan discoverable.
	fc := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, fc)
	fc.On(findFilesCmd("/etc/nginx/sites-available", ""), bssh.Result{Stdout: nginxAvailablePath(s.Sites[0].Domain) + "\n" + goneVhost + "\n"})
	fc.On("cat "+shQuote(goneVhost), bssh.Result{Stdout: managedMarker + "\nserver {}\n"})
	for run := 1; run <= 2; run++ {
		cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, fc)
		if err != nil {
			t.Fatal(err)
		}
		if cr.Satisfied {
			t.Fatalf("run %d: Check must stay unsatisfied while the orphan anchor survives", run)
		}
		var previewed bool
		for _, c := range cr.Changes {
			if c == "remove: "+goneVhost {
				previewed = true
			}
		}
		if !previewed {
			t.Errorf("run %d: Changes must keep previewing the orphan removal; got %v", run, cr.Changes)
		}
	}
}

func TestSiteApplyRemovesOrphanPoolBeforeFPMReload(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	orphanPool := fpmPoolPath(s.PHP.Version, "gone.example.com")
	f.On(findFilesCmd(fpmPoolDir(s.PHP.Version), "*.conf"), bssh.Result{Stdout: orphanPool + "\n"})
	f.On("cat "+shQuote(orphanPool), bssh.Result{Stdout: managedMarkerINI + "\n[gone_example_com]\n"})
	f.On("rm -f "+shQuote(orphanPool), bssh.Result{})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idx := func(want string) int {
		last := -1
		for i, c := range f.Calls() {
			if c.Cmd == want {
				last = i
			}
		}
		return last
	}
	idxRm := idx("rm -f " + shQuote(orphanPool))
	idxPoolGuard := idx("cat " + shQuote(fpmPoolPath(s.PHP.Version, s.Sites[0].Domain)))
	idxTest := idx("php-fpm" + s.PHP.Version + " -t")
	idxReload := idx("systemctl reload " + fpmService(s))
	idxMark := idx(markReloadedCmd(fpmService(s)))
	if idxRm < 0 {
		t.Fatalf("Apply must remove the orphan FPM pool; calls=%v", f.Calls())
	}
	if idxPoolGuard < 0 || idxRm < idxPoolGuard {
		t.Errorf("the orphan pool removal (idx %d) must run AFTER the desired pool writes (write-guard idx %d)", idxRm, idxPoolGuard)
	}
	if idxTest < 0 || idxRm > idxTest {
		t.Errorf("the orphan pool removal (idx %d) must run BEFORE php-fpm -t (idx %d)", idxRm, idxTest)
	}
	if idxReload < 0 || idxTest > idxReload || idxMark < 0 || idxReload > idxMark {
		t.Errorf("expected php-fpm -t (%d) < reload (%d) < mark (%d)", idxTest, idxReload, idxMark)
	}
}

// TestSiteApplyMigratesLegacyCronAtomically pins the pre-write migration of a
// CURRENT site's pre-rename scheduler cron: berth-<pool> -> berth-site-<pool>
// must be one atomic rename, never write-new-then-sweep-old — in that window
// BOTH files schedule schedule:run every minute (duplicate mail/billing risk
// if cron ticks in between). The mv runs before orphan discovery, so the
// sweep never sees the legacy path.
func TestSiteApplyMigratesLegacyCronAtomically(t *testing.T) {
	s := siteServer() // Scheduler: true -> the berth-site- cron is desired
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	// Migration probes (override stubFPMApply's absent default): the legacy
	// cron is berth-managed and the new path does not exist yet (the cat
	// classification probe finds nothing — stubFPMApply's default).
	legacy := "/etc/cron.d/berth-" + poolName(s.Sites[0].Domain)
	f.On("cat "+shQuote(legacy), bssh.Result{Stdout: managedMarker + "\n* * * * * deploy ...\n"})
	mv := "mv " + shQuote(legacy) + " " + shQuote(cronPath(s.Sites[0].Domain))
	f.On(mv, bssh.Result{})
	// Discovery runs AFTER the mv, so on a real host the listing already holds
	// the new path (desired -> skipped) and a backups-namespace cron — never
	// the legacy one.
	f.On(findFilesCmd("/etc/cron.d", "berth-*"), bssh.Result{Stdout: cronPath(s.Sites[0].Domain) + "\n" + backupCronPrefix + "x\n"})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idxMv, idxNewGuard := -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case mv:
			idxMv = i
		case "cat " + shQuote(cronPath(s.Sites[0].Domain)):
			idxNewGuard = i
		}
		if c.Cmd == "rm -f "+shQuote(legacy) {
			t.Errorf("the legacy cron must be renamed, never removed; saw %q", c.Cmd)
		}
		// The backup cron belongs to the backups step: never cat'ed, never rm'ed.
		if strings.Contains(c.Cmd, "berth-backup-") {
			t.Errorf("the migration/sweep must never touch a backups-namespace cron; saw %q", c.Cmd)
		}
	}
	if idxMv < 0 {
		t.Fatal("Apply must migrate the legacy scheduler cron with an atomic mv")
	}
	if idxNewGuard < 0 || idxMv > idxNewGuard {
		t.Errorf("the mv (idx %d) must run BEFORE the new cron's write (write-guard idx %d): at no instant may both or neither path exist", idxMv, idxNewGuard)
	}
	var wroteNew bool
	for _, w := range f.Writes() {
		if w.Path == cronPath(s.Sites[0].Domain) {
			wroteNew = true
		}
	}
	if !wroteNew {
		t.Error("the scheduler cron must still be (re)written at the NEW berth-site- path by the normal drift path")
	}
}

// TestSiteApplyRemovesHalfMigratedLegacyCronEarly pins the corner where BOTH
// paths exist (an earlier run wrote the new cron, then died before its sweep):
// the legacy file must be removed in the same pre-write phase — leaving it to
// the orphan loop would keep both firing until that loop runs. The new path
// carries the berth marker, which is what authorizes deleting the legacy copy.
func TestSiteApplyRemovesHalfMigratedLegacyCronEarly(t *testing.T) {
	s := siteServer() // Scheduler: true
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	legacy := "/etc/cron.d/berth-" + poolName(s.Sites[0].Domain)
	f.On("cat "+shQuote(legacy), bssh.Result{Stdout: managedMarker + "\n* * * * * deploy ...\n"})
	// The new path already exists AND is berth's own file.
	f.On("cat "+shQuote(cronPath(s.Sites[0].Domain)), bssh.Result{Stdout: managedMarker + "\n* * * * * deploy new ...\n"})
	f.On("rm -f "+shQuote(legacy), bssh.Result{})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idxRm, idxNewGuard := -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "rm -f " + shQuote(legacy):
			idxRm = i
		case "cat " + shQuote(cronPath(s.Sites[0].Domain)):
			idxNewGuard = i
		}
		if strings.HasPrefix(c.Cmd, "mv ") {
			t.Errorf("no mv may run when the new path already exists; saw %q", c.Cmd)
		}
	}
	if idxRm < 0 {
		t.Fatal("Apply must remove the half-migrated legacy cron in the pre-write phase")
	}
	if idxNewGuard < 0 || idxRm > idxNewGuard {
		t.Errorf("the legacy rm (idx %d) must run BEFORE the new cron's write (write-guard idx %d)", idxRm, idxNewGuard)
	}
}

// TestSiteApplyLeavesLegacyCronWhenNewPathForeign pins the migration's marker
// guard: when the NEW cron path is occupied by a FOREIGN file, deleting the
// legacy copy would leave NO working berth scheduler cron at all (the managed
// write refuses the foreign file right after). The legacy cron must survive
// untouched; the loud write refusal is the operator's signal.
func TestSiteApplyLeavesLegacyCronWhenNewPathForeign(t *testing.T) {
	s := siteServer() // Scheduler: true
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	legacy := "/etc/cron.d/berth-" + poolName(s.Sites[0].Domain)
	f.On("cat "+shQuote(legacy), bssh.Result{Stdout: managedMarker + "\n* * * * * deploy ...\n"})
	f.On("cat "+shQuote(cronPath(s.Sites[0].Domain)), bssh.Result{Stdout: "# operator's own cron\n"}) // foreign, no marker

	err := Site().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("Apply must refuse the foreign file at the new cron path; got %v", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote(legacy) || strings.HasPrefix(c.Cmd, "mv ") {
			t.Errorf("the working legacy cron must be left alone while the new path is foreign; saw %q", c.Cmd)
		}
	}
}

// TestSiteApplyForceMigratesOverForeignNewCron pins the --force corner: force
// authorizes overwriting the foreign file at the new path, so the legacy copy
// is removed in the pre-write phase — leaving it to the later sweep would
// reopen the double-schedule window between the overwrite and the sweep.
func TestSiteApplyForceMigratesOverForeignNewCron(t *testing.T) {
	s := siteServer() // Scheduler: true
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	legacy := "/etc/cron.d/berth-" + poolName(s.Sites[0].Domain)
	f.On("cat "+shQuote(legacy), bssh.Result{Stdout: managedMarker + "\n* * * * * deploy ...\n"})
	f.On("cat "+shQuote(cronPath(s.Sites[0].Domain)), bssh.Result{Stdout: "# operator's own cron\n"}) // foreign, no marker
	f.On("rm -f "+shQuote(legacy), bssh.Result{})

	if err := Site().Apply(context.Background(), provision.RunCtx{Force: true}, s, f); err != nil {
		t.Fatalf("Apply() with --force error = %v", err)
	}
	var removedLegacy, wroteNew bool
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote(legacy) {
			removedLegacy = true
		}
	}
	for _, w := range f.Writes() {
		if w.Path == cronPath(s.Sites[0].Domain) {
			wroteNew = true
		}
	}
	if !removedLegacy || !wroteNew {
		t.Errorf("with --force the legacy cron must be removed pre-write (got %v) and the new path overwritten (got %v)", removedLegacy, wroteNew)
	}
}

// TestSiteApplyUpdatesSupervisorWhenActiveButDisabled pins the post-removal
// supervisor gate to serviceActive: an ACTIVE but boot-DISABLED supervisord
// still runs the removed site's worker, so reread/update MUST run after the
// orphan conf removal (enablement stays the supervisor step's business).
func TestSiteApplyUpdatesSupervisorWhenActiveButDisabled(t *testing.T) {
	s := siteServer() // no queue, no daemons -> NeedsSupervisor false
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	orphan := "/etc/supervisor/conf.d/berth-app_example_com.conf"
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{Stdout: orphan + "\n"})
	f.On("cat "+shQuote(orphan), bssh.Result{ExitCode: 0, Stdout: managedMarker + "\n[program:berth-app_example_com]\n"})
	f.On("rm -f "+shQuote(orphan), bssh.Result{})
	// supervisord is running but disabled at boot (is-active 0, is-enabled 1).
	f.On("systemctl is-active supervisor", bssh.Result{ExitCode: 0, Stdout: "active\n"})
	f.On("systemctl is-enabled supervisor", bssh.Result{ExitCode: 1, Stdout: "disabled\n"})

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
		t.Errorf("an active-but-disabled supervisord must still be reread/updated after the orphan removal; reread=%v update=%v", sawReread, sawUpdate)
	}
}

func TestRenderFPMPoolMaxChildren(t *testing.T) {
	s := &config.Server{Sites: []config.Site{{Domain: "app.example.com", DeployPath: "/srv/app", User: "webuser"}}}
	def, err := renderFPMPool(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(def), "pm.max_children = 10\n") {
		t.Errorf("default pool must keep pm.max_children = 10 (byte-identity):\n%s", def)
	}
	s.Tuning.PHPFPMMaxChildren = 16
	got, err := renderFPMPool(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "pm.max_children = 16\n") {
		t.Errorf("tuned pool must render pm.max_children = 16:\n%s", got)
	}
}

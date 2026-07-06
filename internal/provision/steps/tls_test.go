package steps

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func tlsServer() *config.Server {
	return &config.Server{
		Host: "203.0.113.10",
		PHP:  config.PHP{Version: "8.4", Source: "auto"},
		Sites: []config.Site{{
			Domain:     "app.example.com",
			DeployPath: "/home/deploy/myapp",
			SSL:        true,
			SSLEmail:   "ops@example.com",
		}},
	}
}

// withResolver swaps the DNS resolver for the duration of a test.
func withResolver(t *testing.T, fn func(host string) ([]string, error)) {
	t.Helper()
	old := resolveA
	resolveA = fn
	t.Cleanup(func() { resolveA = old })
}

func TestTLSRequiresSite(t *testing.T) {
	if got := TLS().Requires(); len(got) != 1 || got[0] != "site" {
		t.Fatalf("Requires() = %v, want [site]", got)
	}
}

// certbotCertsOutput mimics `certbot certificates` for a domain with the given
// expiry.
func certbotCertsOutput(domain string, expiry time.Time) string {
	return "Found the following certs:\n" +
		"  Certificate Name: " + domain + "\n" +
		"    Domains: " + domain + "\n" +
		"    Expiry Date: " + expiry.Format("2006-01-02 15:04:05-07:00") + " (VALID: 60 days)\n"
}

func TestTLSCheckSatisfiedWhenValidCertPresent(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{
		ExitCode: 0,
		Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
	})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0})
	hookStub(t, f)
	cr, err := TLS().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when a valid non-near-expiry cert exists; got %+v", cr)
	}
}

func TestTLSCheckUnsatisfiedWhenNoCert(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: "No certificates found.\n"})
	cr, err := TLS().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when no cert exists")
	}
}

func TestTLSCheckUnsatisfiedWhenNearExpiry(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{
		ExitCode: 0,
		Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(5*24*time.Hour)),
	})
	cr, err := TLS().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the cert is near expiry")
	}
}

func TestTLSApplyShortCircuitsOnValidCert(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{
		ExitCode: 0,
		Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
	})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // hook write-guard: absent
	// No certbot certonly, install, or reload stubbed: a present valid cert must
	// short-circuit Apply entirely.
	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "certonly") {
			t.Error("Apply must short-circuit on a present valid cert (no certonly)")
		}
	}
}

func TestTLSApplyUsesWebrootAndIssuesCert(t *testing.T) {
	s := tlsServer()
	withResolver(t, func(host string) ([]string, error) { return []string{s.Host}, nil })
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: "No certificates found.\n"})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y certbot", bssh.Result{})
	certonly := "certbot certonly --webroot -w /var/www/berth-acme/app.example.com -d app.example.com --agree-tos -m 'ops@example.com' --non-interactive"
	f.On(certonly, bssh.Result{ExitCode: 0})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	f.On("systemctl enable --now certbot.timer", bssh.Result{})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // hook write-guard: absent

	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var sawWebroot, sawHTTPSWrite bool
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "certonly") && strings.Contains(c.Cmd, "--webroot -w /var/www/berth-acme/app.example.com") {
			sawWebroot = true
		}
	}
	for _, w := range f.Writes() {
		if w.Path == nginxAvailablePath(s.Sites[0].Domain) && strings.Contains(string(w.Content), "listen 443") {
			sawHTTPSWrite = true
		}
	}
	if !sawWebroot {
		t.Error("expected certbot certonly --webroot against the ACME webroot")
	}
	if !sawHTTPSWrite {
		t.Error("expected the 443 nginx_https server block to be written")
	}
}

func TestTLSApplyHonorsStagingFlag(t *testing.T) {
	s := tlsServer()
	withResolver(t, func(host string) ([]string, error) { return []string{s.Host}, nil })
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: "No certificates found.\n"})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y certbot", bssh.Result{})
	certonly := "certbot certonly --webroot -w /var/www/berth-acme/app.example.com -d app.example.com --agree-tos -m 'ops@example.com' --non-interactive --staging"
	f.On(certonly, bssh.Result{ExitCode: 0})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	f.On("systemctl enable --now certbot.timer", bssh.Result{})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // hook write-guard: absent

	if err := TLS().Apply(context.Background(), provision.RunCtx{SSLStaging: true}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var sawStaging bool
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "certonly") && strings.Contains(c.Cmd, "--staging") {
			sawStaging = true
		}
	}
	if !sawStaging {
		t.Error("expected --staging to be appended when rc.SSLStaging is set")
	}
}

func TestDNSPointsAtHostHostnameHost(t *testing.T) {
	// config.Host may be a hostname, not just an IP literal. The preflight must
	// resolve both sides and compare their address sets, not string-match the
	// domain's resolved IPs against the hostname.
	withResolver(t, func(host string) ([]string, error) {
		switch host {
		case "app.example.com", "vps.example.net":
			return []string{"203.0.113.10"}, nil
		case "other.example.net":
			return []string{"198.51.100.1"}, nil
		}
		return nil, nil
	})
	if !dnsPointsAtHost("app.example.com", "vps.example.net") {
		t.Error("domain and hostname host resolving to the same IP must match")
	}
	if dnsPointsAtHost("app.example.com", "other.example.net") {
		t.Error("domain and hostname host resolving to different IPs must not match")
	}
}

func TestTLSApplySkipsOnDNSMismatch(t *testing.T) {
	s := tlsServer()
	// The domain resolves to a different IP than the server host.
	withResolver(t, func(host string) ([]string, error) {
		if host == s.Sites[0].Domain {
			return []string{"198.51.100.1"}, nil
		}
		return []string{s.Host}, nil
	})
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: "No certificates found.\n"})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 1}) // never installed: issuance was DNS-skipped
	// install/certonly are NOT stubbed: a DNS mismatch must skip issuance.
	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() should skip (not error) on DNS mismatch; got %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "certonly") {
			t.Error("certbot must not run when DNS does not point at the host")
		}
	}
	for _, w := range f.Writes() {
		if w.Path == certbotDeployHookPath {
			t.Error("hook must not be written on a DNS-skipped box where certbot was never installed")
		}
	}
}

func TestTLSSelfSignedIssuesWithoutCertbotOrDNS(t *testing.T) {
	s := tlsServer()
	s.Sites[0].SSLMode = "selfsigned"
	site := s.Sites[0]
	f := bssh.NewFakeRunner()
	// No cert yet.
	f.On("test -e "+shQuote(certFullchainPath(site)), bssh.Result{ExitCode: 1})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y openssl", bssh.Result{})
	f.On("install -d -m 0755 "+shQuote(certDir(site)), bssh.Result{})
	openssl := fmt.Sprintf("openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout %s -out %s -subj %s -addext %s",
		shQuote(certKeyPath(site)), shQuote(certFullchainPath(site)), shQuote("/CN="+site.Domain), shQuote("subjectAltName=DNS:"+site.Domain))
	f.On(openssl, bssh.Result{})
	f.On("chmod 600 "+shQuote(certKeyPath(site)), bssh.Result{})
	f.On("nginx -t", bssh.Result{})
	f.On("systemctl reload nginx", bssh.Result{})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // no lingering hook

	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "certbot") || strings.Contains(c.Cmd, "certonly") {
			t.Errorf("self-signed mode must not invoke certbot; got %q", c.Cmd)
		}
	}
	// The 443 block must be written, pointing at the self-signed cert dir.
	var wroteHTTPS bool
	for _, w := range f.Writes() {
		if w.Path == nginxAvailablePath(site.Domain) && strings.Contains(string(w.Content), certFullchainPath(site)) {
			wroteHTTPS = true
		}
	}
	if !wroteHTTPS {
		t.Error("expected the 443 block to be written pointing at the self-signed cert")
	}
}

func TestTLSSelfSignedCertValidUsesOpenssl(t *testing.T) {
	s := tlsServer()
	s.Sites[0].SSLMode = "selfsigned"
	site := s.Sites[0]
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(certFullchainPath(site)), bssh.Result{ExitCode: 0})
	f.On(fmt.Sprintf("openssl x509 -checkend %d -noout -in %s", int(certRenewWindow.Seconds()), shQuote(certFullchainPath(site))), bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // no lingering hook
	cr, err := TLS().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("self-signed cert valid beyond the window should be satisfied; got %+v", cr)
	}
}

// hookStub stubs the deploy-hook `cat` probe with the desired managed content.
func hookStub(t *testing.T, f *bssh.FakeRunner) {
	t.Helper()
	hook, err := renderCertbotDeployHook()
	if err != nil {
		t.Fatal(err)
	}
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 0, Stdout: string(hook)})
}

func TestTLSCheckUnsatisfiedWhenDeployHookMissing(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{
		ExitCode: 0,
		Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
	})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // absent
	cr, err := TLS().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("valid certs but no renewal deploy hook must be unsatisfied (renewals would never reload nginx)")
	}
}

func TestTLSCheckAbortsOnForeignDeployHook(t *testing.T) {
	s := tlsServer()
	stubs := func() *bssh.FakeRunner {
		f := bssh.NewFakeRunner()
		f.On("certbot certificates", bssh.Result{
			ExitCode: 0,
			Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
		})
		f.On("dpkg -s certbot", bssh.Result{ExitCode: 0})
		f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 0, Stdout: "service apache2 reload\n"}) // no marker
		return f
	}
	if _, err := TLS().Check(context.Background(), provision.RunCtx{}, s, stubs()); err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("foreign hook must abort without --force; got %v", err)
	}
	cr, err := TLS().Check(context.Background(), provision.RunCtx{Force: true}, s, stubs())
	if err != nil {
		t.Fatalf("with --force the foreign hook is reported unsatisfied, not an error; got %v", err)
	}
	if cr.Satisfied {
		t.Error("foreign hook under --force must be unsatisfied (Apply overwrites it)")
	}
}

func TestTLSApplyWritesDeployHook(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	// Valid cert: the per-site loop short-circuits; the hook must be written anyway.
	f.On("certbot certificates", bssh.Result{
		ExitCode: 0,
		Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
	})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // hook write-guard: absent
	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var hook *bssh.FileSpec
	writes := f.Writes()
	for i := range writes {
		if writes[i].Path == certbotDeployHookPath {
			hook = &writes[i]
		}
	}
	if hook == nil {
		t.Fatal("Apply must write the renewal deploy hook even when all certs are already valid")
	}
	if hook.Mode != 0o755 || hook.Owner != "root" || hook.Group != "root" || !hook.Sudo {
		t.Errorf("hook must be root:root 0755 sudo; got %+v", hook)
	}
	body := string(hook.Content)
	if !strings.HasPrefix(body, managedMarker+"\n") {
		t.Errorf("hook must start with the managed marker:\n%s", body)
	}
	if !strings.Contains(body, "nginx -t\nsystemctl reload nginx\n") {
		t.Errorf("hook must validate then reload nginx:\n%s", body)
	}
	if strings.Contains(body, "pipefail") || strings.Contains(body, "#!") {
		t.Errorf("hook must be strict POSIX sh with no shebang (marker is byte 0):\n%s", body)
	}
}

func TestTLSApplyRefusesForeignDeployHookWithoutForce(t *testing.T) {
	// tls.Check returns unsatisfied at the first invalid cert BEFORE classifying
	// the deploy hook, so Apply's write path must itself refuse to clobber a
	// foreign (unmanaged) hook unless --force.
	s := tlsServer()
	stubs := func() *bssh.FakeRunner {
		f := bssh.NewFakeRunner()
		// Valid cert: the per-site loop short-circuits; hook convergence follows.
		f.On("certbot certificates", bssh.Result{
			ExitCode: 0,
			Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
		})
		f.On("dpkg -s certbot", bssh.Result{ExitCode: 0})
		f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 0, Stdout: "service apache2 reload\n"}) // no marker
		return f
	}

	f := stubs()
	err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	for _, w := range f.Writes() {
		if w.Path == certbotDeployHookPath {
			t.Error("a foreign deploy hook must not be overwritten without --force")
		}
	}

	f2 := stubs()
	if err := TLS().Apply(context.Background(), provision.RunCtx{Force: true}, s, f2); err != nil {
		t.Fatalf("Apply() with --force error = %v", err)
	}
	var overwritten bool
	for _, w := range f2.Writes() {
		if w.Path == certbotDeployHookPath {
			overwritten = true
		}
	}
	if !overwritten {
		t.Error("--force must overwrite the foreign deploy hook")
	}
}

func TestTLSRemovesLingeringHookWhenNoLetsEncryptSites(t *testing.T) {
	s := tlsServer()
	s.Sites[0].SSLMode = "selfsigned"
	site := s.Sites[0]
	certStubs := func(f *bssh.FakeRunner) {
		f.On("test -e "+shQuote(certFullchainPath(site)), bssh.Result{ExitCode: 0})
		f.On(fmt.Sprintf("openssl x509 -checkend %d -noout -in %s", int(certRenewWindow.Seconds()), shQuote(certFullchainPath(site))), bssh.Result{ExitCode: 0})
	}
	lingering := bssh.Result{ExitCode: 0, Stdout: managedMarker + "\nset -eu\nnginx -t\nsystemctl reload nginx\n"}

	// Check: a lingering berth-managed hook with no LE site is drift.
	f := bssh.NewFakeRunner()
	certStubs(f)
	f.On("cat "+shQuote(certbotDeployHookPath), lingering)
	cr, err := TLS().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("lingering managed hook with no LE site must be unsatisfied (removal intent)")
	}

	// Apply removes it (guarded by the marker).
	f2 := bssh.NewFakeRunner()
	certStubs(f2)
	f2.On("cat "+shQuote(certbotDeployHookPath), lingering)
	f2.On("rm -f "+shQuote(certbotDeployHookPath), bssh.Result{})
	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f2); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var removed bool
	for _, c := range f2.Calls() {
		if c.Cmd == "rm -f "+shQuote(certbotDeployHookPath) {
			removed = true
		}
	}
	if !removed {
		t.Error("Apply must rm the lingering berth-managed hook")
	}

	// A FOREIGN hook (no marker) is never touched — rm is deliberately unstubbed.
	f3 := bssh.NewFakeRunner()
	certStubs(f3)
	f3.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 0, Stdout: "service apache2 reload\n"})
	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f3); err != nil {
		t.Fatalf("Apply() must leave a foreign hook alone; got %v", err)
	}
}

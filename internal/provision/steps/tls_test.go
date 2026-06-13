package steps

import (
	"context"
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
	// install/certonly are NOT stubbed: a DNS mismatch must skip issuance.
	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() should skip (not error) on DNS mismatch; got %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "certonly") {
			t.Error("certbot must not run when DNS does not point at the host")
		}
	}
}

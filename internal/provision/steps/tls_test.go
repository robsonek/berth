package steps

import (
	"context"
	"fmt"
	"reflect"
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
			DeployPath: "/var/www/myapp",
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

// certbotStagingCertsOutput mimics `certbot certificates` for a staging
// (test) certificate: certbot flags those with TEST_CERT in the expiry
// annotation.
func certbotStagingCertsOutput(domain string, expiry time.Time) string {
	return "Found the following certs:\n" +
		"  Certificate Name: " + domain + "\n" +
		"    Domains: " + domain + "\n" +
		"    Expiry Date: " + expiry.Format("2006-01-02 15:04:05-07:00") + " (INVALID: TEST_CERT)\n"
}

func TestTLSCheckSatisfiedWhenValidCertPresent(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	stubNoTLSOrphans(f)
	f.On("certbot certificates", bssh.Result{
		ExitCode: 0,
		Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
	})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	hookStub(t, f)
	f.On("systemctl is-active certbot.timer", bssh.Result{ExitCode: 0, Stdout: "active\n"})
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
	stubNoTLSOrphans(f)
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
	stubNoTLSOrphans(f)
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
	stubNoTLSOrphans(f)
	f.On("certbot certificates", bssh.Result{
		ExitCode: 0,
		Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
	})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // hook write-guard: absent
	f.On("systemctl enable --now certbot.timer", bssh.Result{ExitCode: 0})
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

// orderedRunner wraps a FakeRunner and appends every Run command and WriteFile
// path to ONE shared event slice, so cross-channel ordering (a write relative
// to the commands around it) can be asserted — FakeRunner.Calls() orders only
// Run, and a stamp invalidate moved AFTER the vhost write would still pass a
// Calls()-based check. (Pattern precedent: envWriteSpy in database_test.go.)
type orderedRunner struct {
	*bssh.FakeRunner
	events []string
}

func (o *orderedRunner) Run(ctx context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	o.events = append(o.events, "run:"+cmd)
	return o.FakeRunner.Run(ctx, cmd, stdin)
}

func (o *orderedRunner) WriteFile(ctx context.Context, spec bssh.FileSpec) error {
	o.events = append(o.events, "write:"+spec.Path)
	return o.FakeRunner.WriteFile(ctx, spec)
}

func TestTLSApplyUsesWebrootAndIssuesCert(t *testing.T) {
	s := tlsServer()
	withResolver(t, func(_ string) ([]string, error) { return []string{s.Host}, nil })
	f := bssh.NewFakeRunner()
	stubNoTLSOrphans(f)
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: "No certificates found.\n"})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y certbot", bssh.Result{})
	certonly := "certbot certonly --webroot -w /var/www/berth-acme/app.example.com -d app.example.com --cert-name app.example.com --agree-tos -m 'ops@example.com' --non-interactive --server https://acme-v02.api.letsencrypt.org/directory"
	f.On(certonly, bssh.Result{ExitCode: 0})
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{}) // swap invalidates first
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	f.On(markReloadedCmd("nginx"), bssh.Result{})
	f.On("systemctl enable --now certbot.timer", bssh.Result{})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // hook write-guard: absent
	spy := &orderedRunner{FakeRunner: f}

	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, spy); err != nil {
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
	// The swap participates in the transactional reload-stamp contract:
	// invalidate BEFORE the 443 vhost write, validate, reload, and mark only
	// after — otherwise a crash mid-swap could leave the stamp blessing a
	// running nginx that never loaded the 443 block. Asserted on the spy's
	// single event stream so the write's position is pinned too.
	idx := func(want string) int {
		for i, e := range spy.events {
			if e == want {
				return i
			}
		}
		return -1
	}
	invalidate := idx("run:rm -f " + shQuote("/var/lib/berth/nginx.reloaded"))
	write := idx("write:" + nginxAvailablePath(s.Sites[0].Domain))
	validate := idx("run:nginx -t")
	reload := idx("run:systemctl reload nginx")
	mark := idx("run:" + markReloadedCmd("nginx"))
	if invalidate < 0 || write < 0 || validate < 0 || reload < 0 || mark < 0 {
		t.Fatalf("missing swap events; invalidate=%d write=%d validate=%d reload=%d mark=%d\nevents: %v",
			invalidate, write, validate, reload, mark, spy.events)
	}
	if !(invalidate < write && write < validate && validate < reload && reload < mark) {
		t.Errorf("want invalidate < vhost write < nginx -t < reload < mark; got invalidate=%d write=%d validate=%d reload=%d mark=%d",
			invalidate, write, validate, reload, mark)
	}
}

func TestTLSApplyHonorsStagingFlag(t *testing.T) {
	s := tlsServer()
	withResolver(t, func(_ string) ([]string, error) { return []string{s.Host}, nil })
	f := bssh.NewFakeRunner()
	stubNoTLSOrphans(f)
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: "No certificates found.\n"})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y certbot", bssh.Result{})
	certonly := "certbot certonly --webroot -w /var/www/berth-acme/app.example.com -d app.example.com --cert-name app.example.com --agree-tos -m 'ops@example.com' --non-interactive --staging"
	f.On(certonly, bssh.Result{ExitCode: 0})
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	f.On(markReloadedCmd("nginx"), bssh.Result{})
	f.On("systemctl enable --now certbot.timer", bssh.Result{})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
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

func TestParseCertStatus(t *testing.T) {
	const expiry = "2026-08-01 12:00:00+00:00"
	cases := map[string]struct {
		annotation string
		wantTest   bool
	}{
		"production valid": {" (VALID: 60 days)", false},
		"staging":          {" (INVALID: TEST_CERT)", true},
		"staging combined": {" (INVALID: TEST_CERT, EXPIRED)", true},
		"no annotation":    {"", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := "Found the following certs:\n" +
				"  Certificate Name: app.example.com\n" +
				"    Domains: app.example.com\n" +
				"    Expiry Date: " + expiry + tc.annotation + "\n"
			got, testCert, ok := parseCertStatus(out, "app.example.com")
			if !ok {
				t.Fatal("expected ok=true")
			}
			want, _ := time.Parse("2006-01-02 15:04:05-07:00", expiry)
			if !got.Equal(want) {
				t.Errorf("expiry = %v, want %v", got, want)
			}
			if testCert != tc.wantTest {
				t.Errorf("testCert = %v, want %v", testCert, tc.wantTest)
			}
		})
	}
}

func TestParseCertStatusMatchesLineageNameNotSAN(t *testing.T) {
	// Two lineages carry the SAN; only the one whose Certificate Name equals
	// the domain (the /live/<domain> lineage nginx serves) must be selected,
	// regardless of block order.
	staging := "  Certificate Name: app.example.com\n    Domains: app.example.com\n    Expiry Date: 2026-08-01 12:00:00+00:00 (INVALID: TEST_CERT)\n"
	other := "  Certificate Name: app.example.com-0001\n    Domains: app.example.com\n    Expiry Date: 2027-01-01 12:00:00+00:00 (VALID: 200 days)\n"
	for _, out := range []string{"Found:\n" + staging + other, "Found:\n" + other + staging} {
		_, testCert, ok := parseCertStatus(out, "app.example.com")
		if !ok || !testCert {
			t.Errorf("must select the app.example.com lineage (testCert=true); got ok=%v testCert=%v", ok, testCert)
		}
	}
}

func TestParseCertStatusRejectsExactNameWithoutSAN(t *testing.T) {
	// A lineage named exactly app.example.com but issued for a different SAN
	// must NOT be accepted (nginx would serve a hostname-invalid cert).
	out := "Found:\n  Certificate Name: app.example.com\n    Domains: other.example.com\n    Expiry Date: 2027-01-01 12:00:00+00:00 (VALID: 200 days)\n"
	if _, _, ok := parseCertStatus(out, "app.example.com"); ok {
		t.Error("a lineage whose Domains omit the requested SAN must be rejected")
	}
}

func TestTLSCheckReplacesStagingCertOnProductionRun(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	stubNoTLSOrphans(f)
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: certbotStagingCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour))})
	cr, err := TLS().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("a staging cert under a production run must be unsatisfied")
	}
	if !strings.Contains(cr.Reason, "staging certificate") {
		t.Errorf("Reason %q should name the staging certificate", cr.Reason)
	}
}

func TestTLSCheckAcceptsStagingCertUnderStagingRun(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	stubNoTLSOrphans(f)
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: certbotStagingCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour))})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	hookStub(t, f)
	f.On("systemctl is-active certbot.timer", bssh.Result{ExitCode: 0, Stdout: "active\n"})
	cr, err := TLS().Check(context.Background(), provision.RunCtx{SSLStaging: true}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("a valid staging cert under --ssl-staging must satisfy Check; got %+v", cr)
	}
}

func TestTLSApplyForceRenewsStagingCertOnProductionRun(t *testing.T) {
	s := tlsServer()
	withResolver(t, func(_ string) ([]string, error) { return []string{s.Host}, nil })
	f := bssh.NewFakeRunner()
	stubNoTLSOrphans(f)
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: certbotStagingCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour))})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y certbot", bssh.Result{})
	certonly := "certbot certonly --webroot -w /var/www/berth-acme/app.example.com -d app.example.com --cert-name app.example.com --agree-tos -m 'ops@example.com' --non-interactive --server https://acme-v02.api.letsencrypt.org/directory --force-renewal"
	f.On(certonly, bssh.Result{ExitCode: 0})
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	f.On(markReloadedCmd("nginx"), bssh.Result{})
	f.On("systemctl enable --now certbot.timer", bssh.Result{})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1})
	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var sawReissue bool
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "certonly") {
			sawReissue = true
			if !strings.Contains(c.Cmd, "--force-renewal") {
				t.Errorf("certonly must carry --force-renewal when replacing a staging cert; got %q", c.Cmd)
			}
			if !strings.Contains(c.Cmd, "--server https://acme-v02.api.letsencrypt.org/directory") {
				t.Errorf("the replacement must select the production CA explicitly; got %q", c.Cmd)
			}
			if strings.Contains(c.Cmd, "--staging") {
				t.Errorf("the production replacement must not pass --staging; got %q", c.Cmd)
			}
		}
	}
	if !sawReissue {
		t.Error("expected a certonly re-issue for the staging certificate")
	}
}

func TestTLSApplyLeavesProductionCertUnderStagingRun(t *testing.T) {
	// A production cert (valid OR near expiry) must never be replaced by a
	// staging run — certbot.timer renews it against production on its own.
	for name, expiry := range map[string]time.Time{
		"valid":       time.Now().Add(60 * 24 * time.Hour),
		"near expiry": time.Now().Add(5 * 24 * time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			s := tlsServer()
			f := bssh.NewFakeRunner()
			stubNoTLSOrphans(f)
			f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: certbotCertsOutput(s.Sites[0].Domain, expiry)})
			f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
			f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1})
			f.On("systemctl enable --now certbot.timer", bssh.Result{ExitCode: 0})
			if err := TLS().Apply(context.Background(), provision.RunCtx{SSLStaging: true}, s, f); err != nil {
				t.Fatalf("Apply() error = %v", err)
			}
			for _, c := range f.Calls() {
				if strings.Contains(c.Cmd, "certonly") {
					t.Errorf("a production cert must never be issued/replaced by a staging run; ran %q", c.Cmd)
				}
			}
		})
	}
}

func TestTLSApplyRefusesStagingReplacementOnDNSMismatch(t *testing.T) {
	s := tlsServer()
	// Host-aware resolver so the domain and the host do NOT share an address
	// (a flat stub would make them intersect and read as a match).
	withResolver(t, func(host string) ([]string, error) {
		if host == s.Sites[0].Domain {
			return []string{"198.51.100.1"}, nil
		}
		return []string{s.Host}, nil
	})
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: certbotStagingCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour))})
	err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("Apply() = %v, want a hard error refusing to leave a staging cert when DNS does not point at the host", err)
	}
}

func TestTLSApplyErrorsOnDNSMismatchForExistingCertRenewal(t *testing.T) {
	// An existing production cert due for renewal (found=true, valid=false)
	// with a DNS mismatch must fail loudly rather than skip-and-report-Applied.
	s := tlsServer()
	withResolver(t, func(host string) ([]string, error) {
		if host == s.Sites[0].Domain {
			return []string{"198.51.100.1"}, nil
		}
		return []string{s.Host}, nil
	})
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(5*24*time.Hour))})
	err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("Apply() = %v, want a hard error when an existing cert cannot be renewed due to DNS mismatch", err)
	}
}

func TestTLSApplyErrorsOnExpiredProductionCertUnderStagingRun(t *testing.T) {
	// A staging run must not touch a production cert — but an already-expired
	// one it cannot repair, so that is a loud error, not a silent Satisfied.
	s := tlsServer()
	expiredProd := "Found:\n  Certificate Name: app.example.com\n    Domains: app.example.com\n    Expiry Date: " +
		time.Now().Add(-24*time.Hour).Format("2006-01-02 15:04:05-07:00") + " (INVALID: EXPIRED)\n"
	f := bssh.NewFakeRunner()
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: expiredProd})
	err := TLS().Apply(context.Background(), provision.RunCtx{SSLStaging: true}, s, f)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Apply() = %v, want a hard error: a staging run cannot renew an expired production cert", err)
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
	stubNoTLSOrphans(f)
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: "No certificates found.\n"})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 1}) // never installed: issuance was DNS-skipped
	// install/certonly are NOT stubbed: a DNS mismatch must skip issuance.
	var warned, unconverged []string
	rc := provision.RunCtx{
		Warn:            func(msg string) { warned = append(warned, msg) },
		NoteUnconverged: func(reason string) { unconverged = append(unconverged, reason) },
	}
	if err := TLS().Apply(context.Background(), rc, s, f); err != nil {
		t.Fatalf("Apply() should skip (not error) on DNS mismatch; got %v", err)
	}
	// The skip surfaces through the warning channel (renderer-visible), not a
	// raw fmt.Printf that bypasses both renderers.
	if len(warned) != 1 || !strings.Contains(warned[0], "does not resolve") || !strings.Contains(warned[0], s.Sites[0].Domain) {
		t.Errorf("want one warning naming the unresolved domain, got %q", warned)
	}
	// Skipping issuance knowingly leaves the run unconverged: the terminal
	// manifest step must be able to withhold its attestation.
	if len(unconverged) != 1 || !strings.Contains(unconverged[0], s.Sites[0].Domain) || !strings.Contains(unconverged[0], "does not resolve") {
		t.Errorf("DNS-skip must mark the run unconverged with a matching reason, got %q", unconverged)
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
	stubNoTLSOrphans(f)
	// No cert yet.
	f.On("test -e "+shQuote(certFullchainPath(site)), bssh.Result{ExitCode: 1})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y openssl", bssh.Result{})
	f.On("install -d -m 0755 "+shQuote(certDir(site)), bssh.Result{})
	openssl := fmt.Sprintf("openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout %s -out %s -subj %s -addext %s",
		shQuote(certKeyPath(site)), shQuote(certFullchainPath(site)), shQuote("/CN="+site.Domain), shQuote("subjectAltName=DNS:"+site.Domain))
	f.On(openssl, bssh.Result{})
	f.On("chmod 600 "+shQuote(certKeyPath(site)), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})
	f.On("nginx -t", bssh.Result{})
	f.On("systemctl reload nginx", bssh.Result{})
	f.On(markReloadedCmd("nginx"), bssh.Result{})
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
	stubNoTLSOrphans(f)
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
	stubNoTLSOrphans(f)
	f.On("certbot certificates", bssh.Result{
		ExitCode: 0,
		Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
	})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
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
		stubNoTLSOrphans(f)
		f.On("certbot certificates", bssh.Result{
			ExitCode: 0,
			Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
		})
		f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
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
	stubNoTLSOrphans(f)
	// Valid cert: the per-site loop short-circuits; the hook must be written anyway.
	f.On("certbot certificates", bssh.Result{
		ExitCode: 0,
		Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
	})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // hook write-guard: absent
	f.On("systemctl enable --now certbot.timer", bssh.Result{ExitCode: 0})
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

func TestTLSCheckUnsatisfiedWhenCertbotTimerInactive(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	stubNoTLSOrphans(f)
	// A valid production cert exists (per-site loop short-circuits)...
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour))})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	hookStub(t, f) // deploy hook present and current
	f.On("systemctl is-active certbot.timer", bssh.Result{ExitCode: 3, Stdout: "inactive\n"})
	cr, err := TLS().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("Check must be unsatisfied when certbot.timer is not active")
	}
	if !strings.Contains(cr.Reason, "certbot.timer") {
		t.Errorf("Reason %q should name certbot.timer", cr.Reason)
	}
}

func TestTLSApplyEnablesCertbotTimerWithoutIssuing(t *testing.T) {
	s := tlsServer()
	f := bssh.NewFakeRunner()
	stubNoTLSOrphans(f)
	// Valid cert -> per-site loop short-circuits, no certonly this run.
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour))})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 1}) // hook write-guard: absent
	f.On("systemctl enable --now certbot.timer", bssh.Result{ExitCode: 0})
	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var sawEnable, sawCertonly bool
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl enable --now certbot.timer" {
			sawEnable = true
		}
		if strings.Contains(c.Cmd, "certonly") {
			sawCertonly = true
		}
	}
	if !sawEnable {
		t.Error("Apply must enable certbot.timer even when no certificate is issued")
	}
	if sawCertonly {
		t.Error("no certonly should run for a valid cert")
	}
}

func TestTLSApplyRefusesForeignDeployHookWithoutForce(t *testing.T) {
	// tls.Check returns unsatisfied at the first invalid cert BEFORE classifying
	// the deploy hook, so Apply's write path must itself refuse to clobber a
	// foreign (unmanaged) hook unless --force.
	s := tlsServer()
	stubs := func() *bssh.FakeRunner {
		f := bssh.NewFakeRunner()
		stubNoTLSOrphans(f)
		// Valid cert: the per-site loop short-circuits; hook convergence follows.
		f.On("certbot certificates", bssh.Result{
			ExitCode: 0,
			Stdout:   certbotCertsOutput(s.Sites[0].Domain, time.Now().Add(60*24*time.Hour)),
		})
		f.On("dpkg -s certbot", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
		f.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 0, Stdout: "service apache2 reload\n"}) // no marker
		// Reached only on the --force path (the refusal aborts before the timer).
		f.On("systemctl enable --now certbot.timer", bssh.Result{ExitCode: 0})
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
	stubNoTLSOrphans(f)
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
	stubNoTLSOrphans(f2)
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
	stubNoTLSOrphans(f3)
	certStubs(f3)
	f3.On("cat "+shQuote(certbotDeployHookPath), bssh.Result{ExitCode: 0, Stdout: "service apache2 reload\n"})
	if err := TLS().Apply(context.Background(), provision.RunCtx{}, s, f3); err != nil {
		t.Fatalf("Apply() must leave a foreign hook alone; got %v", err)
	}
}

func TestParseRenewalConf(t *testing.T) {
	berth := `# renew_before_expiry = 30 days
version = 2.1.0
archive_dir = /etc/letsencrypt/archive/old.example.com
cert = /etc/letsencrypt/live/old.example.com/cert.pem

[renewalparams]
account = 0123456789abcdef
authenticator = webroot
server = https://acme-v02.api.letsencrypt.org/directory
webroot_path = /var/www/berth-acme/old.example.com,
[[webroot_map]]
old.example.com = /var/www/berth-acme/old.example.com
`
	foreignHookMention := `[renewalparams]
authenticator = nginx
installer = nginx
renew_hook = /usr/local/bin/sync-cdn /var/www/berth-acme/old.example.com
`
	foreignWebroot := `[renewalparams]
authenticator = webroot
webroot_path = /var/www/html,
[[webroot_map]]
foreign.example = /var/www/html
`
	mixedWebroots := `[renewalparams]
authenticator = webroot
webroot_path = /var/www/berth-acme/old.example.com, /var/www/html,
[[webroot_map]]
old.example.com = /var/www/berth-acme/old.example.com
foreign.example = /var/www/html
`
	multiBerth := `[renewalparams]
authenticator = webroot
webroot_path = /var/www/berth-acme/old.example.com, /var/www/berth-acme/kept.example.com,
[[webroot_map]]
old.example.com = /var/www/berth-acme/old.example.com
kept.example.com = /var/www/berth-acme/kept.example.com
`
	subdirWebroot := `[renewalparams]
authenticator = webroot
webroot_path = /var/www/berth-acme/old.example.com/public,
`
	trailingSlash := `[renewalparams]
authenticator = webroot
webroot_path = /var/www/berth-acme/old.example.com/,
`
	dotdotEscape := `[renewalparams]
authenticator = webroot
webroot_path = /var/www/berth-acme/..,
`
	namespaceRoot := `[renewalparams]
authenticator = webroot
webroot_path = /var/www/berth-acme,
`
	authenticatorConflict := `[renewalparams]
authenticator = dns-cloudflare
dns_cloudflare_credentials = /root/.secrets/cloudflare.ini
webroot_path = /var/www/berth-acme/old.example.com,

[stray]
authenticator = webroot
`
	hookOnly := `[renewalparams]
authenticator = webroot
renew_hook = /usr/local/bin/sync-cdn /var/www/berth-acme/old.example.com
`
	cases := []struct {
		name string
		conf string
		want renewalConf
	}{
		{"berth-issued", berth,
			renewalConf{owned: true, refs: []string{"old.example.com"}, domains: []string{"old.example.com"}}},
		{"foreign-authenticator-hook-mentions-namespace", foreignHookMention, renewalConf{}},
		{"foreign-webroot", foreignWebroot,
			renewalConf{domains: []string{"foreign.example"}}},
		{"mixed-webroots-foreign-but-refs-collected", mixedWebroots,
			renewalConf{refs: []string{"old.example.com"}, domains: []string{"old.example.com", "foreign.example"}}},
		{"multi-berth-webroots", multiBerth,
			renewalConf{owned: true, refs: []string{"old.example.com", "kept.example.com"}, domains: []string{"old.example.com", "kept.example.com"}}},
		// Nested value: not berth-shaped for ownership, but the top-level dir
		// it lands in IS a protection root — sweeping it would break this
		// surviving lineage's next renewal.
		{"subdir-webroot-is-foreign-but-protects", subdirWebroot,
			renewalConf{refs: []string{"old.example.com"}}},
		// A trailing slash cleans to berth's exact namespace shape: owned.
		{"trailing-slash-is-berth-shaped", trailingSlash,
			renewalConf{owned: true, refs: []string{"old.example.com"}}},
		// path.Clean resolves the escape to /var/www: fully foreign, no refs.
		{"dotdot-escapes-namespace", dotdotEscape, renewalConf{}},
		// The namespace root itself: every webroot dir potentially serves it.
		{"namespace-root-is-unbounded", namespaceRoot, renewalConf{unbounded: true}},
		// Conflicting authenticator evidence is never ownership, wherever the
		// webroot line sits; the berth-webroot reference still protects.
		{"authenticator-conflict-is-foreign", authenticatorConflict,
			renewalConf{refs: []string{"old.example.com"}}},
		// webroot authenticator but no webroot value at all (hook-only conf):
		// no evidence berth issued it, nothing to protect.
		{"hook-only-no-webroot-values", hookOnly, renewalConf{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseRenewalConf(c.conf); !reflect.DeepEqual(got, c.want) {
				t.Errorf("parseRenewalConf = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestListRenewalConfs(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/a.example.com.conf\n/etc/letsencrypt/renewal/b.example.com.conf\n"})
	got, err := listRenewalConfs(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/etc/letsencrypt/renewal/a.example.com.conf", "/etc/letsencrypt/renewal/b.example.com.conf"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("listRenewalConfs = %v, want %v", got, want)
	}
}

func TestListRenewalConfsErrorsOnFindFailure(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{ExitCode: 1, Stderr: "find: permission denied"})
	if _, err := listRenewalConfs(context.Background(), f); err == nil {
		t.Fatal("a failing find must be an error, not an empty result")
	}
}

func TestCertNameBase(t *testing.T) {
	cases := []struct {
		name string
		base string
		ok   bool
	}{
		{"kept.example.com-0001", "kept.example.com", true},
		{"kept.example.com-1", "kept.example.com", true},
		{"kept.example.com", "", false},
		{"kept.example.com-", "", false},
		{"kept.example.com-abc", "", false},
		{"kept.example.com-00a1", "", false},
		{"-0001", "", false},
	}
	for _, c := range cases {
		if base, ok := certNameBase(c.name); base != c.base || ok != c.ok {
			t.Errorf("certNameBase(%q) = (%q, %v), want (%q, %v)", c.name, base, ok, c.base, c.ok)
		}
	}
}

// stubNoTLSOrphans satisfies the orphan-sweep discovery probes with empty
// results — "no TLS leftovers on this host". Discovery runs FIRST in Check
// and again in Apply, so every tls test needs these.
func stubNoTLSOrphans(f *bssh.FakeRunner) {
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi", bssh.Result{})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
}

// tlsNoSSLServer is a config whose only site does not use SSL — the tls step
// still runs (always registered) and owns only sweep + hook drift-removal.
func tlsNoSSLServer() *config.Server {
	return &config.Server{
		Host: "203.0.113.10",
		PHP:  config.PHP{Version: "8.4", Source: "auto"},
		Sites: []config.Site{{
			Domain:     "kept.example.com",
			DeployPath: "/var/www/kept",
		}},
	}
}

// berthRenewalConf renders a minimal berth-shaped renewal conf whose webroot
// references are the given domains.
func berthRenewalConf(domains ...string) string {
	b := "[renewalparams]\nauthenticator = webroot\nwebroot_path = "
	for i, d := range domains {
		if i > 0 {
			b += ", "
		}
		b += "/var/www/berth-acme/" + d
	}
	b += ",\n[[webroot_map]]\n"
	for _, d := range domains {
		b += d + " = /var/www/berth-acme/" + d + "\n"
	}
	return b
}

func TestTLSCheckFlagsOrphanTLSArtifacts(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/old.example.com.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/old.example.com.conf'",
		bssh.Result{Stdout: berthRenewalConf("old.example.com")})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/var/www/berth-acme/old.example.com\n/var/www/berth-acme/kept.example.com\n"})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/etc/ssl/berth/old.example.com\n"})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("orphan TLS artifacts must be unsatisfied drift")
	}
	want := []string{
		"certbot delete --cert-name old.example.com",
		"rm -rf /var/www/berth-acme/old.example.com",
		"rm -rf /etc/ssl/berth/old.example.com",
	}
	if !reflect.DeepEqual(res.Changes, want) {
		t.Errorf("Changes = %v, want %v", res.Changes, want)
	}
	if !strings.Contains(res.Reason, "no longer in the config") {
		t.Errorf("Reason should explain the orphan drift; got %q", res.Reason)
	}
}

func TestTLSCheckIgnoresForeignLineage(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/foreign.example.conf\n"})
	// Foreign lineage whose renew_hook merely MENTIONS berth's namespace: the
	// parser must not read that as ownership.
	f.On("cat '/etc/letsencrypt/renewal/foreign.example.conf'",
		bssh.Result{Stdout: "[renewalparams]\nauthenticator = nginx\nrenew_hook = /usr/local/bin/sync-cdn /var/www/berth-acme/old.example.com\n"})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("a foreign lineage must be invisible to the sweep; got unsatisfied: %s %v", res.Reason, res.Changes)
	}
}

func TestTLSCheckShieldedLineageProtectsItsWebroots(t *testing.T) {
	// A suffixed lineage (certbot's -0001) referencing BOTH a configured and a
	// removed domain survives (shield), and BOTH its webroot dirs survive with
	// it — deleting old.example.com's webroot would break the surviving
	// lineage's next renewal. Only the self-signed dir of the removed domain
	// is genuinely orphaned here.
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/old.example.com-0001.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/old.example.com-0001.conf'",
		bssh.Result{Stdout: berthRenewalConf("old.example.com", "kept.example.com")})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/var/www/berth-acme/old.example.com\n/var/www/berth-acme/kept.example.com\n"})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/etc/ssl/berth/old.example.com\n"})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("the removed domain's self-signed dir is still orphaned drift")
	}
	want := []string{"rm -rf /etc/ssl/berth/old.example.com"}
	if !reflect.DeepEqual(res.Changes, want) {
		t.Errorf("Changes = %v, want %v (no certbot delete, no webroot removal)", res.Changes, want)
	}
}

func TestTLSCheckMapKeyShieldsSuffixedLineage(t *testing.T) {
	// certbot's collision-suffixed lineage kept.example.com-0001 serves the
	// CONFIGURED kept.example.com through a shared webroot dir: neither the
	// cert name nor the ref ("shared") is a desired domain, but the
	// [[webroot_map]] KEY is — the lineage AND its webroot dir must survive.
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/kept.example.com-0001.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/kept.example.com-0001.conf'",
		bssh.Result{Stdout: "[renewalparams]\nauthenticator = webroot\nwebroot_path = /var/www/berth-acme/shared,\n[[webroot_map]]\nkept.example.com = /var/www/berth-acme/shared\n"})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/var/www/berth-acme/shared\n"})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("a lineage serving a configured domain via its webroot_map key must survive with its webroot dir; got %s %v", res.Reason, res.Changes)
	}
}

func TestTLSCheckSuffixBaseShieldsLineageWithoutMap(t *testing.T) {
	// Same collision-suffixed lineage but with NO [[webroot_map]] at all: the
	// cert name minus the -0001 suffix is the configured domain, which alone
	// must shield it (certbot names the retry lineage after the domain).
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/kept.example.com-0001.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/kept.example.com-0001.conf'",
		bssh.Result{Stdout: "[renewalparams]\nauthenticator = webroot\nwebroot_path = /var/www/berth-acme/shared,\n"})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/var/www/berth-acme/shared\n"})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("a lineage whose suffix-stripped name is a configured domain must survive; got %s %v", res.Reason, res.Changes)
	}
}

func TestTLSCheckSweepsSuffixedLineageWithUndesiredBase(t *testing.T) {
	// Negative control for the suffix shield: old.example.com-0001 whose base,
	// refs and map keys are ALL undesired is still a genuine orphan.
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/old.example.com-0001.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/old.example.com-0001.conf'",
		bssh.Result{Stdout: berthRenewalConf("old.example.com")})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/var/www/berth-acme/old.example.com\n"})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("a suffixed lineage serving nothing configured is orphaned drift")
	}
	want := []string{
		"certbot delete --cert-name old.example.com-0001",
		"rm -rf /var/www/berth-acme/old.example.com",
	}
	if !reflect.DeepEqual(res.Changes, want) {
		t.Errorf("Changes = %v, want %v", res.Changes, want)
	}
}

func TestTLSCheckNestedForeignWebrootProtectsTopLevelDir(t *testing.T) {
	// A surviving foreign lineage whose webroot value is NESTED under a berth
	// webroot dir (…/old.example.com/public) still renews out of that
	// directory: the top-level dir must survive the sweep even though
	// old.example.com is not configured. Only the genuinely unreferenced
	// gone.example.com dir is orphaned.
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/legacy.example.net.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/legacy.example.net.conf'",
		bssh.Result{Stdout: "[renewalparams]\nauthenticator = webroot\nwebroot_path = /var/www/berth-acme/old.example.com/public,\n"})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/var/www/berth-acme/old.example.com\n/var/www/berth-acme/gone.example.com\n"})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("the unreferenced gone.example.com webroot dir is still orphaned drift")
	}
	want := []string{"rm -rf /var/www/berth-acme/gone.example.com"}
	if !reflect.DeepEqual(res.Changes, want) {
		t.Errorf("Changes = %v, want %v (the nested-referenced dir survives, the lineage is never deleted)", res.Changes, want)
	}
}

func TestTLSCheckUnboundedWebrootSuppressesWebrootSweep(t *testing.T) {
	// A surviving foreign conf whose webroot value is the namespace root
	// itself potentially serves EVERY webroot dir: the whole webroot-dir
	// sweep must be suppressed for the run, while the independent
	// self-signed-dir sweep still works.
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/foreign.example.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/foreign.example.conf'",
		bssh.Result{Stdout: "[renewalparams]\nauthenticator = webroot\nwebroot_path = /var/www/berth-acme,\n"})
	// Stubbed so an implementation that still lists (but must not collect)
	// fails on the assertion below, not on an unstubbed probe.
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/var/www/berth-acme/a.example.com\n/var/www/berth-acme/b.example.com\n"})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/etc/ssl/berth/old.example.com\n"})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("the orphan self-signed dir is still drift")
	}
	want := []string{"rm -rf /etc/ssl/berth/old.example.com"}
	if !reflect.DeepEqual(res.Changes, want) {
		t.Errorf("Changes = %v, want %v (no webroot removal may be planned under an unbounded reference)", res.Changes, want)
	}
}

func TestTLSCheckMergesOrphanAndLingeringHookDrift(t *testing.T) {
	// Dry-run completeness for the post-loop tail: with BOTH an orphan
	// self-signed dir and a lingering berth-managed deploy hook, Check must
	// report one unsatisfied result carrying both actions (sweep first —
	// Apply's order), not hide the hook removal behind an orphan-only return.
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi", bssh.Result{})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/etc/ssl/berth/old.example.com\n"})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'",
		bssh.Result{ExitCode: 0, Stdout: managedMarker + "\nset -eu\nnginx -t\nsystemctl reload nginx\n"})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("orphan artifacts plus a lingering hook must be unsatisfied drift")
	}
	want := []string{
		"rm -rf /etc/ssl/berth/old.example.com",
		"remove certbot renewal deploy hook",
	}
	if !reflect.DeepEqual(res.Changes, want) {
		t.Errorf("Changes = %v, want %v (both drift classes, sweep first)", res.Changes, want)
	}
	for _, part := range []string{
		"TLS artifacts linger for sites no longer in the config",
		"certbot deploy hook lingers but no site uses Let's Encrypt",
	} {
		if !strings.Contains(res.Reason, part) {
			t.Errorf("Reason %q must name both drift classes (missing %q)", res.Reason, part)
		}
	}
}

func TestTLSCheckErrorsWhenLineageConfUnreadable(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/old.example.com.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/old.example.com.conf'",
		bssh.Result{ExitCode: 2, Stderr: "cat: I/O error"})
	// Deliberately stub everything a WRONG implementation (treating the read
	// failure as "foreign" and carrying on) would hit next — the test must
	// fail on the assertion below, not on an unstubbed command.
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})

	_, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err == nil || !strings.Contains(err.Error(), "read /etc/letsencrypt/renewal/old.example.com.conf") {
		t.Fatalf("an unreadable renewal conf must be a loud error naming the file, never 'foreign' or 'orphan'; got %v", err)
	}
}

func TestTLSCheckAppendsOrphanChangesToCertDrift(t *testing.T) {
	// Dry-run completeness: a cert-drift early return must still preview the
	// sweep, or --dry-run hides destructive removals a real run performs.
	s := tlsServer() // one Let's Encrypt site, app.example.com
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/old.example.com.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/old.example.com.conf'",
		bssh.Result{Stdout: berthRenewalConf("old.example.com")})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/var/www/berth-acme/old.example.com\n"})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi", bssh.Result{})
	f.On("certbot certificates", bssh.Result{ExitCode: 0, Stdout: "No certificates found.\n"})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("missing cert must stay unsatisfied")
	}
	joined := strings.Join(res.Changes, "\n")
	if !strings.Contains(joined, "issue letsencrypt certificate for app.example.com") {
		t.Errorf("cert-drift changes lost: %v", res.Changes)
	}
	for _, want := range []string{
		"certbot delete --cert-name old.example.com",
		"rm -rf /var/www/berth-acme/old.example.com",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("orphan action %q must be appended to the cert-drift changes; got %v", want, res.Changes)
		}
	}
}

func TestTLSCheckNoSSLCleanHostConvergedReason(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubNoTLSOrphans(f)
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})

	res, err := TLS().Check(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("clean no-SSL host must be satisfied; got %s %v", res.Reason, res.Changes)
	}
	if res.Reason != "TLS state converged" {
		t.Errorf("Reason = %q; a no-SSL run must not claim %q", res.Reason, "valid certificates present")
	}
	if got := len(f.Calls()); got != 4 {
		t.Errorf("clean no-SSL Check cost %d probes, want 4 (three discovery + hook)", got)
	}
}

// stubOrphanTLSHost stubs a host holding all three orphan classes for
// old.example.com plus the no-LE deploy-hook fallthrough of Apply.
func stubOrphanTLSHost(f *bssh.FakeRunner) {
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/old.example.com.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/old.example.com.conf'",
		bssh.Result{Stdout: berthRenewalConf("old.example.com")})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/var/www/berth-acme/old.example.com\n"})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/etc/ssl/berth/old.example.com\n"})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})
}

func TestTLSApplySweepsOrphanArtifactsInOrder(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubOrphanTLSHost(f)
	f.On("dpkg -s certbot", bssh.Result{Stdout: "Status: install ok installed\n"})
	f.On("certbot delete --cert-name 'old.example.com' -n", bssh.Result{})
	f.On("rm -rf '/var/www/berth-acme/old.example.com'", bssh.Result{})
	f.On("rm -rf '/etc/ssl/berth/old.example.com'", bssh.Result{})

	if err := TLS().Apply(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f); err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "certbot delete --cert-name 'old.example.com' -n",
			"rm -rf '/var/www/berth-acme/old.example.com'",
			"rm -rf '/etc/ssl/berth/old.example.com'":
			order = append(order, c.Cmd)
		}
	}
	want := []string{
		"certbot delete --cert-name 'old.example.com' -n",
		"rm -rf '/var/www/berth-acme/old.example.com'",
		"rm -rf '/etc/ssl/berth/old.example.com'",
	}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("sweep order = %v, want %v (lineage first: it references the webroot)", order, want)
	}
}

func TestTLSApplyCertbotDeleteFailureIsFatal(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubOrphanTLSHost(f)
	f.On("dpkg -s certbot", bssh.Result{Stdout: "Status: install ok installed\n"})
	f.On("certbot delete --cert-name 'old.example.com' -n",
		bssh.Result{ExitCode: 1, Stderr: "No certificate found with name old.example.com"})

	err := TLS().Apply(context.Background(), provision.RunCtx{}, tlsNoSSLServer(), f)
	if err == nil || !strings.Contains(err.Error(), "certbot delete") {
		t.Fatalf("a failing certbot delete must abort the step; got %v", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "rm -rf") {
			t.Fatalf("nothing may be removed after the delete failed; got %q", c.Cmd)
		}
	}
}

func TestTLSApplyKeepsLineageWebrootPairWhenCertbotMissing(t *testing.T) {
	// The suffixed-lineage variant on purpose: the kept lineage is named
	// old.example.com-0001 but references old.example.com's webroot — the
	// pairing must follow the REFERENCES, not the cert name.
	f := bssh.NewFakeRunner()
	f.On("if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi",
		bssh.Result{Stdout: "/etc/letsencrypt/renewal/old.example.com-0001.conf\n"})
	f.On("cat '/etc/letsencrypt/renewal/old.example.com-0001.conf'",
		bssh.Result{Stdout: berthRenewalConf("old.example.com")})
	f.On("if [ -d '/var/www/berth-acme' ]; then find '/var/www/berth-acme' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/var/www/berth-acme/old.example.com\n"})
	f.On("if [ -d '/etc/ssl/berth' ]; then find '/etc/ssl/berth' -mindepth 1 -maxdepth 1 -type d; fi",
		bssh.Result{Stdout: "/etc/ssl/berth/old.example.com\n"})
	f.On("cat '/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload'", bssh.Result{ExitCode: 1})
	f.On("dpkg -s certbot", bssh.Result{ExitCode: 1})
	f.On("rm -rf '/etc/ssl/berth/old.example.com'", bssh.Result{})

	var warned, unconverged []string
	rc := provision.RunCtx{
		Warn:            func(msg string) { warned = append(warned, msg) },
		NoteUnconverged: func(reason string) { unconverged = append(unconverged, reason) },
	}
	if err := TLS().Apply(context.Background(), rc, tlsNoSSLServer(), f); err != nil {
		t.Fatal(err)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "certbot is not installed") {
		t.Errorf("expected one certbot-missing warning; got %v", warned)
	}
	if len(unconverged) != 1 {
		t.Errorf("a knowingly kept orphan lineage must mark the run unconverged; got %v", unconverged)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "rm -rf '/var/www/berth-acme/old.example.com'" {
			t.Fatal("the kept lineage's REFERENCED webroot must be kept as a pair")
		}
		if strings.HasPrefix(c.Cmd, "certbot delete") {
			t.Fatal("no certbot delete may run without certbot")
		}
	}
}

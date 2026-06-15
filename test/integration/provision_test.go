//go:build integration

// Package integration holds berth's release-gate smoke test. It is guarded by
// the `integration` build tag so the default `go test ./...` never compiles or
// runs it. Provide a real Debian 13 target via BERTH_TEST_SERVER to exercise it;
// see README.md for how to stand one up (LXD/Incus container or ephemeral VPS).
package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/provision/steps"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// TestProvisionFreshDebian13 provisions a throwaway host described by
// BERTH_TEST_SERVER (a servers/*.yml) and asserts the end state. Self-signed TLS
// runs by default (no DNS needed); Let's Encrypt is opt-in via
// BERTH_TEST_SKIP_SSL=false (it needs real public DNS).
//
// End state asserted (design §9):
//   - `systemctl is-active nginx php{ver}-fpm mariadb valkey-server` all "active"
//   - `nginx -t` exits 0
//   - `mysql --protocol=socket -e 'SELECT 1'` exits 0
//   - HTTP GET / returns a response (502 is acceptable pre-deploy: no app yet)
//   - self-signed cert present + valid beyond the renew window (when configured)
func TestProvisionFreshDebian13(t *testing.T) {
	cfgPath := os.Getenv("BERTH_TEST_SERVER")
	if cfgPath == "" {
		t.Skip("set BERTH_TEST_SERVER to a Debian 13 target to run")
	}

	srv, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config %q: %v", cfgPath, err)
	}

	// A long-lived context: provisioning a fresh box (apt, builds) is slow.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Connect exactly as `berth provision` does, but without interactive TOFU:
	// the test harness is non-interactive, so the target's key must already be
	// pinned (ssh.fingerprint) or present in the known_hosts file.
	client, err := bssh.Connect(ctx, srv, bssh.HostKeyPolicy{
		Pinned:     srv.SSH.Fingerprint,
		KnownHosts: knownHostsPath(),
	})
	if err != nil {
		t.Fatalf("connect to %s: %v", srv.Host, err)
	}
	defer client.Close()

	// Self-signed TLS needs no public DNS, so it runs by default. Let's Encrypt
	// (HTTP-01/ACME) needs real DNS, so it is opt-in via BERTH_TEST_SKIP_SSL=false.
	// BERTH_TEST_SKIP_SSL=true forces a hard skip even for self-signed.
	sslEnv := os.Getenv("BERTH_TEST_SKIP_SSL")
	skipSSL := sslEnv == "true" || (sslEnv == "" && !anySiteSelfSigned(srv))

	// Run the full pipeline.
	red := secret.NewRedactor()
	eng := provision.New(steps.Pipeline(srv, red, skipSSL)...)
	events, err := eng.Run(ctx, srv, client, provision.Options{
		Force:      os.Getenv("BERTH_TEST_FORCE") == "true",
		SSLStaging: os.Getenv("BERTH_TEST_SSL_STAGING") == "true",
	})
	if err != nil {
		t.Fatalf("pipeline pre-flight: %v", err)
	}
	for ev := range events {
		switch ev.Kind {
		case provision.EventFailed:
			t.Fatalf("step %q failed: %v", ev.Step, ev.Err)
		case provision.EventApplied:
			t.Logf("applied %s", ev.Step)
		case provision.EventSatisfied:
			t.Logf("satisfied %s", ev.Step)
		}
	}

	// Assert the documented end state over the same connection.
	assertServicesActive(ctx, t, client, srv)
	assertExitZero(ctx, t, client, "nginx -t", "sudo nginx -t")
	if srv.Database.Engine == "postgres" {
		assertExitZero(ctx, t, client, "postgres peer",
			`sudo -u postgres psql -tAc 'SELECT 1'`)
	} else {
		assertExitZero(ctx, t, client, "mariadb socket",
			`sudo mysql --protocol=socket -e 'SELECT 1'`)
	}
	assertHTTPServes(t, "http://"+net.JoinHostPort(srv.Host, "80")+"/", false)

	// When TLS was actually provisioned, the site must answer over HTTPS too.
	if !skipSSL && anySiteSSL(srv) {
		assertHTTPServes(t, "https://"+srv.Host+"/", anySiteSelfSigned(srv))
	}

	// Self-signed certs are asserted directly on disk (no public CA to validate).
	if !skipSSL && anySiteSelfSigned(srv) {
		assertSelfSignedCert(ctx, t, client, srv)
	}

	// Load-bearing invariants (iter-4): cross-tenant isolation (multi-site only),
	// per-site DB auth over the app's real path + Postgres e2e, hardening end-state.
	// Fresh context — a slow first provision may have nearly exhausted ctx (30m); these
	// are quick read-only checks (mirrors assertSecondRunIdempotent's fresh deadline).
	invCtx, invCancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer invCancel()
	assertMultiSiteIsolation(invCtx, t, client, srv)
	assertDBAuth(invCtx, t, client, srv)
	assertHardeningEndState(invCtx, t, client, srv)

	// iter-5: runtime + deploy-reload (#36) and apt provenance (#35).
	assertRuntime(invCtx, t, client, srv)
	assertOpcacheEffective(invCtx, t, client, srv)
	assertAptProvenance(invCtx, t, client, srv)
	// useHTTPS mirrors the test's TLS path: self-signed/LE provisioned => https, else http.
	assertDeployReload(invCtx, t, client, srv, !skipSSL && anySiteSSL(srv))

	// berth's defining contract: an immediate second run must change nothing
	// (every step satisfied), except preflight which re-runs apt by design.
	assertSecondRunIdempotent(t, eng, srv, client)
}

// assertSecondRunIdempotent runs the pipeline a SECOND time over the same
// connection and asserts berth's defining contract: every step is already
// satisfied. The SOLE exception is `preflight`, the only AlwaysRun step (it
// re-runs `apt-get update` every run by design). Any other EventApplied, or any
// EventFailed, on the second run is an idempotency regression and fails the test.
func assertSecondRunIdempotent(t *testing.T, eng *provision.Engine, srv *config.Server, client *bssh.Client) {
	t.Helper()
	// Fresh deadline: the shared test context may be nearly exhausted by a slow
	// first provision; the second run is read-only Checks + preflight apt and is fast.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	events, err := eng.Run(ctx, srv, client, provision.Options{SSLStaging: os.Getenv("BERTH_TEST_SSL_STAGING") == "true"})
	if err != nil {
		t.Fatalf("second run pre-flight: %v", err)
	}
	for ev := range events {
		switch ev.Kind {
		case provision.EventFailed:
			t.Fatalf("second run: step %q failed: %v", ev.Step, ev.Err)
		case provision.EventApplied:
			if ev.Step != "preflight" {
				t.Errorf("second run: step %q re-applied — berth is not idempotent (only preflight may re-apply)", ev.Step)
			}
		}
	}
}

// anySiteSSL reports whether any configured site enables TLS.
func anySiteSSL(srv *config.Server) bool {
	for _, site := range srv.Sites {
		if site.SSL {
			return true
		}
	}
	return false
}

// anySiteSelfSigned reports whether any site uses a self-signed certificate
// (CertMode "selfsigned"), which needs no DNS/ACME and so can be exercised in
// the gate by default.
func anySiteSelfSigned(srv *config.Server) bool {
	for _, site := range srv.Sites {
		if site.SSL && site.CertMode() == "selfsigned" {
			return true
		}
	}
	return false
}

// assertServicesActive fails unless every core service is reported "active".
func assertServicesActive(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	units := []string{
		"nginx",
		fmt.Sprintf("php%s-fpm", srv.PHP.Version),
		dbServiceName(srv.Database.Engine),
	}
	if srv.Valkey {
		units = append(units, "valkey-server")
	}
	for _, unit := range units {
		res, err := c.Run(ctx, "systemctl is-active "+unit, nil)
		if err != nil {
			t.Fatalf("is-active %s: %v", unit, err)
		}
		if got := strings.TrimSpace(res.Stdout); got != "active" {
			t.Errorf("service %s: is-active = %q (exit %d, stderr %q), want \"active\"",
				unit, got, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
	}
}

// assertSelfSignedCert verifies each self-signed site has a berth-managed
// certificate under /etc/ssl/berth/<domain> (site.go certDir) that is valid
// beyond the renewal window — the same condition the tls step's certValid uses,
// so a re-run's tls.Check stays satisfied.
func assertSelfSignedCert(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	const renewWindowSecs = 30 * 24 * 60 * 60 // mirror steps.certRenewWindow (30 days)
	for _, site := range srv.Sites {
		if !site.SSL || site.CertMode() != "selfsigned" {
			continue
		}
		fullchain := "/etc/ssl/berth/" + site.Domain + "/fullchain.pem"
		assertExitZero(ctx, t, c, "self-signed cert present "+site.Domain,
			"test -e "+fullchain)
		assertExitZero(ctx, t, c, "self-signed cert valid "+site.Domain,
			fmt.Sprintf("openssl x509 -checkend %d -noout -in %s", renewWindowSecs, fullchain))
	}
}

// assertHTTPServes fails if the server never answers, or answers with an
// unexpected server error. A 502 (Bad Gateway) is accepted: nginx is up and
// correctly proxying to PHP-FPM, but no app is deployed yet ("Primary script
// unknown"). Any other 5xx signals a real nginx/PHP-FPM regression and fails.
// insecureTLS skips certificate verification, required when probing a
// self-signed (intentionally untrusted) HTTPS vhost.
func assertHTTPServes(t *testing.T, url string, insecureTLS bool) {
	t.Helper()
	cl := &http.Client{
		Timeout: 10 * time.Second,
		// Do not follow redirects: an HTTP probe should see the 301 to HTTPS.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if insecureTLS {
		cl.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	resp, err := cl.Get(url)
	if err != nil {
		t.Errorf("GET %s: %v", url, err)
		return
	}
	defer resp.Body.Close()
	t.Logf("GET %s -> %d", url, resp.StatusCode)
	if resp.StatusCode >= 500 && resp.StatusCode != http.StatusBadGateway {
		t.Errorf("GET %s -> %d, want < 500 or the pre-deploy 502", url, resp.StatusCode)
	}
}

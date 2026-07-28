//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertRuntime verifies the deployer-handoff runtime, each invariant on its OWN gate:
// every site has an FPM socket; queue-enabled sites have a DORMANT worker (supervisor
// active + all processes STOPPED, never FATAL/BACKOFF); scheduler-enabled sites have a
// valid managed scheduler cron.
func assertRuntime(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	anyQueue := false
	for _, site := range srv.Sites {
		if srv.QueueEnabled(site) {
			anyQueue = true
		}
	}
	if anyQueue {
		assertExitZero(ctx, t, c, "supervisor active", "systemctl is-active supervisor")
	}
	for _, site := range srv.Sites {
		pool := config.PoolName(site.Domain)
		// Every site has its own FPM pool socket.
		assertExitZero(ctx, t, c, "fpm socket "+site.Domain, "test -S /run/php/berth-"+pool+".sock")

		if srv.QueueEnabled(site) {
			prog := "berth-" + pool
			st, err := c.Run(ctx, "sudo supervisorctl status '"+prog+":*'", nil)
			if err != nil {
				t.Fatalf("%s: supervisorctl status: %v", site.Domain, err)
			}
			if !supervisorAllStopped(st.Stdout) {
				t.Errorf("%s: worker %s not fully dormant (want every process STOPPED):\n%s", site.Domain, prog, st.Stdout)
			}
		}

		if srv.SchedulerEnabled(site) {
			cron := "/etc/cron.d/berth-site-" + pool
			if perm, err := c.Run(ctx, "stat -c '%U:%G %a' "+cron, nil); err != nil {
				t.Fatalf("%s: stat cron: %v", site.Domain, err)
			} else if got := strings.TrimSpace(perm.Stdout); got != "root:root 644" {
				t.Errorf("%s: cron %s perms = %q, want root:root 644", site.Domain, cron, got)
			}
			body, err := c.Run(ctx, "cat "+cron, nil)
			if err != nil {
				t.Fatalf("%s: cat cron: %v", site.Domain, err)
			}
			wantLine := "* * * * * " + srv.SiteUser(site)
			if !strings.Contains(body.Stdout, "managed by berth") ||
				!strings.Contains(body.Stdout, wantLine) ||
				!strings.Contains(body.Stdout, "artisan schedule:run") {
				t.Errorf("%s: cron %s is not the managed scheduler cron (want %q + artisan schedule:run):\n%s", site.Domain, cron, wantLine, body.Stdout)
			}
		}
	}
}

// assertOpcacheEffective verifies OPcache validate_timestamps=0 is effective for the FPM
// SAPI. The CLI default SAPI shows the un-overridden value, so the FPM conf.d is loaded
// explicitly via PHP_INI_SCAN_DIR (verified live). `php-fpm -i` works too — the newer
// assertPHPTuning probes through it — this predates that finding.
func assertOpcacheEffective(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	ver := srv.PHP.Version
	dropin := "/etc/php/" + ver + "/fpm/conf.d/99-berth-opcache.ini"
	if body, err := c.Run(ctx, "cat "+dropin, nil); err != nil {
		t.Fatalf("read opcache drop-in: %v", err)
	} else if body.ExitCode != 0 || !strings.Contains(body.Stdout, "managed by berth") {
		t.Errorf("opcache drop-in %s missing or unmanaged (exit %d)", dropin, body.ExitCode)
	}
	info, err := c.Run(ctx, "PHP_INI_SCAN_DIR=/etc/php/"+ver+"/fpm/conf.d php"+ver+" -i", nil)
	if err != nil {
		t.Fatalf("php -i (fpm scan dir): %v", err)
	}
	if !strings.Contains(info.Stdout, "opcache.validate_timestamps => Off") {
		t.Errorf("FPM opcache.validate_timestamps not effective Off:\n%s", grepLines(info.Stdout, "opcache"))
	}
	if !strings.Contains(info.Stdout, "opcache.enable => On") {
		t.Errorf("FPM opcache.enable not On:\n%s", grepLines(info.Stdout, "opcache"))
	}
}

// assertDeployReload validates the deploy-reload contract: each site user is authorized
// to reload FPM via the version-stable wrapper (`sudo /bin/sh
// /usr/local/sbin/berth-reload-fpm` — the exact line deployers hard-code; the PHP
// version never appears in it), the same command with an extra argument is DENIED
// (sudoers exact-args matching — the property that makes a /bin/sh grant safe), and
// running the graceful reload keeps EVERY site's FPM socket up and a .php request
// answering per site (404 fine, never a persistent 5xx gateway error). Each site is
// probed with its own Host header (and SNI over TLS) on the scheme its TLS state
// provably serves (siteHTTPSProbe).
func assertDeployReload(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server, sslExplicit bool) {
	t.Helper()
	ver := srv.PHP.Version
	// Resolve each site's probe scheme ONCE from the actual on-host cert state:
	// siteHTTPSProbe costs an SSH round-trip and cert state cannot change during
	// the reload, so probing it inside the retry loop would only add noise.
	type probeScheme struct{ useHTTPS, insecureTLS bool }
	schemes := make(map[string]probeScheme, len(srv.Sites))
	for _, site := range srv.Sites {
		useHTTPS, insecureTLS := siteHTTPSProbe(ctx, t, c, site, sslExplicit)
		schemes[site.Domain] = probeScheme{useHTTPS, insecureTLS}
	}
	seen := map[string]bool{}
	for _, site := range srv.Sites {
		user := srv.SiteUser(site)
		if seen[user] {
			continue
		}
		seen[user] = true
		assertExitZero(ctx, t, c, user+" authorized to reload fpm",
			fmt.Sprintf("sudo -u %s sudo -n -l /bin/sh /usr/local/sbin/berth-reload-fpm", user))
		// Exact-args property, pinned live: the grant authorizes ONLY the bare
		// wrapper invocation, so the same command with an appended argument must
		// be denied by sudoers (exit non-zero, nothing executed).
		if res, err := c.Run(ctx, fmt.Sprintf("sudo -u %s sudo -n /bin/sh /usr/local/sbin/berth-reload-fpm extra-arg", user), nil); err != nil {
			t.Fatalf("%s: extra-arg denial probe: %v", user, err)
		} else if res.ExitCode == 0 {
			t.Errorf("%s: sudoers accepted the reload wrapper WITH an extra argument — the exact-args boundary is broken", user)
		}
		if res, err := c.Run(ctx, fmt.Sprintf("sudo -u %s sudo -n /bin/sh /usr/local/sbin/berth-reload-fpm", user), nil); err != nil {
			t.Fatalf("%s: deploy reload: %v", user, err)
		} else if res.ExitCode != 0 {
			t.Errorf("%s: deploy reload exit %d: %s", user, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
	}
	// After the reload the FPM stack must settle: active, EVERY site socket present, and a
	// .php request (through FastCGI) answers for EVERY site. Retry — reload returns early.
	ok := eventually(20*time.Second, func() bool {
		a, _ := c.Run(ctx, "systemctl is-active php"+ver+"-fpm", nil)
		if strings.TrimSpace(a.Stdout) != "active" {
			return false
		}
		for _, site := range srv.Sites {
			s, _ := c.Run(ctx, "test -S /run/php/berth-"+config.PoolName(site.Domain)+".sock", nil)
			if s.ExitCode != 0 {
				return false
			}
			sc := schemes[site.Domain]
			if !phpPathServes(srv.Host, site.Domain, sc.useHTTPS, sc.insecureTLS) {
				return false
			}
		}
		return true
	})
	if !ok {
		t.Errorf("FPM did not settle after the deploy reload (active / all sockets / .php request per site)")
	}
}

// phpPathServes GETs a .php URI (forcing nginx -> FastCGI -> FPM) through the host
// address with the tenant's identity forced (Host header; SNI ServerName over TLS)
// and reports whether the FPM chain answered: a 404 for the missing script is fine;
// 502/503/504 means FPM is down, and a 301 is the HTTPS-redirect vhost answering
// WITHOUT reaching FPM (the scheme comes from on-host cert state, so a 301 here
// means the probe was misrouted, never liveness). This is a reload-LIVENESS probe
// only — it requests a deliberately missing path, so it cannot prove WHICH vhost
// or pool answered; the per-tenant routing/pool proof lives in
// assertSiteServesOwnContent.
func phpPathServes(host, domain string, useHTTPS, insecureTLS bool) bool {
	scheme := "http"
	tr := &http.Transport{}
	if useHTTPS {
		scheme = "https"
		tr.TLSClientConfig = &tls.Config{ServerName: domain, InsecureSkipVerify: insecureTLS}
	}
	cl := &http.Client{Timeout: 10 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest(http.MethodGet, scheme+"://"+host+"/berth-probe.php", nil)
	if err != nil {
		return false
	}
	req.Host = domain
	resp, err := cl.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode != http.StatusMovedPermanently &&
		resp.StatusCode != http.StatusBadGateway &&
		resp.StatusCode != http.StatusServiceUnavailable &&
		resp.StatusCode != http.StatusGatewayTimeout
}

// siteCertInstalled reports whether the site's certificate is actually present
// on the host, probing the same fullchain path the cert-aware site step keys
// its vhost rendering on (mirrors the steps package's certDir/certFullchainPath:
// self-signed under /etc/ssl/berth/<domain>, Let's Encrypt under
// /etc/letsencrypt/live/<domain>).
func siteCertInstalled(ctx context.Context, t *testing.T, c *bssh.Client, site config.Site) bool {
	t.Helper()
	dir := "/etc/letsencrypt/live/" + site.Domain
	if site.CertMode() == "selfsigned" {
		dir = "/etc/ssl/berth/" + site.Domain
	}
	res, err := c.Run(ctx, "test -e "+shQuote(dir+"/fullchain.pem"), nil)
	if err != nil {
		t.Fatalf("%s: probe cert presence: %v", site.Domain, err)
	}
	return res.ExitCode == 0
}

// siteHTTPSProbe reports whether a site's tenant probe must run over HTTPS, and
// whether certificate verification must be skipped. Eligibility is decided from
// the ACTUAL on-host cert state, never from how this run was configured: the
// site step's vhost is cert-aware, so once a certificate exists the vhost
// serves HTTPS and 301s all HTTP — even on a later BERTH_TEST_SKIP_SSL=true
// re-run — while a cert-less site (e.g. Let's Encrypt whose issuance was
// skipped without DNS) serves the HTTP-only vhost. CA verification is applied
// only on a real-DNS Let's Encrypt run (BERTH_TEST_SKIP_SSL=false): self-signed
// certs are untrusted by design, and without that explicit opt-in a public CA
// chain has no DNS guarantee to validate against.
func siteHTTPSProbe(ctx context.Context, t *testing.T, c *bssh.Client, site config.Site, sslExplicit bool) (useHTTPS, insecureTLS bool) {
	t.Helper()
	if !site.SSL || !siteCertInstalled(ctx, t, c, site) {
		return false, false
	}
	if site.CertMode() == "selfsigned" || !sslExplicit {
		return true, true
	}
	return true, false
}

// shQuote single-quotes s for a POSIX shell (mirrors the unexported steps.shQuote).
// Config validation already rejects shell metacharacters in deploy_path and domains;
// quoting the staged-probe paths is defense in depth.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// assertSiteServesOwnContent stages a tenant-unique PHP marker under the site's
// docroot, fetches it through the host address while forcing the tenant's identity
// (HTTP Host header; SNI ServerName over TLS), and requires the EXACT marker back.
// A status code cannot prove which vhost answered (berth writes no default_server,
// so nginx answers with the FIRST vhost for any unmatched name, and every SSL vhost
// 301s identically), so only tenant-unique content proves routing — and because the
// marker is executed by PHP-FPM, the response also proves the request hit THIS
// site's pool/socket, not a sibling's. Over TLS the peer certificate's DNS SANs
// must additionally include the domain, proving SNI selected the tenant's
// certificate (berth's self-signed certs carry the domain SAN, so this holds under
// insecureTLS too).
//
// The split for SSL sites is deliberate: their HTTP side 301s to HTTPS by design,
// and the redirect echoes the REQUEST $host — identical for every vhost — so an
// HTTP-side check cannot discriminate tenants and is not attempted; the HTTPS
// marker is the proof. Tenants without an installed certificate (where the
// cert-aware site step keeps the HTTP-only vhost) prove routing over HTTP.
//
// Staging runs entirely AS THE SITE USER: the current/ tree is tenant-controlled
// and outside the appdirs symlink guard, so root must never create or write
// under it (a symlinked current/public could redirect root's write anywhere).
// As the site user, even a check-to-use race lands inside the tenant's own
// privilege. The marker leaf is random per run and created with noclobber, so a
// reused box's real app file is never replaced or deleted.
func assertSiteServesOwnContent(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server, site config.Site, useHTTPS, insecureTLS bool) {
	t.Helper()
	user := srv.SiteUser(site)
	marker := "berth-tenant-" + config.PoolName(site.Domain)
	docroot := site.DeployPath + "/current/public"
	var leafRand [8]byte
	if _, err := rand.Read(leafRand[:]); err != nil {
		t.Fatalf("%s: probe leaf entropy: %v", site.Domain, err)
	}
	leaf := "berth-tenant-probe-" + hex.EncodeToString(leafRand[:]) + ".php"
	probe := docroot + "/" + leaf

	// Symlink-escape guard: resolve the docroot as the site user and refuse to
	// stage unless it stays under deploy_path.
	if res, err := c.Run(ctx, "sudo -u "+user+" realpath -m "+shQuote(docroot), nil); err != nil {
		t.Fatalf("%s: resolve docroot: %v", site.Domain, err)
	} else if res.ExitCode != 0 {
		t.Fatalf("%s: resolve docroot: exit %d, stderr %q", site.Domain, res.ExitCode, strings.TrimSpace(res.Stderr))
	} else if resolved := strings.TrimSpace(res.Stdout); !strings.HasPrefix(resolved, site.DeployPath+"/") {
		t.Fatalf("%s: docroot %s resolves to %q, outside deploy_path %s — refusing to stage the probe",
			site.Domain, docroot, resolved, site.DeployPath)
	}
	// Collision guard before cleanup is armed: after this check, anything at the
	// probe path was created by this run, so the deferred rm -f is provably safe.
	if res, err := c.Run(ctx, "sudo -u "+user+" test -e "+shQuote(probe), nil); err != nil {
		t.Fatalf("%s: probe collision check: %v", site.Domain, err)
	} else if res.ExitCode == 0 {
		t.Fatalf("%s: probe path %s already exists — refusing to touch it", site.Domain, probe)
	}

	// Stage: a pre-deploy box has no current/ tree — create the missing levels
	// as the site user (as a deploy would), remembering exactly which levels
	// were missing so cleanup removes only what this run created (a deployed
	// box's current/ tree is never touched).
	var createdDirs []string
	for _, dir := range []string{site.DeployPath + "/current", docroot} {
		if res, err := c.Run(ctx, "sudo -u "+user+" test -e "+shQuote(dir), nil); err != nil {
			t.Fatalf("%s: probe %s: %v", site.Domain, dir, err)
		} else if res.ExitCode != 0 {
			createdDirs = append(createdDirs, dir)
		}
	}
	if len(createdDirs) > 0 {
		if res, err := c.Run(ctx, "sudo -u "+user+" mkdir -p "+shQuote(docroot), nil); err != nil {
			t.Fatalf("%s: create %s: %v", site.Domain, docroot, err)
		} else if res.ExitCode != 0 {
			t.Fatalf("%s: create %s: exit %d, stderr %q", site.Domain, docroot, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
	}
	// Cleanup even on failure, as the site user, on a FRESH context (the test
	// context may already be cancelled or exhausted), failing the test loudly on
	// any error: the unique probe file, then rmdir — empty-only, never rm -rf —
	// each level this run created, deepest first. Registered before the probe
	// write so a failed write still removes the directories.
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if res, err := c.Run(cctx, "sudo -u "+user+" rm -f "+shQuote(probe), nil); err != nil {
			t.Errorf("%s: cleanup %s: %v", site.Domain, probe, err)
		} else if res.ExitCode != 0 {
			t.Errorf("%s: cleanup %s: exit %d, stderr %q", site.Domain, probe, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		for i := len(createdDirs) - 1; i >= 0; i-- {
			if res, err := c.Run(cctx, "sudo -u "+user+" rmdir "+shQuote(createdDirs[i]), nil); err != nil {
				t.Errorf("%s: cleanup %s: %v", site.Domain, createdDirs[i], err)
			} else if res.ExitCode != 0 {
				t.Errorf("%s: cleanup %s: exit %d, stderr %q", site.Domain, createdDirs[i], res.ExitCode, strings.TrimSpace(res.Stderr))
			}
		}
	}()
	// Write the marker as the site user via stdin; noclobber (set -C) keeps the
	// creation exclusive even against a race after the collision check.
	writeCmd := "sudo -u " + user + " sh -c " + shQuote("set -C; umask 022; cat > "+shQuote(probe))
	if res, err := c.Run(ctx, writeCmd, []byte("<?php echo '"+marker+"';\n")); err != nil {
		t.Fatalf("%s: write probe: %v", site.Domain, err)
	} else if res.ExitCode != 0 {
		t.Fatalf("%s: write probe %s: exit %d, stderr %q", site.Domain, probe, res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	scheme, port := "http", "80"
	tr := &http.Transport{}
	if useHTTPS {
		scheme, port = "https", "443"
		tr.TLSClientConfig = &tls.Config{ServerName: site.Domain, InsecureSkipVerify: insecureTLS}
	}
	cl := &http.Client{Timeout: 10 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	url := scheme + "://" + net.JoinHostPort(srv.Host, port) + "/" + leaf
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("%s: build request: %v", site.Domain, err)
	}
	req.Host = site.Domain
	resp, err := cl.Do(req)
	if err != nil {
		t.Errorf("%s: GET %s (Host %s): %v", site.Domain, url, site.Domain, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	t.Logf("GET %s (Host %s) -> %d %q", url, site.Domain, resp.StatusCode, body)
	if resp.StatusCode != http.StatusOK || string(body) != marker {
		t.Errorf("%s: want 200 %q, got %d %q — tenant routing or pool selection is broken",
			site.Domain, marker, resp.StatusCode, body)
	}
	if useHTTPS {
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
			t.Errorf("%s: no TLS peer certificate", site.Domain)
		} else if err := resp.TLS.PeerCertificates[0].VerifyHostname(site.Domain); err != nil {
			t.Errorf("%s: SNI served a certificate not valid for the domain: %v", site.Domain, err)
		}
	}
}

// eventually polls check until it returns true or the deadline passes.
func eventually(d time.Duration, check func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if check() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return check()
}

// grepLines returns the lines of s containing substr (for readable assertion failures).
func grepLines(s, substr string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, substr) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

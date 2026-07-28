package steps

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

// certRenewWindow is the lead time before expiry within which a certificate is
// treated as needing renewal.
const certRenewWindow = 30 * 24 * time.Hour

// certbotDeployHookPath is the global certbot deploy hook. Certbot runs every
// executable in this directory after EACH successful renewal (of any cert), so
// one managed script covers all present and future certificates on the host.
const certbotDeployHookPath = "/etc/letsencrypt/renewal-hooks/deploy/berth-nginx-reload"

// renderCertbotDeployHook renders the static nginx validate-then-reload hook.
func renderCertbotDeployHook() ([]byte, error) {
	return templates.Render("certbot_deploy_hook.sh.tmpl", nil)
}

// anyLetsEncrypt reports whether any site wants a Let's Encrypt certificate —
// the only cert mode that uses certbot and therefore needs the renewal hook.
func anyLetsEncrypt(s *config.Server) bool {
	for _, site := range s.Sites {
		if site.SSL && site.CertMode() == "letsencrypt" {
			return true
		}
	}
	return false
}

// resolveA resolves the A/AAAA records for a host. It is a package-level var so
// tests can stub DNS without a real lookup; production uses the system resolver.
var resolveA = net.LookupHost

type tls struct{}

// TLS obtains and installs a Let's Encrypt certificate via the dedicated ACME
// webroot, then swaps nginx to the 443 server block (design §4, §6.4). It is
// idempotent: a present, non-near-expiry certificate short-circuits Apply.
func TLS() provision.Step { return tls{} }

func (tls) Name() string       { return "tls" }
func (tls) Requires() []string { return []string{"site"} }

func (tls) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	for _, site := range s.Sites {
		if !site.SSL {
			continue
		}
		found, valid, expired, testCert, err := certStatus(ctx, r, site)
		if err != nil {
			return provision.CheckResult{}, err
		}
		// A staging cert under a production run must be replaced. Conversely a
		// production cert satisfies a --ssl-staging run (a staging run must
		// never issue or replace it) — UNLESS it has already expired, which a
		// staging run cannot repair, so that is a loud error.
		needsReplace := testCert && !rc.SSLStaging
		prodCertUnderStagingRun := rc.SSLStaging && found && !testCert && site.CertMode() == "letsencrypt"
		if prodCertUnderStagingRun && expired {
			return provision.CheckResult{}, fmt.Errorf("production certificate for %s has expired and a --ssl-staging run cannot renew it; re-run without --ssl-staging", site.Domain)
		}
		if (valid && !needsReplace) || prodCertUnderStagingRun {
			continue
		}
		reason := "no valid certificate for " + site.Domain
		changes := []string{"issue " + site.CertMode() + " certificate for " + site.Domain, "install 443 server block"}
		if needsReplace {
			reason = "staging certificate present for " + site.Domain + "; will re-issue against production"
			changes = []string{"re-issue production certificate for " + site.Domain + " (--force-renewal)", "install 443 server block"}
		}
		return provision.CheckResult{Satisfied: false, Reason: reason, Changes: changes}, nil
	}
	// Renewal deploy hook: without it a renewed cert lands on disk while nginx
	// keeps serving the old one from memory (expired at ~day 90). Same gate as
	// Apply — anyLetsEncrypt AND certbot installed — so a DNS-skipped box where
	// certbot never got installed cannot flap between the two.
	if anyLetsEncrypt(s) {
		installed, err := pkgInstalled(ctx, r, "certbot")
		if err != nil {
			return provision.CheckResult{}, err
		}
		if installed {
			hook, err := renderCertbotDeployHook()
			if err != nil {
				return provision.CheckResult{}, err
			}
			state, err := checkManagedFile(ctx, r, certbotDeployHookPath, hook)
			if err != nil {
				return provision.CheckResult{}, err
			}
			ok, err := managedFileSatisfied(state, certbotDeployHookPath, rc.Force)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if !ok {
				return provision.CheckResult{
					Satisfied: false,
					Reason:    "certbot renewal deploy hook missing or out of date",
					Changes:   []string{"install certbot renewal deploy hook (nginx validate + reload)"},
				}, nil
			}
			// The renewal timer must actually be running, or a cert left
			// untouched (e.g. a near-expiry production cert under --ssl-staging,
			// which we deliberately do not reissue) will silently expire.
			active, err := r.Run(ctx, "systemctl is-active certbot.timer", nil)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if strings.TrimSpace(active.Stdout) != "active" {
				return provision.CheckResult{
					Satisfied: false,
					Reason:    "certbot.timer is not active; automatic Let's Encrypt renewal is disabled",
					Changes:   []string{"enable certbot.timer"},
				}, nil
			}
		}
	} else {
		present, err := managedFilePresent(ctx, r, certbotDeployHookPath)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if present {
			return provision.CheckResult{
				Satisfied: false,
				Reason:    "certbot deploy hook lingers but no site uses Let's Encrypt",
				Changes:   []string{"remove certbot renewal deploy hook"},
			}, nil
		}
	}
	return provision.CheckResult{Satisfied: true, Reason: "valid certificates present"}, nil
}

func (st tls) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	for _, site := range s.Sites {
		if !site.SSL {
			continue
		}
		found, valid, expired, testCert, err := certStatus(ctx, r, site)
		if err != nil {
			return err
		}
		needsReplace := testCert && !rc.SSLStaging
		prodCertUnderStagingRun := rc.SSLStaging && found && !testCert && site.CertMode() == "letsencrypt"
		if prodCertUnderStagingRun && expired {
			return fmt.Errorf("production certificate for %s has expired and a --ssl-staging run cannot renew it; re-run without --ssl-staging", site.Domain)
		}
		if (valid && !needsReplace) || prodCertUnderStagingRun {
			continue
		}
		if site.CertMode() == "selfsigned" {
			// No DNS / ACME needed for a self-signed certificate.
			if err := st.issueSelfSigned(ctx, s, site, r); err != nil {
				return err
			}
			continue
		}
		// Let's Encrypt: the domain must resolve to this host or certbot will
		// fail the ACME challenge.
		if !dnsPointsAtHost(site.Domain, s.Host) {
			if found {
				// A certificate already exists (staging cert to replace, or a
				// production cert due for renewal): skipping would report
				// Applied while the host stays unconverged, drifting forever.
				// Only a genuine fresh box (no cert yet) may skip with a warning.
				return fmt.Errorf("cannot issue or renew the certificate for %s: it does not resolve to %s; point DNS at the host (or, for a staging cert, re-run with --ssl-staging to keep it)", site.Domain, s.Host)
			}
			// Fresh issue on a box without DNS yet: skip with a warning (the
			// operator may be staging behind a proxy); do not abort the run.
			// The run is now knowingly unconverged — the terminal manifest
			// step must withhold its "full pipeline completed" attestation.
			rc.Warnf("skipping TLS for %s: it does not resolve to %s", site.Domain, s.Host)
			rc.MarkUnconverged(fmt.Sprintf("tls skipped issuance for %s: it does not resolve to %s", site.Domain, s.Host))
			continue
		}
		if err := st.issue(ctx, rc, s, site, r, needsReplace); err != nil {
			return err
		}
	}
	// Converge the renewal deploy hook regardless of whether any cert was
	// (re)issued this run — an already-provisioned LE host must pick it up.
	if anyLetsEncrypt(s) {
		installed, err := pkgInstalled(ctx, r, "certbot")
		if err != nil {
			return err
		}
		if installed {
			hook, err := renderCertbotDeployHook()
			if err != nil {
				return err
			}
			if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
				Path: certbotDeployHookPath, Content: hook,
				Owner: "root", Group: "root", Mode: 0o755, Sudo: true,
			}); err != nil {
				return fmt.Errorf("write certbot deploy hook: %w", err)
			}
			// Ensure automatic renewal is running even when no cert was issued
			// this run (issue() only reaches this for a freshly issued cert).
			if res, err := r.Run(ctx, "systemctl enable --now certbot.timer", nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("enable certbot.timer: %s", res.Stderr)
			}
		}
	} else {
		// Drift-removal, marker-guarded: never delete a foreign file, even
		// with --force (same contract as the scheduler cron removal).
		present, err := managedFilePresent(ctx, r, certbotDeployHookPath)
		if err != nil {
			return err
		}
		if present {
			if res, err := r.Run(ctx, "rm -f "+shQuote(certbotDeployHookPath), nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("remove certbot deploy hook: %s", res.Stderr)
			}
		}
	}
	return nil
}

// issue installs certbot, obtains a certificate via the ACME webroot, swaps in
// the 443 server block, validates and reloads nginx, and ensures the renew timer.
func (tls) issue(ctx context.Context, rc provision.RunCtx, s *config.Server, site config.Site, r bssh.Runner, forceRenewal bool) error {
	if err := aptInstall(ctx, r, "certbot"); err != nil {
		return fmt.Errorf("install certbot: %w", err)
	}

	certonly := fmt.Sprintf(
		"certbot certonly --webroot -w %s -d %s --cert-name %s --agree-tos -m %s --non-interactive",
		acmeWebroot(site.Domain), site.Domain, site.Domain, shQuote(site.SSLEmail))
	if rc.SSLStaging {
		certonly += " --staging"
	} else {
		// Select the production CA explicitly: --force-renewal is not a CA
		// selector, and certbot derives TEST_CERT from the lineage's saved
		// server, so a replacement without this would stay staging and loop.
		certonly += " --server https://acme-v02.api.letsencrypt.org/directory"
	}
	if forceRenewal {
		// Replacing a still-valid staging certificate: without this, certbot
		// answers "not yet due for renewal" and exits 0 without re-issuing.
		certonly += " --force-renewal"
	}
	if res, err := r.Run(ctx, certonly, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("certbot certonly for %s: %s", site.Domain, res.Stderr)
	}
	if err := swapToHTTPS(ctx, r, s, site); err != nil {
		return err
	}
	// Ensure automatic renewal is enabled.
	if res, err := r.Run(ctx, "systemctl enable --now certbot.timer", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("enable certbot.timer: %s", res.Stderr)
	}
	return nil
}

// issueSelfSigned generates a self-signed certificate (no DNS / ACME) and swaps
// nginx to the 443 block. Useful for staging or domains without public DNS.
func (tls) issueSelfSigned(ctx context.Context, s *config.Server, site config.Site, r bssh.Runner) error {
	if err := aptInstall(ctx, r, "openssl"); err != nil {
		return fmt.Errorf("install openssl: %w", err)
	}
	dir := certDir(site)
	if res, err := r.Run(ctx, "install -d -m 0755 "+shQuote(dir), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("create cert dir %s: %s", dir, res.Stderr)
	}
	gen := fmt.Sprintf("openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout %s -out %s -subj %s -addext %s",
		shQuote(certKeyPath(site)), shQuote(certFullchainPath(site)),
		shQuote("/CN="+site.Domain), shQuote("subjectAltName=DNS:"+site.Domain))
	if res, err := r.Run(ctx, gen, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("openssl self-signed for %s: %s", site.Domain, res.Stderr)
	}
	if res, err := r.Run(ctx, "chmod 600 "+shQuote(certKeyPath(site)), nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("chmod key for %s: %s", site.Domain, res.Stderr)
	}
	return swapToHTTPS(ctx, r, s, site)
}

// swapToHTTPS writes a site's 443 server block (shared renderer with the site
// step so a re-run sees no drift), validates, and reloads nginx. It follows
// the transactional reload-stamp contract for the shared nginx unit:
// invalidate before the vhost write, mark only after the successful reload —
// without the stamp the vhost just written would be newer than the stamp and
// the next site.Check would schedule one spurious reload.
func swapToHTTPS(ctx context.Context, r bssh.Runner, s *config.Server, site config.Site) error {
	https, err := renderNginxHTTPS(s, site)
	if err != nil {
		return fmt.Errorf("render https config for %s: %w", site.Domain, err)
	}
	if err := invalidateReloaded(ctx, r, "nginx"); err != nil {
		return err
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: nginxAvailablePath(site.Domain), Content: https,
		Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write https config for %s: %w", site.Domain, err)
	}
	if res, err := r.Run(ctx, "nginx -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("nginx -t failed after enabling TLS, refusing to reload: %s", res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload nginx", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload nginx: %s", res.Stderr)
	}
	return markReloaded(ctx, r, "nginx")
}

// certStatus reports whether a site's certificate exists (found), is valid
// beyond the renew window, is already expired, and is a certbot test (staging)
// certificate. valid and expired are distinct: a cert inside the renew window
// but not yet past its notAfter is (valid=false, expired=false). Let's Encrypt
// certs are read from `certbot certificates`; self-signed certs keep their
// direct `openssl x509 -checkend` probe, are never test certs, and report
// expired=false (the expired/staging distinction only gates the letsencrypt
// asymmetry, which never applies to self-signed).
func certStatus(ctx context.Context, r bssh.Runner, site config.Site) (found, valid, expired, testCert bool, err error) {
	if site.CertMode() == "selfsigned" {
		exists, err := fileExists(ctx, r, certFullchainPath(site))
		if err != nil || !exists {
			return false, false, false, false, err
		}
		secs := int(certRenewWindow.Seconds())
		res, err := r.Run(ctx, fmt.Sprintf("openssl x509 -checkend %d -noout -in %s", secs, shQuote(certFullchainPath(site))), nil)
		if err != nil {
			return false, false, false, false, err
		}
		return true, res.ExitCode == 0, false, false, nil // exit 0 => valid beyond the window
	}
	res, err := r.Run(ctx, "certbot certificates", nil)
	if err != nil {
		return false, false, false, false, err
	}
	if res.ExitCode != 0 {
		return false, false, false, false, nil // certbot not installed yet / no certs
	}
	expiry, testCert, ok := parseCertStatus(res.Stdout, site.Domain)
	if !ok {
		return false, false, false, false, nil
	}
	return true, time.Until(expiry) > certRenewWindow, time.Until(expiry) <= 0, testCert, nil
}

// parseCertStatus scans `certbot certificates` output for the lineage whose
// Certificate Name equals domain — the /live/<domain> lineage nginx serves,
// NOT merely any lineage listing the SAN (certbot may keep app.example.com and
// app.example.com-0001). It additionally requires that block's Domains: to
// contain domain, so a hand-renamed lineage named app.example.com but issued
// for a different SAN is not accepted (the original parser kept this SAN
// check; the rename must not drop it). It returns the expiry and whether
// certbot flags it as a test (staging) certificate. The block layout is:
//
//	Certificate Name: <name>
//	  Domains: <domain> ...
//	  Expiry Date: 2026-08-01 12:00:00+00:00 (VALID: 60 days)
//
// Staging certificates carry TEST_CERT inside the parenthetical annotation
// (e.g. "(INVALID: TEST_CERT)", or combined "(INVALID: TEST_CERT, EXPIRED)").
func parseCertStatus(out, domain string) (expiry time.Time, testCert bool, ok bool) {
	const layout = "2006-01-02 15:04:05-07:00"
	inBlock := false // Certificate Name == domain
	sanOK := false   // Domains: within this block contains domain
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Certificate Name:"):
			inBlock = strings.TrimSpace(strings.TrimPrefix(line, "Certificate Name:")) == domain
			sanOK = false
		case strings.HasPrefix(line, "Domains:") && inBlock:
			for _, d := range strings.Fields(strings.TrimPrefix(line, "Domains:")) {
				if d == domain {
					sanOK = true
					break
				}
			}
		case strings.HasPrefix(line, "Expiry Date:") && inBlock && sanOK:
			val := strings.TrimSpace(strings.TrimPrefix(line, "Expiry Date:"))
			if i := strings.Index(val, " ("); i >= 0 {
				testCert = strings.Contains(val[i:], "TEST_CERT")
				val = val[:i]
			}
			t, err := time.Parse(layout, strings.TrimSpace(val))
			if err != nil {
				return time.Time{}, false, false
			}
			return t, testCert, true
		}
	}
	return time.Time{}, false, false
}

// dnsPointsAtHost reports whether domain resolves to the same address as host.
// host may itself be an IP literal or a hostname (config.Host validates as
// either), so both sides are resolved to their address sets and intersected.
// It returns true trivially when the domain literally equals the host.
func dnsPointsAtHost(domain, host string) bool {
	if domain == host {
		return true
	}
	domainAddrs, err := resolveA(domain)
	if err != nil {
		return false
	}
	hostAddrs, err := resolveA(host)
	if err != nil {
		return false
	}
	have := make(map[string]bool, len(hostAddrs))
	for _, a := range hostAddrs {
		have[a] = true
	}
	for _, a := range domainAddrs {
		if have[a] {
			return true
		}
	}
	return false
}

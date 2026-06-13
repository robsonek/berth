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

// resolveA resolves the A/AAAA records for a host. It is a package-level var so
// tests can stub DNS without a real lookup; production uses the system resolver.
var resolveA = func(host string) ([]string, error) {
	return net.LookupHost(host)
}

type tls struct{}

// TLS obtains and installs a Let's Encrypt certificate via the dedicated ACME
// webroot, then swaps nginx to the 443 server block (design §4, §6.4). It is
// idempotent: a present, non-near-expiry certificate short-circuits Apply.
func TLS() provision.Step { return tls{} }

func (tls) Name() string       { return "tls" }
func (tls) Requires() []string { return []string{"site"} }

func (tls) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	for _, site := range s.Sites {
		if !site.SSL {
			continue
		}
		ok, err := certValid(ctx, r, site.Domain)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			return provision.CheckResult{
				Satisfied: false,
				Reason:    "no valid certificate for " + site.Domain,
				Changes:   []string{"obtain Let's Encrypt certificate for " + site.Domain, "install 443 server block"},
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
		// Idempotent: a present, non-near-expiry cert short-circuits.
		ok, err := certValid(ctx, r, site.Domain)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		// DNS preflight: the domain must resolve to this host or certbot will
		// fail the ACME challenge. On mismatch, skip with a logged warning (the
		// operator may be staging behind a proxy); do not abort the run.
		if !dnsPointsAtHost(site.Domain, s.Host) {
			fmt.Printf("berth: skipping TLS for %s: it does not resolve to %s\n", site.Domain, s.Host)
			continue
		}
		if err := st.issue(ctx, rc, s, site, r); err != nil {
			return err
		}
	}
	return nil
}

// issue installs certbot, obtains a certificate via the ACME webroot, swaps in
// the 443 server block, validates and reloads nginx, and ensures the renew timer.
func (tls) issue(ctx context.Context, rc provision.RunCtx, s *config.Server, site config.Site, r bssh.Runner) error {
	if err := aptInstall(ctx, r, "certbot"); err != nil {
		return fmt.Errorf("install certbot: %w", err)
	}

	certonly := fmt.Sprintf(
		"certbot certonly --webroot -w %s -d %s --agree-tos -m %s --non-interactive",
		acmeWebroot(site.Domain), site.Domain, site.SSLEmail)
	if rc.SSLStaging {
		certonly += " --staging"
	}
	if res, err := r.Run(ctx, certonly, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("certbot certonly for %s: %s", site.Domain, res.Stderr)
	}

	// Swap nginx to the HTTPS (443) server block at the same site path.
	https, err := templates.Render("nginx_https.conf.tmpl", struct {
		Domain, DeployPath, ACMEWebroot, PHPVersion string
	}{
		Domain: site.Domain, DeployPath: site.DeployPath,
		ACMEWebroot: acmeWebroot(site.Domain), PHPVersion: s.PHP.Version,
	})
	if err != nil {
		return fmt.Errorf("render https config for %s: %w", site.Domain, err)
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: nginxAvailablePath(site.Domain), Content: https,
		Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write https config for %s: %w", site.Domain, err)
	}

	// Validate BEFORE reloading.
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

	// Ensure automatic renewal is enabled.
	if res, err := r.Run(ctx, "systemctl enable --now certbot.timer", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("enable certbot.timer: %s", res.Stderr)
	}
	return nil
}

// certValid reports whether certbot holds a certificate for domain whose expiry
// is beyond the renew window.
func certValid(ctx context.Context, r bssh.Runner, domain string) (bool, error) {
	res, err := r.Run(ctx, "certbot certificates", nil)
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, nil // certbot not installed yet / no certs
	}
	expiry, ok := parseCertExpiry(res.Stdout, domain)
	if !ok {
		return false, nil
	}
	return time.Until(expiry) > certRenewWindow, nil
}

// parseCertExpiry scans `certbot certificates` output for the named certificate
// and returns its expiry. The block layout is:
//
//	Certificate Name: <name>
//	  Domains: <domain> ...
//	  Expiry Date: 2026-08-01 12:00:00+00:00 (VALID: 60 days)
func parseCertExpiry(out, domain string) (time.Time, bool) {
	const layout = "2006-01-02 15:04:05-07:00"
	var current string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Certificate Name:"):
			current = strings.TrimSpace(strings.TrimPrefix(line, "Certificate Name:"))
		case strings.HasPrefix(line, "Domains:"):
			doms := strings.Fields(strings.TrimPrefix(line, "Domains:"))
			matched := false
			for _, d := range doms {
				if d == domain {
					matched = true
					break
				}
			}
			if !matched {
				current = "" // not the certificate we want
			}
		case strings.HasPrefix(line, "Expiry Date:") && current != "":
			val := strings.TrimSpace(strings.TrimPrefix(line, "Expiry Date:"))
			if i := strings.Index(val, " ("); i >= 0 {
				val = val[:i]
			}
			t, err := time.Parse(layout, strings.TrimSpace(val))
			if err != nil {
				return time.Time{}, false
			}
			return t, true
		}
	}
	return time.Time{}, false
}

// dnsPointsAtHost reports whether domain resolves to host (by exact address
// match, or trivially when the domain literally equals the host).
func dnsPointsAtHost(domain, host string) bool {
	if domain == host {
		return true
	}
	addrs, err := resolveA(domain)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a == host {
			return true
		}
	}
	return false
}

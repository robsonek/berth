//go:build integration

package integration

import (
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
)

// sslRunSwitches validates BERTH_TEST_SKIP_SSL and derives the run's two SSL
// switches: skipSSL (whether the tls step is registered at all) and
// sslExplicit (the real-DNS opt-in — only then is a Let's Encrypt site's
// certificate CA-verified; see insecureHTTPSProbes). Anything but "", "true"
// or "false" is rejected up front: a typo like "False" would otherwise RUN
// the TLS pipeline (skipSSL=false) while reading as non-explicit
// (sslExplicit=false), silently downgrading every HTTPS probe to
// skip-verification — the worst of both worlds.
func sslRunSwitches(sslEnv string, anySelfSigned bool) (skipSSL, sslExplicit bool, err error) {
	switch sslEnv {
	case "":
		// Self-signed TLS needs no public DNS, so it runs by default;
		// Let's Encrypt does, so without the explicit opt-in it is skipped.
		return !anySelfSigned, false, nil
	case "true":
		return true, false, nil
	case "false":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("BERTH_TEST_SKIP_SSL must be unset, %q or %q; got %q", "true", "false", sslEnv)
	}
}

// debianStockPHP mirrors internal/provision/steps.debianStockPHP — the PHP version
// Debian 13 ships, for which `auto`/`""` does NOT pull the Surý repo.
const debianStockPHP = "8.4"

// usesSury mirrors steps.useSury: Surý is used for source "sury", or for "auto"/""
// when the requested version is not the Debian stock version.
func usesSury(p config.PHP) bool {
	switch p.Source {
	case "sury":
		return true
	case "auto", "":
		return p.Version != debianStockPHP
	default: // "debian"
		return false
	}
}

// provCheck pairs an upstream apt repo (with its pinned fingerprint) with the package
// whose installed version must originate from it.
type provCheck struct {
	repo apt.Repo
	pkg  string
}

// aptProvenanceChecks returns the (upstream repo, package) pairs to verify, based on
// which sources select an upstream repo (Debian-sourced components add no check).
func aptProvenanceChecks(srv *config.Server) []provCheck {
	var checks []provCheck
	if usesSury(srv.PHP) {
		checks = append(checks, provCheck{apt.Sury(), "php" + srv.PHP.Version + "-fpm"})
	}
	if srv.Nginx.Source == "nginx" {
		checks = append(checks, provCheck{apt.NginxOrg(), "nginx"})
	}
	switch srv.Database.Source {
	case "mariadb":
		checks = append(checks, provCheck{apt.MariaDBOrg(), "mariadb-server"})
	case "pgdg":
		checks = append(checks, provCheck{apt.PostgresPGDG(), "postgresql"})
	}
	return checks
}

// installedFromHost reports whether the INSTALLED version of an `apt-cache policy`
// listing (the `***` row) has a source line referencing host — proving the installed
// package came from that repo, not merely that the repo is available. In the policy
// version table, the installed version is the `***` row; its source lines are the
// following indented `<integer-priority> <url> …` lines, ending at the next version row.
func installedFromHost(policy, host string) bool {
	lines := strings.Split(policy, "\n")
	for i := range lines {
		if !strings.HasPrefix(strings.TrimSpace(lines[i]), "***") {
			continue
		}
		for _, src := range lines[i+1:] {
			f := strings.Fields(src)
			if len(f) < 2 || !isAllDigits(f[0]) {
				break // next version row (or `/var/lib/dpkg/status` with no host) / end
			}
			if strings.Contains(f[1], host) {
				return true
			}
		}
		return false
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// supervisorAllStopped reports whether EVERY process line in `supervisorctl status`
// output has status STOPPED (and there is at least one). A process line looks like
// `berth-<pool>:berth-<pool>_00   STOPPED   Not started`; the status is the 2nd field.
func supervisorAllStopped(out string) bool {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n++
		if f[1] != "STOPPED" {
			return false
		}
	}
	return n > 0
}

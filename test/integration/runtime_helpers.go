//go:build integration

package integration

import (
	"fmt"
	"regexp"
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
// PGDG's witness is postgresql-common, not the postgresql metapackage: berth never
// upgrades the metapackage (Package-Blacklist + `apt-get install --no-upgrade`), so on
// a long-lived PGDG host it can legitimately stay at an old build, while
// postgresql-common is kept current by unattended-upgrades. Right after a debian→pgdg
// switch postgresql-common is still Debian's build too, until the first unattended run
// moves it — the check fails in that window, accurately: the host is not on PGDG yet.
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
		checks = append(checks, provCheck{apt.PostgresPGDG(), "postgresql-common"})
	}
	return checks
}

// buildMarkers are the version-string build signatures of berth's upstream repos,
// keyed by repo name. Every build each repo publishes for Debian 13 carries its
// signature and no Debian build does (Debian's carry `+deb13uN` or nothing), so a
// version that has dropped out of the repo's index can still be attributed to it.
var buildMarkers = map[string]*regexp.Regexp{
	"sury-php":    regexp.MustCompile(`\+0~[0-9]+\.[0-9]+\+debian13~`),
	"nginx-org":   regexp.MustCompile(`~trixie$`),
	"mariadb-org": regexp.MustCompile(`\+maria~deb13$`),
	"pgdg":        regexp.MustCompile(`\.pgdg130?\+[0-9]+$`), // early trixie builds used pgdg130
}

// installedProvenance classifies the INSTALLED version of an `apt-cache policy`
// listing — the `***` row, whose source lines are the following indented
// `<integer-priority> <url> …` lines, ending at the next version row:
//   - fromHost: one of its source lines references host, so the installed package
//     demonstrably came from that repo (not merely: the repo is available);
//   - superseded: its ONLY source is /var/lib/dpkg/status — the repo has dropped
//     that version from its index (Sury and PGDG keep only recent builds) — yet the
//     version string carries the repo's build signature (marker). A Debian build,
//     current or stale, never does. A nil marker never yields superseded.
//
// version is the installed version string ("" when there is no `***` row).
func installedProvenance(policy, host string, marker *regexp.Regexp) (fromHost, superseded bool, version string) {
	lines := strings.Split(policy, "\n")
	for i := range lines {
		f := strings.Fields(lines[i])
		if len(f) < 2 || f[0] != "***" {
			continue
		}
		version = f[1]
		sawStatus, onlyDpkgStatus := false, true
		for _, src := range lines[i+1:] {
			sf := strings.Fields(src)
			if !isPolicySourceLine(sf) {
				break // next version row / end
			}
			if strings.Contains(sf[1], host) {
				return true, false, version
			}
			if sf[1] == "/var/lib/dpkg/status" {
				sawStatus = true
			} else {
				onlyDpkgStatus = false
			}
		}
		return false, sawStatus && onlyDpkgStatus && marker != nil && marker.MatchString(version), version
	}
	return false, false, ""
}

// isPolicySourceLine reports whether the fields of a version-table line form a
// source line — `<priority> <uri-or-absolute-path> …` — rather than a version row
// (`<version> <priority>`). The first field alone cannot tell them apart: Debian's
// postgresql-common version is a bare integer ("278"), so the second field
// decides — a URI (`https://…`, `mirror+file:…`) or a path (`/var/lib/dpkg/status`).
func isPolicySourceLine(f []string) bool {
	return len(f) >= 2 && isAllDigits(f[0]) && (strings.HasPrefix(f[1], "/") || strings.Contains(f[1], ":"))
}

// installedFromHost reports whether the installed version of an `apt-cache policy`
// listing came from host (see installedProvenance).
func installedFromHost(policy, host string) bool {
	fromHost, _, _ := installedProvenance(policy, host, nil)
	return fromHost
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

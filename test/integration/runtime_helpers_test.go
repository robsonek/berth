//go:build integration

package integration

import (
	"testing"

	"github.com/robsonek/berth/internal/config"
)

func TestAptProvenanceChecks(t *testing.T) {
	mar := &config.Server{PHP: config.PHP{Version: "8.5", Source: "sury"}, Nginx: config.Nginx{Source: "nginx"}, Database: config.Database{Source: "mariadb"}}
	got := map[string]string{}
	for _, c := range aptProvenanceChecks(mar) {
		got[c.repo.Name] = c.pkg
	}
	if got["sury-php"] != "php8.5-fpm" || got["nginx-org"] != "nginx" || got["mariadb-org"] != "mariadb-server" || len(got) != 3 {
		t.Errorf("mariadb config checks = %+v", got)
	}
	// php source "auto" + non-stock version still uses Surý (wizard default).
	autoNonStock := &config.Server{PHP: config.PHP{Version: "8.5", Source: "auto"}, Database: config.Database{Source: "pgdg"}}
	names := map[string]string{}
	for _, c := range aptProvenanceChecks(autoNonStock) {
		names[c.repo.Name] = c.pkg
	}
	if names["sury-php"] == "" || names["pgdg"] == "" {
		t.Errorf("auto+8.5+pgdg should check sury+pgdg; got %v", names)
	}
	// PGDG's witness is never the (never-upgraded) postgresql metapackage.
	if names["pgdg"] != "postgresql-common" {
		t.Errorf("pgdg provenance witness = %q, want postgresql-common", names["pgdg"])
	}
	// auto + Debian-stock 8.4 does NOT use Surý; all-debian => no checks.
	stock := &config.Server{PHP: config.PHP{Version: "8.4", Source: "auto"}, Nginx: config.Nginx{Source: "debian"}, Database: config.Database{Source: "debian"}}
	if got := aptProvenanceChecks(stock); len(got) != 0 {
		t.Errorf("auto+8.4+all-debian: want 0 checks, got %+v", got)
	}
}

func TestInstalledFromHost(t *testing.T) {
	fromUpstream := `nginx:
  Installed: 1.27.4-1~trixie
  Candidate: 1.27.4-1~trixie
  Version table:
 *** 1.27.4-1~trixie 500
        500 https://nginx.org/packages/mainline/debian trixie/nginx amd64 Packages
        100 /var/lib/dpkg/status
     1.26.0-1 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages`
	if !installedFromHost(fromUpstream, "nginx.org") {
		t.Error("installed version is from nginx.org; want true")
	}
	if installedFromHost(fromUpstream, "deb.debian.org") {
		t.Error("installed version is NOT from deb.debian.org (that's a non-installed row); want false")
	}

	// Debian-installed but nginx.org merely available (the false-pass the naive check had).
	fromDebian := `nginx:
  Installed: 1.26.0-1
  Candidate: 1.27.4-1~trixie
  Version table:
     1.27.4-1~trixie 500
        500 https://nginx.org/packages/mainline/debian trixie/nginx amd64 Packages
 *** 1.26.0-1 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
        100 /var/lib/dpkg/status`
	if installedFromHost(fromDebian, "nginx.org") {
		t.Error("installed version is from debian, nginx.org only available; want false")
	}
}

func TestSupervisorAllStopped(t *testing.T) {
	one := "berth-x:berth-x_00                STOPPED   Not started"
	two := one + "\nberth-x:berth-x_01                STOPPED   Not started"
	if !supervisorAllStopped(one) || !supervisorAllStopped(two) {
		t.Error("all-STOPPED lines should report dormant")
	}
	if supervisorAllStopped(one + "\nberth-x:berth-x_01   RUNNING   pid 1234") {
		t.Error("a RUNNING process must not count as dormant")
	}
	if supervisorAllStopped("berth-x:berth-x_00   FATAL   exited") {
		t.Error("FATAL must not count as dormant")
	}
	if supervisorAllStopped("") {
		t.Error("no processes must not count as dormant")
	}
}

func TestSSLRunSwitches(t *testing.T) {
	cases := []struct {
		name                 string
		env                  string
		anySelfSigned        bool
		skipSSL, sslExplicit bool
		wantErr              bool
	}{
		{"unset-le-only-skips", "", false, true, false, false},
		{"unset-selfsigned-runs", "", true, false, false, false},
		{"true-hard-skip", "true", true, true, false, false},
		{"true-hard-skip-le-only", "true", false, true, false, false},
		{"false-explicit-optin", "false", false, false, true, false},
		{"false-explicit-optin-selfsigned", "false", true, false, true, false},
		{"typo-rejected", "False", false, false, false, true},
		{"garbage-rejected", "1", true, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			skipSSL, sslExplicit, err := sslRunSwitches(c.env, c.anySelfSigned)
			if (err != nil) != c.wantErr {
				t.Fatalf("sslRunSwitches(%q, %v) err = %v, wantErr %v", c.env, c.anySelfSigned, err, c.wantErr)
			}
			if err != nil {
				return
			}
			if skipSSL != c.skipSSL || sslExplicit != c.sslExplicit {
				t.Errorf("sslRunSwitches(%q, %v) = (%v, %v), want (%v, %v)",
					c.env, c.anySelfSigned, skipSSL, sslExplicit, c.skipSSL, c.sslExplicit)
			}
		})
	}
}

func TestInsecureHTTPSProbes(t *testing.T) {
	cases := []struct {
		name                             string
		selfSigned, sslExplicit, staging bool
		want                             bool
	}{
		{"le-real-dns-production-verifies", false, true, false, false},
		{"le-real-dns-staging-skips", false, true, true, true},
		{"selfsigned-always-untrusted", true, true, false, true},
		{"no-real-dns-opt-in-skips", false, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := insecureHTTPSProbes(c.selfSigned, c.sslExplicit, c.staging); got != c.want {
				t.Errorf("insecureHTTPSProbes(%v, %v, %v) = %v, want %v",
					c.selfSigned, c.sslExplicit, c.staging, got, c.want)
			}
		})
	}
}

// TestInstalledProvenance pins the stale-host rule: Sury and PGDG keep only
// recent builds, so on a long-lived host the INSTALLED version can drop out of
// the index and `apt-cache policy` lists it under /var/lib/dpkg/status alone.
// Such a version still came from the repo when its string carries the repo's
// build signature; a Debian build — current or stale — never does.
func TestInstalledProvenance(t *testing.T) {
	cases := []struct {
		name               string
		policy, host       string
		marker             string // a buildMarkers key
		fromHost, superset bool
	}{
		{"current sury build, listed by the repo", `php8.5-fpm:
  Installed: 8.5.11-1+0~20260924.26+debian13~1.gbpbcb504
  Candidate: 8.5.11-1+0~20260924.26+debian13~1.gbpbcb504
  Version table:
 *** 8.5.11-1+0~20260924.26+debian13~1.gbpbcb504 500
        500 https://packages.sury.org/php trixie/main amd64 Packages
        100 /var/lib/dpkg/status`, "packages.sury.org", "sury-php", true, false},
		// The exact listing that false-failed the suite on 2026-09-30.
		{"superseded sury build, gone from the index", `php8.5-fpm:
  Installed: 8.5.10-1+0~20260828.25+debian13~1.gbpfea0b8
  Candidate: 8.5.11-1+0~20260924.26+debian13~1.gbpbcb504
  Version table:
     8.5.11-1+0~20260924.26+debian13~1.gbpbcb504 500
        500 https://packages.sury.org/php trixie/main amd64 Packages
 *** 8.5.10-1+0~20260828.25+debian13~1.gbpfea0b8 100
        100 /var/lib/dpkg/status`, "packages.sury.org", "sury-php", false, true},
		// The full listing, WITH Debian's lower row: Debian's postgresql-common
		// version is a bare integer ("278"), which a parser keyed on "first
		// field is numeric" mistakes for a source line.
		{"superseded pgdg build, debian row below", `postgresql-common:
  Installed: 293.pgdg13+1
  Candidate: 294.pgdg13+1
  Version table:
     294.pgdg13+1 500
        500 https://apt.postgresql.org/pub/repos/apt trixie-pgdg/main amd64 Packages
 *** 293.pgdg13+1 100
        100 /var/lib/dpkg/status
     278 500
        500 mirror+file:/etc/apt/mirrors/debian.list trixie/main amd64 Packages`, "apt.postgresql.org", "pgdg", false, true},
		// PGDG's early trixie builds used the pgdg130 suffix.
		{"superseded historical pgdg130 build", `postgresql-common:
  Installed: 278.pgdg130+1
  Candidate: 294.pgdg13+1
  Version table:
     294.pgdg13+1 500
        500 https://apt.postgresql.org/pub/repos/apt trixie-pgdg/main amd64 Packages
 *** 278.pgdg130+1 100
        100 /var/lib/dpkg/status
     278 500
        500 mirror+file:/etc/apt/mirrors/debian.list trixie/main amd64 Packages`, "apt.postgresql.org", "pgdg", false, true},
		{"current pgdg build, debian row below", `postgresql-common:
  Installed: 294.pgdg13+1
  Candidate: 294.pgdg13+1
  Version table:
 *** 294.pgdg13+1 500
        500 https://apt.postgresql.org/pub/repos/apt trixie-pgdg/main amd64 Packages
        100 /var/lib/dpkg/status
     278 500
        500 mirror+file:/etc/apt/mirrors/debian.list trixie/main amd64 Packages`, "apt.postgresql.org", "pgdg", true, false},
		// No source line at all under the installed row is not evidence of
		// anything — never "superseded".
		{"installed row without any source line", `postgresql-common:
  Installed: 293.pgdg13+1
  Candidate: 293.pgdg13+1
  Version table:
 *** 293.pgdg13+1 100`, "apt.postgresql.org", "pgdg", false, false},
		// The silent-fallback class (MariaDB mirror bug): Debian's build installed.
		{"debian build installed instead of upstream", `mariadb-server:
  Installed: 1:11.8.6-0+deb13u1
  Candidate: 1:11.8.6-0+deb13u1
  Version table:
 *** 1:11.8.6-0+deb13u1 500
        500 mirror+file:/etc/apt/mirrors/debian.list trixie/main amd64 Packages
        100 /var/lib/dpkg/status`, "dlm.mariadb.com", "mariadb-org", false, false},
		// A stale Debian build is ALSO listed under dpkg status alone — only the
		// missing build signature tells it apart from a superseded upstream one.
		{"stale debian build, gone from the index", `mariadb-server:
  Installed: 1:11.8.5-0+deb13u1
  Candidate: 1:11.8.6-0+deb13u1
  Version table:
     1:11.8.6-0+deb13u1 500
        500 mirror+file:/etc/apt/mirrors/debian.list trixie/main amd64 Packages
 *** 1:11.8.5-0+deb13u1 100
        100 /var/lib/dpkg/status`, "dlm.mariadb.com", "mariadb-org", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fromHost, superseded, _ := installedProvenance(c.policy, c.host, buildMarkers[c.marker])
			if fromHost != c.fromHost || superseded != c.superset {
				t.Errorf("fromHost=%v superseded=%v, want %v/%v", fromHost, superseded, c.fromHost, c.superset)
			}
		})
	}
}

// TestBuildMarkersMatchOnlyUpstream: each repo's build signature matches that
// repo's real version strings and none of Debian's.
func TestBuildMarkersMatchOnlyUpstream(t *testing.T) {
	upstream := map[string][]string{
		"sury-php":    {"8.5.11-1+0~20260924.26+debian13~1.gbpbcb504", "8.4.16-1+0~20260101.3+debian13~1.gbp0123ab"},
		"nginx-org":   {"1.31.6-1~trixie", "1.27.4-1~trixie"},
		"mariadb-org": {"1:12.3.3+maria~deb13"},
		"pgdg":        {"293.pgdg13+1", "18.6-1.pgdg13+2", "278.pgdg130+1"},
	}
	debian := []string{"1:11.8.6-0+deb13u1", "1.26.3-3+deb13u1", "278", "17.6-0+deb13u1", "8.4.16-1~deb13u1", "3.5.7-1~deb13u3",
		// other releases' upstream builds must not pass as trixie ones either
		"293.pgdg120+1", "1.31.6-1~bookworm", "1:12.3.3+maria~deb12"}
	for name, versions := range upstream {
		m := buildMarkers[name]
		if m == nil {
			t.Fatalf("no build marker for %s", name)
		}
		for _, v := range versions {
			if !m.MatchString(v) {
				t.Errorf("%s marker misses its own build %q", name, v)
			}
		}
		for _, v := range debian {
			if m.MatchString(v) {
				t.Errorf("%s marker matches Debian build %q", name, v)
			}
		}
	}
}

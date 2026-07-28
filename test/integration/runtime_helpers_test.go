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
	names := map[string]bool{}
	for _, c := range aptProvenanceChecks(autoNonStock) {
		names[c.repo.Name] = true
	}
	if !names["sury-php"] || !names["pgdg"] {
		t.Errorf("auto+8.5+pgdg should check sury+pgdg; got %v", names)
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
		{"false-explicit-optin", "false", false, false, true, false},
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

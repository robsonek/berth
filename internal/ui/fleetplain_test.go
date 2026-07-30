package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/status"
)

func hostFixture() status.HostStatus {
	at := time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC)
	notAfter := at.Add(61 * 24 * time.Hour)
	days := 61
	newest := at.Add(-3 * time.Hour)
	return status.HostStatus{
		ID: "prod", Endpoint: "203.0.113.10:22", Reachable: true,
		Provisioned: &status.Manifest{Version: "0.27.1", ProvisionedAt: at.Add(-8 * 24 * time.Hour)},
		Sites: []status.SiteStatus{{
			Domain: "app.example.com",
			Cert:   status.CertStatus{Mode: "letsencrypt", Present: true, NotAfter: &notAfter, DaysLeft: &days},
			Backup: status.BackupStatus{Enabled: true, Newest: &newest, Count: 7},
		}},
		Disk:     []status.Mount{{Path: "/", UsedPct: 41}},
		Drift:    &status.DriftReport{Drifted: 0},
		HostTime: at, ProbedAt: at,
	}
}

func TestFleetTableHealthyHost(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{hostFixture()}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"prod", "0.27.1", "clean", "61d", "3h ago", "41%"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
}

func TestFleetTableUnreachableHost(t *testing.T) {
	var buf bytes.Buffer
	h := status.HostStatus{ID: "gone", Endpoint: "203.0.113.12:22", Error: "no route to host"}
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, "unreachable") {
		t.Errorf("table must mark the host unreachable:\n%s", out)
	}
}

// A partial scan must never render as "clean" — that is the one misreading
// this feature cannot afford.
func TestFleetTableAbortedScanIsNotClean(t *testing.T) {
	h := hostFixture()
	h.Drift = &status.DriftReport{Drifted: 0, StoppedAt: "database", Error: "mariadb unreachable"}
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "clean") {
		t.Errorf("an aborted scan rendered as clean:\n%s", out)
	}
	if !strings.Contains(out, "database") {
		t.Errorf("the abort point must be named:\n%s", out)
	}
}

// status.Drift's defensive pre-flight path can populate Error while leaving
// StoppedAt empty: the engine failed before any step ran. Keying "clean" on
// StoppedAt alone would render that report as clean — the exact false reading
// this feature exists to prevent.
func TestFleetTableErrorWithoutStopIsNotClean(t *testing.T) {
	h := hostFixture()
	h.Drift = &status.DriftReport{Drifted: 0, Error: "pre-flight: dependency cycle"}
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "clean") {
		t.Errorf("a scan that failed before running rendered as clean:\n%s", out)
	}
	if !strings.Contains(out, "did not run") {
		t.Errorf("a scan that never ran must say so, not name a step:\n%s", out)
	}
}

func TestFleetTableNotScannedIsDistinctFromClean(t *testing.T) {
	h := hostFixture()
	h.Drift = nil
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "clean") {
		t.Error("a host that was never drift-scanned must not read as clean")
	}
}

func TestFleetTableStaleBackupIsMarked(t *testing.T) {
	h := hostFixture()
	h.Sites[0].Backup.Stale = true
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	// backupCell emits uppercase STALE — match it exactly rather than
	// case-insensitively, so the rendered wording stays pinned.
	if !strings.Contains(buf.String(), "STALE") {
		t.Errorf("a stale backup must be marked:\n%s", buf.String())
	}
}

// Every cell branch that can make a broken host look healthy gets pinned.
func TestFleetTableDistinguishesNoTLSFromMissingCert(t *testing.T) {
	noTLS := hostFixture()
	noTLS.Sites[0].Cert = status.CertStatus{} // Mode empty = site declares no TLS
	missing := hostFixture()
	missing.Sites[0].Cert = status.CertStatus{Mode: "letsencrypt"} // declared, not issued

	for name, tc := range map[string]struct {
		h             status.HostStatus
		want, notWant string
	}{
		"no tls":  {noTLS, "no TLS", "MISSING"},
		"missing": {missing, "MISSING", "no TLS"},
	} {
		var buf bytes.Buffer
		if err := WriteFleetTable(&buf, []status.HostStatus{tc.h}); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if !strings.Contains(out, tc.want) || strings.Contains(out, tc.notWant) {
			t.Errorf("%s: want %q and not %q:\n%s", name, tc.want, tc.notWant, out)
		}
	}
}

func TestFleetTableUnparsedDiskIsNotZeroPercent(t *testing.T) {
	h := hostFixture()
	h.Disk = nil
	// A healthy Services entry, or the SERVICES column also renders "?" and
	// the assertion below no longer isolates the disk column.
	h.Services = []status.Service{{Name: "nginx", Active: true, Enabled: true}}
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "0%") {
		t.Errorf("an unparsed df must not render as a reassuring 0%%:\n%s", out)
	}
	if !strings.Contains(out, "?") {
		t.Errorf("an unparsed df must render as unknown:\n%s", out)
	}
}

func TestFleetTableShowsPartialProbeErrors(t *testing.T) {
	h := hostFixture()
	h.ProbeErrors = []string{"services: connection reset"}
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "connection reset") {
		t.Errorf("a reachable host's probe failures must be visible:\n%s", buf.String())
	}
}

func TestFleetTableServicesColumnCountsDownUnits(t *testing.T) {
	h := hostFixture()
	h.Services = []status.Service{
		{Name: "nginx", Active: true, Enabled: true},
		{Name: "mariadb", Active: false, Enabled: true},
	}
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "1/2 DOWN") {
		t.Errorf("want the down count:\n%s", buf.String())
	}
}

// The reassuring number must not win: with one fresh and one ancient site the
// cell reports the OLDEST.
func TestFleetTableBackupReportsOldestSite(t *testing.T) {
	h := hostFixture()
	old := h.HostTime.Add(-72 * time.Hour)
	h.Sites = append(h.Sites, status.SiteStatus{
		Domain: "second.example.com",
		Backup: status.BackupStatus{Enabled: true, Newest: &old, Stale: true},
	})
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "3d ago") || !strings.Contains(out, "STALE") {
		t.Errorf("want the oldest site's age plus the stale count:\n%s", out)
	}
}

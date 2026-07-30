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

// The abort REASON must reach the operator, not only the abort point: for the
// expected identity abort the error text carries the whole remedy (an endpoint
// mismatch or renamed id, fixed with the narrow `--only identity --force`),
// and hiding it behind --json left the table saying only "aborted at identity".
func TestFleetTableAbortReasonIsVisible(t *testing.T) {
	h := hostFixture()
	h.Drift = &status.DriftReport{
		StoppedAt: "identity",
		Error:     "identity: endpoint mismatch: re-bind with --only identity --force",
	}
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "--only identity --force") {
		t.Errorf("the abort reason must be visible in the table:\n%s", buf.String())
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

// An expired certificate must survive a healthier site listed after it: the
// old -1 "unset" sentinel could not tell "no minimum yet" from a genuinely
// negative minimum, so a later site's 60 days overwrote the -5 and the cell
// read "min 60d" — an expired certificate rendered as healthy.
func TestFleetTableExpiredCertSurvivesAHealthierSite(t *testing.T) {
	h := hostFixture()
	expired, healthy := -5, 60
	h.Sites = []status.SiteStatus{
		{Domain: "old.example.com", Cert: status.CertStatus{Mode: "letsencrypt", Present: true, DaysLeft: &expired}},
		{Domain: "app.example.com", Cert: status.CertStatus{Mode: "letsencrypt", Present: true, DaysLeft: &healthy}},
	}
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "min -5d") || !strings.Contains(out, "!!") {
		t.Errorf("the expired certificate must set the minimum and the critical marker:\n%s", out)
	}
	if strings.Contains(out, "min 60d") {
		t.Errorf("a healthier site must not mask the expired one:\n%s", out)
	}
}

// A timestamp AHEAD of the host clock is an anomaly — a skewed clock or a
// foreign file — and it used to satisfy d < time.Minute, rendering as the
// reassuring "just now".
func TestFleetTableFutureBackupIsNotJustNow(t *testing.T) {
	h := hostFixture()
	future := h.HostTime.Add(45 * time.Second)
	h.Sites[0].Backup.Newest = &future
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "just now") {
		t.Errorf("a future timestamp must not render as freshly backed up:\n%s", out)
	}
	if !strings.Contains(out, "FUTURE") {
		t.Errorf("a future timestamp must render as unmistakably odd:\n%s", out)
	}
}

// A successful --offsite answer must be visible in the plain table, not only
// in --json and the TUI: without it a piped `berth status --offsite` was
// byte-identical to a run without the flag whenever the query succeeded. The
// answer rides a continuation row because the eight-column header is a fixed
// shape every row matches.
func TestFleetTableRendersOffsite(t *testing.T) {
	at := hostFixture().HostTime
	snap := at.Add(-3 * time.Hour)
	for name, tc := range map[string]struct {
		offsite *status.OffsiteStatus
		want    []string
	}{
		"snapshot":       {&status.OffsiteStatus{Configured: true, LastSnapshot: &snap, SnapshotID: "a91f2c"}, []string{"offsite", "3h ago", "a91f2c"}},
		"no snapshot":    {&status.OffsiteStatus{Configured: true}, []string{"offsite", "NO SNAPSHOTS"}},
		"not configured": {&status.OffsiteStatus{Error: "no /etc/berth/offsite.env on the host"}, []string{"offsite", "NOT SET UP", "offsite.env"}},
		"failure":        {&status.OffsiteStatus{Configured: true, Error: "restic could not read the repository"}, []string{"offsite", "FAILED", "could not read"}},
	} {
		t.Run(name, func(t *testing.T) {
			h := hostFixture()
			h.Offsite = tc.offsite
			var buf bytes.Buffer
			if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("missing %q:\n%s", want, buf.String())
				}
			}
		})
	}
}

// The collector records an offsite failure both as OffsiteStatus.Error (the
// state) and as a ProbeErrors entry (exit code, --json). The human views must
// render it ONCE — on the offsite state row, the dedicated answer slot — not
// as an extra `!` row repeating the same text. A transport failure (no
// OffsiteStatus at all) keeps its `!` row: nothing else would show it.
func TestFleetTableRendersFailedOffsiteOnce(t *testing.T) {
	h := hostFixture()
	h.Offsite = &status.OffsiteStatus{Configured: true, Error: "restic could not read the repository"}
	h.ProbeErrors = []string{"offsite: restic could not read the repository"}
	var buf bytes.Buffer
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if got := strings.Count(out, "could not read the repository"); got != 1 {
		t.Errorf("offsite failure must render exactly once, got %d:\n%s", got, out)
	}
	if !strings.Contains(out, "offsite: FAILED: restic could not read the repository") {
		t.Errorf("the surviving copy must be the offsite state row:\n%s", out)
	}

	// Transport failure: probeOffsite returned a Go error, so there is no
	// state row — the ! row must stay.
	h.Offsite = nil
	h.ProbeErrors = []string{"offsite: dial tcp: connection refused"}
	buf.Reset()
	if err := WriteFleetTable(&buf, []status.HostStatus{h}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "! offsite: dial tcp") {
		t.Errorf("a transport failure has no state row and must keep its ! row:\n%s", buf.String())
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

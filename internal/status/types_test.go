package status

import (
	"bytes"
	"flag"
	"os"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

// sampleFleet is the fixture behind the JSON golden. It exercises every
// optional field: a healthy host, a host that has never been provisioned, and
// an unreachable one.
func sampleFleet() []HostStatus {
	at := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 9, 28, 7, 31, 0, 0, time.UTC)
	newest := time.Date(2026, 7, 29, 3, 30, 0, 0, time.UTC)
	days := 61
	return []HostStatus{
		{
			ID: "prod", ConfigPath: "servers/prod.yml", Endpoint: "203.0.113.10:22",
			Reachable:   true,
			Provisioned: &Manifest{Version: "0.27.1", ProvisionedAt: at.Add(-8 * 24 * time.Hour)},
			Sites: []SiteStatus{{
				Domain: "app.example.com",
				Cert:   CertStatus{Mode: "letsencrypt", Present: true, NotAfter: &notAfter, DaysLeft: &days},
				Backup: BackupStatus{Enabled: true, Dir: "/var/backups/berth/app_example_com", Newest: &newest, Count: 7, Bytes: 418000000},
			}},
			Services: []Service{{Name: "nginx", Active: true, Enabled: true}},
			Disk:     []Mount{{Path: "/", UsedPct: 41, FreeBytes: 22000000000}},
			Drift:    &DriftReport{Steps: []StepState{{Step: "site", Satisfied: true}}, Drifted: 0},
			ProbedAt: at, HostTime: at,
		},
		{
			ID: "fresh", ConfigPath: "servers/fresh.yml", Endpoint: "203.0.113.11:22",
			Reachable: true, ProbedAt: at, HostTime: at,
		},
		{
			ID: "gone", ConfigPath: "servers/gone.yml", Endpoint: "203.0.113.12:22",
			Reachable: false, Error: "dial tcp: connect: no route to host", ProbedAt: at,
		},
	}
}

func TestWriteJSONMatchesGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleFleet()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	const golden = "testdata/fleet.json"
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("JSON contract changed.\n--- got ---\n%s\n--- want ---\n%s", buf.String(), want)
	}
}

// TestNeverProvisionedHostOmitsOptionalFields guards the contract a script
// relies on: absence is expressed by omission, never by a zero value that
// reads as real data (a manifest with an empty version, a 1970 timestamp).
func TestNeverProvisionedHostOmitsOptionalFields(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, []HostStatus{sampleFleet()[1]}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	// "0001-01-01" catches the zero time.Time, which omitempty does NOT omit —
	// checking only for "1970" misses it entirely.
	for _, forbidden := range []string{"provisioned", "drift", "sites", "1970", "0001-01-01"} {
		if bytes.Contains(buf.Bytes(), []byte(forbidden)) {
			t.Errorf("output contains %q for a never-provisioned host:\n%s", forbidden, buf.String())
		}
	}
}

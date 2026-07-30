package status

import (
	"context"
	"testing"
	"time"

	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestProbeHostMetaProvisionedHost(t *testing.T) {
	f := bssh.NewFakeRunner().On(hostMetaCmd, bssh.Result{Stdout: "" +
		"1785060000\n+0000\n" +
		"---\n" +
		"# managed by berth\n" +
		"VERSION=0.27.1\n" +
		"PROVISIONED_AT=2026-07-21T09:14:02Z\n" +
		"---\n" +
		"Filesystem     1B-blocks        Used   Available Capacity Mounted on\n" +
		"/dev/vda1    41000000000 16000000000 22000000000      41% /\n" +
		"/dev/vda1    41000000000 16000000000 22000000000      41% /\n"})

	hostTime, m, disks, err := probeHostMeta(context.Background(), f)
	if err != nil {
		t.Fatalf("probeHostMeta: %v", err)
	}
	if want := time.Unix(1785060000, 0).UTC(); !hostTime.Equal(want) {
		t.Errorf("hostTime = %s, want %s", hostTime, want)
	}
	if m == nil || m.Version != "0.27.1" {
		t.Fatalf("manifest = %+v, want version 0.27.1", m)
	}
	if want := time.Date(2026, 7, 21, 9, 14, 2, 0, time.UTC); !m.ProvisionedAt.Equal(want) {
		t.Errorf("ProvisionedAt = %s, want %s", m.ProvisionedAt, want)
	}
	// df prints one row per operand; the same mount point must collapse to one
	// entry or the view double-counts the root filesystem.
	if len(disks) != 1 {
		t.Fatalf("disks = %+v, want 1 deduplicated mount", disks)
	}
	if disks[0].Path != "/" || disks[0].UsedPct != 41 || disks[0].FreeBytes != 22000000000 {
		t.Errorf("disk = %+v, want {/ 41 22000000000}", disks[0])
	}
}

// A host berth has never fully provisioned has no manifest: that is a normal
// state reported as nil, not an error.
func TestProbeHostMetaNeverProvisioned(t *testing.T) {
	f := bssh.NewFakeRunner().On(hostMetaCmd, bssh.Result{Stdout: "" +
		"1785060000\n+0000\n---\n---\n" +
		"Filesystem     1B-blocks Used  Available Capacity Mounted on\n" +
		"/dev/vda1    41000000000 1000 40000000000       1% /\n"})

	_, m, _, err := probeHostMeta(context.Background(), f)
	if err != nil {
		t.Fatalf("probeHostMeta: %v", err)
	}
	if m != nil {
		t.Errorf("manifest = %+v, want nil for a never-provisioned host", m)
	}
}

func TestProbeHostMetaUnreadableClockIsAnError(t *testing.T) {
	f := bssh.NewFakeRunner().On(hostMetaCmd, bssh.Result{Stdout: "nonsense\n+0000\n---\n---\n"})
	if _, _, _, err := probeHostMeta(context.Background(), f); err == nil {
		t.Error("expected an error when the host clock cannot be read")
	}
}

// A non-UTC host is the normal case in practice; without this the timezone
// handling could regress to UTC unnoticed.
func TestProbeHostMetaUsesTheHostZone(t *testing.T) {
	f := bssh.NewFakeRunner().On(hostMetaCmd, bssh.Result{Stdout: "" +
		"1785060000\n+0200\n---\n---\n" +
		"Filesystem 1B-blocks Used Available Capacity Mounted on\n" +
		"/dev/vda1 41000000000 1000 40000000000 1% /\n"})

	hostTime, _, _, err := probeHostMeta(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if _, off := hostTime.Zone(); off != 2*3600 {
		t.Errorf("zone offset = %ds, want 7200 — cron must be matched in the host's zone", off)
	}
	if !hostTime.Equal(time.Unix(1785060000, 0)) {
		t.Error("the instant must be unchanged; only the location differs")
	}
}

// A malformed or missing offset must fail loudly rather than silently
// reverting to UTC — a silent fallback reintroduces the timezone bug invisibly.
func TestProbeHostMetaMalformedOffsetIsAnError(t *testing.T) {
	// +1500 exercises the HOUR bound alone (+9999 violates both, so it would
	// pass even if the hour check were missing); +1260 exercises minutes alone.
	for _, bad := range []string{"", "+1500", "+1260", "0200", "+9999"} {
		f := bssh.NewFakeRunner().On(hostMetaCmd, bssh.Result{
			Stdout: "1785060000\n" + bad + "\n---\n---\nFilesystem\n"})
		if _, _, _, err := probeHostMeta(context.Background(), f); err == nil {
			t.Errorf("offset %q: expected an error", bad)
		}
	}
}

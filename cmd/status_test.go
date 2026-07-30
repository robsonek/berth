package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/status"
)

func TestStatusRegistered(t *testing.T) {
	var found bool
	for _, c := range newRootCmd().Commands() {
		if c.Name() == "status" {
			found = true
		}
	}
	if !found {
		t.Error("status subcommand not registered")
	}
}

// An empty inventory must fail loudly: reporting "0 hosts, all fine" when the
// real cause is a wrong --config-dir is exactly the silent-success failure
// this command exists to prevent.
func TestStatusEmptyInventoryFails(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"status", "--config-dir", t.TempDir()})
	if err := root.Execute(); err == nil {
		t.Error("expected an error for an empty inventory")
	}
}

func TestStatusUnloadableConfigExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.yml")
	if err := os.WriteFile(broken, []byte("this: [is not: valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"status", "--no-tty", broken})
	err := root.Execute()
	if err == nil {
		t.Error("a host that could not be probed must produce a non-zero exit")
	}
	if !strings.Contains(out.String(), "broken.yml") {
		t.Errorf("the failing host must still be rendered:\n%s", out.String())
	}
}

// The abort arm must carry the REASON, symmetric with the did-not-run arm
// below: for the expected identity abort the error text is the whole remedy
// (endpoint mismatch / renamed id -> the narrow `--only identity --force`),
// and a message naming only the step sent the operator to --json to find it.
func TestProbeFailureAbortCarriesReason(t *testing.T) {
	hosts := []status.HostStatus{{
		ConfigPath: "servers/web.yml",
		Reachable:  true,
		Drift: &status.DriftReport{
			StoppedAt: "identity",
			Error:     "endpoint mismatch: re-bind with --only identity --force",
		},
	}}
	err := probeFailure(hosts)
	if err == nil {
		t.Fatal("an aborted drift scan must produce a non-zero exit")
	}
	if !strings.Contains(err.Error(), "aborted at identity") ||
		!strings.Contains(err.Error(), "endpoint mismatch") {
		t.Errorf("the abort message must name the step AND the reason: %v", err)
	}
}

// An unloadable config is a different diagnosis from a dead host: the operator
// must be sent to the file, not the network. Only a loaded config yields an
// endpoint (see status.Collect), which is how the two are told apart.
func TestProbeFailureDistinguishesUnloadableConfig(t *testing.T) {
	hosts := []status.HostStatus{
		{ConfigPath: "servers/broken.yml", Error: "yaml: mapping values are not allowed"},
		{ConfigPath: "servers/gone.yml", ID: "gone", Endpoint: "203.0.113.12:22", Error: "no route to host"},
	}
	err := probeFailure(hosts)
	if err == nil {
		t.Fatal("both hosts failed probing, want a non-zero exit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "servers/broken.yml (config failed to load") {
		t.Errorf("an unloadable config must be labelled as such: %v", err)
	}
	if strings.Contains(msg, "servers/broken.yml (unreachable)") {
		t.Errorf("an unloadable config must not be labelled unreachable: %v", err)
	}
	if !strings.Contains(msg, "servers/gone.yml (unreachable)") {
		t.Errorf("a dead host must still be labelled unreachable: %v", err)
	}
}

// status.Drift's defensive pre-flight path returns a report with Error set and
// StoppedAt EMPTY — the scan never ran at all. Keying the aborted-scan case on
// StoppedAt alone would let that shape exit 0 with no indication anything went
// wrong, so probeFailure must treat it as a probing failure too.
func TestProbeFailureDriftErrorWithoutStoppedAt(t *testing.T) {
	hosts := []status.HostStatus{{
		ConfigPath: "servers/web.yml",
		Reachable:  true,
		Drift:      &status.DriftReport{Error: "pre-flight: unknown step"},
	}}
	err := probeFailure(hosts)
	if err == nil {
		t.Fatal("a drift report with only Error set must produce a non-zero exit")
	}
	// The scan never reached any step, so the message must not claim it
	// aborted AT one.
	if strings.Contains(err.Error(), "aborted at") {
		t.Errorf("message names a step the scan never reached: %v", err)
	}
}

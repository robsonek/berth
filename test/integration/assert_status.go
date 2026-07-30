//go:build integration

package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/status"
)

// assertStatus runs the same fleet collection `berth status --drift` performs
// against the freshly provisioned host — the gate against the probes drifting
// away from reality. It is read-only end to end: status.Collect dials its own
// connection (TOFU disabled, so the host key must already be pinned or in
// known_hosts, which this harness requires anyway) and the drift scan runs the
// pipeline under DryRun, so Apply is never reached. Safe on a shared box: it
// changes nothing beyond what the provisioning it follows already did.
//
// It runs right after assertSecondRunIdempotent on purpose: the engine has
// just proven the host converged, so drift reported here indicts the status
// collector, not the host.
//
// skipSSL truncates the PROVISIONED pipeline (no tls, no manifest) while the
// drift scan deliberately builds the FULL one — on such a run the TLS-phase
// steps are legitimately unconverged, certbot.timer legitimately absent, and
// no manifest was written. The strict assertions therefore apply only to a
// full (!skipSSL) run; a truncated run logs those states instead. Reachability,
// probe completeness and drift-scan COMPLETION are asserted unconditionally: a
// partial scan passing the gate would defeat its purpose.
func assertStatus(t *testing.T, cfgPath string, skipSSL, sslStaging bool) {
	t.Helper()
	// Fresh deadline, mirroring assertSecondRunIdempotent: the shared test
	// context may be nearly exhausted by a slow first provision. The collector
	// composes its own per-host budget (10 minutes with drift) on top of this
	// one; the drift sweep took 30-70s in live validation, so both fit.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	hosts := status.Collect(ctx, []string{cfgPath}, status.Options{
		Drift:      true,
		Parallel:   1,
		KnownHosts: knownHostsPath(),
	})
	if len(hosts) != 1 {
		t.Fatalf("status: got %d hosts, want 1", len(hosts))
	}
	h := hosts[0]
	if !h.Reachable {
		t.Fatalf("status: host unreachable: %s", h.Error)
	}
	if len(h.ProbeErrors) != 0 {
		t.Errorf("status: partial probe failures: %v", h.ProbeErrors)
	}
	// The scan must have COMPLETED regardless of skipSSL: StoppedAt marks a
	// fail-fast abort mid-pipeline, Error without StoppedAt a scan that never
	// reached any step. Either way the report is partial, never clean.
	if h.Drift == nil || h.Drift.StoppedAt != "" || h.Drift.Error != "" {
		t.Fatalf("status: drift scan did not complete: %+v", h.Drift)
	}
	// The unit list derived from any config is never empty (nginx, FPM, the
	// database, fail2ban, cron, ssh at minimum), so an empty slice here means
	// the probe broke silently and the service loops below would be vacuous.
	if len(h.Services) == 0 {
		t.Error("status: no service rows parsed")
	}

	if skipSSL {
		// Truncated run: log what the full-pipeline scan legitimately flags
		// (tls/manifest unconverged, certbot absent) instead of failing.
		for _, st := range h.Drift.Steps {
			if !st.Satisfied && st.Step != "preflight" {
				t.Logf("status: drifted step %q under skip-SSL (expected for the TLS phase): %v", st.Step, st.Changes)
			}
		}
		for _, sv := range h.Services {
			if !sv.Active || !sv.Enabled {
				t.Logf("status: service %s under skip-SSL: active=%v enabled=%v", sv.Name, sv.Active, sv.Enabled)
			}
		}
		return
	}

	if h.Provisioned == nil {
		t.Error("status: no manifest — the host was never fully provisioned")
	}

	// Walk the steps rather than asserting every StepState satisfied:
	// preflight reports Satisfied:false by design (present in Steps, excluded
	// from the Drifted count). Under a staging-TLS run the tls step alone is
	// tolerated: status.Drift passes no SSLStaging, so the scan's production
	// view reads a staging certificate as replaceable — that is a property of
	// the run's flags, not drift on the host.
	tolerated := 0
	var drifted []string
	for _, st := range h.Drift.Steps {
		switch {
		case st.Satisfied, st.Step == "preflight":
		case sslStaging && st.Step == "tls":
			tolerated++
			t.Logf("status: tls unsatisfied under staging TLS (tolerated): %v", st.Changes)
		default:
			drifted = append(drifted, fmt.Sprintf("%s: %v", st.Step, st.Changes))
		}
	}
	if len(drifted) != 0 {
		t.Errorf("status: %d drifted steps on a converged host:\n  %s",
			len(drifted), strings.Join(drifted, "\n  "))
	}
	// Cross-check the count the JSON contract exposes against the per-step
	// walk, so a counting regression in status.Drift cannot slip through. A
	// mismatch with zero offenders means either that, or a new deliberately-
	// unsatisfied step this gate must learn about.
	if want := len(drifted) + tolerated; h.Drift.Drifted != want {
		t.Errorf("status: Drift.Drifted = %d, want %d (per-step walk)", h.Drift.Drifted, want)
	}

	for _, sv := range h.Services {
		if !sv.Active || !sv.Enabled {
			t.Errorf("status: service %s: active=%v enabled=%v, want both true", sv.Name, sv.Active, sv.Enabled)
		}
	}
}

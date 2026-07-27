//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertBreakGlass verifies the berth account's console-password posture
// matches system.break_glass in BOTH directions: on = `passwd -S` reports a
// usable password ("P") and the credential is readable from the local secret
// cache (the whole point — the operator must be able to type it at the
// provider's console); off = the password is locked or absent ("L"/"NP"),
// useradd's default. SSH exposure is covered independently:
// assertHardeningEndState asserts `passwordauthentication no` regardless of
// this knob, so break-glass never opens a network login path.
func assertBreakGlass(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	res, err := c.Run(ctx, "passwd -S berth", nil)
	if err != nil {
		t.Fatalf("passwd -S berth: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("passwd -S berth exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	fields := strings.Fields(res.Stdout)
	if len(fields) < 2 || fields[0] != "berth" {
		t.Fatalf("passwd -S berth: unexpected output %q", strings.TrimSpace(res.Stdout))
	}
	status := fields[1]
	if status != "P" && status != "L" && status != "NP" {
		t.Fatalf("passwd -S berth: unexpected status %q", status)
	}
	if srv.System.BreakGlass {
		if status != "P" {
			t.Errorf("break_glass on: berth password status = %q, want P (usable)", status)
		}
		// The suite provisions the box itself, so the password on it is
		// berth-set and MUST be readable from the local cache — that is the
		// whole point. (An operator-set pre-existing password without a cache
		// entry is a valid state for the STEP, but not one this suite's own
		// flow can produce.)
		cache, err := secret.LoadCache(srv.CacheKey())
		if err != nil {
			t.Fatalf("load local secret cache: %v", err)
		}
		if cache["console:berth"] == "" {
			t.Error("break_glass on: console password missing from the local secret cache (~/.berth/) — the operator cannot read it")
		}
		return
	}
	// Off: the suite's flow means any usable password here would be a berth
	// leftover the lock-back failed to reconcile.
	if status == "P" {
		t.Errorf("break_glass off: berth password status = P, want locked/absent (L or NP)")
	}
}

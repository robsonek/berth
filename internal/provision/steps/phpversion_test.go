package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestPHPGuardRefusesStaleBerthPools(t *testing.T) {
	// A berth-marked pool under another version's pool.d means php.version
	// changed after seeding: the per-site sockets are version-independent, so
	// two masters would fight over them. Hard refusal — not bypassable with
	// --force (owner-guard precedent) — with the manual recipe.
	s := &config.Server{PHP: config.PHP{Version: "8.5"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.5"), bssh.Result{Stdout: "M /etc/php/8.4/fpm/pool.d/app_example_com.conf\n"})
	err := assertPHPVersionExclusive(context.Background(), f, s)
	if err == nil {
		t.Fatal("stale berth pool must refuse")
	}
	for _, want := range []string{"/etc/php/8.4/fpm/pool.d/app_example_com.conf", "revert php.version", "maintenance"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}
	// --force must not bypass: the helper takes no force parameter at all;
	// pin that both steps call it unconditionally via the step tests below.
}

func TestPHPGuardRefusesForeignPoolOnBerthSocket(t *testing.T) {
	// A foreign (unmarked) old-version pool that binds a berth socket is the
	// exact collision the guard exists for — marker-only detection would
	// false-negative it.
	s := &config.Server{PHP: config.PHP{Version: "8.5"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.5"), bssh.Result{Stdout: "S /etc/php/8.3/fpm/pool.d/legacy.conf\n"})
	err := assertPHPVersionExclusive(context.Background(), f, s)
	if err == nil || !strings.Contains(err.Error(), "legacy.conf") || !strings.Contains(err.Error(), "/run/php/berth-") {
		t.Fatalf("foreign pool on a berth socket must refuse naming both; got %v", err)
	}
}

func TestPHPGuardAllowsCleanAndForeignOldPools(t *testing.T) {
	// Fresh host (no output) and foreign old pools with their own sockets are
	// none of berth's business.
	s := &config.Server{PHP: config.PHP{Version: "8.5"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.5"), bssh.Result{})
	if err := assertPHPVersionExclusive(context.Background(), f, s); err != nil {
		t.Fatalf("clean probe must pass: %v", err)
	}
}

func TestPHPApplyGuardRunsBeforeAnyMutation(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{Stdout: "M /etc/php/8.3/fpm/pool.d/x.conf\n"})
	err := PHP().Apply(context.Background(), provision.RunCtx{Force: true}, s, f)
	if err == nil {
		t.Fatal("Apply must refuse on the guard (even with --force)")
	}
	// The refusal must precede repo setup, the reload-stamp invalidation and
	// apt — a refusal that already invalidated the stamp would leave the
	// desired version unsatisfied despite changing nothing.
	if len(f.Calls()) != 1 {
		t.Errorf("guard must be the FIRST and ONLY remote call before refusing; ran %v", f.Calls())
	}
}

func TestPHPCheckGuardIsHardError(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{Stdout: "M /etc/php/8.3/fpm/pool.d/x.conf\n"})
	_, err := PHP().Check(context.Background(), provision.RunCtx{Force: true}, s, f)
	if err == nil {
		t.Fatal("Check must hard-error (not unsatisfied) on the guard")
	}
}

func TestAccountsGuardRunsBeforeAnyMutation(t *testing.T) {
	// accounts renders the configured PHP version into site sudoers and runs
	// BEFORE php in the pipeline: without its own guard a failed run would
	// re-point deploy users' reload grant at the not-yet-installed version.
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{Stdout: "M /etc/php/8.3/fpm/pool.d/x.conf\n"})
	err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{Force: true}, s, f)
	if err == nil {
		t.Fatal("accounts.Apply must refuse on the guard")
	}
	if len(f.Calls()) != 1 {
		t.Errorf("guard must refuse before ANY account/sudoers mutation; ran %v", f.Calls())
	}
	if _, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f); err == nil {
		t.Fatal("accounts.Check must hard-error on the guard")
	}
}

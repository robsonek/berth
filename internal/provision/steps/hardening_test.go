package steps

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// stubGate replaces the anti-lockout gate for the duration of a test, recording
// whether it ran and returning err.
func stubGate(t *testing.T, err error, ran *bool) {
	t.Helper()
	prev := verifyBerthAccess
	verifyBerthAccess = func(_ context.Context, _ *config.Server) error {
		if ran != nil {
			*ran = true
		}
		return err
	}
	t.Cleanup(func() { verifyBerthAccess = prev })
}

func hardeningServer() *config.Server {
	return &config.Server{Host: "192.0.2.10", SSH: config.SSH{Port: 2222}}
}

func TestHardeningRequiresAccounts(t *testing.T) {
	if got := Hardening().Requires(); len(got) != 1 || got[0] != "accounts" {
		t.Fatalf("Requires() = %v, want [accounts]", got)
	}
}

func TestHardeningApplyAllowsBeforeEnableAndGatesBeforeSshd(t *testing.T) {
	var gateRan bool
	stubGate(t, nil, &gateRan)

	s := hardeningServer()
	f := bssh.NewFakeRunner()
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})

	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !gateRan {
		t.Fatal("anti-lockout gate did not run")
	}

	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	idx := func(want string) int {
		for i, c := range cmds {
			if c == want {
				return i
			}
		}
		return -1
	}
	allowSSH := idx("ufw allow 2222/tcp")
	allow80 := idx("ufw allow 80,443/tcp")
	enable := idx("ufw --force enable")
	reload := idx("systemctl reload ssh")
	if allowSSH < 0 || allow80 < 0 || enable < 0 || reload < 0 {
		t.Fatalf("missing expected commands; got %v", cmds)
	}
	if !(allowSSH < enable && allow80 < enable) {
		t.Errorf("ufw allow rules must precede enable; order=%v", cmds)
	}

	// Gate must run before the sshd drop-in is written.
	var sshdWriteSeen bool
	for _, w := range f.Writes() {
		if w.Path == sshdDropInPath {
			sshdWriteSeen = true
		}
	}
	if !sshdWriteSeen {
		t.Error("sshd drop-in not written after a passing gate")
	}
}

func TestHardeningApplyAbortsWhenGateFails(t *testing.T) {
	var gateRan bool
	stubGate(t, errors.New("no berth access"), &gateRan)

	s := hardeningServer()
	f := bssh.NewFakeRunner()
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban", bssh.Result{})

	err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("expected error when anti-lockout gate fails")
	}
	if !strings.Contains(err.Error(), "anti-lockout") {
		t.Errorf("error should mention anti-lockout; got %v", err)
	}
	if !gateRan {
		t.Error("gate should have been consulted")
	}
	// sshd must NOT be touched on a failing gate.
	for _, w := range f.Writes() {
		if w.Path == sshdDropInPath {
			t.Error("sshd drop-in must not be written when the gate fails")
		}
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl reload ssh" {
			t.Error("ssh must not be reloaded when the gate fails")
		}
	}
}

func TestHardeningCheckSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("ufw status", bssh.Result{Stdout: "Status: active\n", ExitCode: 0})
	f.On("systemctl is-active fail2ban", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled fail2ban", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{Stdout: sshdDropInBody, ExitCode: 0})
	cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestHardeningCheckAbortsOnUnmanagedSshdDropIn(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("ufw status", bssh.Result{Stdout: "Status: active\n", ExitCode: 0})
	f.On("systemctl is-active fail2ban", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled fail2ban", bssh.Result{ExitCode: 0})
	// Pre-existing, unmanaged drop-in (no berth marker).
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{Stdout: "PermitRootLogin yes\n", ExitCode: 0})
	_, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil {
		t.Fatal("expected abort when sshd drop-in is unmanaged and --force is absent")
	}

	// With --force, it reconciles instead of aborting (not satisfied, no error).
	cr, err := Hardening().Check(context.Background(), provision.RunCtx{Force: true}, hardeningServer(), f)
	if err != nil {
		t.Fatalf("with --force, expected no error; got %v", err)
	}
	if cr.Satisfied {
		t.Error("with --force on an unmanaged file, expected unsatisfied (will reconcile)")
	}
}

func TestHardeningCheckUnsatisfiedWhenUfwInactive(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("ufw status", bssh.Result{Stdout: "Status: inactive\n", ExitCode: 0})
	f.On("systemctl is-active fail2ban", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled fail2ban", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{Stdout: sshdDropInBody, ExitCode: 0})
	cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when ufw is inactive")
	}
}

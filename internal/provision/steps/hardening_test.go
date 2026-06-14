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
	return &config.Server{
		Host: "192.0.2.10", SSH: config.SSH{Port: 2222},
		Fail2ban: config.Fail2ban{Bantime: "1h", Findtime: "10m", Maxretry: 5},
	}
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
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})
	f.On("fail2ban-client -t", bssh.Result{})
	f.On("systemctl enable --now fail2ban", bssh.Result{})
	f.On("systemctl reload fail2ban", bssh.Result{})

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
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban", bssh.Result{})

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
	jailWant, _ := renderFail2banJail(hardeningServer())
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{Stdout: string(jailWant), ExitCode: 0})
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
	// The --force branch proceeds past the unmanaged sshd file to the jail check.
	jailWant, _ := renderFail2banJail(hardeningServer())
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{Stdout: string(jailWant), ExitCode: 0})
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
	jailWant, _ := renderFail2banJail(hardeningServer())
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{Stdout: string(jailWant), ExitCode: 0})
	cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when ufw is inactive")
	}
}

func TestHardeningApplyOpensUDP443WhenHTTP3(t *testing.T) {
	stubGate(t, nil, nil)
	s := hardeningServer()
	s.Sites = []config.Site{{Domain: "a.example.com", HTTP3: true}}
	f := bssh.NewFakeRunner()
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On("ufw allow 443/udp", bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})
	f.On("fail2ban-client -t", bssh.Result{})
	f.On("systemctl enable --now fail2ban", bssh.Result{})
	f.On("systemctl reload fail2ban", bssh.Result{})

	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var sawUDP bool
	for _, c := range f.Calls() {
		if c.Cmd == "ufw allow 443/udp" {
			sawUDP = true
		}
	}
	if !sawUDP {
		t.Error("expected `ufw allow 443/udp` when a site enables http3")
	}
}

func TestHardeningCheckRequiresUDP443WhenHTTP3(t *testing.T) {
	s := hardeningServer()
	s.Sites = []config.Site{{Domain: "a.example.com", HTTP3: true}}
	f := bssh.NewFakeRunner()
	// ufw active with 80,443/tcp but NOT 443/udp -> an http3 site is not satisfied.
	f.On("ufw status", bssh.Result{Stdout: "Status: active\n80,443/tcp ALLOW Anywhere\n", ExitCode: 0})
	f.On("systemctl is-active fail2ban", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled fail2ban", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{Stdout: sshdDropInBody, ExitCode: 0})
	jailWant, _ := renderFail2banJail(s)
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{Stdout: string(jailWant), ExitCode: 0})
	cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied: an http3 site needs 443/udp open")
	}
	// A decoy UDP rule whose port merely ends in 443 must NOT count as 443/udp.
	f.On("ufw status", bssh.Result{Stdout: "Status: active\n80,443/tcp ALLOW Anywhere\n10443/udp ALLOW Anywhere\n", ExitCode: 0})
	cr, err = Hardening().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied: 10443/udp must not be mistaken for 443/udp")
	}
	// Once 443/udp is also allowed, it is satisfied.
	f.On("ufw status", bssh.Result{Stdout: "Status: active\n80,443/tcp ALLOW Anywhere\n443/udp ALLOW Anywhere\n", ExitCode: 0})
	cr, err = Hardening().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied once 443/udp is open; got %+v", cr)
	}
}

func TestHardeningCheckUnsatisfiedWhenJailMissing(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("ufw status", bssh.Result{Stdout: "Status: active\n", ExitCode: 0})
	f.On("systemctl is-active fail2ban", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled fail2ban", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{Stdout: sshdDropInBody, ExitCode: 0})
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{ExitCode: 1}) // jail.local absent
	cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the fail2ban jail.local is absent")
	}
}

func TestHardeningCheckUnsatisfiedWhenJailDrifted(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("ufw status", bssh.Result{Stdout: "Status: active\n", ExitCode: 0})
	f.On("systemctl is-active fail2ban", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled fail2ban", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{Stdout: sshdDropInBody, ExitCode: 0})
	// Managed by berth but stale content (different hash) -> drifted -> unsatisfied.
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{Stdout: managedMarker + "\n[sshd]\nenabled = true\nport = 9999\n", ExitCode: 0})
	cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the managed jail.local content has drifted")
	}
}

func TestHardeningApplyWritesFail2banJail(t *testing.T) {
	stubGate(t, nil, nil)
	s := hardeningServer()
	f := bssh.NewFakeRunner()
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})
	f.On("fail2ban-client -t", bssh.Result{})
	f.On("systemctl enable --now fail2ban", bssh.Result{})
	f.On("systemctl reload fail2ban", bssh.Result{})

	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var jail *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == fail2banJailPath {
			jail = &f.Writes()[i]
		}
	}
	if jail == nil {
		t.Fatal("fail2ban jail.local was not written")
	}
	body := string(jail.Content)
	if !strings.Contains(body, "managed by berth") || !strings.Contains(body, "port = 2222") {
		t.Errorf("jail must carry the marker and bind the configured SSH port;\n%s", body)
	}
	var idxTest, idxEnable, idxReload = -1, -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "fail2ban-client -t":
			idxTest = i
		case "systemctl enable --now fail2ban":
			idxEnable = i
		case "systemctl reload fail2ban":
			idxReload = i
		}
	}
	if idxTest < 0 || idxReload < 0 || idxTest > idxReload {
		t.Errorf("fail2ban-client -t must run before reload; test=%d reload=%d", idxTest, idxReload)
	}
	// enable --now must converge fail2ban (active+enabled) before the reload.
	if idxEnable < 0 || !(idxTest < idxEnable && idxEnable <= idxReload) {
		t.Errorf("enable --now must run after -t and before/at reload; test=%d enable=%d reload=%d", idxTest, idxEnable, idxReload)
	}
}

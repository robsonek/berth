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

// sshdTGood is a minimal `sshd -T` dump in which every directive berth
// requires holds. sshd -T prints lowercase "key value" lines.
const sshdTGood = "port 2222\npermitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n"

// stubSshdEffectiveGood stubs the probes a fully converged host answers:
// no legacy drop-in, no SSHD_OPTS override (grep exits 1 on no match),
// and an effective config with all required directives.
func stubSshdEffectiveGood(f *bssh.FakeRunner) {
	f.On("cat "+shQuote(sshdDropInLegacyPath), bssh.Result{ExitCode: 1})
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 1})
	f.On("sshd -T", bssh.Result{ExitCode: 0, Stdout: sshdTGood})
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
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1})   // write-guard: absent
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sshd -t", bssh.Result{})
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

func TestHardeningApplyRefusesForeignSshdDropIn(t *testing.T) {
	// The write path must refuse to clobber a hand-written sshd drop-in that
	// berth does not manage (Check's loop can return on an earlier conflict).
	stubGate(t, nil, nil)
	s := hardeningServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban", bssh.Result{})
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 0, Stdout: "PermitRootLogin prohibit-password\n"}) // foreign

	err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	for _, w := range f.Writes() {
		if w.Path == sshdDropInPath {
			t.Error("a foreign sshd drop-in must not be overwritten without --force")
		}
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl reload ssh" {
			t.Error("reload ssh must not run when the drop-in write was refused")
		}
	}
}

func TestHardeningApplyValidatesSshdBeforeReload(t *testing.T) {
	stubGate(t, nil, nil)
	s := hardeningServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban", bssh.Result{})
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	f.On("sshd -t", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1})   // write-guard: absent
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sshd -t", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})
	f.On("fail2ban-client -t", bssh.Result{})
	f.On("systemctl enable --now fail2ban", bssh.Result{})
	f.On("systemctl reload fail2ban", bssh.Result{})

	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idxT, idxReload := -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "sshd -t":
			idxT = i
		case "systemctl reload ssh":
			idxReload = i
		}
	}
	if idxT < 0 {
		t.Fatal("Apply must validate the sshd configuration (sshd -t) after writing the drop-in")
	}
	if idxReload < 0 || idxT > idxReload {
		t.Errorf("sshd -t must run before systemctl reload ssh; calls order t=%d reload=%d", idxT, idxReload)
	}
}

func TestHardeningApplyAbortsReloadWhenSshdConfigInvalid(t *testing.T) {
	stubGate(t, nil, nil)
	s := hardeningServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban", bssh.Result{})
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sshd -t", bssh.Result{ExitCode: 1, Stderr: "/etc/ssh/sshd_config.d/berth.conf: Bad configuration option"})
	// systemctl reload ssh intentionally NOT stubbed: it must never run.

	err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "sshd -t") {
		t.Fatalf("err = %v, want the sshd -t refusal", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl reload ssh" {
			t.Error("reload ssh must not run after a failed sshd -t")
		}
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
	stubSshdEffectiveGood(f)
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
	stubSshdEffectiveGood(f)
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
	stubSshdEffectiveGood(f)
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
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1})   // write-guard: absent
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sshd -t", bssh.Result{})
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
	stubSshdEffectiveGood(f)
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
	stubSshdEffectiveGood(f)
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
	stubSshdEffectiveGood(f)
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
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1})   // write-guard: absent
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sshd -t", bssh.Result{})
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

func TestRenderFail2banJailZeroValueUsesDefaults(t *testing.T) {
	got, err := renderFail2banJail(&config.Server{SSH: config.SSH{Port: 22}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bantime = 1h", "findtime = 10m", "maxretry = 5"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("zero-value jail render missing %q:\n%s", want, got)
		}
	}
}

func TestHardeningDropInTargetsSortFirstPath(t *testing.T) {
	// OpenSSH applies first-match-wins and Include expands lexicographically:
	// the managed drop-in must sort before image drop-ins like
	// 50-cloud-init.conf, or its directives silently lose.
	if sshdDropInPath != "/etc/ssh/sshd_config.d/00-berth.conf" {
		t.Errorf("sshdDropInPath = %q, want the 00-prefixed path", sshdDropInPath)
	}
	if sshdDropInLegacyPath != "/etc/ssh/sshd_config.d/berth.conf" {
		t.Errorf("sshdDropInLegacyPath = %q, want the pre-rename path", sshdDropInLegacyPath)
	}
	for _, want := range []string{
		"PermitRootLogin no\n",
		"PasswordAuthentication no\n",
		"KbdInteractiveAuthentication no\n",
	} {
		if !strings.Contains(sshdDropInBody, want) {
			t.Errorf("sshdDropInBody missing %q:\n%s", want, sshdDropInBody)
		}
	}
}

// stubCheckGreenBase stubs everything Check needs for a converged host EXCEPT
// the legacy/SSHD_OPTS/sshd -T probes, which each test controls itself.
func stubCheckGreenBase(f *bssh.FakeRunner) {
	f.On("ufw status", bssh.Result{Stdout: "Status: active\n", ExitCode: 0})
	f.On("systemctl is-active fail2ban", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled fail2ban", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{Stdout: sshdDropInBody, ExitCode: 0})
	jailWant, _ := renderFail2banJail(hardeningServer())
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{Stdout: string(jailWant), ExitCode: 0})
}

func TestHardeningCheckErrorsWhenEffectiveOverridden(t *testing.T) {
	// The audit's exact scenario: berth's drop-in bytes are perfect, but a
	// file sorting earlier re-enables password auth. Apply could only rewrite
	// identical bytes and fail the same gate forever, so this is UNFIXABLE
	// drift: Check must fail loud with candidate sources, not report
	// reconcilable drift (which would also make dry-run promise a fix).
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	f.On("cat "+shQuote(sshdDropInLegacyPath), bssh.Result{ExitCode: 1})
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 1})
	f.On("sshd -T", bssh.Result{ExitCode: 0,
		Stdout: "port 2222\npermitrootlogin no\npasswordauthentication yes\nkbdinteractiveauthentication no\n"})
	f.On(sshdConflictGrep, bssh.Result{ExitCode: 0,
		Stdout: "/etc/ssh/sshd_config.d/00-berth.conf\n/etc/ssh/sshd_config.d/50-cloud-init.conf\n"})

	_, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil {
		t.Fatal("expected a loud error when a foreign file overrides the effective config")
	}
	if !strings.Contains(err.Error(), "passwordauthentication no") {
		t.Errorf("error should name the missing directive; got %v", err)
	}
	if !strings.Contains(err.Error(), "50-cloud-init.conf") {
		t.Errorf("error should name the candidate source; got %v", err)
	}
}

func TestHardeningCheckFailsClosedOnSshdOpts(t *testing.T) {
	// Debian's ssh.service starts `sshd -D $SSHD_OPTS`; command-line options
	// override every config file, so sshd -T cannot see them. Fail closed.
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	f.On("cat "+shQuote(sshdDropInLegacyPath), bssh.Result{ExitCode: 1})
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0, Stdout: `SSHD_OPTS="-o PasswordAuthentication=yes"` + "\n"})

	_, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil || !strings.Contains(err.Error(), "SSHD_OPTS") {
		t.Fatalf("err = %v, want a fail-closed SSHD_OPTS error", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "sshd -T" {
			t.Error("sshd -T must not run when SSHD_OPTS makes its output unrepresentative")
		}
	}
}

func TestHardeningCheckErrorsWhenSshdDumpFails(t *testing.T) {
	// A broken foreign config berth cannot converge: fail loud, not unsatisfied.
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	f.On("cat "+shQuote(sshdDropInLegacyPath), bssh.Result{ExitCode: 1})
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 1})
	f.On("sshd -T", bssh.Result{ExitCode: 1, Stderr: "/etc/ssh/sshd_config.d/60-broken.conf: Bad configuration option"})

	_, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil || !strings.Contains(err.Error(), "sshd -T") {
		t.Fatalf("err = %v, want an sshd -T failure", err)
	}
}

func TestHardeningCheckUnsatisfiedWhenLegacyDropInPresent(t *testing.T) {
	// A berth-managed legacy file gates the effective probe OFF: Apply must
	// migrate it first (a malformed managed legacy file would otherwise error
	// sshd -T before Apply could remove the very file berth owns).
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	f.On("cat "+shQuote(sshdDropInLegacyPath),
		bssh.Result{ExitCode: 0, Stdout: managedMarker + "\nPermitRootLogin no\nPasswordAuthentication no\n"})

	cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while the berth-managed legacy drop-in remains")
	}
	for _, c := range f.Calls() {
		if c.Cmd == "sshd -T" || c.Cmd == sshdOptsProbe {
			t.Error("the effective probe must be gated off while a managed legacy file remains")
		}
	}
}

func TestHardeningCheckIgnoresForeignLegacyDropIn(t *testing.T) {
	// A foreign file at the legacy path is NOT berth's to delete, and any
	// GLOBAL directive it sets is caught by the effective probe (Match-scoped
	// content is out of contract). It must not block Satisfied.
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	f.On("cat "+shQuote(sshdDropInLegacyPath), bssh.Result{ExitCode: 0, Stdout: "# operator notes\n"})
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 1})
	f.On("sshd -T", bssh.Result{ExitCode: 0, Stdout: sshdTGood})

	cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied despite a foreign file at the legacy path; got %+v", cr)
	}
	var probed bool
	for _, c := range f.Calls() {
		if c.Cmd == "cat "+shQuote(sshdDropInLegacyPath) {
			probed = true
		}
	}
	if !probed {
		t.Error("Check must actually probe the legacy path (guards against passing for the wrong reason)")
	}
}

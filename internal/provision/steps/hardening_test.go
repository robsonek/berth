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
// no SSHD_OPTS override (/etc/default/ssh missing: exit 0, empty output)
// and an effective config with all required directives.
func stubSshdEffectiveGood(f *bssh.FakeRunner) {
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0})
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
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f)

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
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 0, Stdout: "PermitRootLogin prohibit-password\n"}) // foreign
	stubApplyStampsGreen(f)

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
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f)

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
	// Covers Apply's up-front SSHD_OPTS guard; the helper's sshd -T stub
	// stays inert (the failing sshd -t aborts first).
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f) // ssh up: the heal skips its own sshd -t
	f.On("sshd -t", bssh.Result{ExitCode: 1, Stderr: "/etc/ssh/sshd_config.d/00-berth.conf: Bad configuration option"})
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
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0})
	stubApplyStampsGreen(f) // ssh up: the pre-gate heal is a no-op probe

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
	stubStampsGreen(f)
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
	stubStampsGreen(f)
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
	stubStampsGreen(f)
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
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f)

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
	stubStampsGreen(f)
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
	stubStampsGreen(f)
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
	stubStampsGreen(f)
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
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f)

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
// the SSHD_OPTS/sshd -T probes, which each test controls itself.
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
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0})
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

func TestHardeningCheckErrorsWhenSshdOptsUnreadable(t *testing.T) {
	// A present-but-unreadable /etc/default/ssh is a read FAILURE, not
	// "unset": berth must refuse to trust sshd -T rather than assume
	// SSHD_OPTS is empty.
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 1, Stderr: "cat: /etc/default/ssh: Permission denied"})

	_, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil || !strings.Contains(err.Error(), "cannot read /etc/default/ssh") {
		t.Fatalf("err = %v, want a fail-closed unreadable-file error", err)
	}
}

func TestSshdOptsHelpers(t *testing.T) {
	// sshdOptsEmpty accepts only values PROVABLY empty (``, `""`, `''`);
	// anything else — including a dangling opening quote that systemd's
	// EnvironmentFile parser would continue across lines, or a trailing
	// comment — conservatively counts as set.
	tests := []struct {
		name  string
		in    string
		found bool
		raw   string
		empty bool
	}{
		{"no assignment", "# defaults for openssh-server\nUNRELATED=1\n", false, "", true},
		{"bare empty value", `SSHD_OPTS=`, true, "", true},
		{"empty double quotes", `SSHD_OPTS=""`, true, `""`, true},
		{"empty single quotes", `SSHD_OPTS=''`, true, `''`, true},
		{"double-quoted options", `SSHD_OPTS="-o PasswordAuthentication=yes"`, true, `"-o PasswordAuthentication=yes"`, false},
		{"dangling opening quote", `SSHD_OPTS='`, true, `'`, false},
		{"multiline quoted value", "SSHD_OPTS='\n-o PasswordAuthentication=yes'", true, `'`, false},
		{"last assignment empty wins", "SSHD_OPTS=\"-4\"\nSSHD_OPTS=\"\"", true, `""`, true},
		{"last assignment set wins", "SSHD_OPTS=\"\"\nSSHD_OPTS=\"-6\"", true, `"-6"`, false},
		{"leading whitespace recognized", `  SSHD_OPTS="-4"`, true, `"-4"`, false},
		{"commented-out assignment ignored", `#SSHD_OPTS=x`, false, "", true},
		{"trailing comment counts as set", `SSHD_OPTS="" # comment`, true, `"" # comment`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, found := sshdOptsAssignment(tt.in)
			if found != tt.found || raw != tt.raw {
				t.Errorf("sshdOptsAssignment(%q) = (%q, %v), want (%q, %v)", tt.in, raw, found, tt.raw, tt.found)
			}
			if got := sshdOptsEmpty(raw); got != tt.empty {
				t.Errorf("sshdOptsEmpty(%q) = %v, want %v", raw, got, tt.empty)
			}
		})
	}
}

func TestHardeningCheckErrorsWhenSshdDumpFails(t *testing.T) {
	// A broken foreign config berth cannot converge: fail loud, not unsatisfied.
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0})
	f.On("sshd -T", bssh.Result{ExitCode: 1, Stderr: "/etc/ssh/sshd_config.d/60-broken.conf: Bad configuration option"})

	_, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil || !strings.Contains(err.Error(), "sshd -T") {
		t.Fatalf("err = %v, want an sshd -T failure", err)
	}
}

func TestHardeningCheckFreshHostGatesEffectiveProbeOff(t *testing.T) {
	// A fresh host (berth's drop-in absent) must report reconcilable drift,
	// not probe the effective config: cloud-init images ship drop-ins that
	// re-enable password auth, so an ungated sshd -T would hard-error every
	// first provision instead of letting Apply converge berth's file first.
	// The SSHD_OPTS guard still runs — it is unconditional by design.
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1}) // fresh: drop-in absent
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0})
	stubStampsGreen(f)

	cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied on a fresh host (drop-in absent)")
	}
	for _, c := range f.Calls() {
		if c.Cmd == "sshd -T" {
			t.Error("sshd -T must be gated off while berth's own drop-in is not converged")
		}
	}
}

// stubApplyGreenBase stubs the fixed early part of Apply (packages, ufw) and
// the fail2ban tail, leaving the sshd-related probes to each test.
func stubApplyGreenBase(f *bssh.FakeRunner) {
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban", bssh.Result{})
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("fail2ban-client -t", bssh.Result{})
	f.On("systemctl enable --now fail2ban", bssh.Result{})
	f.On("systemctl reload fail2ban", bssh.Result{})
}

func TestHardeningApplyFailsLoudWhenEffectiveConfigLoses(t *testing.T) {
	stubGate(t, nil, nil)
	f := bssh.NewFakeRunner()
	stubApplyGreenBase(f)
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sshd -t", bssh.Result{})
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0})
	// A file sorting before 00-berth.conf keeps password auth enabled.
	f.On("sshd -T", bssh.Result{ExitCode: 0,
		Stdout: "port 2222\npermitrootlogin no\npasswordauthentication yes\nkbdinteractiveauthentication no\n"})
	f.On(sshdConflictGrep, bssh.Result{ExitCode: 0,
		Stdout: "/etc/ssh/sshd_config.d/00-berth.conf\n/etc/ssh/sshd_config.d/50-cloud-init.conf\n"})
	stubApplyStampsGreen(f)
	// systemctl reload ssh intentionally NOT stubbed: it must never run.

	err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil {
		t.Fatal("expected a loud failure when the effective config loses")
	}
	if !strings.Contains(err.Error(), "passwordauthentication no") {
		t.Errorf("error should name the missing directive; got %v", err)
	}
	if !strings.Contains(err.Error(), "50-cloud-init.conf") {
		t.Errorf("error should name the candidate source; got %v", err)
	}
	if strings.Contains(err.Error(), "00-berth.conf,") || strings.HasSuffix(err.Error(), "00-berth.conf") {
		t.Errorf("berth's own drop-in must be filtered out of the candidate list; got %v", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl reload ssh" {
			t.Error("reload ssh must not run when the effective config is wrong")
		}
	}
}

// stubStampsGreen stubs Check's reload-stamp probes and the sshd liveness
// probe the way a converged host answers: both stamps fresh, ssh
// active+enabled.
func stubStampsGreen(f *bssh.FakeRunner) {
	f.On(reloadedSinceCmd("fail2ban", fail2banJailPath), bssh.Result{})
	f.On("systemctl is-active ssh", bssh.Result{})
	f.On("systemctl is-enabled ssh", bssh.Result{})
	f.On(reloadedSinceCmd("ssh", sshdDropInPath), bssh.Result{})
}

// stubApplyStampsGreen stubs Apply's stamp commands for a fully successful
// run (ssh already up, so the liveness heal is a no-op probe).
func stubApplyStampsGreen(f *bssh.FakeRunner) {
	f.On("systemctl is-active ssh", bssh.Result{})
	f.On("systemctl is-enabled ssh", bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/ssh.reloaded"), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/fail2ban.reloaded"), bssh.Result{})
	f.On(markReloadedCmd("ssh"), bssh.Result{})
	f.On(markReloadedCmd("fail2ban"), bssh.Result{})
}

func TestHardeningCheckUnsatisfiedWhenJailNewerThanStamp(t *testing.T) {
	// A crash between writing jail.local and reloading fail2ban leaves the
	// old jails active (e.g. guarding port 22 instead of ssh.port) while the
	// file bytes read converged — only the reload stamp catches it.
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	stubSshdEffectiveGood(f)
	stubStampsGreen(f)
	f.On(reloadedSinceCmd("fail2ban", fail2banJailPath), bssh.Result{ExitCode: 1})

	res, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if res.Satisfied {
		t.Fatal("a jail.local newer than the fail2ban reload stamp must be unsatisfied (written but not reloaded)")
	}
}

func TestHardeningCheckUnsatisfiedWhenSSHDropInNewerThanStamp(t *testing.T) {
	// The sshd -T probe reads the on-disk config, not what the running daemon
	// loaded — the write→reload window is covered only by the stamp.
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	stubSshdEffectiveGood(f)
	stubStampsGreen(f)
	f.On(reloadedSinceCmd("ssh", sshdDropInPath), bssh.Result{ExitCode: 1})

	res, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if res.Satisfied {
		t.Fatal("an sshd drop-in newer than the ssh reload stamp must be unsatisfied (written but not reloaded)")
	}
}

func TestHardeningCheckUnsatisfiedWhenSSHDown(t *testing.T) {
	// A stopped sshd is invisible over berth's established connection but
	// locks out every NEW connection — Check must flag it.
	f := bssh.NewFakeRunner()
	stubCheckGreenBase(f)
	stubSshdEffectiveGood(f)
	stubStampsGreen(f)
	f.On("systemctl is-active ssh", bssh.Result{ExitCode: 3})

	res, err := Hardening().Check(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if res.Satisfied {
		t.Fatal("a stopped sshd must be unsatisfied — every NEW connection is locked out")
	}
}

func TestHardeningApplyStampsAfterReloads(t *testing.T) {
	stubGate(t, nil, nil)
	f := bssh.NewFakeRunner()
	stubApplyGreenBase(f)
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f)
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sshd -t", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})

	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idx := func(want string) int {
		for i, c := range f.Calls() {
			if c.Cmd == want {
				return i
			}
		}
		return -1
	}
	reloadSSH := idx("systemctl reload ssh")
	markSSH := idx(markReloadedCmd("ssh"))
	reloadF2b := idx("systemctl reload fail2ban")
	markF2b := idx(markReloadedCmd("fail2ban"))
	if markSSH < 0 || markF2b < 0 {
		t.Fatalf("both reload stamps must be recorded; markSSH=%d markF2b=%d", markSSH, markF2b)
	}
	if reloadSSH < 0 || reloadSSH > markSSH {
		t.Errorf("ssh stamp must be recorded AFTER systemctl reload ssh; reload=%d mark=%d", reloadSSH, markSSH)
	}
	if reloadF2b < 0 || reloadF2b > markF2b {
		t.Errorf("fail2ban stamp must be recorded AFTER systemctl reload fail2ban; reload=%d mark=%d", reloadF2b, markF2b)
	}
}

func TestHardeningApplyNoStampWhenFail2banValidationFails(t *testing.T) {
	stubGate(t, nil, nil)
	f := bssh.NewFakeRunner()
	stubApplyGreenBase(f)
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f)
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sshd -t", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})
	f.On("fail2ban-client -t", bssh.Result{ExitCode: 1, Stderr: "bad jail"})

	err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil || !strings.Contains(err.Error(), "fail2ban-client -t") {
		t.Fatalf("err = %v, want the fail2ban-client -t refusal", err)
	}
	// The invalidating rm before the write is the transactional contract; the
	// stamp must never be CREATED after a failed validation, and no reload
	// may run either.
	for _, c := range f.Calls() {
		if c.Cmd == markReloadedCmd("fail2ban") {
			t.Error("the fail2ban reload stamp must not be recorded after a failed validation")
		}
		if c.Cmd == "systemctl reload fail2ban" {
			t.Error("reload fail2ban must not run after a failed validation")
		}
	}
}

func TestHardeningApplyStartsStoppedSSHBeforeAntiLockout(t *testing.T) {
	// A stopped sshd would fail the anti-lockout dial before anything could
	// heal it, so the heal must run first — verified by snapshotting the
	// commands issued up to the moment the gate dials.
	f := bssh.NewFakeRunner()
	var callsAtDial []string
	prev := verifyBerthAccess
	verifyBerthAccess = func(_ context.Context, _ *config.Server) error {
		for _, c := range f.Calls() {
			callsAtDial = append(callsAtDial, c.Cmd)
		}
		return nil
	}
	t.Cleanup(func() { verifyBerthAccess = prev })

	stubApplyGreenBase(f)
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f)
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("systemctl is-active ssh", bssh.Result{ExitCode: 3})      // ssh is down
	f.On("systemctl is-enabled ssh", bssh.Result{ExitCode: 1})
	f.On("sshd -t", bssh.Result{})
	f.On("systemctl enable --now ssh", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})

	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var healedBeforeDial bool
	for _, cmd := range callsAtDial {
		if cmd == "systemctl enable --now ssh" {
			healedBeforeDial = true
		}
	}
	if !healedBeforeDial {
		t.Error("systemctl enable --now ssh must run BEFORE the anti-lockout dial")
	}
}

func TestHardeningApplyHealsCorruptManagedDropInWhenSSHDown(t *testing.T) {
	// Stopped sshd + a corrupt BERTH-MANAGED drop-in: the heal's sshd -t fails,
	// and the file is berth's to fix — but the heal must fix it by REMOVAL,
	// never by writing the restrictive body: the drop-in disables root and
	// password auth, so writing it and starting sshd BEFORE the anti-lockout
	// dial would put the lockdown live without the gate. The gated rewrite
	// later in the same Apply re-hardens.
	f := bssh.NewFakeRunner()
	var writesAtDial []bssh.FileSpec
	prev := verifyBerthAccess
	verifyBerthAccess = func(_ context.Context, _ *config.Server) error {
		writesAtDial = append(writesAtDial, f.Writes()...)
		return nil
	}
	t.Cleanup(func() { verifyBerthAccess = prev })

	stubApplyGreenBase(f)
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f)
	f.On("systemctl is-active ssh", bssh.Result{ExitCode: 3}) // ssh is down
	f.On("systemctl is-enabled ssh", bssh.Result{ExitCode: 1})
	// Corrupt but berth-managed drop-in (marker present, content drifted).
	f.On("cat "+shQuote(sshdDropInPath),
		bssh.Result{ExitCode: 0, Stdout: managedMarker + "\nPermitRootLogin broken\n"})
	// First sshd -t (heal) fails on the corrupt drop-in; after the removal it
	// passes (and keeps passing for the gated rewrite's validation).
	f.OnSeq("sshd -t",
		bssh.Result{ExitCode: 1, Stderr: "00-berth.conf: Bad configuration option"},
		bssh.Result{})
	f.On("rm -f "+shQuote(sshdDropInPath), bssh.Result{})
	f.On("systemctl enable --now ssh", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})

	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	// The heal must not write the restrictive drop-in before the gate dialed.
	for _, w := range writesAtDial {
		if w.Path == sshdDropInPath {
			t.Error("the heal must not write the sshd drop-in BEFORE the anti-lockout gate")
		}
	}
	// The gated normal path still rewrites it afterwards.
	var wrote bool
	for _, w := range f.Writes() {
		if w.Path == sshdDropInPath && string(w.Content) == sshdDropInBody {
			wrote = true
		}
	}
	if !wrote {
		t.Error("the gated rewrite must still install the drop-in after the gate")
	}
	tRuns, firstT, start, stampRm, dropRm := 0, -1, -1, -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "sshd -t":
			tRuns++
			if firstT < 0 {
				firstT = i
			}
		case "systemctl enable --now ssh":
			start = i
		case "rm -f " + shQuote("/var/lib/berth/ssh.reloaded"):
			if stampRm < 0 {
				stampRm = i
			}
		case "rm -f " + shQuote(sshdDropInPath):
			if dropRm < 0 {
				dropRm = i
			}
		}
	}
	if dropRm < 0 {
		t.Fatal("the heal must remove the corrupt berth-managed drop-in")
	}
	// The removal mutates ssh's config, so the stamp invalidate must precede it.
	if stampRm < 0 || stampRm > dropRm {
		t.Errorf("the ssh stamp must be invalidated BEFORE the drop-in removal; rm-stamp=%d rm-dropin=%d", stampRm, dropRm)
	}
	if tRuns < 2 {
		t.Errorf("the heal must re-run sshd -t after the removal; got %d run(s)", tRuns)
	}
	if start < 0 || start < firstT {
		t.Errorf("ssh must be started only after the heal validated; first -t=%d start=%d", firstT, start)
	}
}

func TestHardeningApplyHealRefusesForeignDropInWhenSSHDown(t *testing.T) {
	// Stopped sshd + failing sshd -t + a FOREIGN drop-in: not berth's to fix.
	// Apply must fail loud (naming the file) without writing it or starting ssh.
	var gateRan bool
	stubGate(t, nil, &gateRan)
	f := bssh.NewFakeRunner()
	stubApplyGreenBase(f)
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0})
	f.On("rm -f "+shQuote("/var/lib/berth/fail2ban.reloaded"), bssh.Result{}) // invalidated before apt
	f.On("systemctl is-active ssh", bssh.Result{ExitCode: 3})                 // ssh is down
	f.On("systemctl is-enabled ssh", bssh.Result{ExitCode: 1})
	f.On("sshd -t", bssh.Result{ExitCode: 1, Stderr: "Bad configuration option"})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 0, Stdout: "PermitRootLogin yes\n"}) // foreign
	// systemctl enable --now ssh intentionally NOT stubbed: it must never run.

	err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil || !strings.Contains(err.Error(), sshdDropInPath) {
		t.Fatalf("err = %v, want a loud error naming %s", err, sshdDropInPath)
	}
	for _, w := range f.Writes() {
		if w.Path == sshdDropInPath {
			t.Error("a foreign drop-in must not be written by the heal")
		}
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl enable --now ssh" {
			t.Error("ssh must not be started while its config is foreign and invalid")
		}
	}
	if gateRan {
		t.Error("the anti-lockout gate must not run after the heal refused")
	}
}

func TestHardeningApplyHealFailsWhenRemovalDoesNotFixSshd(t *testing.T) {
	// Stopped sshd + failing sshd -t + a berth-managed drop-in, but removing it
	// does not fix the validation (another file is broken): fail loud, no
	// start, and never write the restrictive body pre-gate.
	stubGate(t, nil, nil)
	f := bssh.NewFakeRunner()
	stubApplyGreenBase(f)
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0})
	f.On("rm -f "+shQuote("/var/lib/berth/fail2ban.reloaded"), bssh.Result{}) // invalidated before apt
	f.On("rm -f "+shQuote("/var/lib/berth/ssh.reloaded"), bssh.Result{})      // heal invalidates before the removal
	f.On("systemctl is-active ssh", bssh.Result{ExitCode: 3})                 // ssh is down
	f.On("systemctl is-enabled ssh", bssh.Result{ExitCode: 1})
	f.On("sshd -t", bssh.Result{ExitCode: 1, Stderr: "60-foreign.conf: Bad configuration option"})
	f.On("cat "+shQuote(sshdDropInPath),
		bssh.Result{ExitCode: 0, Stdout: managedMarker + "\nPermitRootLogin broken\n"})
	f.On("rm -f "+shQuote(sshdDropInPath), bssh.Result{})
	// systemctl enable --now ssh intentionally NOT stubbed: it must never run.

	err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil || !strings.Contains(err.Error(), sshdDropInPath) {
		t.Fatalf("err = %v, want a loud error naming %s", err, sshdDropInPath)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl enable --now ssh" {
			t.Error("ssh must not be started while sshd -t still fails after the removal")
		}
	}
	for _, w := range f.Writes() {
		if w.Path == sshdDropInPath {
			t.Error("the heal must never write the restrictive drop-in")
		}
	}
}

func TestHardeningApplyHealFailsWhenDropInAbsent(t *testing.T) {
	// Stopped sshd + failing sshd -t + berth's drop-in ABSENT: nothing
	// berth-owned to remove, the breakage is foreign — fail loud, no start,
	// and never write the restrictive body pre-gate.
	stubGate(t, nil, nil)
	f := bssh.NewFakeRunner()
	stubApplyGreenBase(f)
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0})
	f.On("rm -f "+shQuote("/var/lib/berth/fail2ban.reloaded"), bssh.Result{}) // invalidated before apt
	f.On("systemctl is-active ssh", bssh.Result{ExitCode: 3})                 // ssh is down
	f.On("systemctl is-enabled ssh", bssh.Result{ExitCode: 1})
	f.On("sshd -t", bssh.Result{ExitCode: 1, Stderr: "60-foreign.conf: Bad configuration option"})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1}) // absent
	// systemctl enable --now ssh intentionally NOT stubbed: it must never run.

	err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil || !strings.Contains(err.Error(), sshdDropInPath) {
		t.Fatalf("err = %v, want a loud error naming %s", err, sshdDropInPath)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl enable --now ssh" {
			t.Error("ssh must not be started while sshd -t fails for a foreign reason")
		}
		if c.Cmd == "rm -f "+shQuote(sshdDropInPath) {
			t.Error("nothing berth-owned exists to remove; the heal must not rm the path")
		}
	}
	for _, w := range f.Writes() {
		if w.Path == sshdDropInPath {
			t.Error("the heal must never write the restrictive drop-in")
		}
	}
}

func TestHardeningApplyInvalidatesBeforeWrites(t *testing.T) {
	stubGate(t, nil, nil)
	f := bssh.NewFakeRunner()
	stubApplyGreenBase(f)
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f)
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("sshd -t", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})

	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idx := func(want string) int {
		for i, c := range f.Calls() {
			if c.Cmd == want {
				return i
			}
		}
		return -1
	}
	// The write-guard cat is issued by writeManagedFile immediately before
	// each WriteFile — the closest observable proxy for the write itself
	// (Run and WriteFile orders cannot be correlated on the FakeRunner).
	rmSSH := idx("rm -f " + shQuote("/var/lib/berth/ssh.reloaded"))
	guardSSH := idx("cat " + shQuote(sshdDropInPath))
	rmF2b := idx("rm -f " + shQuote("/var/lib/berth/fail2ban.reloaded"))
	install := idx("DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban")
	guardF2b := idx("cat " + shQuote(fail2banJailPath))
	if rmSSH < 0 || guardSSH < 0 || rmSSH > guardSSH {
		t.Errorf("ssh stamp must be invalidated BEFORE the drop-in write; rm=%d write-guard=%d", rmSSH, guardSSH)
	}
	// The fail2ban package can ship jail conffile changes, so its stamp must be
	// invalidated BEFORE the apt install, not just before the jail write.
	if rmF2b < 0 || install < 0 || rmF2b > install {
		t.Errorf("fail2ban stamp must be invalidated BEFORE the apt install; rm=%d install=%d", rmF2b, install)
	}
	if guardF2b < 0 || rmF2b > guardF2b {
		t.Errorf("fail2ban stamp must be invalidated BEFORE the jail write; rm=%d write-guard=%d", rmF2b, guardF2b)
	}
	reloadSSH := idx("systemctl reload ssh")
	markSSH := idx(markReloadedCmd("ssh"))
	reloadF2b := idx("systemctl reload fail2ban")
	markF2b := idx(markReloadedCmd("fail2ban"))
	if markSSH < 0 || reloadSSH < 0 || reloadSSH > markSSH {
		t.Errorf("ssh stamp must be recorded after the reload; reload=%d mark=%d", reloadSSH, markSSH)
	}
	if markF2b < 0 || reloadF2b < 0 || reloadF2b > markF2b {
		t.Errorf("fail2ban stamp must be recorded after the reload; reload=%d mark=%d", reloadF2b, markF2b)
	}
}

func TestHardeningApplyFailsClosedOnSshdOptsBeforeMutating(t *testing.T) {
	// A set SSHD_OPTS dooms the effective gate at the end of Apply, so Apply
	// must refuse up front — before installing packages or touching ufw.
	stubGate(t, nil, nil)
	f := bssh.NewFakeRunner()
	f.On(sshdOptsProbe, bssh.Result{ExitCode: 0, Stdout: `SSHD_OPTS="-o PasswordAuthentication=yes"` + "\n"})

	err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f)
	if err == nil || !strings.Contains(err.Error(), "SSHD_OPTS") {
		t.Fatalf("err = %v, want a fail-closed SSHD_OPTS error", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban" || strings.HasPrefix(c.Cmd, "ufw ") {
			t.Errorf("Apply must not mutate after the SSHD_OPTS refusal; ran %q", c.Cmd)
		}
	}
	if len(f.Writes()) != 0 {
		t.Error("Apply must not write files after the SSHD_OPTS refusal")
	}
}

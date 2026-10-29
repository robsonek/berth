package steps

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// firewallServer is hardeningServer with two owned rules: one with a source
// (the full ufw form) and one without (the short form).
func firewallServer() *config.Server {
	s := hardeningServer()
	s.Firewall.Allow = []config.FirewallRule{
		{Name: "zabbix", Port: 10050, Proto: "tcp", From: "203.0.113.10"},
		{Name: "node-exporter", Port: 9100},
	}
	return s
}

const (
	ufwZabbixLine       = "ufw allow from 203.0.113.10 to any port 10050 proto tcp comment 'berth:zabbix'"
	ufwNodeExporterLine = "ufw allow 9100/tcp comment 'berth:node-exporter'"
	ufwStaleLine        = "ufw allow 9/tcp comment 'berth:stale'"
	ufwInstallCmd       = "DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban"
)

var ufwActiveResult = bssh.Result{Stdout: "Status: active\n", ExitCode: 0}

// showAdded builds a `ufw show added` answer: the real header, berth's
// built-in rules as the test server (ssh 2222) prints them, then the given lines.
func showAdded(lines ...string) bssh.Result {
	out := ufwAddedHeader + "\nufw allow 2222/tcp\nufw allow 80,443/tcp\n"
	for _, l := range lines {
		out += l + "\n"
	}
	return bssh.Result{Stdout: out}
}

// stubCheckGreenFirewall stubs everything hardening.Check needs for a
// converged host EXCEPT the two ufw probes, which each test controls.
func stubCheckGreenFirewall(f *bssh.FakeRunner, s *config.Server) {
	f.On("systemctl is-active fail2ban", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled fail2ban", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{Stdout: sshdDropInBody, ExitCode: 0})
	jailWant, _ := renderFail2banJail(s)
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{Stdout: string(jailWant), ExitCode: 0})
	stubSshdEffectiveGood(f)
	stubStampsGreen(f)
}

// stubApplyTail stubs the part of Apply after the firewall: sshd probes, the
// drop-in write guards, fail2ban and the stamps.
func stubApplyTail(f *bssh.FakeRunner) {
	f.On("cat "+shQuote(sshdDropInPath), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(fail2banJailPath), bssh.Result{ExitCode: 1})
	f.On("sshd -t", bssh.Result{})
	f.On("systemctl reload ssh", bssh.Result{})
	f.On("fail2ban-client -t", bssh.Result{})
	f.On("systemctl enable --now fail2ban", bssh.Result{})
	f.On("systemctl reload fail2ban", bssh.Result{})
	stubSshdEffectiveGood(f)
	stubApplyStampsGreen(f)
}

func calls(f *bssh.FakeRunner) []string {
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	return cmds
}

// cmdIndex returns the position of the exact command in cmds, or -1.
func ufwCmdIndex(cmds []string, want string) int {
	for i, c := range cmds {
		if c == want {
			return i
		}
	}
	return -1
}

func hasCallContaining(f *bssh.FakeRunner, sub string) bool {
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, sub) {
			return true
		}
	}
	return false
}

func hasChangeContaining(changes []string, sub string) bool {
	for _, c := range changes {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func hasPlannedCmd(changes []string, want string) bool {
	for _, c := range changes {
		if c == want || strings.HasPrefix(c, want+" (") {
			return true
		}
	}
	return false
}

func TestHardeningCheckFirewallRules(t *testing.T) {
	check := func(t *testing.T, s *config.Server, status, added bssh.Result) (provision.CheckResult, []string, error) {
		t.Helper()
		f := bssh.NewFakeRunner()
		f.On(ufwStatusCmd, status)
		f.On(ufwShowAddedCmd, added)
		stubCheckGreenFirewall(f, s)
		cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, s, f)
		return cr, calls(f), err
	}
	t.Run("converged", func(t *testing.T) {
		cr, _, err := check(t, firewallServer(), ufwActiveResult, showAdded(ufwZabbixLine, ufwNodeExporterLine))
		if err != nil {
			t.Fatal(err)
		}
		if !cr.Satisfied {
			t.Errorf("expected satisfied; got %+v", cr)
		}
	})
	t.Run("missing rule is planned as its exact command", func(t *testing.T) {
		cr, _, err := check(t, firewallServer(), ufwActiveResult, showAdded(ufwZabbixLine))
		if err != nil {
			t.Fatal(err)
		}
		if cr.Satisfied || !hasPlannedCmd(cr.Changes, ufwNodeExporterLine) {
			t.Errorf("expected unsatisfied with the add planned; got %+v", cr)
		}
	})
	t.Run("stale rule is planned for deletion by its printed line", func(t *testing.T) {
		cr, _, err := check(t, firewallServer(), ufwActiveResult, showAdded(ufwZabbixLine, ufwNodeExporterLine, ufwStaleLine))
		if err != nil {
			t.Fatal(err)
		}
		if cr.Satisfied || !hasPlannedCmd(cr.Changes, "ufw delete allow 9/tcp comment 'berth:stale'") {
			t.Errorf("expected the delete planned; got %+v", cr)
		}
	})
	t.Run("changed source plans delete then add", func(t *testing.T) {
		old := "ufw allow from 203.0.113.11 to any port 10050 proto tcp comment 'berth:zabbix'"
		cr, _, err := check(t, firewallServer(), ufwActiveResult, showAdded(old, ufwNodeExporterLine))
		if err != nil {
			t.Fatal(err)
		}
		del := "ufw delete " + strings.TrimPrefix(old, "ufw ")
		if cr.Satisfied || !hasPlannedCmd(cr.Changes, del) || !hasPlannedCmd(cr.Changes, ufwZabbixLine) {
			t.Errorf("expected %q and %q planned; got %+v", del, ufwZabbixLine, cr)
		}
	})
	t.Run("uncommented identical rule is adopted", func(t *testing.T) {
		cr, _, err := check(t, firewallServer(), ufwActiveResult, showAdded(ufwZabbixLine, "ufw allow 9100/tcp"))
		if err != nil {
			t.Fatal(err)
		}
		if cr.Satisfied {
			t.Fatal("expected unsatisfied: the rule lacks berth's comment")
		}
		var adopt bool
		for _, c := range cr.Changes {
			if strings.HasPrefix(c, ufwNodeExporterLine) && strings.Contains(c, "adopts") {
				adopt = true
			}
		}
		if !adopt || hasChangeContaining(cr.Changes, "ufw delete") {
			t.Errorf("expected an adopting add and no delete; got %q", cr.Changes)
		}
	})
	t.Run("ufw absent: no show added probe, plan lists everything", func(t *testing.T) {
		cr, cmds, err := check(t, firewallServer(), bssh.Result{ExitCode: 127, Stderr: "sh: 1: ufw: not found"}, bssh.Result{})
		if err != nil {
			t.Fatal(err)
		}
		if cr.Satisfied || ufwCmdIndex(cmds, ufwShowAddedCmd) >= 0 {
			t.Errorf("expected unsatisfied without a show added probe; got %+v calls=%q", cr, cmds)
		}
		for _, want := range []string{"ufw allow 2222/tcp", "ufw allow 80,443/tcp", ufwZabbixLine, ufwNodeExporterLine, "ufw --force enable"} {
			if !hasPlannedCmd(cr.Changes, want) {
				t.Errorf("Changes should list %q on a fresh host; got %q", want, cr.Changes)
			}
		}
	})
	t.Run("show added failure fails closed", func(t *testing.T) {
		_, _, err := check(t, firewallServer(), ufwActiveResult, bssh.Result{ExitCode: 1, Stderr: "ERROR: problem running"})
		if err == nil || !strings.Contains(err.Error(), ufwShowAddedCmd) {
			t.Fatalf("expected an error naming %q; got %v", ufwShowAddedCmd, err)
		}
	})
	t.Run("show added with a broken frame fails closed", func(t *testing.T) {
		_, _, err := check(t, firewallServer(), ufwActiveResult, bssh.Result{Stdout: "ufw allow 22/tcp\n"})
		if err == nil {
			t.Fatal("expected an error on a listing without the header")
		}
	})
	t.Run("berth comment on a foreign shape fails closed", func(t *testing.T) {
		_, _, err := check(t, firewallServer(), ufwActiveResult, showAdded(ufwZabbixLine, ufwNodeExporterLine, "ufw allow ExampleApp comment 'berth:app'"))
		if err == nil || !strings.Contains(err.Error(), "berth's comment") {
			t.Fatalf("expected a refusal naming berth's comment; got %v", err)
		}
	})
	t.Run("empty allow still sweeps a leftover berth rule", func(t *testing.T) {
		cr, _, err := check(t, hardeningServer(), ufwActiveResult, showAdded("ufw allow 10050/tcp comment 'berth:old'"))
		if err != nil {
			t.Fatal(err)
		}
		if cr.Satisfied || !hasPlannedCmd(cr.Changes, "ufw delete allow 10050/tcp comment 'berth:old'") {
			t.Errorf("expected the sweep planned; got %+v", cr)
		}
	})
	t.Run("production fixture without a firewall block is converged", func(t *testing.T) {
		s := hardeningServer()
		s.SSH.Port = 22
		cr, _, err := check(t, s, bssh.Result{Stdout: ufwStatusProd}, bssh.Result{Stdout: ufwShowAddedProd})
		if err != nil {
			t.Fatal(err)
		}
		if !cr.Satisfied {
			t.Errorf("the production host must read converged; got %+v", cr)
		}
	})
	t.Run("status rows are not read: one family listed still reads converged (documented boundary)", func(t *testing.T) {
		status := bssh.Result{Stdout: ufwStatusProd + "9100/tcp                   ALLOW       Anywhere                   # berth:node-exporter\n"}
		cr, _, err := check(t, firewallServer(), status, showAdded(ufwZabbixLine, ufwNodeExporterLine))
		if err != nil {
			t.Fatal(err)
		}
		if !cr.Satisfied {
			t.Errorf("berth reconciles on show added only; got %+v", cr)
		}
	})
	t.Run("ufw status exit 1 is an error, not inactive", func(t *testing.T) {
		_, _, err := check(t, firewallServer(), bssh.Result{ExitCode: 1, Stderr: "ERROR: problem running iptables"}, bssh.Result{})
		if err == nil || !strings.Contains(err.Error(), "ufw status failed") {
			t.Fatalf("expected a loud ufw status failure; got %v", err)
		}
	})
	t.Run("unrecognized ufw status output is an error", func(t *testing.T) {
		for _, out := range []string{"Firewall status: unknown\n", "Status: activeXYZ\n", "Status: inactive-broken\n"} {
			_, _, err := check(t, firewallServer(), bssh.Result{Stdout: out}, bssh.Result{})
			if err == nil || !strings.Contains(err.Error(), "unrecognized") {
				t.Errorf("stdout %q: expected an unrecognized-output error (whole first line, not a prefix); got %v", out, err)
			}
		}
	})
	t.Run("header-only show added is a truncated listing, not an empty one", func(t *testing.T) {
		_, _, err := check(t, firewallServer(), ufwActiveResult, bssh.Result{Stdout: ufwAddedHeader + "\n"})
		if err == nil {
			t.Fatal("expected an error: the header alone must not read as zero rules")
		}
	})
	t.Run("http3 needs the exact built-in 443/udp line, not a source-limited one", func(t *testing.T) {
		// The owned, source-limited 443/udp rule is DECLARED and present in
		// both listings, so the only difference between the two runs is the
		// bare built-in line — a verdict driven by anything else (a stale
		// delete, a missing add) would mask what this test pins.
		s := firewallServer()
		s.Sites = []config.Site{{Domain: "a.example.com", HTTP3: true}}
		s.Firewall.Allow = append(s.Firewall.Allow, config.FirewallRule{Name: "q", Port: 443, Proto: "udp", From: "203.0.113.10"})
		qLine := "ufw allow from 203.0.113.10 to any port 443 proto udp comment 'berth:q'"
		cr, _, err := check(t, s, ufwActiveResult, showAdded(ufwZabbixLine, ufwNodeExporterLine, qLine))
		if err != nil {
			t.Fatal(err)
		}
		if cr.Satisfied || !hasPlannedCmd(cr.Changes, "ufw allow 443/udp") {
			t.Errorf("expected the built-in QUIC rule to be required; got %+v", cr)
		}
		if hasChangeContaining(cr.Changes, "ufw delete") || hasChangeContaining(cr.Changes, "comment 'berth:") {
			t.Errorf("the owned rule is declared and present: nothing to delete or add; got %q", cr.Changes)
		}
		cr, _, err = check(t, s, ufwActiveResult, showAdded("ufw allow 443/udp", ufwZabbixLine, ufwNodeExporterLine, qLine))
		if err != nil {
			t.Fatal(err)
		}
		if !cr.Satisfied {
			t.Errorf("the bare built-in line must satisfy the QUIC check; got %+v", cr)
		}
	})
	t.Run("transition: http3 switched on while a leftover owned 443/udp exists", func(t *testing.T) {
		s := hardeningServer()
		s.Sites = []config.Site{{Domain: "a.example.com", HTTP3: true}}
		cr, _, err := check(t, s, ufwActiveResult, showAdded("ufw allow 443/udp comment 'berth:q'"))
		if err != nil {
			t.Fatal(err)
		}
		if cr.Satisfied || hasChangeContaining(cr.Changes, "ufw delete") {
			t.Errorf("expected unsatisfied without a delete; got %+v", cr)
		}
		if !hasPlannedCmd(cr.Changes, "ufw allow 443/udp") || !hasChangeContaining(cr.Changes, "replaces the berth:q") {
			t.Errorf("expected the built-in allow with a takeover note; got %q", cr.Changes)
		}
	})
	t.Run("transition: ssh port moved onto a leftover owned rule", func(t *testing.T) {
		cr, _, err := check(t, hardeningServer(), ufwActiveResult, showAdded("ufw allow 2222/tcp comment 'berth:alt'"))
		if err != nil {
			t.Fatal(err)
		}
		if cr.Satisfied || hasChangeContaining(cr.Changes, "ufw delete") || !hasChangeContaining(cr.Changes, "replaces the berth:alt") {
			t.Errorf("expected a takeover note and no delete; got %+v", cr)
		}
	})
	t.Run("changes list the literal built-in commands", func(t *testing.T) {
		cr, _, err := check(t, firewallServer(), ufwActiveResult, showAdded(ufwZabbixLine))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"ufw allow 2222/tcp", "ufw allow 80,443/tcp", "ufw --force enable"} {
			if !hasPlannedCmd(cr.Changes, want) {
				t.Errorf("Changes should list %q literally; got %q", want, cr.Changes)
			}
		}
		if hasChangeContaining(cr.Changes, "ssh/80/443") {
			t.Errorf("the summary line must give way to literal commands; got %q", cr.Changes)
		}
	})
}

func TestHardeningApplyFirewallRulesOrder(t *testing.T) {
	stubGate(t, nil, nil)
	s := hardeningServer()
	s.Firewall.Allow = []config.FirewallRule{{Name: "zabbix", Port: 10050, Proto: "tcp", From: "203.0.113.10"}}
	f := bssh.NewFakeRunner()
	f.On(ufwInstallCmd, bssh.Result{})
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On(ufwShowAddedCmd, showAdded(ufwStaleLine, "ufw allow 5432/tcp comment 'ops'"))
	f.On("ufw delete allow 9/tcp comment 'berth:stale'", bssh.Result{})
	f.On(ufwZabbixLine, bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	stubApplyTail(f)

	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	cmds := calls(f)
	prev := -1
	// The listing comes FIRST (frame and ownership checks before any ufw
	// mutation), then the built-ins (SSH open before enable), the deletes,
	// the declared allows and the enable.
	for _, want := range []string{
		ufwInstallCmd, ufwShowAddedCmd, "ufw allow 2222/tcp", "ufw allow 80,443/tcp",
		"ufw delete allow 9/tcp comment 'berth:stale'", ufwZabbixLine, "ufw --force enable", "systemctl reload ssh",
	} {
		i := ufwCmdIndex(cmds, want)
		if i < 0 {
			t.Fatalf("missing %q in %q", want, cmds)
		}
		if i <= prev {
			t.Errorf("%q out of order; calls=%q", want, cmds)
		}
		prev = i
	}
	if hasCallContaining(f, "'ops'") {
		t.Errorf("a foreign rule must never be touched; calls=%q", cmds)
	}
}

// The zero-change pin for a config WITHOUT a firewall block on a host without
// berth-owned rules: the ufw mutations are exactly the pre-firewall ones
// (built-ins, then enable), and the only addition is the read-only listing,
// issued before the first mutation.
func TestHardeningApplyZeroChangeWithoutFirewallBlock(t *testing.T) {
	stubGate(t, nil, nil)
	f := bssh.NewFakeRunner()
	f.On(ufwInstallCmd, bssh.Result{})
	f.On(ufwShowAddedCmd, showAdded())
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	stubApplyTail(f)
	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, hardeningServer(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var ufwCmds []string
	for _, c := range calls(f) {
		if strings.HasPrefix(c, "ufw ") || strings.HasPrefix(c, ufwLocalePin+"ufw ") {
			ufwCmds = append(ufwCmds, c)
		}
	}
	want := []string{ufwShowAddedCmd, "ufw allow 2222/tcp", "ufw allow 80,443/tcp", "ufw --force enable"}
	if !reflect.DeepEqual(ufwCmds, want) {
		t.Errorf("ufw commands without a firewall block = %q, want exactly %q", ufwCmds, want)
	}
}

func TestHardeningApplyStopsOnFirewallErrors(t *testing.T) {
	s := firewallServer()
	setup := func() *bssh.FakeRunner {
		f := bssh.NewFakeRunner()
		f.On(ufwInstallCmd, bssh.Result{})
		f.On("ufw allow 2222/tcp", bssh.Result{})
		f.On("ufw allow 80,443/tcp", bssh.Result{})
		f.On("ufw --force enable", bssh.Result{})
		f.On(ufwZabbixLine, bssh.Result{})
		f.On(ufwNodeExporterLine, bssh.Result{})
		stubApplyTail(f)
		return f
	}
	assertStopped := func(t *testing.T, f *bssh.FakeRunner, err error, after ...string) {
		t.Helper()
		if err == nil {
			t.Fatal("expected Apply to fail")
		}
		for _, cmd := range after {
			if ufwCmdIndex(calls(f), cmd) >= 0 {
				t.Errorf("%q must not run after the failure; calls=%q", cmd, calls(f))
			}
		}
	}
	// A discovery failure must stop BEFORE any ufw mutation — the built-in
	// allows included: issued earlier they could replace (and so hide) a
	// rule berth refuses to touch.
	noMutation := []string{"ufw allow 2222/tcp", "ufw allow 80,443/tcp", "ufw delete allow 9/tcp comment 'berth:stale'", ufwZabbixLine, ufwNodeExporterLine, "ufw --force enable", "systemctl reload ssh"}
	t.Run("show added failure", func(t *testing.T) {
		stubGate(t, nil, nil)
		f := setup()
		f.On(ufwShowAddedCmd, bssh.Result{ExitCode: 1, Stderr: "ERROR"})
		err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f)
		assertStopped(t, f, err, noMutation...)
	})
	t.Run("show added with a broken frame at exit 0", func(t *testing.T) {
		stubGate(t, nil, nil)
		f := setup()
		f.On(ufwShowAddedCmd, bssh.Result{Stdout: "ufw allow 22/tcp\n"})
		err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f)
		assertStopped(t, f, err, noMutation...)
	})
	t.Run("show added header only", func(t *testing.T) {
		stubGate(t, nil, nil)
		f := setup()
		f.On(ufwShowAddedCmd, bssh.Result{Stdout: ufwAddedHeader + "\n"})
		err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f)
		assertStopped(t, f, err, noMutation...)
	})
	t.Run("berth comment on a foreign shape", func(t *testing.T) {
		stubGate(t, nil, nil)
		f := setup()
		f.On(ufwShowAddedCmd, showAdded("ufw allow ExampleApp comment 'berth:app'", ufwStaleLine))
		err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f)
		assertStopped(t, f, err, noMutation...)
		if !strings.Contains(err.Error(), "berth's comment") {
			t.Errorf("error should name berth's comment; got %v", err)
		}
	})
	t.Run("delete failure", func(t *testing.T) {
		stubGate(t, nil, nil)
		f := setup()
		f.On(ufwShowAddedCmd, showAdded(ufwStaleLine))
		f.On("ufw delete allow 9/tcp comment 'berth:stale'", bssh.Result{ExitCode: 1, Stderr: "ERROR: Bad port"})
		err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f)
		assertStopped(t, f, err, ufwZabbixLine, ufwNodeExporterLine, "ufw --force enable")
		if !strings.Contains(err.Error(), "ufw delete allow 9/tcp comment 'berth:stale'") {
			t.Errorf("error should quote the failing command; got %v", err)
		}
	})
	t.Run("allow failure", func(t *testing.T) {
		stubGate(t, nil, nil)
		f := setup()
		f.On(ufwShowAddedCmd, showAdded())
		f.On(ufwZabbixLine, bssh.Result{ExitCode: 1, Stderr: "ERROR: Bad source address"})
		err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f)
		assertStopped(t, f, err, ufwNodeExporterLine, "ufw --force enable", "systemctl reload ssh")
	})
}

func TestHardeningApplyDeletesRuleDroppedFromConfig(t *testing.T) {
	stubGate(t, nil, nil)
	s := hardeningServer() // no firewall block at all
	f := bssh.NewFakeRunner()
	f.On(ufwInstallCmd, bssh.Result{})
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	f.On(ufwShowAddedCmd, showAdded("ufw allow 10050/tcp comment 'berth:zabbix'"))
	f.On("ufw delete allow 10050/tcp comment 'berth:zabbix'", bssh.Result{})
	f.On("ufw --force enable", bssh.Result{})
	stubApplyTail(f)
	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	cmds := calls(f)
	del, enable := ufwCmdIndex(cmds, "ufw delete allow 10050/tcp comment 'berth:zabbix'"), ufwCmdIndex(cmds, "ufw --force enable")
	if del < 0 || enable < 0 || del > enable {
		t.Errorf("the leftover rule must be deleted before enable; calls=%q", cmds)
	}
	if hasCallContaining(f, " comment 'berth:") && !hasCallContaining(f, "ufw delete") {
		t.Errorf("no rule may be added without an entry; calls=%q", cmds)
	}
}

// Apply issues exactly the adds Check plans — the declared rules whose exact
// line is absent — so a dry-run never under-reports what the real run does
// (Greptile on PR #105: re-issuing every declared allow listed one add while
// issuing two). A converged host sees no owned-rule command at all.
func TestHardeningApplyIssuesOnlyMissingAllows(t *testing.T) {
	t.Run("converged: no owned-rule command", func(t *testing.T) {
		stubGate(t, nil, nil)
		f := bssh.NewFakeRunner()
		f.On(ufwInstallCmd, bssh.Result{})
		f.On("ufw allow 2222/tcp", bssh.Result{})
		f.On("ufw allow 80,443/tcp", bssh.Result{})
		f.On(ufwShowAddedCmd, showAdded(ufwZabbixLine, ufwNodeExporterLine))
		f.On("ufw --force enable", bssh.Result{})
		stubApplyTail(f)
		if err := Hardening().Apply(context.Background(), provision.RunCtx{}, firewallServer(), f); err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		if hasCallContaining(f, "comment 'berth:") || hasCallContaining(f, "ufw delete") {
			t.Errorf("a converged ruleset must not be re-issued or deleted; calls=%q", calls(f))
		}
	})
	t.Run("one missing: only that one, as the plan says", func(t *testing.T) {
		stubGate(t, nil, nil)
		f := bssh.NewFakeRunner()
		f.On(ufwInstallCmd, bssh.Result{})
		f.On("ufw allow 2222/tcp", bssh.Result{})
		f.On("ufw allow 80,443/tcp", bssh.Result{})
		f.On(ufwShowAddedCmd, showAdded(ufwZabbixLine))
		f.On(ufwNodeExporterLine, bssh.Result{Stdout: "Rule added\nRule added (v6)\n"})
		f.On("ufw --force enable", bssh.Result{})
		stubApplyTail(f)
		if err := Hardening().Apply(context.Background(), provision.RunCtx{}, firewallServer(), f); err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		cmds := calls(f)
		if ufwCmdIndex(cmds, ufwNodeExporterLine) < 0 {
			t.Errorf("the missing rule must be added; calls=%q", cmds)
		}
		if ufwCmdIndex(cmds, ufwZabbixLine) >= 0 {
			t.Errorf("a present rule must not be re-issued; calls=%q", cmds)
		}
	})
}

func TestHardeningApplyAdoptsUncommentedRule(t *testing.T) {
	stubGate(t, nil, nil)
	s := hardeningServer()
	s.Firewall.Allow = []config.FirewallRule{{Name: "zabbix", Port: 10050}}
	f := bssh.NewFakeRunner()
	f.On(ufwInstallCmd, bssh.Result{})
	f.On("ufw allow 2222/tcp", bssh.Result{})
	f.On("ufw allow 80,443/tcp", bssh.Result{})
	// The host holds the operator's uncommented rule; the adopting allow makes
	// ufw print it back with berth's comment.
	f.On(ufwShowAddedCmd, showAdded("ufw allow 10050/tcp"))
	f.On("ufw allow 10050/tcp comment 'berth:zabbix'", bssh.Result{Stdout: "Rule updated\nRule updated (v6)\n"})
	f.On("ufw --force enable", bssh.Result{})
	stubApplyTail(f)
	if err := Hardening().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if ufwCmdIndex(calls(f), "ufw allow 10050/tcp comment 'berth:zabbix'") < 0 || hasCallContaining(f, "ufw delete") {
		t.Errorf("the adopting allow must be issued and nothing deleted; calls=%q", calls(f))
	}
	f2 := bssh.NewFakeRunner()
	f2.On(ufwStatusCmd, ufwActiveResult)
	f2.On(ufwShowAddedCmd, showAdded("ufw allow 10050/tcp comment 'berth:zabbix'"))
	stubCheckGreenFirewall(f2, s)
	cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, s, f2)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("after adoption the rule is berth's and Check must be satisfied; got %+v", cr)
	}
}

func TestHardeningFirewallDisabled(t *testing.T) {
	off := false
	disabled := func() *config.Server {
		s := hardeningServer()
		s.Firewall.Enabled = &off
		return s
	}
	check := func(t *testing.T, s *config.Server, status bssh.Result) (provision.CheckResult, []string, error) {
		t.Helper()
		f := bssh.NewFakeRunner()
		f.On(ufwStatusCmd, status)
		stubCheckGreenFirewall(f, s)
		cr, err := Hardening().Check(context.Background(), provision.RunCtx{}, s, f)
		return cr, calls(f), err
	}
	t.Run("check: inactive ufw is satisfied, no show added", func(t *testing.T) {
		cr, cmds, err := check(t, disabled(), bssh.Result{Stdout: "Status: inactive\n"})
		if err != nil {
			t.Fatal(err)
		}
		if !cr.Satisfied || ufwCmdIndex(cmds, ufwShowAddedCmd) >= 0 {
			t.Errorf("expected satisfied without a show added probe; got %+v calls=%q", cr, cmds)
		}
	})
	t.Run("check: ufw not installed is satisfied", func(t *testing.T) {
		cr, _, err := check(t, disabled(), bssh.Result{ExitCode: 127, Stderr: "sh: 1: ufw: not found"})
		if err != nil {
			t.Fatal(err)
		}
		if !cr.Satisfied {
			t.Errorf("expected satisfied without ufw; got %+v", cr)
		}
	})
	t.Run("check: active ufw is drift", func(t *testing.T) {
		cr, _, err := check(t, disabled(), ufwActiveResult)
		if err != nil {
			t.Fatal(err)
		}
		if cr.Satisfied || !hasPlannedCmd(cr.Changes, "ufw --force disable") {
			t.Errorf("expected the disable planned; got %+v", cr)
		}
	})
	t.Run("check: ufw status exit 1 is an error", func(t *testing.T) {
		_, _, err := check(t, disabled(), bssh.Result{ExitCode: 1, Stderr: "ERROR: problem running iptables"})
		if err == nil {
			t.Fatal("expected an error: a failing ufw status must not read as absent")
		}
	})
	t.Run("check: unknown ufw status output is an error", func(t *testing.T) {
		for _, out := range []string{"\n", "Status: inactive-broken\n", "Status: activeXYZ\n"} {
			_, _, err := check(t, disabled(), bssh.Result{Stdout: out})
			if err == nil {
				t.Errorf("stdout %q: expected an error — only the exact status lines count", out)
			}
		}
	})
	t.Run("check: the HTTP/3 udp rule is not required while disabled", func(t *testing.T) {
		s := disabled()
		s.Sites = []config.Site{{Domain: "a.example.com", HTTP3: true}}
		cr, _, err := check(t, s, bssh.Result{Stdout: "Status: inactive\n"})
		if err != nil {
			t.Fatal(err)
		}
		if !cr.Satisfied {
			t.Errorf("expected satisfied; got %+v", cr)
		}
	})
	apply := func(t *testing.T, status bssh.Result, extra func(*bssh.FakeRunner)) (*bssh.FakeRunner, error) {
		t.Helper()
		stubGate(t, nil, nil)
		f := bssh.NewFakeRunner()
		f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban", bssh.Result{})
		f.On(ufwStatusCmd, status)
		if extra != nil {
			extra(f)
		}
		stubApplyTail(f)
		return f, Hardening().Apply(context.Background(), provision.RunCtx{}, disabled(), f)
	}
	t.Run("apply: installs fail2ban only and disables an active ufw", func(t *testing.T) {
		f, err := apply(t, ufwActiveResult, func(f *bssh.FakeRunner) { f.On("ufw --force disable", bssh.Result{}) })
		if err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		if ufwCmdIndex(calls(f), "ufw --force disable") < 0 {
			t.Errorf("expected ufw --force disable; calls=%q", calls(f))
		}
		for _, forbidden := range []string{"install -y ufw fail2ban", "ufw allow", "ufw --force enable", ufwShowAddedCmd} {
			if hasCallContaining(f, forbidden) {
				t.Errorf("%q must not be issued while the firewall is disabled; calls=%q", forbidden, calls(f))
			}
		}
	})
	t.Run("apply: inactive ufw is left alone", func(t *testing.T) {
		f, err := apply(t, bssh.Result{Stdout: "Status: inactive\n"}, nil)
		if err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		if hasCallContaining(f, "ufw --force disable") {
			t.Error("an inactive ufw must not be disabled again")
		}
	})
	t.Run("apply: missing ufw is left alone", func(t *testing.T) {
		f, err := apply(t, bssh.Result{ExitCode: 127, Stderr: "sh: 1: ufw: not found"}, nil)
		if err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		if hasCallContaining(f, "ufw --force disable") {
			t.Error("ufw --force disable must not run when ufw is not installed")
		}
	})
	t.Run("apply: ufw status exit 1 stops the step", func(t *testing.T) {
		f, err := apply(t, bssh.Result{ExitCode: 1, Stderr: "ERROR"}, nil)
		if err == nil {
			t.Fatal("expected an error")
		}
		if hasCallContaining(f, "ufw --force disable") || hasCallContaining(f, "systemctl reload ssh") {
			t.Errorf("nothing may run after the status failure; calls=%q", calls(f))
		}
	})
	t.Run("apply: unrecognized ufw status line stops the step", func(t *testing.T) {
		f, err := apply(t, bssh.Result{Stdout: "Status: inactive-broken\n"}, nil)
		if err == nil {
			t.Fatal("expected an error: a prefix of the status line is not the status line")
		}
		if hasCallContaining(f, "ufw --force disable") || hasCallContaining(f, "systemctl reload ssh") {
			t.Errorf("nothing may run after the status failure; calls=%q", calls(f))
		}
	})
	t.Run("apply: disable failure stops the step", func(t *testing.T) {
		f, err := apply(t, ufwActiveResult, func(f *bssh.FakeRunner) { f.On("ufw --force disable", bssh.Result{ExitCode: 1, Stderr: "ERROR"}) })
		if err == nil {
			t.Fatal("expected an error")
		}
		if hasCallContaining(f, "systemctl reload ssh") {
			t.Errorf("nothing may run after the disable failure; calls=%q", calls(f))
		}
	})
}

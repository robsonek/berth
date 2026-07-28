package steps

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

const (
	// sshdDropInPath is 00-prefixed on purpose: sshd's Include expands
	// lexicographically and each directive keeps its FIRST value, so berth
	// must sort before image drop-ins (e.g. cloud-init's 50-cloud-init.conf
	// re-enabling PasswordAuthentication).
	sshdDropInPath = "/etc/ssh/sshd_config.d/00-berth.conf"
	sshdDropInBody = managedMarker + "\nPermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
	// fail2banJailPath lives in jail.d/, NOT jail.local: jail.local is the
	// canonical operator customization file and loads AFTER jail.d/*.conf,
	// so an operator can override berth's jail settings there without
	// tripping drift — berth deliberately does not own that file. 99- (not
	// 00-): within jail.d the LAST-sorted file wins per key, and Debian
	// ships jail.d/defaults-debian.conf — berth must sort after every stock
	// drop-in while still yielding to jail.local.
	fail2banJailPath = "/etc/fail2ban/jail.d/99-berth.conf"
)

// sshdEffectiveWant lists the directives (exactly as sshd -T prints them:
// lowercase key, single space, value) that must hold in the EFFECTIVE global
// configuration. Byte-comparing berth's own drop-in is not enough: sshd
// keeps the FIRST value it parses per directive, so a drop-in sorting
// earlier can override berth's file while its bytes stay perfect.
// Contract: global directives only — Match blocks are not evaluated
// (sshd -T without -C), by design; see the README wording.
var sshdEffectiveWant = []string{
	"permitrootlogin no",
	"passwordauthentication no",
	"kbdinteractiveauthentication no",
}

// sshdOptsProbe reads /etc/default/ssh whole. A missing file is fine (exit 0,
// empty output — Debian marks the EnvironmentFile optional), but a present
// file that cannot be read exits non-zero so the caller fails CLOSED instead
// of treating a read failure as "unset".
const sshdOptsProbe = `test ! -e /etc/default/ssh || cat -- /etc/default/ssh`

// sshdOptsAssignment returns the raw value text of the LAST SSHD_OPTS
// assignment line in the file body (later assignments win for systemd's
// EnvironmentFile), trimmed of surrounding whitespace only — quotes are NOT
// stripped. found is false when no assignment line exists.
func sshdOptsAssignment(body string) (raw string, found bool) {
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SSHD_OPTS="); ok {
			raw, found = strings.TrimSpace(rest), true
		}
	}
	return raw, found
}

// sshdOptsEmpty reports whether a raw assignment value PROVABLY denotes an
// empty SSHD_OPTS: exactly the empty string, a pair of double quotes, or a
// pair of single quotes. Anything else — a real value, a trailing comment,
// or a dangling opening quote that systemd's EnvironmentFile parser would
// continue across lines — counts as set: berth fails closed on what it
// cannot prove empty rather than parsing systemd quoting in full.
func sshdOptsEmpty(raw string) bool { return raw == "" || raw == `""` || raw == `''` }

// sshdOptsGuard fails closed unless SSHD_OPTS is provably absent or empty:
// Debian's ssh.service starts `sshd -D $SSHD_OPTS` (EnvironmentFile), and
// command-line options override every config file, so any value berth cannot
// prove empty means `sshd -T` would not reproduce the daemon's view.
func sshdOptsGuard(ctx context.Context, r bssh.Runner) error {
	res, err := r.Run(ctx, sshdOptsProbe, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("cannot read /etc/default/ssh to verify SSHD_OPTS (refusing to trust sshd -T): %s", res.Stderr)
	}
	if raw, found := sshdOptsAssignment(res.Stdout); found && !sshdOptsEmpty(raw) {
		return fmt.Errorf("cannot verify the effective sshd config: /etc/default/ssh sets SSHD_OPTS=%s, and sshd command-line options override sshd_config; clear it (or move it into a config drop-in) and re-run", raw)
	}
	return nil
}

// sshdEffective dumps the effective global sshd configuration (sshd -T) and
// returns which required directives are missing. A non-zero sshd -T exit is
// an error: the config is broken in a way berth does not own.
func sshdEffective(ctx context.Context, r bssh.Runner) (missing []string, err error) {
	res, err := r.Run(ctx, "sshd -T", nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("sshd -T failed (cannot verify effective sshd config): %s", res.Stderr)
	}
	have := make(map[string]bool)
	for _, line := range strings.Split(res.Stdout, "\n") {
		have[strings.TrimSpace(line)] = true
	}
	for _, want := range sshdEffectiveWant {
		if !have[want] {
			missing = append(missing, want)
		}
	}
	return missing, nil
}

// sshdConflictGrep lists files that mention the protected directives (plus
// challengeresponseauthentication, the deprecated alias sshd still accepts
// for kbdinteractiveauthentication). Anchored + case-insensitive so pure
// comment lines do not match; explicit paths, no recursion — sshd includes
// nothing else. Kept as one stable string so tests can stub it.
const sshdConflictGrep = `grep -ilE '^[[:space:]]*(passwordauthentication|permitrootlogin|kbdinteractiveauthentication|challengeresponseauthentication)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf`

// sshdConflictSources best-effort names CANDIDATE files that could be
// overriding berth's drop-in (grep cannot attribute first-match precedence,
// hence "candidate"). Berth's own drop-in is filtered out; on any failure it
// degrades to a generic hint.
func sshdConflictSources(ctx context.Context, r bssh.Runner) string {
	const hint = "inspect /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/"
	res, err := r.Run(ctx, sshdConflictGrep, nil)
	if err != nil || res.ExitCode != 0 {
		return hint
	}
	var files []string
	for _, line := range strings.Split(res.Stdout, "\n") {
		if f := strings.TrimSpace(line); f != "" && f != sshdDropInPath {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return hint
	}
	return "candidate sources: " + strings.Join(files, ", ")
}

// renderFail2banJail renders the managed jail.d drop-in: a port-bound sshd
// jail (journald backend) plus the recidive jail, with operator-tunable knobs.
func renderFail2banJail(s *config.Server) ([]byte, error) {
	return templates.Render("fail2ban_jail.tmpl", struct {
		Bantime, Findtime string
		Maxretry, SSHPort int
	}{
		Bantime: s.Fail2ban.BantimeEff(), Findtime: s.Fail2ban.FindtimeEff(),
		Maxretry: s.Fail2ban.MaxretryEff(), SSHPort: s.SSH.Port,
	})
}

// re443udp matches a `443/udp` ufw rule on a port boundary so unrelated UDP rules
// whose port merely ends in 443 (e.g. 10443/udp, 8443/udp) do not false-positive
// the QUIC firewall check.
var re443udp = regexp.MustCompile(`(^|[^0-9])443/udp`)

// verifyBerthAccess is the anti-lockout gate (design §6.2). It opens a brand-new
// SSH session as the berth account and confirms key auth + passwordless sudo
// work, BEFORE hardening disables root/password login. It is a package-level var
// so unit tests can stub it without a real dial; production dials a genuine
// second connection (exercised by the integration smoke test, Task 11).
var verifyBerthAccess = func(ctx context.Context, s *config.Server) error {
	policy := bssh.HostKeyPolicy{Pinned: s.SSH.Fingerprint, KnownHosts: "~/.ssh/known_hosts"}
	addr := fmt.Sprintf("%s:%d", s.Host, s.SSH.Port)
	auth, err := bssh.AuthMethods(s.SSH.Key)
	if err != nil {
		return err
	}
	c, err := bssh.Dial(ctx, addr, bssh.ClientConfig("berth", auth, policy), true)
	if err != nil {
		return fmt.Errorf("dial as berth: %w", err)
	}
	defer c.Close()
	res, err := c.Run(ctx, "sudo -n true", nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("berth sudo -n failed: %s", res.Stderr)
	}
	return nil
}

type hardening struct{}

func Hardening() provision.Step { return hardening{} }

func (hardening) Name() string       { return "hardening" }
func (hardening) Requires() []string { return []string{"accounts"} }

func (hardening) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	// ufw must be active.
	status, err := r.Run(ctx, "ufw status", nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	ufwActive := status.ExitCode == 0 && strings.Contains(status.Stdout, "Status: active")
	// HTTP/3 sites also need UDP/443 (QUIC) opened in the firewall.
	udpOK := !anySiteHTTP3(s) || re443udp.MatchString(status.Stdout)

	// fail2ban must be installed and running.
	f2bUp, err := serviceUp(ctx, r, "fail2ban")
	if err != nil {
		return provision.CheckResult{}, err
	}

	// The sshd drop-in must be the berth-managed one with the desired content.
	sshdState, err := checkManagedFile(ctx, r, sshdDropInPath, []byte(sshdDropInBody))
	if err != nil {
		return provision.CheckResult{}, err
	}
	sshdOK, err := managedFileSatisfied(sshdState, sshdDropInPath, rc.Force)
	if err != nil {
		return provision.CheckResult{}, err
	}

	// SSHD_OPTS guard, unconditional: Apply cannot clear a foreign SSHD_OPTS,
	// so a doomed run must fail on every Check — before dry-run promises a
	// fix — not only once berth's own files have converged.
	if err := sshdOptsGuard(ctx, r); err != nil {
		return provision.CheckResult{}, err
	}

	// Effective-config probe (sshd -T only — the SSHD_OPTS guard above is
	// unconditional), gated on everything berth owns being converged
	// (otherwise the step is unsatisfied anyway and Apply reconciles berth's
	// files first).
	effectiveOK := false
	if sshdOK {
		missing, err := sshdEffective(ctx, r)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if len(missing) > 0 {
			// Berth's inputs are converged, so Apply could only rewrite
			// identical bytes and fail the same gate forever: an effective
			// override is unfixable from here and must fail loud, not report
			// reconcilable drift (dry-run would otherwise promise a fix).
			return provision.CheckResult{}, fmt.Errorf(
				"sshd effective config lacks %q although %s is up to date — another file wins first-match (%s)",
				strings.Join(missing, ", "), sshdDropInPath, sshdConflictSources(ctx, r))
		}
		effectiveOK = true
	}

	// The managed fail2ban jail must be present and up to date.
	jailWant, err := renderFail2banJail(s)
	if err != nil {
		return provision.CheckResult{}, err
	}
	jailState, err := checkManagedFile(ctx, r, fail2banJailPath, jailWant)
	if err != nil {
		return provision.CheckResult{}, err
	}
	jailOK, err := managedFileSatisfied(jailState, fail2banJailPath, rc.Force)
	if err != nil {
		return provision.CheckResult{}, err
	}

	// The RUNNING fail2ban must postdate the managed jail: a crash between
	// writing the jail drop-in and reloading leaves the old jails active forever
	// (e.g. the sshd jail guarding port 22 instead of ssh.port) while the
	// bytes on disk read converged.
	f2bLoaded, err := reloadedSince(ctx, r, "fail2ban", fail2banJailPath)
	if err != nil {
		return provision.CheckResult{}, err
	}
	// sshd itself must be up (enabled+active): a stopped ssh.service is
	// invisible over berth's already-established connection but locks out
	// every NEW connection — and lockout prevention is this step's mission.
	// serviceUp (not serviceActive): a disabled sshd is a reboot away from
	// the same lockout, and Apply's heal re-enables deliberately.
	sshUp, err := serviceUp(ctx, r, "ssh")
	if err != nil {
		return provision.CheckResult{}, err
	}
	// And the running sshd must postdate the managed drop-in: the sshd -T
	// probe above validates the on-disk effective config, not what the
	// running daemon loaded — only the reload stamp covers the write→reload
	// window.
	sshdLoaded, err := reloadedSince(ctx, r, "ssh", sshdDropInPath)
	if err != nil {
		return provision.CheckResult{}, err
	}

	if ufwActive && f2bUp && sshdOK && effectiveOK && udpOK && jailOK && f2bLoaded && sshUp && sshdLoaded {
		return provision.CheckResult{Satisfied: true, Reason: "firewall, fail2ban and sshd hardening in place"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "host not fully hardened",
		Changes: []string{
			"ufw allow ssh/80/443 + enable",
			"install fail2ban",
			"write managed fail2ban jail (sshd port-bound, recidive)",
			"disable root login, password and kbd-interactive auth (after anti-lockout gate)",
			"verify the directives win in the effective sshd config (sshd -T)",
			"reload fail2ban to load the managed jail",
			"start/enable sshd when stopped",
			"reload ssh to load the managed drop-in",
		},
	}, nil
}

func (h hardening) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	// Fail closed on SSHD_OPTS before mutating anything: the effective gate
	// below could never be trusted with it set, so the run is doomed — refuse
	// up front rather than after installing packages and touching the firewall.
	if err := sshdOptsGuard(ctx, r); err != nil {
		return err
	}

	// Invalidate fail2ban's reload stamp before the package transaction: the
	// fail2ban package can ship jail conffile changes, so the mutation window
	// opens at the apt install, not at the jail write further down. From here
	// until markReloaded after the successful reload at the end of Apply, a
	// crash leaves no stamp and the next run reconciles with one reload.
	if err := invalidateReloaded(ctx, r, "fail2ban"); err != nil {
		return err
	}

	// Install the firewall and intrusion-prevention packages first: a minimal
	// Debian install ships neither ufw nor fail2ban, so the ufw commands below
	// would otherwise fail with "ufw: not found".
	if res, err := r.Run(ctx, "DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("install ufw/fail2ban: %s", res.Stderr)
	}

	// Firewall: allow the actual SSH port plus 80/443 BEFORE enabling ufw, so
	// enabling the firewall can never cut off the current connection (§6.2).
	cmds := []string{
		fmt.Sprintf("ufw allow %d/tcp", s.SSH.Port),
		"ufw allow 80,443/tcp",
	}
	if anySiteHTTP3(s) {
		cmds = append(cmds, "ufw allow 443/udp") // QUIC (HTTP/3)
	}
	cmds = append(cmds, "ufw --force enable")
	for _, cmd := range cmds {
		if res, err := r.Run(ctx, cmd, nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("hardening %q: %s", cmd, res.Stderr)
		}
	}

	// A stopped/disabled sshd locks out every NEW connection while berth's
	// established one still works — and it would make the anti-lockout dial
	// below fail before anything could heal it. Validate the on-disk config
	// first, then start+enable.
	sshUp, err := serviceUp(ctx, r, "ssh")
	if err != nil {
		return err
	}
	if !sshUp {
		if res, err := r.Run(ctx, "sshd -t", nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			// The gated rewrite runs AFTER this heal, so a corrupt
			// BERTH-MANAGED drop-in would otherwise wedge every future run on
			// this validation. Heal by REMOVAL, never by writing the
			// restrictive body: the drop-in only tightens auth, so removing
			// berth's own file restores the stock sshd config and can only
			// relax access — writing it here would put the root/password
			// lockdown live BEFORE the anti-lockout gate below. The brief
			// window of stock sshd config between this removal and the gated
			// re-hardening is deliberate: a failed gate must leave the host
			// reachable, not locked down. A foreign or absent file means the
			// breakage is not berth's to fix — fail loud.
			state, cerr := checkManagedFile(ctx, r, sshdDropInPath, []byte(sshdDropInBody))
			if cerr != nil {
				return cerr
			}
			switch state {
			case fileUnmanaged:
				return fmt.Errorf("sshd is stopped and sshd -t fails, but %s is not managed by berth — a foreign sshd config blocks the heal; fix it manually, refusing to start ssh: %s", sshdDropInPath, res.Stderr)
			case fileAbsent:
				return fmt.Errorf("sshd is stopped and sshd -t fails although %s is absent — the breakage is outside berth's file; fix the sshd config manually, refusing to start ssh: %s", sshdDropInPath, res.Stderr)
			}
			// The removal mutates ssh's config: invalidate its stamp first
			// (transactional contract; the gated path re-invalidates before
			// its own rewrite).
			if err := invalidateReloaded(ctx, r, "ssh"); err != nil {
				return err
			}
			if res, err := r.Run(ctx, "rm -f "+shQuote(sshdDropInPath), nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("remove corrupt %s: %s", sshdDropInPath, res.Stderr)
			}
			if res, err := r.Run(ctx, "sshd -t", nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("sshd -t still fails after removing %s — a foreign sshd config blocks the heal; fix it manually, refusing to start ssh: %s", sshdDropInPath, res.Stderr)
			}
		}
		if res, err := r.Run(ctx, "systemctl enable --now ssh", nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("start ssh: %s", res.Stderr)
		}
	}

	// Anti-lockout gate: only after confirming a FRESH berth session with sudo
	// do we touch sshd. On failure, abort without modifying sshd (fail safe).
	if err := verifyBerthAccess(ctx, s); err != nil {
		return fmt.Errorf("anti-lockout: refusing to harden sshd, berth access not verified: %w", err)
	}

	// Invalidate ssh's reload stamp before the first mutation of its config:
	// from here until markReloaded after the successful reload, a crash
	// leaves no stamp and the next run reconciles with one reload.
	if err := invalidateReloaded(ctx, r, "ssh"); err != nil {
		return err
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
		Path: sshdDropInPath, Content: []byte(sshdDropInBody),
		Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", sshdDropInPath, err)
	}
	// Validate before reloading (same contract as nginx -t / visudo -cf): the
	// anti-lockout gate above proves access, not config syntax — a bad drop-in
	// left on disk would break sshd on its next restart/reboot.
	if res, err := r.Run(ctx, "sshd -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("sshd -t failed after writing %s, refusing to reload ssh: %s", sshdDropInPath, res.Stderr)
	}
	// Effective gate: valid syntax is not enough — sshd keeps the FIRST value
	// per directive, so a drop-in sorting before ours can override it. Refuse
	// to reload (and fail the step) rather than report a hardening that the
	// config sshd loads does not contain. Same helper as Check; the SSHD_OPTS
	// guard already ran at the top of Apply.
	if missing, err := sshdEffective(ctx, r); err != nil {
		return err
	} else if len(missing) > 0 {
		return fmt.Errorf("sshd effective config still lacks %q after writing %s — another file wins first-match (%s); refusing to reload ssh",
			strings.Join(missing, ", "), sshdDropInPath, sshdConflictSources(ctx, r))
	}
	if res, err := r.Run(ctx, "systemctl reload ssh", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload ssh: %s", res.Stderr)
	}
	// No ssh config mutation follows this stamp — the transactional contract
	// (invalidate before mutating, mark after the reload) holds.
	if err := markReloaded(ctx, r, "ssh"); err != nil {
		return err
	}

	// Managed fail2ban jail: harden sshd (bound to the real port, journald backend)
	// and enable recidive. Validate before reloading, mirroring nginx -t / visudo.
	jail, err := renderFail2banJail(s)
	if err != nil {
		return err
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
		Path: fail2banJailPath, Content: jail, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", fail2banJailPath, err)
	}
	if res, err := r.Run(ctx, "fail2ban-client -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("fail2ban-client -t failed, refusing to reload: %s", res.Stderr)
	}
	// Guarantee fail2ban is enabled+active before reloading: a stopped service
	// cannot be reloaded, and an active-but-not-enabled one never converges
	// (Check requires both). enable --now makes both true; reload then applies
	// the freshly written jail.
	if res, err := r.Run(ctx, "systemctl enable --now fail2ban", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("enable fail2ban: %s", res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload fail2ban", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload fail2ban: %s", res.Stderr)
	}
	return markReloaded(ctx, r, "fail2ban")
}

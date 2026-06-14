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
	sshdDropInPath   = "/etc/ssh/sshd_config.d/berth.conf"
	sshdDropInBody   = managedMarker + "\nPermitRootLogin no\nPasswordAuthentication no\n"
	fail2banJailPath = "/etc/fail2ban/jail.local"
)

// renderFail2banJail renders the managed jail.local: a port-bound sshd jail
// (journald backend) plus the recidive jail, with operator-tunable knobs.
func renderFail2banJail(s *config.Server) ([]byte, error) {
	return templates.Render("fail2ban_jail.tmpl", struct {
		Bantime, Findtime string
		Maxretry, SSHPort int
	}{
		Bantime: s.Fail2ban.Bantime, Findtime: s.Fail2ban.Findtime,
		Maxretry: s.Fail2ban.Maxretry, SSHPort: s.SSH.Port,
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

	if ufwActive && f2bUp && sshdOK && udpOK && jailOK {
		return provision.CheckResult{Satisfied: true, Reason: "firewall, fail2ban and sshd hardening in place"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "host not fully hardened",
		Changes: []string{
			"ufw allow ssh/80/443 + enable",
			"install fail2ban",
			"write managed fail2ban jail (sshd port-bound, recidive)",
			"disable root login and password auth (after anti-lockout gate)",
		},
	}, nil
}

func (h hardening) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
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

	// Anti-lockout gate: only after confirming a FRESH berth session with sudo
	// do we touch sshd. On failure, abort without modifying sshd (fail safe).
	if err := verifyBerthAccess(ctx, s); err != nil {
		return fmt.Errorf("anti-lockout: refusing to harden sshd, berth access not verified: %w", err)
	}

	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: sshdDropInPath, Content: []byte(sshdDropInBody),
		Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", sshdDropInPath, err)
	}
	if res, err := r.Run(ctx, "systemctl reload ssh", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload ssh: %s", res.Stderr)
	}

	// Managed fail2ban jail: harden sshd (bound to the real port, journald backend)
	// and enable recidive. Validate before reloading, mirroring nginx -t / visudo.
	jail, err := renderFail2banJail(s)
	if err != nil {
		return err
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: fail2banJailPath, Content: jail, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", fail2banJailPath, err)
	}
	if res, err := r.Run(ctx, "fail2ban-client -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("fail2ban-client -t failed, refusing to reload: %s", res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload fail2ban", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("reload fail2ban: %s", res.Stderr)
	}
	return nil
}

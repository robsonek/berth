package steps

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// The hardening step's ufw reconciliation (config block `firewall:`). berth
// owns exactly the rules it tags with the comment berth:<name>; everything
// else ufw holds — the operator's rules and berth's own comment-less built-in
// rules (ssh.port/tcp, 80,443/tcp, 443/udp) — is never selected for deletion.
// The one way berth changes a foreign rule is adoption: a declared entry for
// the same port/proto/source replaces it, because ufw keeps one rule per tuple.
//
// Both probes run under LC_ALL=C LANGUAGE=C: ufw translates its status line
// and the listing header through Python's gettext, whose catalog lookup reads
// LANGUAGE before LC_ALL (and, unlike glibc, does not drop LANGUAGE for the C
// locale), so a host with LANGUAGE=pl would still answer in Polish under
// LC_ALL=C alone. The parsers below compare the English text exactly; the
// read-only classifier strips exactly this token pair.

const (
	ufwLocalePin = "LC_ALL=C LANGUAGE=C "
	// ufwStatusCmd answers the firewall's state in its first line.
	ufwStatusCmd = ufwLocalePin + "ufw status"
	// ufwShowAddedCmd lists the rules ufw holds as the commands that re-create
	// them (one line per rule, IPv4/IPv6 twins collapsed), comments included —
	// the one read berth needs to own its rules. Read-only: ufw's
	// get_show_added walks the rules parsed at startup and writes nothing.
	ufwShowAddedCmd = ufwLocalePin + "ufw show added"
	// ufwAddedHeader is the first line of that listing (ufw 0.36).
	ufwAddedHeader = "Added user rules (see 'ufw status' for running firewall):"
	ufwAddedNone   = "(None)"
)

// ufwState is what `ufw status` tells about the firewall.
type ufwState int

const (
	ufwAbsent   ufwState = iota // the ufw binary is not installed
	ufwActive                   // Status: active
	ufwInactive                 // Status: inactive
)

// ufwStatus runs `ufw status` and reads it as a tri-state. Exit 127 is the
// shell's "ufw: not found"; on a zero exit the first line, trailing whitespace
// trimmed, must BE one of the two status lines ufw prints (a prefix match
// would accept "Status: activeXYZ"). Anything else — exit 1/2/126 (iptables,
// ip6tables or configuration failures), an empty or unrecognized stdout — is
// an error, never "inactive": a mistaken "inactive" would read as converged
// under firewall.enabled: false and would skip the disable in Apply.
func ufwStatus(ctx context.Context, r bssh.Runner) (ufwState, error) {
	res, err := r.Run(ctx, ufwStatusCmd, nil)
	if err != nil {
		return 0, err
	}
	first, _, _ := strings.Cut(res.Stdout, "\n")
	first = strings.TrimRight(first, " \t\r")
	switch {
	case res.ExitCode == 127:
		return ufwAbsent, nil
	case res.ExitCode == 0 && first == "Status: active":
		return ufwActive, nil
	case res.ExitCode == 0 && first == "Status: inactive":
		return ufwInactive, nil
	case res.ExitCode != 0:
		return 0, fmt.Errorf("ufw status failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	default:
		return 0, fmt.Errorf("unrecognized ufw status output (expected the first line to be \"Status: active\" or \"Status: inactive\"): %q", first)
	}
}

// ufwAddedRules validates the frame of `ufw show added` output and returns
// the rule commands without their "ufw " prefix. Line 1 must be the exact
// header; then either the single line "(None)" or lines that all start with
// "ufw "; a line carrying a comment must end with the closing quote (ufw
// refuses a quote inside a comment but accepts a newline, which would split a
// rule over two lines). Anything else — empty output, another header, a
// prefix-less line — is an error: a listing berth cannot read whole is not a
// listing to plan deletions from.
func ufwAddedRules(stdout string) ([]string, error) {
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if lines[0] != ufwAddedHeader {
		return nil, fmt.Errorf("unrecognized %s output: expected the header %q, got %q", ufwShowAddedCmd, ufwAddedHeader, lines[0])
	}
	rest := lines[1:]
	if len(rest) == 0 {
		// ufw prints "(None)" for an empty ruleset; the header alone is a
		// truncated listing, not an empty one.
		return nil, fmt.Errorf("unrecognized %s output: the header alone, without %q or any rule", ufwShowAddedCmd, ufwAddedNone)
	}
	if len(rest) == 1 && rest[0] == ufwAddedNone {
		return nil, nil
	}
	cmds := make([]string, 0, len(rest))
	for _, line := range rest {
		cmd, ok := strings.CutPrefix(line, "ufw ")
		if !ok || cmd == "" {
			return nil, fmt.Errorf("unrecognized %s output: line %q is not a rule (expected \"ufw …\"); refusing to reconcile firewall rules from a listing berth cannot read whole", ufwShowAddedCmd, line)
		}
		if strings.Contains(cmd, " comment '") && !strings.HasSuffix(cmd, "'") {
			return nil, fmt.Errorf("unrecognized %s output: rule %q has an unterminated comment", ufwShowAddedCmd, line)
		}
		cmds = append(cmds, cmd)
	}
	return cmds, nil
}

// ufwRuleComment returns the rule's comment when cmd ends with " comment '<c>'"
// (ufw prints a comment nowhere else).
func ufwRuleComment(cmd string) (comment string, ok bool) {
	i := strings.LastIndex(cmd, " comment '")
	if i < 0 || !strings.HasSuffix(cmd, "'") {
		return "", false
	}
	return cmd[i+len(" comment '") : len(cmd)-1], true
}

// ufwBare strips the comment clause: "allow 9100/tcp comment 'x'" -> "allow 9100/tcp".
func ufwBare(cmd string) (bare string, hadComment bool) {
	i := strings.LastIndex(cmd, " comment '")
	if i < 0 || !strings.HasSuffix(cmd, "'") {
		return cmd, false
	}
	return cmd[:i], true
}

// reUfwOwnedShape is the allowlist of the two shapes berth writes — the
// mirror of config.FirewallRuleCommand. A berth: comment on any other shape is
// NOT berth's to delete: ufw expands an application profile in a delete by
// the profile name alone (foreign rules of that profile would go too), and
// prints route rules in a form `ufw delete` does not accept.
var reUfwOwnedShape = regexp.MustCompile(`^allow (?:[0-9]+/(?:tcp|udp)|from [0-9a-f.:/]+ to any port [0-9]+ proto (?:tcp|udp)) comment 'berth:[a-z0-9-]+'$`)

// ufwOwnedRules groups berth-owned commands by rule name (comment
// "berth:<name>" on an owned shape). Foreign and uncommented rules are left
// out; a berth: comment on a foreign shape is an error with the way out.
func ufwOwnedRules(cmds []string) (map[string][]string, error) {
	owned := map[string][]string{}
	for _, cmd := range cmds {
		comment, ok := ufwRuleComment(cmd)
		if !ok || !strings.HasPrefix(comment, config.FirewallCommentPrefix) {
			continue
		}
		if !reUfwOwnedShape.MatchString(cmd) {
			return nil, fmt.Errorf("ufw rule %q carries berth's comment but is not a rule berth writes (berth owns only `allow <port>/<proto>` and `allow from <source> to any port <port> proto <proto>` rules); delete it or change its comment with ufw, then re-run", "ufw "+cmd)
		}
		name := strings.TrimPrefix(comment, config.FirewallCommentPrefix)
		owned[name] = append(owned[name], cmd)
	}
	return owned, nil
}

// ufwBuiltins are the bare commands of the built-in rules the step issues on
// every Apply, in issue order: the SSH port, the web ports and, with an HTTP/3
// site, QUIC.
func ufwBuiltins(s *config.Server) []string {
	b := []string{fmt.Sprintf("allow %d/tcp", s.SSH.Port), "allow 80,443/tcp"}
	if anySiteHTTP3(s) {
		b = append(b, "allow 443/udp")
	}
	return b
}

// ufwPlan reconciles the host's listing against the config.
//
// dels: every berth-owned line that is not the exact expected line of its
// name — stale names and changed rules — EXCEPT lines whose bare command
// equals a built-in rule: Apply issues the built-ins right after this
// discovery and ufw replaces such a line then ("Rule updated"), so planning a
// delete would promise a command that hits nothing; those come back in
// takeovers, for the plan text, and count as drift. adds: every configured
// rule whose exact line is absent, in config order. Deletes are issued by the
// printed line, so ufw matches the full tuple AND the comment — a foreign rule
// for the same tuple is never hit.
func ufwPlan(have []string, want []config.FirewallRule, builtins []string) (dels, adds, takeovers []string, err error) {
	owned, err := ufwOwnedRules(have)
	if err != nil {
		return nil, nil, nil, err
	}
	wanted := make(map[string]string, len(want))
	for _, r := range want {
		wanted[r.Name] = config.FirewallRuleCommand(r)
	}
	for _, name := range slices.Sorted(maps.Keys(owned)) {
		for _, line := range owned[name] {
			if line == wanted[name] {
				continue
			}
			if bare, _ := ufwBare(line); slices.Contains(builtins, bare) {
				takeovers = append(takeovers, fmt.Sprintf("ufw %s (built-in; replaces the %s rule sharing its port/proto/source)", bare, config.FirewallRuleComment(name)))
				continue
			}
			dels = append(dels, "ufw delete "+line)
		}
	}
	for _, r := range want {
		if !slices.Contains(owned[r.Name], wanted[r.Name]) {
			adds = append(adds, "ufw "+wanted[r.Name])
		}
	}
	return dels, adds, takeovers, nil
}

// ufwAdopts reports whether adding r takes over a rule already on the host: a
// listed command whose bare form equals r's bare command but which is not r's
// exact line (uncommented, or another comment). ufw keeps one rule per
// port/proto/source and replaces the existing one, comment included. Same
// action only — a deny/reject/limit line has another prefix and is reported as
// a plain add although ufw replaces it too.
func ufwAdopts(have []string, r config.FirewallRule) bool {
	want := config.FirewallRuleCommand(r)
	bare := config.FirewallRuleCommandBare(r)
	for _, cmd := range have {
		if cmd == want {
			continue
		}
		if b, _ := ufwBare(cmd); b == bare {
			return true
		}
	}
	return false
}

// ufwListAdded runs `ufw show added` and validates its frame.
func ufwListAdded(ctx context.Context, r bssh.Runner) ([]string, error) {
	res, err := r.Run(ctx, ufwShowAddedCmd, nil)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%s failed (exit %d): %s", ufwShowAddedCmd, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return ufwAddedRules(res.Stdout)
}

// checkFirewall is the firewall half of hardening.Check. With the firewall
// on it lists the rules ufw holds (when ufw is installed) and plans the
// reconciliation: the built-in commands Apply always issues, the takeovers,
// the deletes of stale berth-owned rules, the adds of missing ones (annotated
// when they take over an existing rule) and the enable. With the firewall
// off, an active ufw is the one thing to change. The plan lines are the
// literal commands Apply runs, so --dry-run shows exactly what will happen.
func checkFirewall(ctx context.Context, r bssh.Runner, s *config.Server, state ufwState) (ok bool, changes []string, err error) {
	if !s.Firewall.IsEnabled() {
		if state == ufwActive {
			return false, []string{"ufw --force disable (firewall.enabled: false)"}, nil
		}
		return true, nil, nil
	}
	builtins := ufwBuiltins(s)
	var have []string
	if state != ufwAbsent {
		if have, err = ufwListAdded(ctx, r); err != nil {
			return false, nil, err
		}
	}
	dels, adds, takeovers, err := ufwPlan(have, s.Firewall.Allow, builtins)
	if err != nil {
		return false, nil, err
	}
	// HTTP/3 needs the built-in QUIC rule itself — the exact comment-less
	// line — not any rule that happens to mention 443/udp.
	udpOK := !anySiteHTTP3(s) || slices.Contains(have, "allow 443/udp")
	// A takeover is drift too: Apply has to run so the built-in allow replaces
	// the leftover's comment; otherwise it would stay forever.
	ok = state == ufwActive && udpOK && len(dels)+len(adds)+len(takeovers) == 0
	for _, b := range builtins {
		changes = append(changes, "ufw "+b)
	}
	changes = append(changes, takeovers...)
	changes = append(changes, dels...)
	for _, rule := range s.Firewall.Allow {
		add := "ufw " + config.FirewallRuleCommand(rule)
		if !slices.Contains(adds, add) {
			continue
		}
		if ufwAdopts(have, rule) {
			add += " (adopts the existing rule for that port/proto/source)"
		}
		changes = append(changes, add)
	}
	changes = append(changes, "ufw --force enable")
	return ok, changes, nil
}

// runUfw runs one ufw command and turns a non-zero exit into the step's
// error. Every caller stops at the first failure: a half-applied firewall must
// never be enabled on top of an unknown state.
func runUfw(ctx context.Context, r bssh.Runner, cmd string) error {
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("hardening %q: %s", cmd, res.Stderr)
	}
	return nil
}

// applyFirewall is the firewall half of hardening.Apply.
//
// Firewall on: list what ufw holds FIRST — the frame and ownership checks
// must precede every mutation, or a built-in allow could replace (and so
// hide) a rule berth would otherwise refuse to touch — then allow the actual
// SSH port plus 80/443 (and QUIC) BEFORE enabling ufw, so enabling the
// firewall can never cut off the current connection; delete the berth-owned
// rules the config no longer declares (by the exact printed line, comment
// included — never a line equal to a built-in, which the built-in allow has
// just taken over); issue every declared rule (idempotent, like the
// built-ins: an identical rule is skipped by ufw, a rule for the same
// port/proto/source is replaced and thereby adopted); enable.
//
// Firewall off: disable an active ufw and leave an inactive or absent one as
// it is.
func applyFirewall(ctx context.Context, r bssh.Runner, s *config.Server) error {
	if !s.Firewall.IsEnabled() {
		state, err := ufwStatus(ctx, r)
		if err != nil {
			return err
		}
		if state == ufwActive {
			return runUfw(ctx, r, "ufw --force disable")
		}
		return nil
	}
	have, err := ufwListAdded(ctx, r)
	if err != nil {
		return err
	}
	builtins := ufwBuiltins(s)
	dels, _, _, err := ufwPlan(have, s.Firewall.Allow, builtins)
	if err != nil {
		return err
	}
	for _, b := range builtins {
		if err := runUfw(ctx, r, "ufw "+b); err != nil {
			return err
		}
	}
	for _, cmd := range dels {
		if err := runUfw(ctx, r, cmd); err != nil {
			return err
		}
	}
	for _, rule := range s.Firewall.Allow {
		if err := runUfw(ctx, r, "ufw "+config.FirewallRuleCommand(rule)); err != nil {
			return err
		}
	}
	return runUfw(ctx, r, "ufw --force enable")
}

package steps

import (
	"strings"
	"testing"
)

// TestClassifyCommandPolicy is the policy, stated as a table. Rows are either
// shapes this package's Checks issue today, or shapes that could hide a write.
//
// The design has NO shell parser on purpose: a command is judged by the tables
// only when it contains no shell metacharacter. Anything with one must match the
// audited-script registry exactly. A review of the first draft found four
// fail-open bypasses in a hand-rolled scanner, so the scanner is gone.
func TestClassifyCommandPolicy(t *testing.T) {
	tests := []struct {
		cmd  string
		want cmdVerdict
	}{
		// Metacharacter-free reads, judged by the tables.
		{"cat '/etc/nginx/sites-available/app.example.com'", cmdReadOnly},
		{"test -e '/var/www/app/shared'", cmdReadOnly},
		{"stat -c '%U %u %F' '/var/www/app'", cmdReadOnly},
		{"dpkg -s nginx", cmdReadOnly},
		{"systemctl is-active nginx", cmdReadOnly},
		{"systemctl is-enabled php8.4-fpm", cmdReadOnly},
		{"systemctl show -p NeedDaemonReload --value berth-valkey-x.service", cmdReadOnly},
		{"getent passwd appuser", cmdReadOnly},
		{"id -u appuser", cmdReadOnly},

		// The two exceptions, both evidence-backed (spec §4.2). Exact shapes.
		{"nginx -t", cmdException},
		{"php-fpm8.4 -t", cmdException},

		// Mutations, metacharacter-free — the tables must reject each one.
		{"rm -f '/etc/cron.d/berth-site-x'", cmdRejected},
		{"install -d -m 0755 /var/log/php", cmdRejected},
		{"systemctl start nginx", cmdRejected},
		{"systemctl daemon-reload", cmdRejected},
		{"useradd -m appuser", cmdRejected},
		{"apt-get update", cmdRejected},

		// Verb-only allowlisting was unsafe; these are the shapes that proved it.
		{"date -u +%s", cmdReadOnly},
		{"date -s @0", cmdRejected},
		{"hostname", cmdReadOnly},
		{"hostname changed.example", cmdRejected},
		{"hostname -F /etc/hostname", cmdRejected},
		{"sort /etc/hosts", cmdReadOnly},
		{"sort -o /tmp/out /etc/hosts", cmdRejected},
		{"logrotate -d /etc/logrotate.d/berth", cmdReadOnly},
		{"logrotate -f /etc/logrotate.conf", cmdRejected},
		{"fail2ban-client -t", cmdReadOnly},
		{"fail2ban-client set sshd banip 203.0.113.9", cmdRejected},
		{"visudo -cf /etc/sudoers", cmdReadOnly},
		{"visudo -f /tmp/new-sudoers", cmdRejected},
		{"sshd -T", cmdReadOnly},
		{"sshd", cmdRejected},
		{"sed -n 1p /etc/x", cmdReadOnly},
		{"sed -i s/a/b/ /etc/x", cmdRejected},
		{"sed -n w/tmp/x /etc/hosts", cmdRejected},

		// Subcommand matching must be POSITIONAL, not "any argument token".
		{"systemctl start cat", cmdRejected},
		{"hostnamectl set-hostname status", cmdRejected},
		{"sysctl -w vm.swappiness=1", cmdRejected},
		{"sysctl -n vm.swappiness", cmdReadOnly},
		{"sysctl -n -w vm.swappiness=1", cmdRejected},
		{"sysctl vm.swappiness=1", cmdRejected},
		{"openssl x509 -noout -in /etc/ssl/cert.pem", cmdReadOnly},
		{"openssl x509 -noout -out /tmp/x -in /etc/ssl/cert.pem", cmdRejected},

		// An untrusted executable path must never inherit a trusted basename.
		{"/tmp/cat /etc/hosts", cmdRejected},
		{"/tmp/php-fpm-wiper -t", cmdRejected},

		// Every metacharacter forces the audited registry. None of these is
		// registered, so all are rejected — including ones that only READ.
		{"cat /x && cat /y", cmdRejected},
		{"cat /x; cat /y", cmdRejected},
		{"cat /x | head -1", cmdRejected},
		{"cat /x > /var/log/y", cmdRejected},
		{"cat /x 2>/dev/null", cmdRejected},
		{"printf '%s' \"$(rm -rf /x)\"", cmdRejected},
		{"cat /dev/null & rm -f /x", cmdRejected},
		{"cat <> /tmp/created", cmdRejected},
		{"{ test -e /x; }", cmdRejected},
		{"echo `rm x`", cmdRejected},
		{". /etc/os-release && echo $VERSION_CODENAME", cmdRejected},

		// Unknown verbs are rejected, not assumed safe.
		{"sometool --probe /etc/x", cmdRejected},
	}

	for _, tc := range tests {
		t.Run(tc.cmd, func(t *testing.T) {
			got, detail := classifyCommand(tc.cmd, nil)
			if got != tc.want {
				t.Errorf("classifyCommand(%q) = %s (%s), want %s", tc.cmd, got, detail, tc.want)
			}
		})
	}
}

// TestAuditedScriptMustMatchExactly: the registry is the reason this design is
// stronger than parsing. A registered script passes; the same script with one
// character changed does NOT, so editing a helper forces a fresh audit.
func TestAuditedScriptMustMatchExactly(t *testing.T) {
	const script = `for f in /x/*; do [ -e "$f" ] || continue; printf '%s\n' "$f"; done`
	auditedScripts[script] = "test entry: read-only glob walk"
	t.Cleanup(func() { delete(auditedScripts, script) })

	if got, _ := classifyCommand(script, nil); got != cmdAudited {
		t.Errorf("registered script = %s, want audited", got)
	}
	if got, _ := classifyCommand(script+" ", nil); got != cmdRejected {
		t.Errorf("a one-character change still passed as %s — the registry must be exact", got)
	}
}

// TestStdinIsDefaultDenied: a program can arrive on stdin rather than in the
// command (`sed -n -f - file`), so a metacharacter-free command with a payload
// is not safe by virtue of its verb.
func TestStdinIsDefaultDenied(t *testing.T) {
	if got, _ := classifyCommand("sed -n -f - /etc/hosts", []byte("w /tmp/x\n")); got != cmdRejected {
		t.Errorf("stdin payload = %s, want rejected — a program on stdin is invisible to the tables", got)
	}
	// The same command with no stdin is judged normally (and rejected anyway,
	// because `-f -` reads a program from somewhere).
	if got, _ := classifyCommand("sed -n -f - /etc/hosts", nil); got != cmdRejected {
		t.Errorf("sed -f - = %s, want rejected", got)
	}
}

// cmdVerdict is how the read-only contract judges one command.
type cmdVerdict int

const (
	cmdReadOnly  cmdVerdict = iota // a pure read, judged by the tables
	cmdException                   // allowed, but known to write (the nginx -t table entry and the php-fpm branch in classifySimple)
	cmdAudited                     // a generated script whose exact text a human signed off
	cmdRejected                    // everything else — mutating, unknown, or unparsed
)

func (v cmdVerdict) String() string {
	switch v {
	case cmdReadOnly:
		return "read-only"
	case cmdException:
		return "exception"
	case cmdAudited:
		return "audited-script"
	default:
		return "REJECTED"
	}
}

// shellMetachars force a command into the audited registry. The set is
// deliberately broad: anything that can compose, redirect, substitute, group or
// escape is beyond what the tables can honestly judge, so it needs a human's
// signature instead of a parser's guess.
const shellMetachars = "&|;<>$`(){}\\\n"

// auditedScripts maps the EXACT text of a generated script to the note
// recording what was audited about it. Task 5 fills this from the first real
// run; each entry must name the helper that produces the script and why every
// command inside it only reads.
//
// Exactness is the whole point: editing a helper breaks its entry, the contract
// fails, and somebody re-reads the new script. That is stronger than parsing,
// which would silently bless whatever the edit produced.
var auditedScripts = map[string]string{}

// classifyCommand judges one (command, stdin) pair. The detail string names the
// reason, so a contract failure is actionable rather than a riddle.
func classifyCommand(cmd string, stdin []byte) (cmdVerdict, string) {
	if len(stdin) > 0 {
		// A program can arrive on stdin (`sed -f -`, `awk -f -`), which the
		// tables cannot see. Default-deny; Task 5 registers the audited pairs
		// where stdin is genuinely data (the database comparison probes).
		if note, ok := auditedStdin[stdinKey{cmd: cmd, stdin: string(stdin)}]; ok {
			return cmdAudited, note
		}
		return cmdRejected, "non-empty stdin is default-denied: a program can hide there"
	}
	if strings.ContainsAny(cmd, shellMetachars) {
		if note, ok := auditedScripts[cmd]; ok {
			return cmdAudited, note
		}
		return cmdRejected, "contains a shell metacharacter and is not in auditedScripts"
	}
	return classifySimple(cmd)
}

// stdinKey identifies one audited (command, stdin) pair.
type stdinKey struct{ cmd, stdin string }

// auditedStdin registers the pairs where stdin carries DATA, not a program.
var auditedStdin = map[stdinKey]string{}

// simpleShape is an exact predicate for one metacharacter-free command shape.
// verb is matched exactly (never by basename, so /tmp/cat is not cat), and
// allow decides on the remaining arguments.
type simpleShape struct {
	verb    string
	allow   func(args []string) bool
	verdict cmdVerdict
	why     string
}

// hasExact reports whether args contains tok.
func hasExact(args []string, tok string) bool {
	for _, a := range args {
		if a == tok {
			return true
		}
	}
	return false
}

// firstNonFlag returns the first argument that does not start with '-', which
// is where a subcommand lives for the verbs that take one.
func firstNonFlag(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// noneOf reports whether args avoids every listed token.
func noneOf(args []string, toks ...string) bool {
	for _, t := range toks {
		if hasExact(args, t) {
			return false
		}
	}
	return true
}

// simpleShapes is the whole table-judged surface. Every entry is an EXACT
// predicate rather than a bare verb: a review found that verb-only allowlisting
// blessed `date -s @0`, `hostname changed.example`, `sort -o /tmp/out`,
// `logrotate -f`, `fail2ban-client set … banip`, `visudo -f` and a bare `sshd`,
// all of which mutate.
var simpleShapes = []simpleShape{
	// Intrinsically read-only: no flag of theirs writes.
	{verb: "cat", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "test", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "stat", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "getent", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "id", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "df", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "wc", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "head", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "tail", allow: func(a []string) bool { return noneOf(a, "-f", "--follow") }, verdict: cmdReadOnly,
		why: "-f would block forever, which is a hang rather than a write, but still forbidden"},
	{verb: "readlink", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "basename", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "dirname", allow: func([]string) bool { return true }, verdict: cmdReadOnly},

	// Verbs with a writing mode: the predicate must exclude it.
	{verb: "date", allow: func(a []string) bool { return noneOf(a, "-s", "--set") }, verdict: cmdReadOnly,
		why: "date -s sets the system clock"},
	{verb: "hostname", allow: func(a []string) bool {
		return (len(a) == 0 || strings.HasPrefix(a[0], "-")) && noneOf(a, "-F", "--file", "-b", "--boot")
	}, verdict: cmdReadOnly,
		why: "hostname <name> sets the hostname, and so do -F/--file and -b/--boot"},
	{verb: "sort", allow: func(a []string) bool { return noneOf(a, "-o", "--output") }, verdict: cmdReadOnly,
		why: "sort -o writes a file"},
	{verb: "grep", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "printf", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "echo", allow: func([]string) bool { return true }, verdict: cmdReadOnly},

	// sed and awk embed interpreters, so only the narrowest shapes are allowed:
	// no -i (in-place), no -f (program from a file or stdin), and no program
	// text that could contain a write or exec command. A review showed
	// `sed -n 'w /tmp/x'` writes and GNU sed's `e` executes.
	{verb: "sed", allow: sedIsReadOnly, verdict: cmdReadOnly},

	// Validators. The four measured clean on a live host (spec §4.2.1) are
	// read-only in their check-only shape ONLY.
	{verb: "sshd", allow: func(a []string) bool { return hasExact(a, "-T") }, verdict: cmdReadOnly},
	{verb: "visudo", allow: func(a []string) bool { return hasExact(a, "-cf") || (hasExact(a, "-c") && hasExact(a, "-f")) }, verdict: cmdReadOnly},
	{verb: "logrotate", allow: func(a []string) bool { return hasExact(a, "-d") && noneOf(a, "-f", "--force") }, verdict: cmdReadOnly},
	{verb: "fail2ban-client", allow: func(a []string) bool { return hasExact(a, "-t") && firstNonFlag(a) == "" }, verdict: cmdReadOnly},

	// The two exceptions: allowed, but they WRITE (spec §4.2).
	{verb: "nginx", allow: func(a []string) bool { return hasExact(a, "-t") && len(a) == 1 }, verdict: cmdException,
		why: "as root may create a missing log file"},

	// Subcommand verbs, matched POSITIONALLY. `systemctl start cat` must not
	// pass by containing the token "cat".
	{verb: "systemctl", allow: systemctlIsReadOnly, verdict: cmdReadOnly},
	{verb: "dpkg", allow: func(a []string) bool { return len(a) >= 1 && (a[0] == "-s" || a[0] == "--status") }, verdict: cmdReadOnly},
	{verb: "timedatectl", allow: func(a []string) bool { return firstNonFlag(a) == "show" || firstNonFlag(a) == "status" }, verdict: cmdReadOnly},
	{verb: "hostnamectl", allow: func(a []string) bool { return firstNonFlag(a) == "status" || firstNonFlag(a) == "" }, verdict: cmdReadOnly},
	{verb: "swapon", allow: func(a []string) bool { return len(a) == 1 && a[0] == "--show" }, verdict: cmdReadOnly},
	{verb: "sysctl", allow: sysctlIsReadOnly, verdict: cmdReadOnly},
	{verb: "command", allow: func(a []string) bool { return len(a) == 2 && a[0] == "-v" }, verdict: cmdReadOnly},
	{verb: "openssl", allow: func(a []string) bool {
		return len(a) >= 1 && a[0] == "x509" && hasExact(a, "-noout") && noneOf(a, "-out", "-o")
	}, verdict: cmdReadOnly,
		why: "-out/-o writes a file; berth never passes it, so rejecting is free"},
	{verb: "find", allow: findIsReadOnly, verdict: cmdReadOnly},
	{verb: "gpg", allow: gpgIsReadOnly, verdict: cmdReadOnly},
}

// sedIsReadOnly allows only `sed -n <script> <file>...` where the ONLY option
// is -n and the script contains no write (`w`) and no execute (`e`) command.
//
// Options are an allowlist of exactly {-n}, not a denylist: -i writes in
// place, -e and -f load more program text, and a value-taking option (-l N)
// would displace which token is the script, so a denylist is fail-open.
// With options pinned to -n, the script is provably the FIRST non-option
// argument; everything after it is an input file, which sed only reads —
// and which must not be letter-checked, because real paths contain 'e'
// (/etc/x) while carrying no program text.
func sedIsReadOnly(args []string) bool {
	if !hasExact(args, "-n") {
		return false
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") && a != "-n" {
			return false
		}
	}
	// A sed script containing `w` writes and GNU sed's `e` executes. Rejecting
	// any script with those letters is coarse; it is also the safe direction,
	// and berth's own sed scripts (`1p`) do not contain them.
	return !strings.ContainsAny(firstNonFlag(args), "we")
}

// sysctlIsReadOnly allows only `sysctl -n <key>...`. Checking a[0] alone is
// not enough: -w/--write can follow -n, and the bare `key=value` form writes
// the kernel parameter even WITHOUT -w, so any argument containing '=' is
// rejected as well.
func sysctlIsReadOnly(args []string) bool {
	if len(args) < 1 || args[0] != "-n" || !noneOf(args, "-w", "--write") {
		return false
	}
	for _, a := range args {
		if strings.Contains(a, "=") {
			return false
		}
	}
	return true
}

// systemctlIsReadOnly allows only the query subcommands, taken from the FIRST
// non-flag position so an allowed word cannot appear as a unit name.
func systemctlIsReadOnly(args []string) bool {
	switch firstNonFlag(args) {
	case "is-active", "is-enabled", "is-failed", "show", "list-units", "cat", "status":
		return true
	}
	return false
}

// findMutators are the predicates that act instead of reporting.
var findMutators = []string{
	"-delete", "-exec", "-execdir", "-ok", "-okdir",
	"-fls", "-fprint", "-fprint0", "-fprintf",
}

func findIsReadOnly(args []string) bool { return noneOf(args, findMutators...) }

// gpgIsReadOnly requires the EXACT flag set that was measured to write nothing.
// A review pointed out that accepting any gpg command containing --no-options
// would bless a regression that drops --trust-model always, which is the
// load-bearing flag: without it gpg creates trustdb.gpg.
func gpgIsReadOnly(args []string) bool {
	need := []string{"--no-options", "--no-keyring", "--trust-model", "always", "--show-keys"}
	for _, n := range need {
		if !hasExact(args, n) {
			return false
		}
	}
	// Nothing that writes may be present alongside them.
	return noneOf(args, "--export", "--import", "--output", "-o", "--dearmor", "--gen-key", "--batch-key")
}

// classifySimple judges a metacharacter-free command by the shape tables.
func classifySimple(cmd string) (cmdVerdict, string) {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return cmdRejected, "empty command"
	}
	verb, args := fields[0], fields[1:]
	// An absolute or relative path is NOT trusted by its basename: /tmp/cat is
	// not cat. Only a bare verb name may match the tables.
	if strings.ContainsRune(verb, '/') {
		return cmdRejected, "executable given by path, not by name: " + verb
	}
	// php-fpm<version> is the one verb whose name varies, so it is matched by
	// prefix. It is an EXCEPTION, not a read: it appends a "test is successful"
	// notice to the PHP-FPM log on every invocation (measured, spec §1.1).
	if strings.HasPrefix(verb, "php-fpm") {
		if hasExact(args, "-t") && len(args) == 1 {
			return cmdException, "php-fpm -t appends a notice to the PHP-FPM log"
		}
		return cmdRejected, "only `php-fpm<ver> -t` is allowed"
	}
	for _, sh := range simpleShapes {
		if sh.verb != verb {
			continue
		}
		if sh.allow(args) {
			return sh.verdict, sh.why
		}
		return cmdRejected, verb + " in a shape the tables do not allow" + suffix(sh.why)
	}
	return cmdRejected, "unknown verb: " + verb
}

func suffix(why string) string {
	if why == "" {
		return ""
	}
	return " (" + why + ")"
}

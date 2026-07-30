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

		// The three exceptions, all evidence-backed (spec §4.2; certbot
		// measured 2026-07, see its shape entry). Exact shapes.
		{"nginx -t", cmdException},
		{"php-fpm8.4 -t", cmdException},
		{"certbot certificates", cmdException},
		// Every other certbot subcommand drives issuance/renewal state and
		// must reject — pinned the way mysql's and runuser's mutating
		// siblings were. Extra arguments on the listing reject too: only the
		// bare inventory was measured.
		{"certbot certonly --webroot -w /var/www/berth-acme/app.example.com -d app.example.com", cmdRejected},
		{"certbot renew", cmdRejected},
		{"certbot delete --cert-name app.example.com -n", cmdRejected},
		{"certbot revoke --cert-name app.example.com", cmdRejected},
		{"certbot certificates --cert-name app.example.com", cmdRejected},
		{"certbot", cmdRejected},

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

		// Getopt spellings — glued values (--set=@0, -F/path), short-option
		// bundles (-bF, -us) and abbreviated long options (--se) — must not
		// bypass the writing-flag denylists the way exact tokens once did.
		{"date --set=@0", cmdRejected},
		{"date --se=@0", cmdRejected},
		{"date -us @0", cmdRejected},
		{"hostname --file=/etc/hostname", cmdRejected},
		{"hostname -F/etc/hostname", cmdRejected},
		{"hostname -bF /etc/hostname", cmdRejected},
		{"hostname -y example", cmdRejected},
		{"sort --output=/tmp/x /etc/hosts", cmdRejected},
		{"tail -n 5 /var/log/x", cmdReadOnly},
		{"tail -F /var/log/x", cmdRejected},
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

		// The locale pin berth's parsers use (stat %F and id output are
		// localized). Only the exact LC_ALL=C token is stripped; the rest is
		// judged normally, so the pin can never bless a mutation — and no other
		// assignment is stripped, because a variable like PATH changes WHAT
		// runs, not how it prints.
		{"LC_ALL=C stat -c '%U %u %F' '/var/www/app.example.com'", cmdReadOnly},
		{"LC_ALL=C id -nG appuser", cmdReadOnly},
		{"LC_ALL=C rm -f /x", cmdRejected},
		{"LC_ALL=C", cmdRejected},
		{"PATH=/tmp cat /etc/hosts", cmdRejected},

		// ufw: only the bare status query reads; every other subcommand
		// (allow, enable, delete…) rewrites rules, so the shape is pinned to
		// exactly ["status"].
		{"ufw status", cmdReadOnly},
		{"ufw status verbose", cmdRejected},
		{"ufw allow 80,443/tcp", cmdRejected},
		{"ufw --force enable", cmdRejected},

		// passwd: -S prints status metadata (never a hash); everything else —
		// including the bare form, -l and -u — changes credentials.
		{"passwd -S berth", cmdReadOnly},
		{"passwd -l berth", cmdRejected},
		{"passwd berth", cmdRejected},
		{"passwd -S", cmdRejected},

		// Subcommand matching must be POSITIONAL, not "any argument token".
		{"systemctl start cat", cmdRejected},
		{"hostnamectl set-hostname status", cmdRejected},
		{"sysctl -w vm.swappiness=1", cmdRejected},
		{"sysctl -n vm.swappiness", cmdReadOnly},
		{"sysctl -n -w vm.swappiness=1", cmdRejected},
		{"sysctl vm.swappiness=1", cmdRejected},
		{"sysctl -n -p /etc/sysctl.conf", cmdRejected},
		{"sysctl -n --system", cmdRejected},
		{"sysctl -n --load=/etc/sysctl.conf", cmdRejected},
		{"openssl x509 -noout -in /etc/ssl/cert.pem", cmdReadOnly},
		// openssl accepts an option with one or two dashes and a separate or
		// glued '=' value, and every such spelling of -out creates and
		// truncates its file even under -noout (verified on 3.6.3). All four
		// must reject — two rounds of enumerating exact tokens each missed
		// one, so the predicate now matches the normalized option NAME.
		{"openssl x509 -noout -out /tmp/x -in /etc/ssl/cert.pem", cmdRejected},
		{"openssl x509 -noout --out /tmp/x -in /etc/ssl/cert.pem", cmdRejected},
		{"openssl x509 -noout -out=/tmp/x -in /etc/ssl/cert.pem", cmdRejected},
		{"openssl x509 -noout --out=/tmp/x -in /etc/ssl/cert.pem", cmdRejected},
		// The database step's information_schema probes (probeSQL,
		// internal/database/mariadb.go): only the pinned
		// `--protocol=socket -N -e "SELECT 1 FROM information_schema.…"`
		// shape reads. Everything else the client could be told to run —
		// DDL/DML, a second ;-separated statement, INTO OUTFILE (which
		// writes files as the server), an extra option smuggling its own
		// statement — must reject.
		{`mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='app'"`, cmdReadOnly},
		{`mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='app' AND GRANTEE='''app''@''localhost''' LIMIT 1"`, cmdReadOnly},
		{`mysql --protocol=socket -N -e "DROP DATABASE app"`, cmdRejected},
		{`mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='app' INTO OUTFILE '/tmp/x'"`, cmdRejected},
		{`mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA; DROP DATABASE app"`, cmdRejected},
		{`mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='app'" --init-command="DROP DATABASE app"`, cmdRejected},
		{`mysql --protocol=socket`, cmdRejected},
		{`mysql -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='app'"`, cmdRejected},

		// valkey's per-site liveness probe (valkeyPingCmd, valkey.go): PING
		// over the tenant's own socket mutates nothing. Any other valkey-cli
		// verb (FLUSHALL, SHUTDOWN, SET…), a socket outside berth's runtime
		// base, or any other program behind runuser is arbitrary code under
		// another uid and must reject.
		{`runuser -u 'appuser' -- valkey-cli -s '/run/berth-valkey/app_example_com/valkey.sock' ping`, cmdReadOnly},
		{`runuser -u 'appuser' -- valkey-cli -s '/run/berth-valkey/app_example_com/valkey.sock' flushall`, cmdRejected},
		{`runuser -u 'appuser' -- valkey-cli -s '/run/berth-valkey/app_example_com/valkey.sock' shutdown`, cmdRejected},
		{`runuser -u 'appuser' -- valkey-cli -s '/tmp/evil.sock' ping`, cmdRejected},
		{`runuser -u 'appuser' -- rm -rf /var/www`, cmdRejected},
		{`runuser -l root`, cmdRejected},

		// The test builtin's -ef comparison (site.Check probes that the
		// sites-enabled entry IS berth's symlink to the vhost): an inode
		// identity read. ONLY that exact five-token shape is allowed — every
		// other [ expression stays unregistered (the reloadedSince chains
		// carry && and go through the audited registry instead).
		{`[ '/etc/nginx/sites-enabled/app.example.com' -ef '/etc/nginx/sites-available/app.example.com' ]`, cmdReadOnly},
		{`[ -e '/var/lib/berth/nginx.reloaded' ]`, cmdRejected},
		{`[ '/a' -nt '/b' ]`, cmdRejected},
		{`[ -w '/etc' ]`, cmdRejected},

		// supervisorctl: only the single-program status query reads (a state
		// dump over supervisord's RPC socket). start/stop/restart/reread/
		// update all mutate the process set, and the bare all-programs status
		// is not a shape berth issues, so it stays rejected (safe direction).
		{`supervisorctl status 'berth-app_example_com:*'`, cmdReadOnly},
		{`supervisorctl status`, cmdRejected},
		{`supervisorctl reread`, cmdRejected},
		{`supervisorctl update`, cmdRejected},
		{`supervisorctl restart 'berth-app_example_com:*'`, cmdRejected},
		{`supervisorctl start status`, cmdRejected},

		// The keyring probe's exact read shape as issued by
		// apt.KeyringHoldsExactly (internal/apt/apt.go), and proof that
		// dropping --trust-model always — the flag that suppresses
		// trustdb.gpg creation — breaks the match.
		{"gpg --no-options --no-keyring --trust-model always --show-keys --with-colons /usr/share/keyrings/example.gpg", cmdReadOnly},
		{"gpg --no-options --no-keyring --show-keys --with-colons /usr/share/keyrings/example.gpg", cmdRejected},

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

// TestAuditedStdinMustMatchExactly: the stdin registry carries the same
// one-character-drift property as the script registry, on BOTH halves of the
// pair — a changed script or a changed payload each force a fresh audit.
func TestAuditedStdinMustMatchExactly(t *testing.T) {
	cmd := envValueMatchProbeCmd(fixtureSharedEnv, "DB_PASSWORD")
	stdin := "DB_PASSWORD=" + fixtureDBValue + "\n"
	if got, _ := classifyCommand(cmd, []byte(stdin)); got != cmdAudited {
		t.Errorf("registered (cmd, stdin) pair = %s, want audited", got)
	}
	if got, _ := classifyCommand(cmd, []byte(stdin+" ")); got != cmdRejected {
		t.Errorf("a one-character stdin change still passed as %s — the pair must be exact", got)
	}
	if got, _ := classifyCommand(cmd+" ", []byte(stdin)); got != cmdRejected {
		t.Errorf("a one-character command change still passed as %s — the pair must be exact", got)
	}
	// The path is part of the audited key: the same script aimed at a file the
	// audit never covered must reject, not ride the fixture's registration.
	if got, _ := classifyCommand(envValueMatchProbeCmd("/etc/shadow", "DB_PASSWORD"), []byte(stdin)); got != cmdRejected {
		t.Errorf("an unregistered path still passed as %s — the pair must be exact", got)
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
	cmdException                   // allowed, but known to write (the nginx -t and certbot certificates table entries and the php-fpm branch in classifySimple)
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
// which would silently bless whatever the edit produced. The parameterized
// keys are built by the test-local generators below — deliberate COPIES of the
// production composition, never calls into the helpers themselves, so a
// production edit still breaks the match and forces a fresh audit.
var auditedScripts = map[string]string{
	// assertPHPVersionExclusive's probe, generated by phpPoolConflictProbeCmd
	// (phpversion.go) for the fixture's php.version 8.4 and issued first by
	// accounts.Check and php.Check. Audited command by command: a for-loop
	// over the pool.d globs; `[ -e "$f" ]` (existence test); a `case` pattern
	// skip of the configured version's own directory; `head -n 1` (reads one
	// line); a string comparison; `grep -Eq` (reads); `printf` to stdout.
	// Nothing writes, nothing executes file content.
	phpPoolConflictProbe84: "phpPoolConflictProbeCmd (phpversion.go): glob loop of [ -e ], case, head -n 1, grep -Eq, printf — reads only",

	// bssh.AssertRootControlledAncestry's probe (internal/ssh/ancestry.go),
	// issued by accounts.Check via assertSafeAncestry("/home/x") and by
	// appdirs.Check for the deploy path + ACME webroot ancestry. Audited:
	// `export LC_ALL=C` (locale pin, process-local); `[ -e ]`/`[ -L ]`
	// existence tests; `stat -c '%n %u %a %F'` (reads metadata); `exit 91`.
	// Nothing writes.
	ancestryProbeCmd("/", "/home"):                                   "AssertRootControlledAncestry (ssh/ancestry.go) for accounts' /home/x pattern: export + test + stat — reads only",
	ancestryProbeCmd("/", "/var", "/var/www", "/var/www/berth-acme"): "AssertRootControlledAncestry (ssh/ancestry.go) for appdirs' deploy path + ACME webroot: export + test + stat — reads only",

	// noSymlinkInPath's walk (appdirs.go), issued by accounts.Check and
	// appdirs.Check over the deploy tree and by appdirs.Check over the ACME
	// webroot. Audited: brace-grouped `test ! -e || { test ! -L && test -d; }`
	// chains joined with && — existence/type tests only, nothing writes.
	noSymlinkWalkCmd("/var/www/app.example.com/shared/tmp"): "noSymlinkInPath (appdirs.go) over the fixture deploy tree: test -e/-L/-d chains — reads only",
	noSymlinkWalkCmd("/var/www/berth-acme/app.example.com"): "noSymlinkInPath (appdirs.go) over the fixture ACME webroot: test -e/-L/-d chains — reads only",

	// assertOwnSSHDir's probe (accounts.go), one per managed account. Audited:
	// `export LC_ALL=C`; `[ -e ]`/`[ -L ]` existence tests; `stat -c '%U %F'`
	// (reads owner and type); `exit 91`/`exit 92` as signals. Nothing writes.
	sshDirProbeCmd("/home/berth/.ssh"):   "assertOwnSSHDir (accounts.go) for the berth account: test + stat + exit signals — reads only",
	sshDirProbeCmd("/home/appuser/.ssh"): "assertOwnSSHDir (accounts.go) for the fixture site user: test + stat + exit signals — reads only",

	// sshdOptsProbe (hardening.go), pasted literally — never referencing the
	// production const, which would let an edit re-bless itself. Audited:
	// `test ! -e` (existence test) short-circuiting into `cat --` (reads the
	// file; `--` ends option parsing). Nothing writes.
	`test ! -e /etc/default/ssh || cat -- /etc/default/ssh`: "sshdOptsProbe (hardening.go): test short-circuit into cat — reads only",

	// reloadedSince's stamp comparisons (reloadstamp.go), issued by
	// hardening.Check for the ssh and fail2ban units. Audited: `[ -e ]`
	// existence test and `[ ! … -nt … ]` mtime comparisons — reads only.
	reloadedSinceCmd("ssh", "/etc/ssh/sshd_config.d/00-berth.conf"):    "reloadedSince (reloadstamp.go) for ssh vs the sshd drop-in: [ -e ] + [ -nt ] — reads only",
	reloadedSinceCmd("fail2ban", "/etc/fail2ban/jail.d/99-berth.conf"): "reloadedSince (reloadstamp.go) for fail2ban vs the managed jail: [ -e ] + [ -nt ] — reads only",

	// Wave 3 (nginx, php, valkey, tuning, database), same discipline: pasted
	// literals for production consts, test-local mirror generators for the
	// parameterized compositions — never the production helpers themselves.

	// reloadedSince's stamp comparisons for the two units whose core config
	// nginx.Check and php.Check own. Audited: `[ -e ]` existence test and
	// `[ ! … -nt … ]` mtime comparisons — reads only.
	reloadedSinceCmd("nginx", "/etc/nginx/nginx.conf"): "reloadedSince (reloadstamp.go) for nginx vs its core config: [ -e ] + [ -nt ] — reads only",
	reloadedSinceCmd("php8.4-fpm", "/etc/php/8.4/fpm/conf.d/99-berth-opcache.ini", "/etc/php/8.4/fpm/conf.d/99-berth-tuning.ini"): "reloadedSince (reloadstamp.go) for php8.4-fpm vs the two managed drop-ins: [ -e ] + [ -nt ] — reads only",

	// valkey's instance-unit discovery (valkeyListUnitsCmd, valkey.go), a
	// production const pasted literally. Audited: `ls -1` over a fixed glob
	// prints matching paths (reads directory entries only); `2>/dev/null`
	// discards diagnostics into the null device, which is not host state.
	// Nothing writes.
	valkeyListUnitsPasted: "valkeyListUnitsCmd (valkey.go): ls -1 over the berth-valkey unit glob, stderr discarded — reads only",

	// valkeyExecCmd's binary-staleness probe (valkey.go) for the fixture
	// instance. Audited: `systemctl show -p MainPID --value` (reads a unit
	// property) captured into a shell variable; two `stat -Lc %i` inode reads
	// (of /proc/<pid>/exe and the packaged binary — -L follows the
	// valkey-server → valkey-check-rdb symlink, the live-found lesson);
	// a `[ … = … ]` string comparison. Nothing writes.
	valkeyExecProbeCmd(fixtureValkeyUnit): "valkeyExecCmd (valkey.go): systemctl show MainPID + two stat -L inode reads compared with [ = ] — reads only",

	// serviceConfigLoaded's mtime-vs-activation probes (tuning.go), issued by
	// tuning.Check for mariadb and by valkey.Check for each instance unit.
	// Audited: `stat -c %Y` (mtime read), `systemctl show -p
	// ActiveEnterTimestamp --value --timestamp=unix` (property read), `tr -d @`
	// (stream filter on the substitution output), integer `[ -le ]`. Nothing
	// writes.
	serviceLoadedProbeCmd(fixtureMariaDBTuning, "mariadb.service"):  "serviceConfigLoaded (tuning.go) for mariadb vs the tuning drop-in: stat %Y + systemctl show + tr + [ -le ] — reads only",
	serviceLoadedProbeCmd(fixtureValkeyUnitPath, fixtureValkeyUnit): "serviceConfigLoaded (tuning.go) for the fixture valkey instance vs its unit file: stat %Y + systemctl show + tr + [ -le ] — reads only",

	// tuning's RAM probe (memTotalCmd, tuning.go), a production const pasted
	// literally. Audited: awk reads /proc/meminfo and prints field 2 of the
	// MemTotal line — the program text contains no output-redirect, no
	// system() and no getline into a command. Nothing writes.
	memTotalPasted: "memTotalCmd (tuning.go): awk prints MemTotal's field 2 from /proc/meminfo — reads only",

	// database's shared/.env presence probes (database.go). Audited,
	// command by command: the C-locale pin (assignment + export, process-local);
	// `grep -m1` selects the first KEY= line; the shape verdict rides a second
	// `grep -Eq` (envCredentialPresentScript) or a `printf | sed | grep -Eq`
	// pipeline (envBerthAppKeyScript) whose sed script only trims trailing
	// whitespace (s///, no w, no e); verdicts travel as exit codes so the
	// secret never reaches stdout. Nothing writes.
	envCredentialProbeCmd(fixtureSharedEnv): "envCredentialPresentScript (database.go): locale pin + grep -m1 | grep -Eq, exit-code verdict — reads only",
	envAppKeyProbeCmd(fixtureSharedEnv):     "envBerthAppKeyScript (database.go): locale pin + grep -m1 capture + printf|sed|grep -Eq shape test, exit-code signals — reads only",

	// Wave 4 (site, tls, backups, offsite), same discipline: pasted literals
	// for production consts and const-composed commands, test-local mirror
	// generators for the parameterized compositions.

	// site's supervisor-program discovery (listSupervisorPrograms, site.go),
	// a const-composed command pasted literally. Audited: `ls -1` prints the
	// paths matching a fixed glob (reads directory entries only);
	// `2>/dev/null` discards the no-match diagnostic into the null device.
	// Nothing writes.
	supervisorListPasted: "listSupervisorPrograms (site.go): ls -1 over the berth-*.conf program glob, stderr discarded — reads only",

	// backups' three orphan-discovery listings (lsGlob over backupScriptGlob /
	// backupCronGlob / backupManifestGlob, backups.go). Same two commands as
	// the supervisor listing above: ls -1 over a fixed glob, stderr to the
	// null device. Reads only.
	backupScriptListPasted:   "lsGlob(backupScriptGlob) (backups.go): ls -1 over /usr/local/sbin/berth-backup-*, stderr discarded — reads only",
	backupCronListPasted:     "lsGlob(backupCronGlob) (backups.go): ls -1 over /etc/cron.d/berth-backup-*, stderr discarded — reads only",
	backupManifestListPasted: "lsGlob(backupManifestGlob) (backups.go): ls -1 over /var/backups/berth/*/manifest, stderr discarded — reads only",

	// commandExists' PATH probe (backups.go), issued for the engine's dump
	// binary. Audited: `command -v` resolves a name against PATH without
	// executing anything; both redirections aim at the null device and the
	// caller reads only the exit code. Nothing writes.
	commandVProbeCmd("mysqldump"): "commandExists (backups.go) for the mariadb dump client: command -v with output discarded — reads only",

	// findRegularFiles' guarded listings (site.go), issued by orphanSiteFiles
	// over the three orphan namespaces. Audited: `[ -d ]` existence test
	// short-circuiting the whole listing; `find -maxdepth 1 -type f` (with an
	// optional -name filter) has NO action predicate, so it defaults to
	// -print — it only reads directory entries. Nothing writes.
	findRegularProbeCmd("/etc/nginx/sites-available", ""):    "findRegularFiles (site.go) over sites-available: [ -d ] + find -type f -print — reads only",
	findRegularProbeCmd("/etc/php/8.4/fpm/pool.d", "*.conf"): "findRegularFiles (site.go) over the 8.4 pool dir: [ -d ] + find -type f -name — reads only",
	findRegularProbeCmd("/etc/cron.d", "berth-site-*"):       "findRegularFiles (site.go) over the scheduler-cron namespace: [ -d ] + find -type f -name — reads only",

	// findDirectories' guarded listings (site.go), issued by
	// discoverTLSOrphans over berth's two TLS directory namespaces. Same
	// shape as above with -type d. Reads only.
	findDirsProbeCmd("/var/www/berth-acme"): "findDirectories (site.go) over the ACME webroot namespace: [ -d ] + find -type d -print — reads only",
	findDirsProbeCmd("/etc/ssl/berth"):      "findDirectories (site.go) over the self-signed namespace: [ -d ] + find -type d -print — reads only",

	// listRenewalConfs' inventory (tls.go), a const-composed command pasted
	// literally. Audited: `[ -d ]` guard; `find -H` follows a symlinkED
	// ARGUMENT only (no directory traversal through links) and carries no
	// action predicate — print only, deliberately no -type filter. Nothing
	// writes.
	renewalConfListPasted: "listRenewalConfs (tls.go): [ -d ] + find -H -name '*.conf' -print — reads only",

	// reloadedSince's stamp comparisons for site.Check's two unit windows:
	// nginx vs the fixture vhost + the sites-enabled DIRECTORY (its mtime
	// covers link topology drift), php-fpm vs the fixture pool + the pool.d
	// directory. Audited: `[ -e ]` existence test and `[ ! … -nt … ]` mtime
	// comparisons — reads only.
	reloadedSinceCmd("nginx", "/etc/nginx/sites-available/app.example.com", "/etc/nginx/sites-enabled"):       "reloadedSince (reloadstamp.go) for nginx vs the fixture vhost + sites-enabled dir: [ -e ] + [ -nt ] — reads only",
	reloadedSinceCmd("php8.4-fpm", "/etc/php/8.4/fpm/pool.d/app_example_com.conf", "/etc/php/8.4/fpm/pool.d"): "reloadedSince (reloadstamp.go) for php8.4-fpm vs the fixture pool + pool.d dir: [ -e ] + [ -nt ] — reads only",
}

// phpPoolConflictProbe84 is the EXACT text phpPoolConflictProbeCmd("8.4")
// produces today, pasted as a literal so an edit to the production helper
// breaks the registry match and forces a fresh audit.
const phpPoolConflictProbe84 = `for f in /etc/php/*/fpm/pool.d/*.conf; do [ -e "$f" ] || continue; case "$f" in /etc/php/8.4/fpm/pool.d/*) continue;; esac; if [ "$(head -n 1 "$f" 2>/dev/null)" = '; managed by berth' ]; then printf 'M %s\n' "$f"; elif grep -Eq '^[[:space:]]*listen[[:space:]]*=[[:space:]]*"?/run/php/berth-' "$f" 2>/dev/null; then printf 'S %s\n' "$f"; fi; done`

// ancestryProbeCmd mirrors the composition in ssh/ancestry.go's
// AssertRootControlledAncestry — a copy on purpose (see auditedScripts).
func ancestryProbeCmd(paths ...string) string {
	q := make([]string, 0, len(paths))
	for _, p := range paths {
		q = append(q, shQuote(p))
	}
	return "export LC_ALL=C; for p in " + strings.Join(q, " ") +
		"; do if [ -e \"$p\" ] || [ -L \"$p\" ]; then stat -c '%n %u %a %F' \"$p\" || exit 91; fi; done"
}

// noSymlinkWalkCmd mirrors noSymlinkInPath's composition (appdirs.go) — a copy
// on purpose (see auditedScripts).
func noSymlinkWalkCmd(p string) string {
	cur := ""
	var tests []string
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		cur += "/" + part
		q := shQuote(cur)
		tests = append(tests, "{ test ! -e "+q+" || { test ! -L "+q+" && test -d "+q+"; }; }")
	}
	return strings.Join(tests, " && ")
}

// sshDirProbeCmd mirrors assertOwnSSHDir's probe composition (accounts.go) —
// a copy on purpose (see auditedScripts).
func sshDirProbeCmd(dir string) string {
	q := shQuote(dir)
	return "export LC_ALL=C; if [ -e " + q + " ] || [ -L " + q + " ]; then stat -c '%U %F' " + q + " || exit 91; else exit 92; fi"
}

// valkeyListUnitsPasted / memTotalPasted are the EXACT texts of the
// production consts valkeyListUnitsCmd (valkey.go) and memTotalCmd
// (tuning.go), pasted as literals — never referencing the consts, which
// would let an edit re-bless itself.
const (
	valkeyListUnitsPasted = `ls -1 /etc/systemd/system/berth-valkey-*.service 2>/dev/null`
	memTotalPasted        = `awk '/^MemTotal:/{print $2}' /proc/meminfo`
)

// valkeyExecProbeCmd mirrors valkeyExecCmd's composition (valkey.go) — a copy
// on purpose (see auditedScripts).
func valkeyExecProbeCmd(unit string) string {
	return `p="$(systemctl show -p MainPID --value ` + unit + `)"; [ "$(stat -Lc %i /proc/$p/exe 2>/dev/null)" = "$(stat -Lc %i /usr/bin/valkey-server 2>/dev/null)" ]`
}

// serviceLoadedProbeCmd mirrors serviceConfigLoaded's composition (tuning.go)
// — a copy on purpose (see auditedScripts).
func serviceLoadedProbeCmd(path, unit string) string {
	return `[ "$(stat -c %Y ` + shQuote(path) + ` 2>/dev/null)" -le "$(systemctl show -p ActiveEnterTimestamp --value --timestamp=unix ` + unit + ` 2>/dev/null | tr -d @)" ]`
}

// envCredentialProbeCmd mirrors envCredentialPresentScript's composition
// (database.go) — a copy on purpose (see auditedScripts).
func envCredentialProbeCmd(path string) string {
	return "LC_ALL=C; export LC_ALL; grep -m1 '^DB_PASSWORD=' " + shQuote(path) +
		" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'"
}

// envAppKeyProbeCmd mirrors envBerthAppKeyScript's composition (database.go)
// — a copy on purpose (see auditedScripts).
func envAppKeyProbeCmd(path string) string {
	return "LC_ALL=C; export LC_ALL; line=$(grep -m1 '^APP_KEY=' " + shQuote(path) + "); s=$?; " +
		"if [ $s -eq 1 ]; then exit 1; elif [ $s -ne 0 ]; then exit 2; fi; " +
		`printf '%s' "$line" | sed 's/[[:space:]]*$//' | grep -Eq '^APP_KEY=base64:[A-Za-z0-9+/]{43}=$' && exit 0; exit 3`
}

// supervisorListPasted / backupScriptListPasted / backupCronListPasted /
// backupManifestListPasted / renewalConfListPasted are the EXACT texts of the
// const-composed listings in listSupervisorPrograms (site.go), lsGlob's three
// backups.Check call sites (backups.go) and listRenewalConfs (tls.go), pasted
// as literals — never referencing the production consts, which would let an
// edit re-bless itself.
const (
	supervisorListPasted     = `ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null`
	backupScriptListPasted   = `ls -1 /usr/local/sbin/berth-backup-* 2>/dev/null`
	backupCronListPasted     = `ls -1 /etc/cron.d/berth-backup-* 2>/dev/null`
	backupManifestListPasted = `ls -1 /var/backups/berth/*/manifest 2>/dev/null`
	renewalConfListPasted    = `if [ -d '/etc/letsencrypt/renewal' ]; then find -H '/etc/letsencrypt/renewal' -mindepth 1 -maxdepth 1 -name '*.conf'; fi`
)

// commandVProbeCmd mirrors commandExists' composition (backups.go) — a copy
// on purpose (see auditedScripts).
func commandVProbeCmd(bin string) string {
	return "command -v " + bin + " >/dev/null 2>&1"
}

// findRegularProbeCmd mirrors findRegularFiles' composition (site.go) — a
// copy on purpose (see auditedScripts).
func findRegularProbeCmd(dir, namePattern string) string {
	cmd := "find " + shQuote(dir) + " -maxdepth 1 -type f"
	if namePattern != "" {
		cmd += " -name " + shQuote(namePattern)
	}
	return "if [ -d " + shQuote(dir) + " ]; then " + cmd + "; fi"
}

// findDirsProbeCmd mirrors findDirectories' composition (site.go) — a copy
// on purpose (see auditedScripts).
func findDirsProbeCmd(dir string) string {
	return "if [ -d " + shQuote(dir) + " ]; then find " + shQuote(dir) + " -mindepth 1 -maxdepth 1 -type d; fi"
}

// envValueMatchProbeCmd mirrors envValueMatchScript's composition
// (database.go) — a copy on purpose (see auditedStdin).
func envValueMatchProbeCmd(path, key string) string {
	return "LC_ALL=C; export LC_ALL; IFS= read -r want; " +
		"line=$(grep -m1 '^" + key + "=' " + shQuote(path) + "); s=$?; " +
		"if [ $s -eq 1 ]; then exit 3; elif [ $s -ne 0 ]; then exit 2; fi; " +
		`line=$(printf '%s' "$line" | sed 's/[[:space:]]*$//'); ` +
		`[ "$line" = "$want" ] && exit 0; exit 1`
}

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
// Keyed by the EXACT (command, stdin) pair — the same one-character-drift
// discipline as auditedScripts, on both halves.
var auditedStdin = map[stdinKey]string{
	// envValueMatches' value-agreement probes (database.go), issued by
	// database.Check per site for DB_PASSWORD (always) and APP_KEY (when the
	// live key is berth-shaped). The stdin is the expected KEY=value line —
	// consumed by `IFS= read -r want` into a shell variable and used ONLY as
	// the right-hand side of a quoted [ "$line" = "$want" ] string equality:
	// data, never a program (no eval, no sh, no `-f -`). The script itself:
	// C-locale pin, read, grep -m1 capture with explicit exit mapping, a
	// printf|sed trailing-whitespace trim (s///, no w, no e), [ = ]. Reads
	// only; the verdict is the exit code, the secret never reaches stdout.
	{cmd: envValueMatchProbeCmd(fixtureSharedEnv, "DB_PASSWORD"), stdin: "DB_PASSWORD=" + fixtureDBValue + "\n"}: "envValueMatchScript (database.go), DB_PASSWORD agreement: stdin is the expected line, read into a variable and string-compared — data, not a program",
	{cmd: envValueMatchProbeCmd(fixtureSharedEnv, "APP_KEY"), stdin: "APP_KEY=" + fixtureAppKey + "\n"}:          "envValueMatchScript (database.go), APP_KEY agreement: stdin is the expected line, read into a variable and string-compared — data, not a program",
}

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

// mentionsFlag reports whether args mentions any of the given flags in a
// spelling getopt accepts. Exact-token matching proved bypassable by ordinary
// spellings — `--set=@0`, `-F/etc/hostname` and the bundle `-bF` all slipped
// past an exact-token denylist — so every denylisted WRITING flag must be
// matched here instead.
//
// Matching by flag shape:
//   - a long flag (--file) matches the exact token, the glued form
//     (--file=/x), and any >=3-char prefix abbreviation with or without a
//     glued value (--fil, --fil=/x) — getopt_long accepts unique
//     abbreviations. Prefix matching can over-reject an ambiguous
//     abbreviation the tool itself would refuse, which is the safe direction.
//   - a single-letter short flag (-F) matches any single-dash token whose
//     letters include it: the exact -F, the glued -F/x and the bundle -bF
//     are one and the same match.
//   - a single-dash multi-letter flag (-out, -delete) matches exactly: that
//     spelling belongs to non-getopt CLIs (openssl, find) which accept
//     neither glue nor bundles, and letter-matching would falsely hit reads
//     such as openssl's -noout.
func mentionsFlag(args []string, flags ...string) bool {
	for _, a := range args {
		for _, f := range flags {
			if flagMatches(a, f) {
				return true
			}
		}
	}
	return false
}

// flagMatches implements mentionsFlag for one (argument, flag) pair.
func flagMatches(arg, flag string) bool {
	switch {
	case strings.HasPrefix(flag, "--"): // getopt long flag
		if !strings.HasPrefix(arg, "--") {
			return false
		}
		name, _, _ := strings.Cut(arg, "=")
		return len(name) > 2 && strings.HasPrefix(flag, name)
	case len(flag) == 2: // getopt short flag: -X
		return len(arg) >= 2 && arg[0] == '-' && arg[1] != '-' &&
			strings.ContainsRune(arg[1:], rune(flag[1]))
	default: // non-getopt single-dash word: -out, -delete
		return arg == flag
	}
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
	{verb: "tail", allow: func(a []string) bool { return !mentionsFlag(a, "-f", "-F", "--follow") }, verdict: cmdReadOnly,
		why: "-f/-F would follow forever, which is a hang rather than a write, but still forbidden"},
	{verb: "readlink", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "basename", allow: func([]string) bool { return true }, verdict: cmdReadOnly},
	{verb: "dirname", allow: func([]string) bool { return true }, verdict: cmdReadOnly},

	// Verbs with a writing mode: the predicate must exclude it.
	{verb: "date", allow: func(a []string) bool { return !mentionsFlag(a, "-s", "--set") }, verdict: cmdReadOnly,
		why: "date -s/--set sets the system clock"},
	{verb: "hostname", allow: hostnameIsReadOnly, verdict: cmdReadOnly,
		why: "hostname <name>, -F/--file, -b/--boot and -y/--yp/--nis all set names"},
	{verb: "sort", allow: func(a []string) bool { return !mentionsFlag(a, "-o", "--output") }, verdict: cmdReadOnly,
		why: "sort -o/--output writes a file"},
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
	{verb: "logrotate", allow: func(a []string) bool { return hasExact(a, "-d") && !mentionsFlag(a, "-f", "--force") }, verdict: cmdReadOnly},
	{verb: "fail2ban-client", allow: func(a []string) bool { return hasExact(a, "-t") && firstNonFlag(a) == "" }, verdict: cmdReadOnly},

	// The named exceptions: allowed, but they WRITE (spec §4.2; php-fpm's
	// lives in classifySimple because its verb carries the version).
	{verb: "nginx", allow: func(a []string) bool { return hasExact(a, "-t") && len(a) == 1 }, verdict: cmdException,
		why: "as root may create a missing log file"},

	// The third exception, measurement-backed like the first two (spec
	// §4.2.1 method, two passes, on a provisioned Debian 13 host with
	// certbot 4.0.0): `certbot certificates` appends its full certificate
	// inventory — serial, key type, domains, expiry, paths — to
	// /var/log/letsencrypt/letsencrypt.log on EVERY invocation (+1068 bytes
	// per run, deterministic across both passes) and touches lock files
	// under /etc/letsencrypt and /var/lib/letsencrypt (mtime changes). That
	// is over ten times php-fpm -t's 99-byte notice. Pinned to exactly the
	// bare inventory listing: certonly/renew/delete/revoke change issuance
	// state, and an argument-carrying listing was never measured.
	{verb: "certbot", allow: func(a []string) bool { return len(a) == 1 && a[0] == "certificates" }, verdict: cmdException,
		why: "appends its certificate inventory to /var/log/letsencrypt/letsencrypt.log (~1068 bytes/run) and touches its lock files (measured: certbot 4.0.0, Debian 13)"},

	// The test builtin: ONLY the five-token -ef inode comparison
	// (`[ <path> -ef <path> ]`, site.Check's enabled-symlink probe) is
	// allowed. test itself is intrinsically read-only, but pinning the shape
	// keeps the table honest about what berth actually issues.
	{verb: "[", allow: func(a []string) bool { return len(a) == 4 && a[1] == "-ef" && a[3] == "]" }, verdict: cmdReadOnly,
		why: "the [ … -ef … ] inode comparison reads; no other [ shape is issued table-side"},

	// supervisorctl: status is a state query over supervisord's RPC socket
	// and writes nothing; start/stop/restart/reread/update mutate the
	// process set (the spec's §4.3 names the verb mutating as a class, so
	// the read shape is pinned to exactly `status <one program>` — the shape
	// site.Check issues).
	{verb: "supervisorctl", allow: func(a []string) bool { return len(a) == 2 && a[0] == "status" }, verdict: cmdReadOnly,
		why: "only `supervisorctl status <program>` reads; every other subcommand drives the process set"},

	// Subcommand verbs, matched POSITIONALLY. `systemctl start cat` must not
	// pass by containing the token "cat".
	{verb: "systemctl", allow: systemctlIsReadOnly, verdict: cmdReadOnly},
	{verb: "dpkg", allow: func(a []string) bool { return len(a) >= 1 && (a[0] == "-s" || a[0] == "--status") }, verdict: cmdReadOnly},
	{verb: "timedatectl", allow: func(a []string) bool { return firstNonFlag(a) == "show" || firstNonFlag(a) == "status" }, verdict: cmdReadOnly},
	{verb: "hostnamectl", allow: func(a []string) bool { return firstNonFlag(a) == "status" || firstNonFlag(a) == "" }, verdict: cmdReadOnly},
	{verb: "swapon", allow: func(a []string) bool { return len(a) == 1 && a[0] == "--show" }, verdict: cmdReadOnly},
	{verb: "sysctl", allow: sysctlIsReadOnly, verdict: cmdReadOnly},
	{verb: "ufw", allow: func(a []string) bool { return len(a) == 1 && a[0] == "status" }, verdict: cmdReadOnly,
		why: "only the bare status query reads; allow/enable/delete rewrite firewall rules"},
	{verb: "passwd", allow: func(a []string) bool { return len(a) == 2 && a[0] == "-S" }, verdict: cmdReadOnly,
		why: "passwd -S prints status metadata; every other mode changes credentials"},
	{verb: "command", allow: func(a []string) bool { return len(a) == 2 && a[0] == "-v" }, verdict: cmdReadOnly},
	{verb: "openssl", allow: opensslX509IsReadOnly, verdict: cmdReadOnly,
		why: "every spelling of -out creates and truncates its file even under -noout (verified on OpenSSL 3.6.3)"},
	{verb: "find", allow: findIsReadOnly, verdict: cmdReadOnly},
	{verb: "gpg", allow: gpgIsReadOnly, verdict: cmdReadOnly},
	{verb: "mysql", allow: mysqlIsReadOnlyProbe, verdict: cmdReadOnly,
		why: "only probeSQL's -N -e information_schema SELECT reads; any other statement, a ;-chain, INTO OUTFILE or an extra option mutates"},
	{verb: "runuser", allow: runuserIsValkeyPing, verdict: cmdReadOnly,
		why: "only `runuser -u <user> -- valkey-cli -s <berth socket> ping` reads; anything else is an arbitrary program under another uid"},
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

// hostnameIsReadOnly: hostname writes when given ANY non-flag argument (the
// new name to set), via -F/--file (name read from a file), -b/--boot, or
// -y/--yp/--nis (sets the NIS domain when given a value). So every argument
// must be a flag, and none may mention a writing one in any getopt spelling.
func hostnameIsReadOnly(args []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return false
		}
	}
	return !mentionsFlag(args, "-F", "--file", "-b", "--boot", "-y", "--yp", "--nis")
}

// sysctlIsReadOnly allows only `sysctl -n <key>...`. Checking a[0] alone is
// not enough: -w/--write can follow -n, -p/--load/--system apply a config
// file (writing kernel parameters), and the bare `key=value` form writes
// even WITHOUT -w, so any argument containing '=' is rejected as well.
func sysctlIsReadOnly(args []string) bool {
	if len(args) < 1 || args[0] != "-n" ||
		mentionsFlag(args, "-w", "--write", "-p", "--load", "--system") {
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

// optName normalizes one argument to the option NAME openssl's parser would
// see: apps/lib/opt.c strips one or two leading dashes ("Allow -nnn and
// --nnn") and snips a glued "=value" ("If we have --flag=foo, snip it off").
// A non-option argument normalizes to "". Matching the normalized name
// covers every spelling the parser derives, so nothing here depends on
// enumerating them.
func optName(arg string) string {
	if !strings.HasPrefix(arg, "-") {
		return ""
	}
	name := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
	name, _, _ = strings.Cut(name, "=")
	return name
}

// opensslX509IsReadOnly allows only `openssl x509 -noout …` where no argument
// normalizes to the option name "out". Two rounds of enumerating -out's exact
// tokens each missed a spelling (first --out, then the glued -out=FILE and
// --out=FILE — every one of which creates and truncates its file even under
// -noout), so the predicate matches by normalized name instead. -noout
// normalizes to "noout", never "out" — the property that keeps the read
// alive, and the reason openssl does not route through mentionsFlag, whose
// short-flag rule would letter-match the 'o' in -noout. "o" is also denied:
// openssl refuses it as unknown, so that is free over-rejection.
//
// Probed on OpenSSL 3.6.3: -out=F and --out=F exit 0 and create F; -o, --o,
// the abbreviation -ou= and the three-dash ---out= all exit 1 with no file.
func opensslX509IsReadOnly(args []string) bool {
	if len(args) < 1 || args[0] != "x509" || !hasExact(args, "-noout") {
		return false
	}
	for _, a := range args {
		switch optName(a) {
		case "out", "o":
			return false
		}
	}
	return true
}

// mysqlIsReadOnlyProbe allows only probeSQL's shape
// (internal/database/mariadb.go): `mysql --protocol=socket -N -e
// "SELECT 1 FROM information_schema.…"`. Every pin is load-bearing:
// --protocol=socket keeps the probe on the local server, -N -e is the exact
// spelling probeSQL composes, and the statement must be a single SELECT
// against information_schema. Rejected on top of that: a second statement
// (';'), INTO (OUTFILE/DUMPFILE write files as the SERVER process — matching
// the bare word over-rejects a column literally named INTO, the safe
// direction), LOAD_FILE (reads server-side files into the result — not a
// mutation, but nothing berth issues needs it), and any extra double quote
// (exactly one opening and one closing), so a trailing option such as
// --init-command="…" cannot smuggle its own statement past the prefix check.
func mysqlIsReadOnlyProbe(args []string) bool {
	if len(args) < 4 || args[0] != "--protocol=socket" || args[1] != "-N" || args[2] != "-e" {
		return false
	}
	q := strings.Join(args[3:], " ")
	if !strings.HasPrefix(q, `"SELECT 1 FROM information_schema.`) ||
		!strings.HasSuffix(q, `"`) || strings.Count(q, `"`) != 2 {
		return false
	}
	up := strings.ToUpper(q)
	return !strings.Contains(q, ";") && !strings.Contains(up, "INTO") && !strings.Contains(up, "LOAD_FILE")
}

// runuserIsValkeyPing allows only valkeyPingCmd's shape (valkey.go):
// `runuser -u <user> -- valkey-cli -s '/run/berth-valkey/…' ping`, argument
// by argument. The trailing verb is pinned to `ping` (a PONG probe, mutates
// nothing) and the socket to berth's per-site runtime base. The user and the
// socket tail stay free: they are shQuote'd values, and the shape is what
// makes the command a read.
func runuserIsValkeyPing(args []string) bool {
	return len(args) == 7 && args[0] == "-u" && args[2] == "--" &&
		args[3] == "valkey-cli" && args[4] == "-s" && args[6] == "ping" &&
		strings.HasPrefix(args[5], "'/run/berth-valkey/")
}

// findMutators are the predicates that act instead of reporting. find's
// predicates are non-getopt single-dash words, so mentionsFlag degrades to
// exact matching for every one of them by design — glued and bundled
// spellings do not exist for find.
var findMutators = []string{
	"-delete", "-exec", "-execdir", "-ok", "-okdir",
	"-fls", "-fprint", "-fprint0", "-fprintf",
}

func findIsReadOnly(args []string) bool { return !mentionsFlag(args, findMutators...) }

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
	// Nothing that writes may be present alongside them, in any spelling
	// (gpg also accepts glued values and abbreviated long options).
	return !mentionsFlag(args, "--export", "--import", "--output", "-o", "--dearmor", "--gen-key", "--batch-key")
}

// classifySimple judges a metacharacter-free command by the shape tables.
func classifySimple(cmd string) (cmdVerdict, string) {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return cmdRejected, "empty command"
	}
	verb, args := fields[0], fields[1:]
	// The locale pin berth's probes use so parsed output is stable (%F file
	// types and id's messages are localized). The assignment itself mutates
	// nothing; the command behind it is judged normally, so the pin can never
	// launder a mutation. ONLY this exact token is stripped: any other
	// assignment (PATH=…, IFS=…) changes what runs rather than how it prints,
	// and stays an unknown verb.
	if verb == "LC_ALL=C" && len(args) > 0 {
		return classifySimple(strings.Join(args, " "))
	}
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

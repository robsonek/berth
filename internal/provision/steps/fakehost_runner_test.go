package steps

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestRecordingRunnerAnswersFromTheModel(t *testing.T) {
	h := newFakeHost(t, "converged", contractServer(t))
	r := newRecordingRunner(h)
	ctx := context.Background()

	res, err := r.Run(ctx, "cat '/etc/logrotate.d/berth'", nil)
	if err != nil {
		t.Fatalf("cat: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "managed by berth") {
		t.Errorf("cat = %+v, want the managed content at exit 0", res)
	}

	// A missing file answers non-zero WITHOUT an error: that is how
	// checkManagedFile learns "absent", so it must not look like a failure.
	if res, err = r.Run(ctx, "cat '/etc/nope'", nil); err != nil || res.ExitCode == 0 {
		t.Errorf("missing file = (%+v, %v), want exit!=0 and no error", res, err)
	}
	if res, _ = r.Run(ctx, "systemctl is-active nginx", nil); res.ExitCode != 0 {
		t.Error("converged: nginx must answer is-active exit 0")
	}
	if res, _ = r.Run(ctx, "dpkg -s nginx", nil); !strings.Contains(res.Stdout, "install ok installed") {
		t.Errorf("dpkg -s = %q, want the Status line pkgInstalled parses", res.Stdout)
	}
}

// The contract's completion rule depends on this: an unanswerable command is
// RETAINED, so a Check that swallows the error cannot hide it. A review of the
// first draft found that inspecting only the Check's final error was not enough,
// because sshdConflictSources already degrades deliberately on probe failure.
func TestRecordingRunnerRetainsUnansweredCommands(t *testing.T) {
	r := newRecordingRunner(newFakeHost(t, "fresh", contractServer(t)))
	ctx := context.Background()
	_, _ = r.Run(ctx, "cat '/a'", nil)
	_, err := r.Run(ctx, "somenewtool --probe /etc/x", nil)
	if err == nil {
		t.Fatal("an unanswerable command must return an error")
	}
	if got := r.unanswered(); len(got) != 1 || got[0] != "somenewtool --probe /etc/x" {
		t.Errorf("unanswered = %q, want exactly the one command the model could not answer", got)
	}
	// It must ALSO be recorded: the contract classifies what a Check ASKED.
	if len(r.recorded()) != 2 {
		t.Errorf("recorded %d commands, want 2 — an unanswerable command is still a command", len(r.recorded()))
	}
}

func TestRecordingRunnerRecordsStdin(t *testing.T) {
	r := newRecordingRunner(newFakeHost(t, "fresh", contractServer(t)))
	_, _ = r.Run(context.Background(), "sed -n -f - /etc/hosts", []byte("w /tmp/x\n"))
	rec := r.recorded()
	if len(rec) != 1 || string(rec[0].stdin) != "w /tmp/x\n" {
		t.Errorf("recorded = %+v, want the stdin payload captured — a program can hide there", rec)
	}
}

func TestRecordingRunnerRejectsUnknownUnitProperty(t *testing.T) {
	r := newRecordingRunner(newFakeHost(t, "converged", contractServer(t)))
	_, err := r.Run(context.Background(), "systemctl show -p NoSuchProperty --value nginx", nil)
	if err == nil {
		t.Error("an unmodelled unit property must be an error, not blank success — blank success lets a Check take an unmodelled branch")
	}
}

func TestRecordingRunnerRecordsWritesWithoutPerformingThem(t *testing.T) {
	h := newFakeHost(t, "fresh", contractServer(t))
	r := newRecordingRunner(h)
	if err := r.WriteFile(context.Background(), bssh.FileSpec{Path: "/etc/x", Content: []byte("y")}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if len(r.writes()) != 1 {
		t.Fatalf("recorded %d writes, want 1", len(r.writes()))
	}
	if _, ok := h.files["/etc/x"]; ok {
		t.Error("WriteFile must not change the model — a Check that writes is a violation, not a state change")
	}
}

// gpgKeys is populated for ALL profiles including fresh, which has no keyring
// on disk. The gpg answer must therefore be gated on the keyring file actually
// existing in the model, or a fresh host would look keyring-converged and
// KeyringHoldsExactly's absent-keyring branch would go unexercised.
func TestRecordingRunnerGatesGpgOnKeyringPresence(t *testing.T) {
	const probe = "gpg --no-options --no-keyring --trust-model always --show-keys --with-colons /usr/share/keyrings/example.gpg"

	fresh := newFakeHost(t, "fresh", contractServer(t))
	r := newRecordingRunner(fresh)
	res, err := r.Run(context.Background(), probe, nil)
	if err != nil {
		t.Fatalf("absent keyring must answer like real gpg (non-zero exit), not error: %v", err)
	}
	if res.ExitCode == 0 || res.Stdout != "" {
		t.Errorf("absent keyring = %+v, want exit!=0 and no key output", res)
	}

	// With the keyring present, the model's key material is the answer.
	fresh.files["/usr/share/keyrings/example.gpg"] = fakeFile{
		owner: "root", group: "root", mode: "644", kind: "regular file"}
	if res, err = r.Run(context.Background(), probe, nil); err != nil || res.ExitCode != 0 {
		t.Fatalf("present keyring = (%+v, %v), want the modelled keys at exit 0", res, err)
	}
	if !strings.Contains(res.Stdout, "fpr:") {
		t.Errorf("present keyring stdout = %q, want the colon output KeyringHoldsExactly parses", res.Stdout)
	}

	// Only the EXACT production argv is answered. A drifted spelling —
	// dropping --with-colons changes the output format the probe parses —
	// must fall to unanswered, not ride the colon-formatted answer.
	if _, err := r.Run(context.Background(),
		"gpg --no-options --no-keyring --trust-model always --show-keys /usr/share/keyrings/example.gpg", nil); err == nil {
		t.Error("a gpg spelling other than KeyringHoldsExactly's exact argv must be unanswered — answering it would mask a production format drift")
	}
}

// userExists (accounts.go) reads ONLY the exit code of `id <user>`, and
// accounts.Check early-returns "account missing" on it. A blanket exit 0 made
// that branch unreachable on EVERY profile — fresh exists to walk it — and let
// fresh record probes a real fresh host never issues. The answer is gated on
// the modelled account set, exactly like the gpg keyring gate.
func TestRecordingRunnerGatesIDOnModelledAccounts(t *testing.T) {
	ctx := context.Background()
	s := contractServer(t)

	fresh := newRecordingRunner(newFakeHost(t, "fresh", s))
	res, err := fresh.Run(ctx, "id "+s.SiteUser(s.Sites[0]), nil)
	if err != nil || res.ExitCode == 0 {
		t.Errorf("fresh id = (%+v, %v), want exit!=0 and no error — that is how userExists reads absent", res, err)
	}

	conv := newRecordingRunner(newFakeHost(t, "converged", s))
	if res, err = conv.Run(ctx, "id "+s.SiteUser(s.Sites[0]), nil); err != nil || res.ExitCode != 0 {
		t.Errorf("converged id site user = (%+v, %v), want exit 0", res, err)
	}
	if res, err = conv.Run(ctx, "id berth", nil); err != nil || res.ExitCode != 0 {
		t.Errorf("converged id berth = (%+v, %v), want exit 0 — managedAccounts includes it", res, err)
	}
	if res, err = conv.Run(ctx, "id nosuchuser", nil); err != nil || res.ExitCode == 0 {
		t.Errorf("converged id unknown = (%+v, %v), want exit!=0 and no error", res, err)
	}

	// getent stdout is PARSED (userHome splits the passwd row), so a placeholder
	// answer would be a format lie. It must fall to unanswered until Task 5
	// models a real passwd row from evidence.
	if _, err = conv.Run(ctx, "getent passwd "+s.SiteUser(s.Sites[0]), nil); err == nil {
		t.Error("getent must be unanswered — its stdout is parsed, a placeholder masks the parse")
	}
}

// sshd -T is not a validator: sshdEffective PARSES its stdout, and an empty
// answer at exit 0 would read as "every directive missing", driving
// hardening.Check into the misdiagnosis branch and truncating its tail out of
// classification. So the answer is MODELLED, never blind: the hardened
// directives appear exactly when berth's drop-in is byte-converged in the
// model, and a fresh host answers the stock values instead.
func TestRecordingRunnerAnswersOnlyCheckShapedValidators(t *testing.T) {
	s := contractServer(t)
	r := newRecordingRunner(newFakeHost(t, "converged", s))
	ctx := context.Background()

	if res, err := r.Run(ctx, "sshd -t", nil); err != nil || res.ExitCode != 0 {
		t.Errorf("sshd -t = (%+v, %v), want blind success — it is a pure validator", res, err)
	}
	res, err := r.Run(ctx, "sshd -T", nil)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("converged sshd -T = (%+v, %v), want the modelled dump", res, err)
	}
	for _, want := range sshdEffectiveWant {
		if !strings.Contains(res.Stdout, want) {
			t.Errorf("converged sshd -T lacks %q — hardening.Check would misdiagnose an override", want)
		}
	}
	fresh := newRecordingRunner(newFakeHost(t, "fresh", s))
	if res, err = fresh.Run(ctx, "sshd -T", nil); err != nil {
		t.Fatalf("fresh sshd -T: %v", err)
	}
	if strings.Contains(res.Stdout, "permitrootlogin no") {
		t.Error("fresh sshd -T must answer the STOCK values — a hardened dump without the drop-in would bless an unhardened host")
	}
	if _, err := r.Run(ctx, "nginx -s reload", nil); err == nil {
		t.Error("nginx without -t must be unanswered — only the validator shape is blind-answered")
	}
}

// The wave-3 answers must derive from modelled STATE, never canned: a reply
// that ignores the model would mask exactly the branch its profile exists to
// walk. Four pins: the instance-unit listing follows the modelled files, the
// PONG and the information_schema scalar follow the modelled runtime, and the
// value-agreement probe follows its stdin.
func TestRecordingRunnerDerivesWave3AnswersFromState(t *testing.T) {
	ctx := context.Background()
	s := contractServer(t)

	// Instance discovery: fresh has no unit files (ls fails on the literal
	// glob, output empty); converged lists exactly the modelled unit path.
	fresh := newRecordingRunner(newFakeHost(t, "fresh", s))
	if res, err := fresh.Run(ctx, valkeyListUnitsPasted, nil); err != nil || res.ExitCode == 0 || res.Stdout != "" {
		t.Errorf("fresh unit listing = (%+v, %v), want empty at exit!=0", res, err)
	}
	convHost := newFakeHost(t, "converged", s)
	conv := newRecordingRunner(convHost)
	if res, err := conv.Run(ctx, valkeyListUnitsPasted, nil); err != nil || res.Stdout != fixtureValkeyUnitPath+"\n" {
		t.Errorf("converged unit listing = (%+v, %v), want exactly the modelled unit", res, err)
	}

	// The PONG follows the unit's runtime state, not the command shape.
	ping := valkeyPingProbeCmd("appuser", "app_example_com")
	if res, err := conv.Run(ctx, ping, nil); err != nil || res.ExitCode != 0 || !strings.Contains(res.Stdout, "PONG") {
		t.Errorf("active instance ping = (%+v, %v), want PONG at exit 0", res, err)
	}
	down := convHost.units[fixtureValkeyUnit]
	down.active = false
	convHost.units[fixtureValkeyUnit] = down
	if res, err := conv.Run(ctx, ping, nil); err != nil || res.ExitCode == 0 {
		t.Errorf("stopped instance ping = (%+v, %v), want a connect failure", res, err)
	}

	// The scalar probe follows the modelled database set and daemon state.
	if res, err := conv.Run(ctx, mariadbDBExistsProbe("app"), nil); err != nil || strings.TrimSpace(res.Stdout) != "1" {
		t.Errorf("existing database probe = (%+v, %v), want \"1\"", res, err)
	}
	delete(convHost.databases, "app")
	if res, err := conv.Run(ctx, mariadbDBExistsProbe("app"), nil); err != nil || res.ExitCode != 0 || res.Stdout != "" {
		t.Errorf("missing database probe = (%+v, %v), want an empty result set at exit 0", res, err)
	}

	// The agreement probe compares the stdin-borne expectation against the
	// modelled .env: the fixture value matches, any other honestly does not.
	match := envValueMatchProbeCmd(fixtureSharedEnv, "DB_PASSWORD")
	if res, err := conv.Run(ctx, match, []byte("DB_PASSWORD="+fixtureDBValue+"\n")); err != nil || res.ExitCode != 0 {
		t.Errorf("agreeing value = (%+v, %v), want exit 0", res, err)
	}
	if res, err := conv.Run(ctx, match, []byte("DB_PASSWORD=SomethingElse0000000000000000000\n")); err != nil || res.ExitCode != 1 {
		t.Errorf("disagreeing value = (%+v, %v), want exit 1", res, err)
	}
}

// Every standalone show probe today passes --value (valkey.go); answering
// value-only output to a probe WITHOUT it would silently hand Task 5 the wrong
// format, so the shape is refused instead.
func TestRecordingRunnerRejectsValueLessSystemctlShow(t *testing.T) {
	r := newRecordingRunner(newFakeHost(t, "converged", contractServer(t)))
	if _, err := r.Run(context.Background(), "systemctl show -p NeedDaemonReload nginx", nil); err == nil {
		t.Error("show without --value must be unanswered — the answer format is value-only")
	}
}

// recordedCmd is one thing a Check asked the host to do. The stdin is part of
// the record because a program can arrive there rather than in the command
// (`sed -n -f -`), and the classifier must see the pair.
type recordedCmd struct {
	cmd   string
	stdin []byte
}

// recordingRunner is a bssh.Runner over a fakeHost. It answers probes from the
// model, records every (cmd, stdin) pair, and separately RETAINS every command
// it could not answer — the contract asserts that list is empty regardless of
// what the Check returned, because a Check may swallow a probe error.
type recordingRunner struct {
	h       *fakeHost
	rec     []recordedCmd
	unknown []string
	written []bssh.FileSpec
}

func newRecordingRunner(h *fakeHost) *recordingRunner { return &recordingRunner{h: h} }

func (r *recordingRunner) recorded() []recordedCmd { return r.rec }
func (r *recordingRunner) unanswered() []string    { return r.unknown }
func (r *recordingRunner) writes() []bssh.FileSpec { return r.written }

// WriteFile records the attempt and changes nothing: a Check calling this is
// itself a violation, so there is no state to update.
func (r *recordingRunner) WriteFile(_ context.Context, f bssh.FileSpec) error {
	r.written = append(r.written, f)
	return nil
}

func (r *recordingRunner) Run(_ context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	r.rec = append(r.rec, recordedCmd{cmd: cmd, stdin: stdin})
	res, ok := r.answer(cmd, stdin)
	if !ok {
		r.unknown = append(r.unknown, cmd)
		return bssh.Result{}, fmt.Errorf("fake host cannot answer: %s", cmd)
	}
	return res, nil
}

// unq strips the quoting shQuote adds so the model can be keyed on plain paths.
func unq(s string) string { return strings.Trim(s, "'\"") }

// answer maps one command shape onto the model, returning ok=false for a shape
// it does not know. Task 5 extends this; keep every addition narrow — answering
// "any unknown command succeeds" would destroy the contract's value. stdin is
// consulted only by the shapes whose script actually reads it (the database
// value-agreement probes' `IFS= read -r want`).
func (r *recordingRunner) answer(cmd string, stdin []byte) (bssh.Result, bool) {
	// The locale pin berth's parse-sensitive probes carry
	// (assertSiteTreeOwners, assertGroupMembership). The assignment changes
	// output language only, so the answer is the pinned command's; only this
	// exact token is stripped, mirroring the classifier's rule.
	if rest, ok := strings.CutPrefix(cmd, "LC_ALL=C "); ok {
		return r.answer(rest, stdin)
	}
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return bssh.Result{}, false
	}
	switch {
	// preflight's codename probe, keyed to the production const so the model
	// can never drift from the shape the step issues. The Check PARSES the
	// matching line (TrimPrefix "VERSION_CODENAME=", strip one quote layer),
	// so the answer must be real grep semantics over the modelled file: the
	// first matching line at exit 0, exit 1 on no match, exit 2 when the file
	// itself is missing.
	case cmd == osReleaseCodenameCmd:
		file, ok := r.h.files["/etc/os-release"]
		if !ok {
			return bssh.Result{ExitCode: 2, Stderr: "grep: /etc/os-release: No such file or directory"}, true
		}
		for _, line := range strings.Split(file.content, "\n") {
			if strings.HasPrefix(line, "VERSION_CODENAME=") {
				return bssh.Result{Stdout: line + "\n"}, true
			}
		}
		return bssh.Result{ExitCode: 1}, true

	// The apt step's sweep discovery, keyed to the production const. Answered
	// from the model (never canned): the matching paths, NUL-separated the way
	// find -print0 emits them — discoverUserLists PARSES this by splitting on
	// \x00. find exits 0 with empty output when nothing matches, so an empty
	// namespace is data, not an error.
	case cmd == aptUserListsCmd:
		var out strings.Builder
		for _, p := range r.h.aptUserLists() {
			out.WriteString(p)
			out.WriteByte(0)
		}
		return bssh.Result{Stdout: out.String()}, true

	case f[0] == "cat" && len(f) == 2:
		if file, ok := r.h.files[unq(f[1])]; ok {
			return bssh.Result{Stdout: file.content}, true
		}
		return bssh.Result{ExitCode: 1, Stderr: "No such file or directory"}, true

	case f[0] == "test" && len(f) == 3:
		file, ok := r.h.files[unq(f[2])]
		pass := false
		switch f[1] {
		case "-e":
			pass = ok
		case "-d":
			pass = ok && file.kind == "directory"
		case "-f":
			pass = ok && file.kind == "regular file"
		case "-L":
			pass = ok && file.linkTarget != ""
		default:
			return bssh.Result{}, false
		}
		if pass {
			return bssh.Result{}, true
		}
		return bssh.Result{ExitCode: 1}, true

	// swapfileSize's probe (system.go), keyed to the pasted literal in
	// auditedScripts and answered from the modelled file size — the only
	// consumer of fakeFile.size. A missing swapfile answers exit 1 with the
	// diagnostic already discarded by the probe's own 2>/dev/null. This case
	// must sit ABOVE the generic stat case: the Fields-parse there would
	// take "2>/dev/null" for the path and answer from the wrong entry.
	case cmd == swapfileSizeProbePasted:
		file, ok := r.h.files[swapfilePath]
		if !ok {
			return bssh.Result{ExitCode: 1}, true
		}
		return bssh.Result{Stdout: strconv.FormatInt(file.size, 10) + "\n"}, true

	case f[0] == "stat":
		file, ok := r.h.files[unq(f[len(f)-1])]
		if !ok {
			return bssh.Result{ExitCode: 1, Stderr: "No such file or directory"}, true
		}
		// The mode is emitted verbatim: fakeFile.mode holds what `stat -c %a`
		// prints (no leading zero), and berth compares this raw stdout against
		// literals like "root:root 755" (statOwnerMode) — do not normalize.
		switch {
		case strings.Contains(cmd, "%U %u %F"):
			return bssh.Result{Stdout: fmt.Sprintf("%s %d %s\n", file.owner, file.uid, file.kind)}, true
		case strings.Contains(cmd, "%U:%G %a"):
			return bssh.Result{Stdout: fmt.Sprintf("%s:%s %s\n", file.owner, file.group, file.mode)}, true
		case strings.Contains(cmd, "%Y"):
			return bssh.Result{Stdout: fmt.Sprintf("%d\n", file.mtimeUnix)}, true
		}
		return bssh.Result{}, false

	case f[0] == "dpkg" && len(f) == 3 && f[1] == "-s":
		if status, ok := r.h.packages[f[2]]; ok {
			return bssh.Result{Stdout: "Package: " + f[2] + "\n" + status + "\n"}, true
		}
		return bssh.Result{ExitCode: 1}, true

	case f[0] == "systemctl" && len(f) >= 3 && (f[1] == "is-active" || f[1] == "is-enabled"):
		u, ok := r.h.unit(f[len(f)-1])
		if !ok {
			// An ABSENT unit and an INACTIVE unit must both answer non-zero:
			// serviceUp and serviceActive read only the exit code, and an absent
			// unit must never read as up.
			return bssh.Result{ExitCode: 4, Stdout: "\n"}, true
		}
		state, word := u.active, "active"
		if f[1] == "is-enabled" {
			state, word = u.enabled, "enabled"
		}
		if !state {
			return bssh.Result{ExitCode: 3, Stdout: "in" + word + "\n"}, true
		}
		return bssh.Result{Stdout: word + "\n"}, true

	// Gated on --value because the answer IS value-only: every standalone show
	// probe today passes it (valkey.go), and answering a value-less probe in
	// this format would silently hand it the wrong shape rather than an honest
	// "cannot answer".
	case f[0] == "systemctl" && len(f) >= 4 && f[1] == "show" && hasExact(f, "--value"):
		u, ok := r.h.unit(f[len(f)-1])
		if !ok {
			return bssh.Result{ExitCode: 4}, true
		}
		for k, v := range u.props {
			if hasExact(f, "-p") && hasExact(f, k) {
				return bssh.Result{Stdout: v + "\n"}, true
			}
		}
		// An unmodelled property is NOT blank success: that would let a Check
		// take a branch the model never modelled.
		return bssh.Result{}, false

	case f[0] == "command" && len(f) == 3 && f[1] == "-v":
		if r.h.tools[f[2]] {
			return bssh.Result{Stdout: "/usr/bin/" + f[2] + "\n"}, true
		}
		return bssh.Result{ExitCode: 1}, true

	// userExists reads ONLY the exit code of a bare `id <user>`, so the answer
	// is gated on the modelled account set: a blanket exit 0 made the
	// "account missing" early return unreachable on every profile, and fresh
	// exists to walk it. Absent is exit 1, data — not a Go error. No stdout is
	// modelled: nobody parses it (`LC_ALL=C id -nG …` is stripped of its
	// locale pin and answered by the group-membership case below). getent is
	// deliberately NOT answered here — userHome PARSES its passwd row, so
	// Task 5 must model a real row from evidence.
	case f[0] == "id" && len(f) == 2:
		if r.h.users[f[1]] {
			return bssh.Result{}, true
		}
		return bssh.Result{ExitCode: 1, Stderr: "id: '" + f[1] + "': no such user"}, true

	// assertGroupMembership (accounts.go) PARSES the space-separated group
	// names looking for the account's eponymous group. useradd -m creates
	// exactly that group, so a modelled account's membership is its own name —
	// and nothing more, so a Check requiring some OTHER group would honestly
	// fail rather than be masked. Absent accounts answer exit 1, the same gate
	// as the bare `id` above.
	case f[0] == "id" && len(f) == 3 && f[1] == "-nG":
		u := unq(f[2])
		if r.h.users[u] {
			return bssh.Result{Stdout: u + "\n"}, true
		}
		return bssh.Result{ExitCode: 1, Stderr: "id: '" + u + "': no such user"}, true

	// hardening.Check PARSES this stdout twice: strings.Contains for
	// "Status: active" and the 443/udp QUIC rule regexp. Provisioned profiles
	// answer the enabled ruleset berth writes; a host without the package
	// answers the way a shell does — exit 127, which the Check reads as
	// "not active" data.
	case cmd == "ufw status":
		if _, ok := r.h.packages["ufw"]; !ok {
			return bssh.Result{ExitCode: 127, Stderr: "sh: 1: ufw: not found"}, true
		}
		return bssh.Result{Stdout: "Status: active\n\n" +
			"To                         Action      From\n" +
			"--                         ------      ----\n" +
			"22/tcp                     ALLOW       Anywhere\n" +
			"80,443/tcp                 ALLOW       Anywhere\n"}, true

	// consolePasswordUsable (accounts.go) PARSES field 2 of the status line:
	// P (usable), L (locked), NP (none) — anything else is a hard error there.
	// A provisioned account whose password berth never set is locked, which is
	// useradd's default and the fixture's break_glass-off posture. Reached
	// only for existing accounts: accounts.Check early-returns on a missing
	// account long before the console probe.
	case f[0] == "passwd" && len(f) == 3 && f[1] == "-S":
		if r.h.users[f[2]] {
			return bssh.Result{Stdout: f[2] + " L 07/30/2026 0 99999 7 -1\n"}, true
		}
		return bssh.Result{ExitCode: 252, Stderr: "passwd: user '" + f[2] + "' does not exist"}, true

	case f[0] == "df":
		return bssh.Result{Stdout: r.h.dfRows}, true

	// The three system-knob queries, each pinned to the ONE argv its Check
	// issues (swapActive / checkTimezone / checkHostname, system.go) because
	// each PARSES the answer: swapActive scans for a line that IS the bare
	// path (the --show=NAME --noheadings format — no header, no columns),
	// the other two TrimSpace a single value. Answering a different spelling
	// in these formats would hand a production drift the wrong shape, so it
	// falls to unanswered.
	case cmd == "swapon --show=NAME --noheadings":
		return bssh.Result{Stdout: r.h.swapRows}, true
	case cmd == "timedatectl show -p Timezone --value":
		return bssh.Result{Stdout: r.h.timezone + "\n"}, true
	case cmd == "hostnamectl --static":
		return bssh.Result{Stdout: r.h.hostname + "\n"}, true

	// checkSysctl's read-back of the RUNNING kernel values (string-compared,
	// one bare value line). Answered only for modelled keys: an unmodelled
	// key is a modelling gap, not blank success.
	case f[0] == "sysctl" && len(f) == 3 && f[1] == "-n":
		if v, ok := r.h.sysctlValues[f[2]]; ok {
			return bssh.Result{Stdout: v + "\n"}, true
		}
		return bssh.Result{}, false

	case f[0] == "gpg":
		// Only the EXACT argv KeyringHoldsExactly issues (apt.go) is answered;
		// any other gpg spelling falls to unanswered. Answering every
		// gpg-shaped command with the colon output would keep the contract
		// green while a production drift — dropping --with-colons, say —
		// changed the real format under the parser.
		if len(f) != 8 || cmd != "gpg --no-options --no-keyring --trust-model always --show-keys --with-colons "+f[7] {
			return bssh.Result{}, false
		}
		// gpgKeys is populated for ALL profiles including fresh, so answering
		// unconditionally would make a keyring-less host look converged and
		// mask KeyringHoldsExactly's absent-keyring branch. The keyring path is
		// the probe's last argument; when it is not in the model, answer the
		// way real gpg does — a non-zero exit, which the probe reads as "not
		// converged" data, never a Go error.
		if _, ok := r.h.files[unq(f[7])]; !ok {
			return bssh.Result{ExitCode: 2, Stderr: "gpg: can't open: No such file or directory"}, true
		}
		return bssh.Result{Stdout: r.h.gpgKeys}, true

	// The generated read scripts wave 2 audited, each keyed to the exact text
	// the fixture produces (the same test-local generators the registry uses)
	// and answered from the model, never canned.

	// assertPHPVersionExclusive PARSES 'M <path>' / 'S <path>' lines. The scan
	// stays live rather than answering a canned empty: a future profile that
	// models another version's pool changes the answer instead of being masked.
	case cmd == phpPoolConflictProbe84:
		return r.answerPHPPoolConflicts("8.4"), true

	// AssertRootControlledAncestry PARSES '%n %u %a %F' lines for the
	// components that exist; absent ones are skipped, like the real script.
	case cmd == ancestryProbeCmd(accountsAncestry...):
		return r.answerAncestry(accountsAncestry), true
	case cmd == ancestryProbeCmd(appdirsAncestry...):
		return r.answerAncestry(appdirsAncestry), true

	// noSymlinkInPath reads ONLY the exit code: every existing component must
	// be a real directory (a symlink or other type answers 1).
	case cmd == noSymlinkWalkCmd(fixtureDeployTreeTail):
		return r.answerNoSymlinkWalk(fixtureDeployTreeTail), true
	case cmd == noSymlinkWalkCmd(fixtureACMEWebroot):
		return r.answerNoSymlinkWalk(fixtureACMEWebroot), true

	// assertOwnSSHDir PARSES '%U %F' when the entry exists and reads exit 92
	// as its own "absent" signal.
	case cmd == sshDirProbeCmd("/home/berth/.ssh"):
		return r.answerSSHDirProbe("/home/berth/.ssh"), true
	case cmd == sshDirProbeCmd("/home/appuser/.ssh"):
		return r.answerSSHDirProbe("/home/appuser/.ssh"), true

	// accounts.Check's git known-host lookup, keyed to the exact fixture
	// composition and answered with real ssh-keygen -F semantics over the
	// modelled file (the caller reads ONLY the exit code — both streams aim
	// at the null device): 0 iff some line's host field carries the token,
	// 1 on a present file without it, 255 when the file itself is missing.
	case cmd == sshKnownHostProbeCmd(fixtureGitHost, fixtureKnownHostsPath):
		return r.answerKnownHostLookup(fixtureGitHost, fixtureKnownHostsPath), true

	// sshdOptsGuard PARSES the file body for the last SSHD_OPTS assignment;
	// keyed to the production const so the model tracks the issued shape. A
	// missing file is exit 0 with no output — the probe's own semantics
	// (`test ! -e` short-circuits the cat).
	case cmd == sshdOptsProbe:
		if file, ok := r.h.files["/etc/default/ssh"]; ok {
			return bssh.Result{Stdout: file.content}, true
		}
		return bssh.Result{}, true

	// sshdEffective PARSES this dump (lowercase "key value" lines, first-match
	// semantics). The effective values derive from the modelled sshd state:
	// berth's drop-in is the only auth-directive source the model knows, so
	// exactly when it is byte-converged do the hardened values hold; otherwise
	// the stock Debian defaults answer, so a misconverged host honestly lacks
	// the directives instead of being blessed.
	case cmd == "sshd -T":
		lines := []string{"port 22", "addressfamily any", "pubkeyauthentication yes"}
		if file, ok := r.h.files[sshdDropInPath]; ok && file.content == sshdDropInBody {
			lines = append(lines, "permitrootlogin no", "passwordauthentication no", "kbdinteractiveauthentication no")
		} else {
			lines = append(lines, "permitrootlogin prohibit-password", "passwordauthentication yes", "kbdinteractiveauthentication yes")
		}
		return bssh.Result{Stdout: strings.Join(lines, "\n") + "\n"}, true

	// reloadedSince (reloadstamp.go) reads ONLY the exit code of its stamp
	// existence + mtime chain. Recognized by strict parse-and-reconstruct, so
	// only the production shape is ever answered; evaluated from the model's
	// mtimes with real `-nt` semantics (an absent path is never newer).
	case strings.HasPrefix(cmd, "[ -e '"):
		stamp, paths, ok := parseReloadedSince(cmd)
		if !ok {
			return bssh.Result{}, false
		}
		st, present := r.h.files[stamp]
		if !present {
			return bssh.Result{ExitCode: 1}, true
		}
		for _, p := range paths {
			if file, ok := r.h.files[p]; ok && file.mtimeUnix > st.mtimeUnix {
				return bssh.Result{ExitCode: 1}, true
			}
		}
		return bssh.Result{}, true

	// The wave-3 generated read scripts, each keyed to the exact text the
	// fixture produces (the same test-local mirrors the registry uses) and
	// answered from the model, never canned.

	// listValkeyUnits PARSES the ls output line by line. Answered from a live
	// scan of the model; when nothing matches, the shell hands ls the literal
	// glob and ls fails on it — exit 2, diagnostics discarded by the script's
	// own 2>/dev/null, empty stdout.
	case cmd == valkeyListUnitsPasted:
		var units []string
		for p := range r.h.files {
			if strings.HasPrefix(p, "/etc/systemd/system/berth-valkey-") && strings.HasSuffix(p, ".service") {
				units = append(units, p)
			}
		}
		if len(units) == 0 {
			return bssh.Result{ExitCode: 2}, true
		}
		slices.Sort(units)
		return bssh.Result{Stdout: strings.Join(units, "\n") + "\n"}, true

	// valkeyExecCurrent reads ONLY the exit code: 0 iff the instance's
	// process still executes the current binary.
	case cmd == valkeyExecProbeCmd(fixtureValkeyUnit):
		return r.answerValkeyExec(fixtureValkeyUnit), true

	// valkeyPong PARSES stdout (trimmed "PONG") AND the exit code.
	case cmd == valkeyPingProbeCmd("appuser", "app_example_com"):
		if u, ok := r.h.unit(fixtureValkeyUnit); ok && u.active {
			return bssh.Result{Stdout: "PONG\n"}, true
		}
		return bssh.Result{ExitCode: 1, Stderr: "Could not connect to Valkey"}, true

	// serviceConfigLoaded reads ONLY the exit code of its mtime-vs-activation
	// integer comparison.
	case cmd == serviceLoadedProbeCmd(fixtureMariaDBTuning, "mariadb.service"):
		return r.answerServiceLoaded(fixtureMariaDBTuning, "mariadb.service"), true
	case cmd == serviceLoadedProbeCmd(fixtureValkeyUnitPath, fixtureValkeyUnit):
		return r.answerServiceLoaded(fixtureValkeyUnitPath, fixtureValkeyUnit), true

	// hostMemTotalBytes PARSES the kB figure (ParseUint), so the answer is a
	// bare integer line from the modelled RAM size.
	case cmd == memTotalPasted:
		return bssh.Result{Stdout: strconv.FormatInt(r.h.memTotalKB, 10) + "\n"}, true

	// probeSQL PARSES stdout (trimmed "1") and the exit code. Answered from
	// the modelled database/grant sets; an empty result set is exit 0 with no
	// output, exactly what mysql -N -e prints.
	case cmd == mariadbDBExistsProbe("app"):
		return r.answerMySQLScalar(r.h.databases["app"]), true
	case cmd == mariadbUserGrantedProbe("app", "app"):
		return r.answerMySQLScalar(r.h.dbGrants["app:app"]), true

	// envCredentialPresent / envHasBerthAppKey / envValueMatches read ONLY
	// exit codes (the secret never enters stdout); evaluated over the
	// modelled .env with each script's own exit map, the value-agreement one
	// consuming its expected line from stdin the way `IFS= read -r want`
	// does.
	case cmd == envCredentialProbeCmd(fixtureSharedEnv):
		return r.answerEnvCredential(fixtureSharedEnv), true
	case cmd == envAppKeyProbeCmd(fixtureSharedEnv):
		return r.answerEnvAppKey(fixtureSharedEnv), true
	case cmd == envValueMatchProbeCmd(fixtureSharedEnv, "DB_PASSWORD"):
		return r.answerEnvValueMatch(fixtureSharedEnv, "DB_PASSWORD", stdin), true
	case cmd == envValueMatchProbeCmd(fixtureSharedEnv, "APP_KEY"):
		return r.answerEnvValueMatch(fixtureSharedEnv, "APP_KEY", stdin), true

	// envDBConnection PARSES the first KEY= line of grep's stdout (and
	// Apply's passwordFromEnv/appKeyFromEnv share the shape). Real grep
	// semantics over the model: first matching line at exit 0, exit 1 on no
	// match, exit 2 when the file is missing. Guarded by reconstruction and a
	// plain-identifier key so a pattern with real regex syntax is never
	// prefix-matched by mistake.
	case f[0] == "grep" && len(f) == 4 && f[1] == "-m1" &&
		strings.HasPrefix(f[2], "'^") && strings.HasSuffix(f[2], "='"):
		key := strings.TrimSuffix(strings.TrimPrefix(f[2], "'^"), "='")
		path := unq(f[3])
		if !reEnvIdentKey.MatchString(key) || cmd != "grep -m1 '^"+key+"=' "+shQuote(path) {
			return bssh.Result{}, false
		}
		file, ok := r.h.files[path]
		if !ok {
			return bssh.Result{ExitCode: 2, Stderr: "grep: " + path + ": No such file or directory"}, true
		}
		if line, found := firstEnvLine(file.content, key); found {
			return bssh.Result{Stdout: line + "\n"}, true
		}
		return bssh.Result{ExitCode: 1}, true

	// The wave-4 generated read scripts and probes (site, tls, backups),
	// each keyed to the exact fixture composition and answered from the
	// model, never canned.

	// listSupervisorPrograms PARSES the ls output line by line; same ls-glob
	// semantics as the valkey listing (no match: ls fails on the literal
	// glob at exit 2, diagnostics eaten by the script's own 2>/dev/null).
	case cmd == supervisorListPasted:
		return r.answerLsGlob("/etc/supervisor/conf.d/berth-", ".conf"), true
	case cmd == backupScriptListPasted:
		return r.answerLsGlob("/usr/local/sbin/berth-backup-", ""), true
	case cmd == backupCronListPasted:
		return r.answerLsGlob("/etc/cron.d/berth-backup-", ""), true
	case cmd == backupManifestListPasted:
		return r.answerLsGlob("/var/backups/berth/", "/manifest"), true

	// commandExists reads ONLY the exit code (both streams aim at the null
	// device). Recognized by reconstruction so only the production shape is
	// answered; gated on the modelled tool set like the bare `command -v`.
	case len(f) == 5 && f[0] == "command" && f[1] == "-v" && cmd == commandVProbeCmd(f[2]):
		if r.h.tools[f[2]] {
			return bssh.Result{}, true
		}
		return bssh.Result{ExitCode: 1}, true

	// findRegularFiles / findDirectories / listRenewalConfs all PARSE the
	// find output line by line. Answered from a live scan of the model with
	// the scripts' own semantics: a missing directory is the [ -d ]-guarded
	// quiet empty (exit 0, no output), matches are the immediate children of
	// the directory filtered by type and name.
	case cmd == findRegularProbeCmd("/etc/nginx/sites-available", ""):
		return r.answerFindRegular("/etc/nginx/sites-available", ""), true
	case cmd == findRegularProbeCmd("/etc/php/8.4/fpm/pool.d", "*.conf"):
		return r.answerFindRegular("/etc/php/8.4/fpm/pool.d", "*.conf"), true
	case cmd == findRegularProbeCmd("/etc/cron.d", "berth-site-*"):
		return r.answerFindRegular("/etc/cron.d", "berth-site-*"), true
	case cmd == findDirsProbeCmd(fixtureACMEWebrootBase):
		return r.answerFindDirs(fixtureACMEWebrootBase), true
	case cmd == findDirsProbeCmd("/etc/ssl/berth"):
		return r.answerFindDirs("/etc/ssl/berth"), true
	case cmd == renewalConfListPasted:
		return r.answerFindNamed("/etc/letsencrypt/renewal", ".conf"), true

	// certStatus PARSES `certbot certificates` output (parseCertStatus reads
	// the Certificate Name / Domains / Expiry Date block). The answer derives
	// from the modelled lineage set — every /etc/letsencrypt/live/<domain>/
	// fullchain.pem — and the modelled expiry; a host without the certbot
	// package answers the way a shell does (exit 127), which certStatus
	// reads as "no certificate" data.
	case cmd == "certbot certificates":
		return r.answerCertbotCertificates(), true

	// site.Check's enabled-symlink probe reads ONLY the exit code of the
	// [ … -ef … ] inode comparison. Recognized by reconstruction; evaluated
	// by resolving both sides through the modelled symlinks.
	case len(f) == 5 && f[0] == "[" && f[2] == "-ef" && f[4] == "]" &&
		cmd == "[ "+shQuote(unq(f[1]))+" -ef "+shQuote(unq(f[3]))+" ]":
		return r.answerSameFile(unq(f[1]), unq(f[3])), true

	// site.Check PARSES supervisorctl's stdout+stderr for "no such" only —
	// the loaded/not-loaded distinction is the whole verdict. Loaded derives
	// from the model: the program's conf file exists and supervisord runs.
	// No profile models the on-disk-but-never-reread state, so that branch
	// stays unexercised (same documented limit as the valkey stale-binary
	// branch). A loaded-but-dormant worker answers STOPPED at exit 3 —
	// supervisorctl's real exit for a non-RUNNING program, which the Check
	// ignores.
	case len(f) == 3 && f[0] == "supervisorctl" && f[1] == "status" &&
		strings.HasSuffix(unq(f[2]), ":*") &&
		cmd == "supervisorctl status "+shQuote(unq(f[2])):
		prog := strings.TrimSuffix(unq(f[2]), ":*")
		conf, ok := r.h.files["/etc/supervisor/conf.d/"+prog+".conf"]
		sup, supOK := r.h.unit("supervisor")
		if ok && conf.kind == "regular file" && supOK && sup.active {
			return bssh.Result{ExitCode: 3, Stdout: prog + ":" + prog + "_00" + strings.Repeat(" ", 8) + "STOPPED   Not started\n"}, true
		}
		return bssh.Result{ExitCode: 4, Stdout: unq(f[2]) + ": ERROR (no such group)\n"}, true

	// Validators just need to succeed so the Check continues. Whether ISSUING
	// them is allowed is the classifier's judgement, not the model's. Only the
	// exact check-only shapes are answered blindly: `sshd -T` in particular is
	// NOT a validator — sshdEffective parses its stdout, so it is answered
	// from the modelled drop-in state above, never blindly.
	// hasExact is case-sensitive, so -T never matches -t and falls through.
	case f[0] == "nginx" && hasExact(f, "-t"),
		strings.HasPrefix(f[0], "php-fpm") && hasExact(f, "-t"),
		f[0] == "sshd" && hasExact(f, "-t"),
		f[0] == "visudo" && hasExact(f, "-cf"),
		f[0] == "logrotate" && hasExact(f, "-d"),
		f[0] == "fail2ban-client" && hasExact(f, "-t"):
		return bssh.Result{}, true
	}
	return bssh.Result{}, false
}

// The fixture paths the wave-2 generated scripts walk, and the component lists
// the two ancestry probes cover — spelled once so the answer cases and the
// audited-script keys cannot drift apart.
const (
	fixtureDeployTreeTail  = "/var/www/app.example.com/shared/tmp"
	fixtureACMEWebroot     = "/var/www/berth-acme/app.example.com"
	fixtureACMEWebrootBase = "/var/www/berth-acme"

	// Wave 3: the paths and identities the valkey/tuning/database probes are
	// keyed on, plus the two secret VALUES the fixture treats as already
	// provisioned — they appear in the modelled shared/.env, in the seeded
	// local secret cache and in the audited stdin pairs, and all three must
	// agree or database.Check honestly reports disagreement.
	fixtureSharedEnv      = "/var/www/app.example.com/shared/.env"
	fixtureValkeyUnit     = "berth-valkey-app_example_com.service"
	fixtureValkeyUnitPath = "/etc/systemd/system/berth-valkey-app_example_com.service"
	fixtureMariaDBTuning  = "/etc/mysql/mariadb.conf.d/99-berth.cnf"
	// The fixture site's DB password: 32 alphanumeric chars, the exact shape
	// secret.Generate produces and reDBPassword accepts. The identifier and
	// value deliberately avoid gosec G101's name heuristics — this is
	// test-fixture data, not a credential.
	fixtureDBValue = "Fixture0DBvalue0Fixture0DBvalue0"
	// "base64:" + 43 chars of [A-Za-z0-9+/] + "=" — the exact berth APP_KEY
	// shape (appKeyShape); a malformed value here would fail the database
	// step's cache preflight loudly, so the shape is self-checking.
	fixtureAppKey = "base64:Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1C="

	// The fixture repository's endpoint pieces (maximal variant): the git
	// host GitEndpoint parses out of sites[0].repository, and the site
	// user's known_hosts path accounts.Check composes for the -F lookup.
	fixtureGitHost        = "git.example.com"
	fixtureKnownHostsPath = "/home/appuser/.ssh/known_hosts"

	// Wave 4: the offsite secret trio, seeded into the cache AND rendered
	// into the modelled /etc/berth/offsite.env (they must agree, or
	// offsite.Check honestly reports drift). fixtureResticValue is 32
	// alphanumerics — the exact shape the step's own secret.Generate seeding
	// produces; the s3 pair is operator-supplied, so any single-line
	// quote-free value is faithful. Identifiers and values deliberately
	// avoid gosec G101's name heuristics — test-fixture data, not
	// credentials.
	fixtureResticValue   = "Fixture0Restic0value0Fixture0000"
	fixtureOffsiteKeyID  = "Fixture0OffsiteKeyID0Fixture0000"
	fixtureOffsiteKeyVal = "Fixture0OffsiteKeyVal0Fixture000"
)

var (
	accountsAncestry = []string{"/", "/home"}
	appdirsAncestry  = []string{"/", "/var", "/var/www", "/var/www/berth-acme"}
)

// rePoolListen mirrors the listen-directive match inside
// phpPoolConflictProbeCmd's grep -Eq, in Go regexp form.
var rePoolListen = regexp.MustCompile(`(?m)^[ \t]*listen[ \t]*=[ \t]*"?/run/php/berth-`)

// answerPHPPoolConflicts evaluates the pool-conflict probe over the model:
// every pool.d conf of a version other than the configured one, classified
// 'M' (berth's INI marker as the first line) or 'S' (a foreign file bound to
// a berth socket), in sorted order because the real glob expands sorted.
func (r *recordingRunner) answerPHPPoolConflicts(version string) bssh.Result {
	var pools []string
	for p := range r.h.files {
		if strings.HasPrefix(p, "/etc/php/") && strings.Contains(p, "/fpm/pool.d/") &&
			strings.HasSuffix(p, ".conf") && !strings.HasPrefix(p, "/etc/php/"+version+"/") {
			pools = append(pools, p)
		}
	}
	slices.Sort(pools)
	var out strings.Builder
	for _, p := range pools {
		first, _, _ := strings.Cut(r.h.files[p].content, "\n")
		switch {
		case first == managedMarkerINI:
			fmt.Fprintf(&out, "M %s\n", p)
		case rePoolListen.MatchString(r.h.files[p].content):
			fmt.Fprintf(&out, "S %s\n", p)
		}
	}
	return bssh.Result{Stdout: out.String()}
}

// answerAncestry emits one '%n %u %a %F' line per component that exists in
// the model, skipping absent ones — the production script's exact behavior.
func (r *recordingRunner) answerAncestry(paths []string) bssh.Result {
	var out strings.Builder
	for _, p := range paths {
		if file, ok := r.h.files[p]; ok {
			fmt.Fprintf(&out, "%s %d %s %s\n", p, file.uid, file.mode, file.kind)
		}
	}
	return bssh.Result{Stdout: out.String()}
}

// answerNoSymlinkWalk evaluates the brace-group walk: exit 1 when any
// EXISTING component is a symlink or not a directory, 0 otherwise (absent
// components pass — a fresh path is created normally).
func (r *recordingRunner) answerNoSymlinkWalk(p string) bssh.Result {
	cur := ""
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		cur += "/" + part
		if file, ok := r.h.files[cur]; ok && (file.linkTarget != "" || file.kind != "directory") {
			return bssh.Result{ExitCode: 1}
		}
	}
	return bssh.Result{}
}

// answerSSHDirProbe evaluates assertOwnSSHDir's probe: exit 92 for a
// genuinely absent entry, otherwise the '%U %F' pair the guard parses.
func (r *recordingRunner) answerSSHDirProbe(dir string) bssh.Result {
	file, ok := r.h.files[dir]
	if !ok {
		return bssh.Result{ExitCode: 92}
	}
	return bssh.Result{Stdout: file.owner + " " + file.kind + "\n"}
}

// answerKnownHostLookup evaluates ssh-keygen -F over the modelled file: a
// known_hosts host field is a comma-separated list of tokens, and the find
// mode matches a whole token (never a substring). A missing file is exit 255
// — ssh-keygen's own usage-error exit, distinct from the not-found 1; the
// consumer treats every non-zero alike (accounts.go: "either way Apply
// re-scans"), so the distinction costs nothing and stays honest.
func (r *recordingRunner) answerKnownHostLookup(token, path string) bssh.Result {
	file, ok := r.h.files[path]
	if !ok {
		return bssh.Result{ExitCode: 255}
	}
	for _, line := range strings.Split(file.content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if slices.Contains(strings.Split(fields[0], ","), token) {
			return bssh.Result{}
		}
	}
	return bssh.Result{ExitCode: 1}
}

// mariadbDBExistsProbe / mariadbUserGrantedProbe mirror probeSQL's
// composition over DatabaseExists/UserGranted (internal/database/mariadb.go)
// — copies on purpose, so a production probe change makes the answer fall
// away loudly instead of feeding the new shape a stale reply.
func mariadbDBExistsProbe(db string) string {
	return `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='` + db + `'"`
}

func mariadbUserGrantedProbe(user, db string) string {
	return `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='` + db + `' AND GRANTEE='''` + user + `''@''localhost''' LIMIT 1"`
}

// valkeyPingProbeCmd mirrors valkeyPingCmd's composition (valkey.go) — a copy
// on purpose (see above).
func valkeyPingProbeCmd(user, pool string) string {
	qu := shQuote(user)
	return "setpriv --reuid " + qu + " --regid " + qu + " --init-groups -- valkey-cli -s " +
		shQuote("/run/berth-valkey/"+pool+"/valkey.sock") + " ping"
}

// answerMySQLScalar evaluates a probeSQL query whose modelled truth is hit:
// mysql prints "1" for a matching row, nothing for an empty result set, both
// at exit 0 — but only while the server package is present and the daemon
// runs; a stopped daemon answers the client's connect error.
func (r *recordingRunner) answerMySQLScalar(hit bool) bssh.Result {
	if _, ok := r.h.packages["mariadb-server"]; !ok {
		return bssh.Result{ExitCode: 127, Stderr: "sh: 1: mysql: not found"}
	}
	if u, ok := r.h.unit("mariadb.service"); !ok || !u.active {
		return bssh.Result{ExitCode: 1, Stderr: "ERROR 2002 (HY000): Can't connect to local server"}
	}
	if hit {
		return bssh.Result{Stdout: "1\n"}
	}
	return bssh.Result{}
}

// answerValkeyExec evaluates valkeyExecCmd: exit 0 iff the unit runs (has a
// MainPID) and the packaged binary path resolves — through the modelled
// valkey-server → valkey-check-rdb symlink, the way stat -L does — to a real
// file. No profile models a replaced-binary state today, so a healthy
// instance answers current and everything else answers stale.
func (r *recordingRunner) answerValkeyExec(unit string) bssh.Result {
	u, ok := r.h.unit(unit)
	if !ok || !u.active || u.props["MainPID"] == "" {
		return bssh.Result{ExitCode: 1}
	}
	path := "/usr/bin/valkey-server"
	for range 4 { // bounded symlink walk; the model has no loops on purpose
		f, ok := r.h.files[path]
		if !ok {
			return bssh.Result{ExitCode: 1}
		}
		if f.linkTarget == "" {
			if f.kind != "regular file" {
				return bssh.Result{ExitCode: 1}
			}
			return bssh.Result{}
		}
		path = f.linkTarget
	}
	return bssh.Result{ExitCode: 1}
}

// answerServiceLoaded evaluates serviceConfigLoaded's integer comparison from
// the model: file mtime vs the unit's ActiveEnterTimestamp (the "@<epoch>"
// form `--timestamp=unix` prints, whose @ the script's tr strips). A missing
// file or an empty timestamp leaves [ with a non-integer operand — exit 2,
// which the production reader treats as "not loaded".
func (r *recordingRunner) answerServiceLoaded(path, unit string) bssh.Result {
	file, fok := r.h.files[path]
	u, uok := r.h.unit(unit)
	ts, terr := strconv.ParseInt(strings.TrimPrefix(u.props["ActiveEnterTimestamp"], "@"), 10, 64)
	if !fok || !uok || terr != nil {
		return bssh.Result{ExitCode: 2, Stderr: "sh: 1: [: Illegal number:"}
	}
	if file.mtimeUnix <= ts {
		return bssh.Result{}
	}
	return bssh.Result{ExitCode: 1}
}

// answerLsGlob evaluates one `ls -1 <glob> 2>/dev/null` discovery over the
// model: paths matching prefix + one non-empty starred segment + suffix (see
// globStarSegment for how the segment rules compare to a real shell's). No
// match answers the way the shell does: ls receives the literal unexpanded
// glob and fails on it (exit 2, diagnostics eaten by the script's own
// 2>/dev/null).
func (r *recordingRunner) answerLsGlob(prefix, suffix string) bssh.Result {
	var out []string
	for p := range r.h.files {
		if mid, ok := globStarSegment(p, prefix, suffix); ok && mid != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return bssh.Result{ExitCode: 2}
	}
	slices.Sort(out)
	return bssh.Result{Stdout: strings.Join(out, "\n") + "\n"}
}

// globStarSegment reports whether path is prefix + <segment> + suffix, with
// the segment barred from containing '/' or starting with a dot. That is
// STRICTER than a real shell star — mid-component a shell's * happily
// matches a leading dot (the hidden-file rule applies only when the pattern
// starts the component), and here the dot rule is applied unconditionally —
// so the evaluator can only under-match, the safe direction; no fixture
// path is affected either way.
func globStarSegment(path, prefix, suffix string) (string, bool) {
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return "", false
	}
	mid, ok := strings.CutSuffix(rest, suffix)
	if !ok || strings.Contains(mid, "/") || strings.HasPrefix(mid, ".") {
		return "", false
	}
	return mid, true
}

// answerFindRegular evaluates findRegularFiles' guarded listing: a missing
// directory is the [ -d ]-guarded quiet empty; otherwise the immediate
// REGULAR children matching the -name pattern ("" = all, else one glob star).
func (r *recordingRunner) answerFindRegular(dir, pattern string) bssh.Result {
	return r.answerFindChildren(dir, "regular file", func(name string) bool {
		if pattern == "" {
			return true
		}
		pre, suf, _ := strings.Cut(pattern, "*")
		_, ok := globStarSegment(name, pre, suf)
		return ok
	})
}

// answerFindDirs evaluates findDirectories: the immediate subdirectories.
func (r *recordingRunner) answerFindDirs(dir string) bssh.Result {
	return r.answerFindChildren(dir, "directory", func(string) bool { return true })
}

// answerFindNamed evaluates listRenewalConfs' listing: every immediate child
// with the suffix, deliberately with NO type filter (the production find has
// none, so symlinked confs are included).
func (r *recordingRunner) answerFindNamed(dir, suffix string) bssh.Result {
	return r.answerFindChildren(dir, "", func(name string) bool {
		return strings.HasSuffix(name, suffix)
	})
}

func (r *recordingRunner) answerFindChildren(dir, kind string, match func(string) bool) bssh.Result {
	if d, ok := r.h.files[dir]; !ok || d.kind != "directory" {
		return bssh.Result{} // [ -d ] short-circuits: exit 0, no output
	}
	var out []string
	for p, f := range r.h.files {
		name, ok := strings.CutPrefix(p, dir+"/")
		if !ok || strings.Contains(name, "/") {
			continue
		}
		if kind != "" && f.kind != kind {
			continue
		}
		if match(name) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return bssh.Result{}
	}
	slices.Sort(out)
	return bssh.Result{Stdout: strings.Join(out, "\n") + "\n"}
}

// answerCertbotCertificates emits the block layout parseCertStatus consumes,
// one block per modelled lineage (a /etc/letsencrypt/live/<domain>/
// fullchain.pem), with the modelled expiry. The host without the package
// answers exit 127; a certbot with no lineages prints its no-certs notice at
// exit 0. None of the modelled lineages is a staging cert, so no TEST_CERT
// annotation appears (the fixture provisions against production).
func (r *recordingRunner) answerCertbotCertificates() bssh.Result {
	if _, ok := r.h.packages["certbot"]; !ok {
		return bssh.Result{ExitCode: 127, Stderr: "sh: 1: certbot: not found"}
	}
	var domains []string
	for p := range r.h.files {
		rest, ok := strings.CutPrefix(p, "/etc/letsencrypt/live/")
		if !ok {
			continue
		}
		if dom, ok := strings.CutSuffix(rest, "/fullchain.pem"); ok && !strings.Contains(dom, "/") {
			domains = append(domains, dom)
		}
	}
	if len(domains) == 0 {
		return bssh.Result{Stdout: "No certificates found.\n"}
	}
	slices.Sort(domains)
	var b strings.Builder
	b.WriteString("Found the following certs:\n")
	days := int(time.Until(r.h.certExpiry).Hours() / 24)
	for _, d := range domains {
		fmt.Fprintf(&b, "  Certificate Name: %s\n", d)
		fmt.Fprintf(&b, "    Serial Number: 0\n    Key Type: ECDSA\n")
		fmt.Fprintf(&b, "    Domains: %s\n", d)
		fmt.Fprintf(&b, "    Expiry Date: %s (VALID: %d days)\n",
			r.h.certExpiry.Format("2006-01-02 15:04:05-07:00"), days)
		fmt.Fprintf(&b, "    Certificate Path: /etc/letsencrypt/live/%s/fullchain.pem\n", d)
		fmt.Fprintf(&b, "    Private Key Path: /etc/letsencrypt/live/%s/privkey.pem\n", d)
	}
	return bssh.Result{Stdout: b.String()}
}

// answerSameFile evaluates the [ … -ef … ] inode comparison: both paths must
// exist and resolve — through the modelled symlinks, bounded like the valkey
// exec walk — to the same file.
func (r *recordingRunner) answerSameFile(a, b string) bssh.Result {
	ra, aok := r.resolve(a)
	rb, bok := r.resolve(b)
	if aok && bok && ra == rb {
		return bssh.Result{}
	}
	return bssh.Result{ExitCode: 1}
}

// resolve follows modelled symlinks to a final path (bounded walk; the model
// has no link loops on purpose).
func (r *recordingRunner) resolve(path string) (string, bool) {
	for range 4 {
		f, ok := r.h.files[path]
		if !ok {
			return "", false
		}
		if f.linkTarget == "" {
			return path, true
		}
		path = f.linkTarget
	}
	return "", false
}

// reEnvIdentKey / reEnvCredentialLine / reEnvAppKeyLine are the Go forms of
// the shapes the database probes grep for. The whitespace classes spell out
// the C-locale [[:space:]] set minus newline (the probes work line-wise).
var (
	reEnvIdentKey       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	reEnvCredentialLine = regexp.MustCompile(`^DB_PASSWORD=[A-Za-z0-9]+[ \t\v\f\r]*$`)
	reEnvAppKeyLine     = regexp.MustCompile(`^APP_KEY=base64:[A-Za-z0-9+/]{43}=$`)
)

// firstEnvLine returns content's first "key=" line — grep -m1 semantics over
// the anchored prefix the probes use.
func firstEnvLine(content, key string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, key+"=") {
			return line, true
		}
	}
	return "", false
}

// trimTrailingASCIISpace trims exactly the set the probes' C-locale
// sed 's/[[:space:]]*$//' trims off a captured line.
func trimTrailingASCIISpace(s string) string { return strings.TrimRight(s, " \t\v\f\r") }

// answerEnvCredential evaluates envCredentialPresentScript: exit 0 iff the
// FIRST DB_PASSWORD line carries a charset-valid value. A missing file makes
// the first grep fail into an empty pipe, so the -Eq stage answers 1 — the
// script never distinguishes missing from murky.
func (r *recordingRunner) answerEnvCredential(path string) bssh.Result {
	file, ok := r.h.files[path]
	if !ok {
		return bssh.Result{ExitCode: 1}
	}
	if line, found := firstEnvLine(file.content, "DB_PASSWORD"); found && reEnvCredentialLine.MatchString(line) {
		return bssh.Result{}
	}
	return bssh.Result{ExitCode: 1}
}

// answerEnvAppKey evaluates envBerthAppKeyScript's exit map: 0 = first
// APP_KEY line is berth-shaped, 1 = no line, 3 = present but another shape,
// 2 = the file itself unreadable (grep exit >= 2 — a hard error upstream).
func (r *recordingRunner) answerEnvAppKey(path string) bssh.Result {
	file, ok := r.h.files[path]
	if !ok {
		return bssh.Result{ExitCode: 2}
	}
	line, found := firstEnvLine(file.content, "APP_KEY")
	if !found {
		return bssh.Result{ExitCode: 1}
	}
	if reEnvAppKeyLine.MatchString(trimTrailingASCIISpace(line)) {
		return bssh.Result{}
	}
	return bssh.Result{ExitCode: 3}
}

// answerEnvValueMatch evaluates envValueMatchScript: the expected KEY=value
// line arrives on stdin (`IFS= read -r want` consumes exactly the first
// line), the live line is trimmed of trailing ASCII whitespace, and the
// verdict is plain string equality. Exit map: 0 match, 1 mismatch, 3 no
// KEY= line, 2 unreadable file.
func (r *recordingRunner) answerEnvValueMatch(path, key string, stdin []byte) bssh.Result {
	want, _, _ := strings.Cut(string(stdin), "\n")
	file, ok := r.h.files[path]
	if !ok {
		return bssh.Result{ExitCode: 2}
	}
	line, found := firstEnvLine(file.content, key)
	if !found {
		return bssh.Result{ExitCode: 3}
	}
	if trimTrailingASCIISpace(line) == want {
		return bssh.Result{}
	}
	return bssh.Result{ExitCode: 1}
}

// parseReloadedSince recognizes reloadstamp.go's probe shape:
//
//	[ -e '<stamp>' ] && [ ! '<p1>' -nt '<stamp>' ] && …
//
// A loose scan extracts the candidate stamp and paths, then the command is
// RECONSTRUCTED via reloadedSinceCmd and compared byte-for-byte, so only the
// exact production shape is ever recognized — anything else stays unanswered.
func parseReloadedSince(cmd string) (stamp string, paths []string, ok bool) {
	rest, found := strings.CutPrefix(cmd, "[ -e '")
	if !found {
		return "", nil, false
	}
	stamp, rest, found = strings.Cut(rest, "' ]")
	if !found || strings.Contains(stamp, "'") {
		return "", nil, false
	}
	for rest != "" {
		seg, found := strings.CutPrefix(rest, " && [ ! '")
		if !found {
			return "", nil, false
		}
		p, tail, found := strings.Cut(seg, "' -nt '"+stamp+"' ]")
		if !found || strings.Contains(p, "'") {
			return "", nil, false
		}
		paths = append(paths, p)
		rest = tail
	}
	unit, found := strings.CutPrefix(stamp, "/var/lib/berth/")
	if !found {
		return "", nil, false
	}
	unit, found = strings.CutSuffix(unit, ".reloaded")
	if !found || reloadedSinceCmd(unit, paths...) != cmd {
		return "", nil, false
	}
	return stamp, paths, true
}

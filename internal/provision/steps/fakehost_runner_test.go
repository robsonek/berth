package steps

import (
	"context"
	"fmt"
	"strings"
	"testing"

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
// answer at exit 0 reads as "every directive missing", driving hardening.Check
// into the misdiagnosis branch and truncating its tail out of classification.
// Only the exact check-only shapes may be answered blindly.
func TestRecordingRunnerAnswersOnlyCheckShapedValidators(t *testing.T) {
	r := newRecordingRunner(newFakeHost(t, "converged", contractServer(t)))
	ctx := context.Background()

	if res, err := r.Run(ctx, "sshd -t", nil); err != nil || res.ExitCode != 0 {
		t.Errorf("sshd -t = (%+v, %v), want blind success — it is a pure validator", res, err)
	}
	if _, err := r.Run(ctx, "sshd -T", nil); err == nil {
		t.Error("sshd -T must be unanswered — its stdout is parsed, blank success misdiagnoses")
	}
	if _, err := r.Run(ctx, "nginx -s reload", nil); err == nil {
		t.Error("nginx without -t must be unanswered — only the validator shape is blind-answered")
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
	res, ok := r.answer(cmd)
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
// "any unknown command succeeds" would destroy the contract's value.
func (r *recordingRunner) answer(cmd string) (bssh.Result, bool) {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return bssh.Result{}, false
	}
	switch {
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
		u, ok := r.h.units[f[len(f)-1]]
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
		u, ok := r.h.units[f[len(f)-1]]
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
	// modelled: nobody parses it, and `LC_ALL=C id -nG …` falls to unanswered
	// via its env prefix. getent is deliberately NOT answered here — userHome
	// PARSES its passwd row, so Task 5 must model a real row from evidence.
	case f[0] == "id" && len(f) == 2:
		if r.h.users[f[1]] {
			return bssh.Result{}, true
		}
		return bssh.Result{ExitCode: 1, Stderr: "id: '" + f[1] + "': no such user"}, true

	case f[0] == "df":
		return bssh.Result{Stdout: r.h.dfRows}, true
	case f[0] == "swapon":
		return bssh.Result{Stdout: r.h.swapRows}, true
	case f[0] == "timedatectl":
		return bssh.Result{Stdout: r.h.timezone + "\n"}, true
	case f[0] == "hostnamectl":
		return bssh.Result{Stdout: r.h.hostname + "\n"}, true

	case f[0] == "gpg":
		// gpgKeys is populated for ALL profiles including fresh, so answering
		// unconditionally would make a keyring-less host look converged and
		// mask KeyringHoldsExactly's absent-keyring branch. The keyring path is
		// the probe's last argument (apt.go); when it is not in the model,
		// answer the way real gpg does — a non-zero exit, which the probe reads
		// as "not converged" data, never a Go error.
		if _, ok := r.h.files[unq(f[len(f)-1])]; !ok {
			return bssh.Result{ExitCode: 2, Stderr: "gpg: can't open: No such file or directory"}, true
		}
		return bssh.Result{Stdout: r.h.gpgKeys}, true

	// Validators just need to succeed so the Check continues. Whether ISSUING
	// them is allowed is the classifier's judgement, not the model's. Only the
	// exact check-only shapes are answered blindly: `sshd -T` in particular is
	// NOT a validator — sshdEffective parses its stdout, and a blank success
	// would read as "every directive missing" and misdiagnose hardening.Check.
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

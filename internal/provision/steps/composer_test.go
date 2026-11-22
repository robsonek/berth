package steps

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// stubComposerSig replaces the run-time signature fetch for the test's
// duration; the stubbed fetch always succeeds (no test exercises its failure).
func stubComposerSig(t *testing.T, sig string) {
	t.Helper()
	prev := fetchComposerSig
	fetchComposerSig = func(_ context.Context) (string, error) { return sig, nil }
	t.Cleanup(func() { fetchComposerSig = prev })
}

func TestComposerRequiresPHP(t *testing.T) {
	if got := Composer().Requires(); len(got) != 1 || got[0] != "php" {
		t.Fatalf("Requires() = %v, want [php]", got)
	}
}

// composerCronCat is the one read Check and Apply make of the cron file.
var composerCronCat = "cat " + shQuote(composerUpdateCronPath)

// renderedComposerCron is berth's own rendered cron content.
func renderedComposerCron(t *testing.T) string {
	t.Helper()
	b, err := renderComposerUpdateCron()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// stubComposerMissing makes the host read back with no composer on PATH and
// no cron file: Apply takes the install path, then writes the cron.
func stubComposerMissing(f *bssh.FakeRunner) {
	f.On("command -v composer", bssh.Result{ExitCode: 1})
	f.On(composerCronCat, bssh.Result{ExitCode: 1})
}

// stubCronDaemonUp makes the cron daemon read back active and enabled.
func stubCronDaemonUp(f *bssh.FakeRunner) {
	f.On("systemctl is-active cron", bssh.Result{})
	f.On("systemctl is-enabled cron", bssh.Result{})
}

func composerAutoUpdateOff() *config.Server {
	off := false
	return &config.Server{Composer: config.Composer{AutoUpdate: &off}}
}

const foreignCron = "0 3 * * * root /opt/ops/update-composer\n"

func TestComposerCheckSatisfiedWhenPresentAndCronCurrent(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	f.On("command -v composer", bssh.Result{ExitCode: 0})
	f.On(composerCronCat, bssh.Result{Stdout: renderedComposerCron(t)})
	cr, err := Composer().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied with composer present and the cron current; got %+v", cr)
	}
}

func TestComposerCheckUnsatisfiedWhenAbsent(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	f.On("command -v composer", bssh.Result{ExitCode: 1})
	f.On(composerCronCat, bssh.Result{Stdout: renderedComposerCron(t)})
	cr, err := Composer().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when composer is absent")
	}
	if got := strings.Join(cr.Changes, "\n"); !strings.Contains(got, "install composer") || strings.Contains(got, composerUpdateCronPath) {
		t.Errorf("Changes must plan the install only; got %q", got)
	}
}

func TestComposerCheckUnsatisfiedWhenCronAbsent(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	f.On("command -v composer", bssh.Result{ExitCode: 0})
	f.On(composerCronCat, bssh.Result{ExitCode: 1})
	cr, err := Composer().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatalf("expected unsatisfied with the cron absent; got %+v", cr)
	}
	if got := strings.Join(cr.Changes, "\n"); !strings.Contains(got, "write "+composerUpdateCronPath) || strings.Contains(got, "install composer") {
		t.Errorf("Changes must plan the cron write only; got %q", got)
	}
}

func TestComposerCheckUnsatisfiedWhenCronDrifted(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	f.On("command -v composer", bssh.Result{ExitCode: 0})
	f.On(composerCronCat, bssh.Result{Stdout: managedMarker + "\n# stale content from an older berth\n"})
	cr, err := Composer().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatalf("expected unsatisfied with a drifted cron; got %+v", cr)
	}
}

func TestComposerCheckRefusesForeignCron(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	f.On("command -v composer", bssh.Result{ExitCode: 0})
	f.On(composerCronCat, bssh.Result{Stdout: foreignCron})
	_, err := Composer().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), composerUpdateCronPath) {
		t.Fatalf("a foreign cron must refuse naming the path; got %v", err)
	}
	cr, err := Composer().Check(context.Background(), provision.RunCtx{Force: true}, &config.Server{}, f)
	if err != nil {
		t.Fatalf("--force must not refuse; got %v", err)
	}
	if cr.Satisfied {
		t.Error("--force over a foreign cron must plan the overwrite, not report satisfied")
	}
}

func TestComposerCheckKnobOff(t *testing.T) {
	cases := []struct {
		name      string
		cron      bssh.Result
		satisfied bool
	}{
		{"no file", bssh.Result{ExitCode: 1}, true},
		{"berth-managed file lingers", bssh.Result{Stdout: managedMarker + "\nanything\n"}, false},
		{"foreign file is left alone", bssh.Result{Stdout: foreignCron}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			stubCronDaemonUp(f)
			f.On("command -v composer", bssh.Result{ExitCode: 0})
			f.On(composerCronCat, c.cron)
			cr, err := Composer().Check(context.Background(), provision.RunCtx{}, composerAutoUpdateOff(), f)
			if err != nil {
				t.Fatal(err)
			}
			if cr.Satisfied != c.satisfied {
				t.Errorf("Satisfied = %v, want %v (%+v)", cr.Satisfied, c.satisfied, cr)
			}
			if cmd := ranAny(f, "systemctl"); cmd != "" {
				t.Errorf("knob off must not probe the cron daemon; ran %q", cmd)
			}
			if !c.satisfied && !strings.Contains(strings.Join(cr.Changes, "\n"), "remove "+composerUpdateCronPath) {
				t.Errorf("Changes must plan the removal; got %v", cr.Changes)
			}
		})
	}
}

// ranAny reports whether any recorded command starts with one of the prefixes.
func ranAny(f *bssh.FakeRunner, prefixes ...string) string {
	for _, c := range f.Calls() {
		for _, p := range prefixes {
			if strings.HasPrefix(c.Cmd, p) {
				return c.Cmd
			}
		}
	}
	return ""
}

// The state of every host provisioned before the cron existed: composer is
// installed, the cron is not. Apply writes the cron and must not touch the
// installer (an unstubbed installer command would also fail the FakeRunner).
func TestComposerApplyWritesCronWithoutReinstalling(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	f.On("command -v composer", bssh.Result{ExitCode: 0})
	f.On(composerCronCat, bssh.Result{ExitCode: 1})
	if err := Composer().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if cmd := ranAny(f, "mktemp", "php "); cmd != "" {
		t.Errorf("the installer must not run when composer is present; ran %q", cmd)
	}
	w := f.Writes()
	if len(w) != 1 {
		t.Fatalf("want exactly one write, got %d", len(w))
	}
	if w[0].Path != composerUpdateCronPath || string(w[0].Content) != renderedComposerCron(t) || w[0].Mode != 0o644 || w[0].Owner != "root" || w[0].Group != "root" {
		t.Errorf("unexpected cron write: %+v", w[0])
	}
}

func TestComposerApplyKnobOffRemovesManagedCron(t *testing.T) {
	rm := "rm -f " + shQuote(composerUpdateCronPath)
	cases := []struct {
		name   string
		cron   bssh.Result
		force  bool
		wantRm bool
	}{
		{"berth-managed file", bssh.Result{Stdout: managedMarker + "\nanything\n"}, false, true},
		{"absent", bssh.Result{ExitCode: 1}, false, false},
		{"foreign, even with --force", bssh.Result{Stdout: foreignCron}, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			stubCronDaemonUp(f)
			f.On("command -v composer", bssh.Result{ExitCode: 0})
			f.On(composerCronCat, c.cron)
			f.On(rm, bssh.Result{})
			if err := Composer().Apply(context.Background(), provision.RunCtx{Force: c.force}, composerAutoUpdateOff(), f); err != nil {
				t.Fatalf("Apply() error = %v", err)
			}
			if got := ranAny(f, "rm ") != ""; got != c.wantRm {
				t.Errorf("rm ran = %v, want %v", got, c.wantRm)
			}
			if len(f.Writes()) != 0 {
				t.Errorf("knob off must write nothing; got %+v", f.Writes())
			}
			if cmd := ranAny(f, "systemctl", "apt"); cmd != "" {
				t.Errorf("knob off must not touch the cron daemon; ran %q", cmd)
			}
		})
	}
}

func TestComposerApplyRefusesForeignCron(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	f.On("command -v composer", bssh.Result{ExitCode: 0})
	f.On(composerCronCat, bssh.Result{Stdout: foreignCron})
	err := Composer().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil || !strings.Contains(err.Error(), composerUpdateCronPath) {
		t.Fatalf("a foreign cron must refuse naming the path; got %v", err)
	}
	if len(f.Writes()) != 0 {
		t.Errorf("nothing may be written over a foreign cron; got %+v", f.Writes())
	}
}

// Composer missing and the knob off: the installer still runs, no cron.
func TestComposerApplyKnobOffStillInstalls(t *testing.T) {
	const sig = "abc123def456"
	stubComposerSig(t, sig)
	setup := fakeComposerDir + "/composer-setup.php"
	installCmd := fmt.Sprintf("php %s --install-dir=/usr/local/bin --filename=composer", setup)
	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	stubComposerMissing(f)
	f.On("mktemp -d /tmp/berth-composer.XXXXXXXXXX", bssh.Result{Stdout: fakeComposerDir + "\n"})
	f.On(fmt.Sprintf("php -r \"copy('%s', '%s');\"", composerInstallerURL, setup), bssh.Result{})
	f.On(fmt.Sprintf("php -r \"echo hash_file('sha384', '%s');\"", setup), bssh.Result{Stdout: sig})
	f.On(installCmd, bssh.Result{})
	f.On("rm -rf "+shQuote(fakeComposerDir), bssh.Result{})
	if err := Composer().Apply(context.Background(), provision.RunCtx{}, composerAutoUpdateOff(), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if ranAny(f, installCmd) == "" {
		t.Error("the installer must run when composer is missing, knob off or not")
	}
	if len(f.Writes()) != 0 {
		t.Errorf("knob off must write no cron; got %+v", f.Writes())
	}
}

// fakeComposerDir is the fixed directory the stubbed mktemp -d hands back.
const fakeComposerDir = "/tmp/berth-composer.abcd123456"

func TestComposerApplyInstallsOnMatchingHash(t *testing.T) {
	const sig = "abc123def456" // stand-in for the run-time SHA-384
	stubComposerSig(t, sig)

	setup := fakeComposerDir + "/composer-setup.php"
	hashCmd := fmt.Sprintf("php -r \"echo hash_file('sha384', '%s');\"", setup)
	installCmd := fmt.Sprintf("php %s --install-dir=/usr/local/bin --filename=composer", setup)
	cleanupCmd := "rm -rf " + shQuote(fakeComposerDir)

	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	stubComposerMissing(f)
	f.On("mktemp -d /tmp/berth-composer.XXXXXXXXXX", bssh.Result{Stdout: fakeComposerDir + "\n"})
	f.On(fmt.Sprintf("php -r \"copy('%s', '%s');\"", composerInstallerURL, setup), bssh.Result{})
	f.On(hashCmd, bssh.Result{Stdout: sig})
	f.On(installCmd, bssh.Result{})
	f.On(cleanupCmd, bssh.Result{})

	if err := Composer().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{installCmd, cleanupCmd} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
	// A fresh host gets the self-update cron right after the install.
	if w := f.Writes(); len(w) != 1 || w[0].Path != composerUpdateCronPath {
		t.Errorf("want the cron written after the install; writes: %+v", w)
	}
}

func TestComposerApplyAbortsOnHashMismatch(t *testing.T) {
	stubComposerSig(t, "the-expected-hash")

	setup := fakeComposerDir + "/composer-setup.php"
	hashCmd := fmt.Sprintf("php -r \"echo hash_file('sha384', '%s');\"", setup)
	installCmd := fmt.Sprintf("php %s --install-dir=/usr/local/bin --filename=composer", setup)
	cleanupCmd := "rm -rf " + shQuote(fakeComposerDir)

	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	stubComposerMissing(f)
	f.On("mktemp -d /tmp/berth-composer.XXXXXXXXXX", bssh.Result{Stdout: fakeComposerDir + "\n"})
	f.On(fmt.Sprintf("php -r \"copy('%s', '%s');\"", composerInstallerURL, setup), bssh.Result{})
	f.On(hashCmd, bssh.Result{Stdout: "a-different-hash"})
	f.On(cleanupCmd, bssh.Result{})

	err := Composer().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil {
		t.Fatal("expected error on checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("error should mention checksum mismatch; got %v", err)
	}
	// The installer must NOT have been executed when the hash does not match,
	// while the deferred cleanup must still remove the temp dir.
	ranCleanup := false
	for _, c := range f.Calls() {
		if c.Cmd == installCmd {
			t.Error("composer installer must not run when the checksum does not match")
		}
		if c.Cmd == cleanupCmd {
			ranCleanup = true
		}
	}
	if !ranCleanup {
		t.Errorf("deferred cleanup %q did not run after the mismatch", cleanupCmd)
	}
	// No cron for a Composer that was never installed.
	if len(f.Writes()) != 0 {
		t.Errorf("a failed install must not write the cron; got %+v", f.Writes())
	}
}

// ctxSpyRunner wraps a FakeRunner and records, per command, the state of the
// context it was invoked with (Err at call time, deadline presence).
type ctxSpyRunner struct {
	*bssh.FakeRunner
	errAtCall   map[string]error
	hadDeadline map[string]bool
}

func (s *ctxSpyRunner) Run(ctx context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	s.errAtCall[cmd] = ctx.Err()
	_, ok := ctx.Deadline()
	s.hadDeadline[cmd] = ok
	return s.FakeRunner.Run(ctx, cmd, stdin)
}

func TestComposerApplyCleanupSurvivesCancelAndIsBounded(t *testing.T) {
	const sig = "abc123def456"
	stubComposerSig(t, sig)

	setup := fakeComposerDir + "/composer-setup.php"
	dlCmd := fmt.Sprintf("php -r \"copy('%s', '%s');\"", composerInstallerURL, setup)
	cleanupCmd := "rm -rf " + shQuote(fakeComposerDir)

	f := bssh.NewFakeRunner()
	stubCronDaemonUp(f)
	f.On("mktemp -d /tmp/berth-composer.XXXXXXXXXX", bssh.Result{Stdout: fakeComposerDir + "\n"})
	stubComposerMissing(f)
	f.On(dlCmd, bssh.Result{})
	f.On(fmt.Sprintf("php -r \"echo hash_file('sha384', '%s');\"", setup), bssh.Result{Stdout: sig})
	f.On(fmt.Sprintf("php %s --install-dir=/usr/local/bin --filename=composer", setup), bssh.Result{})
	f.On(cleanupCmd, bssh.Result{})

	spy := &ctxSpyRunner{FakeRunner: f, errAtCall: map[string]error{}, hadDeadline: map[string]bool{}}

	// An already-cancelled parent: the FakeRunner ignores contexts, so Apply
	// still walks its happy path and the deferred cleanup fires.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := Composer().Apply(ctx, provision.RunCtx{}, &config.Server{}, spy); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// Sanity: the in-run commands really did observe the cancelled parent.
	if spy.errAtCall[dlCmd] == nil {
		t.Error("expected the download to observe the cancelled parent context")
	}
	got, ran := spy.errAtCall[cleanupCmd]
	if !ran {
		t.Fatalf("cleanup %q never ran", cleanupCmd)
	}
	if got != nil {
		t.Errorf("cleanup ctx must survive the parent's cancellation; got Err() = %v", got)
	}
	if !spy.hadDeadline[cleanupCmd] {
		t.Error("cleanup ctx must carry a deadline so a wedged transport cannot hang Apply")
	}
}

func TestComposerApplyRejectsUnexpectedMktempOutput(t *testing.T) {
	stubComposerSig(t, "irrelevant")

	cases := []struct {
		name   string
		stdout string // what the stubbed mktemp -d prints
	}{
		{"empty", ""},
		{"relative-path", "berth-composer.XXXXXXXXXX\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			stubCronDaemonUp(f)
			stubComposerMissing(f)
			f.On("mktemp -d /tmp/berth-composer.XXXXXXXXXX", bssh.Result{Stdout: c.stdout})

			err := Composer().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f)
			if err == nil {
				t.Fatalf("expected error when mktemp -d returns %q", c.stdout)
			}
			if !strings.Contains(err.Error(), "unexpected path") {
				t.Errorf("error should mention the unexpected path; got %v", err)
			}
			// Nothing may be downloaded (or removed) when no private dir exists.
			for _, call := range f.Calls() {
				if strings.HasPrefix(call.Cmd, "php -r") || strings.HasPrefix(call.Cmd, "rm ") {
					t.Errorf("no download or cleanup may run after a bad mktemp result; got %q", call.Cmd)
				}
			}
		})
	}
}

// The cron updates exactly the binary berth's installer wrote, by absolute
// path and behind an -x guard — never whatever `composer` resolves to on PATH.
func TestComposerCronTargetsBerthsOwnBinary(t *testing.T) {
	cron := renderedComposerCron(t)
	for _, want := range []string{"[ -x " + composerBin + " ]", composerBin + " self-update --stable"} {
		if !strings.Contains(cron, want) {
			t.Errorf("cron must contain %q; got:\n%s", want, cron)
		}
	}
}

// A cron.d file is inert without a running cron daemon, and nothing else
// guarantees one (scheduler off, no backups): the step probes it itself.
func TestComposerCheckUnsatisfiedWhenCronDaemonDown(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("command -v composer", bssh.Result{ExitCode: 0})
	f.On(composerCronCat, bssh.Result{Stdout: renderedComposerCron(t)})
	f.On("systemctl is-active cron", bssh.Result{ExitCode: 3})
	f.On("systemctl is-enabled cron", bssh.Result{ExitCode: 1})
	cr, err := Composer().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatalf("expected unsatisfied with the cron daemon down; got %+v", cr)
	}
	if got := strings.Join(cr.Changes, "\n"); !strings.Contains(got, "cron daemon") {
		t.Errorf("Changes must plan the cron daemon; got %q", got)
	}
}

// lenientRunner answers every unstubbed command with success, so a test can
// assert on the order of commands whose exact strings it does not own (apt).
type lenientRunner struct {
	*bssh.FakeRunner
	order []string
}

func (l *lenientRunner) Run(ctx context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	l.order = append(l.order, cmd)
	res, err := l.FakeRunner.Run(ctx, cmd, stdin)
	if err != nil && strings.Contains(err.Error(), "unstubbed command") {
		return bssh.Result{}, nil
	}
	return res, err
}

// Apply installs and enables the cron daemon BEFORE writing the cron file
// that depends on it. The file's write-guard cat is the observable proxy for
// the write (WriteFile calls are not interleaved with Run calls).
func TestComposerApplyEnsuresCronDaemonBeforeTheCron(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("command -v composer", bssh.Result{ExitCode: 0})
	f.On(composerCronCat, bssh.Result{ExitCode: 1})
	f.On("systemctl is-active cron", bssh.Result{ExitCode: 3})
	f.On("systemctl is-enabled cron", bssh.Result{ExitCode: 1})
	l := &lenientRunner{FakeRunner: f}
	if err := Composer().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, l); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	enable, guard := -1, -1
	for i, cmd := range l.order {
		switch cmd {
		case "systemctl enable --now cron":
			enable = i
		case composerCronCat:
			guard = i
		}
	}
	if enable < 0 {
		t.Fatalf("Apply must enable the cron daemon; ran:\n%s", strings.Join(l.order, "\n"))
	}
	if guard < enable {
		t.Errorf("the cron daemon must be ensured before the cron file is written; ran:\n%s", strings.Join(l.order, "\n"))
	}
	if len(f.Writes()) != 1 {
		t.Errorf("want the cron written; writes: %+v", f.Writes())
	}
}

// A Composer that berth did not install (a distro package in /usr/bin) is
// never touched — and the self-update cron, which names berth's own binary,
// does nothing for it. Saying "cron in place" and nothing else would be a
// promise the host does not keep, so the step says it in a warning.
func TestComposerWarnsWhenTheComposerOnPathIsNotBerths(t *testing.T) {
	cases := []struct {
		name     string
		path     string // what `command -v composer` prints
		server   *config.Server
		wantWarn bool
	}{
		{"berth's own binary", "/usr/local/bin/composer\n", &config.Server{}, false},
		{"a foreign composer", "/usr/bin/composer\n", &config.Server{}, true},
		{"a foreign composer, auto-update off: nothing is promised", "/usr/bin/composer\n", composerAutoUpdateOff(), false},
		{"no path printed (cannot tell)", "", &config.Server{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			stubCronDaemonUp(f)
			f.On("command -v composer", bssh.Result{Stdout: c.path})
			cron := bssh.Result{Stdout: renderedComposerCron(t)}
			if !c.server.Composer.AutoUpdateEnabled() {
				cron = bssh.Result{ExitCode: 1}
			}
			f.On(composerCronCat, cron)
			cr, err := Composer().Check(context.Background(), provision.RunCtx{}, c.server, f)
			if err != nil {
				t.Fatal(err)
			}
			if !cr.Satisfied {
				t.Fatalf("a foreign composer is not drift; got %+v", cr)
			}
			if got := len(cr.Warnings) == 1; got != c.wantWarn {
				t.Fatalf("warnings = %q, want one: %v", cr.Warnings, c.wantWarn)
			}
			if c.wantWarn && (!strings.Contains(cr.Warnings[0], "/usr/bin/composer") || !strings.Contains(cr.Warnings[0], composerBin)) {
				t.Errorf("the warning must name both binaries; got %q", cr.Warnings[0])
			}
			var applied []string
			rc := provision.RunCtx{Warn: func(m string) { applied = append(applied, m) }}
			if err := Composer().Apply(context.Background(), rc, c.server, f); err != nil {
				t.Fatal(err)
			}
			if got := len(applied) == 1; got != c.wantWarn {
				t.Errorf("Apply warnings = %q, want one: %v", applied, c.wantWarn)
			}
		})
	}
}

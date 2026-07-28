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

func TestComposerCheckSatisfiedWhenPresent(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("command -v composer", bssh.Result{ExitCode: 0})
	cr, err := Composer().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when composer is present; got %+v", cr)
	}
}

func TestComposerCheckUnsatisfiedWhenAbsent(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("command -v composer", bssh.Result{ExitCode: 1})
	cr, err := Composer().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when composer is absent")
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
}

func TestComposerApplyAbortsOnHashMismatch(t *testing.T) {
	stubComposerSig(t, "the-expected-hash")

	setup := fakeComposerDir + "/composer-setup.php"
	hashCmd := fmt.Sprintf("php -r \"echo hash_file('sha384', '%s');\"", setup)
	installCmd := fmt.Sprintf("php %s --install-dir=/usr/local/bin --filename=composer", setup)
	cleanupCmd := "rm -rf " + shQuote(fakeComposerDir)

	f := bssh.NewFakeRunner()
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
	f.On("mktemp -d /tmp/berth-composer.XXXXXXXXXX", bssh.Result{Stdout: fakeComposerDir + "\n"})
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

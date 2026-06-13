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

// stubComposerSig replaces the run-time signature fetch for the test's duration.
func stubComposerSig(t *testing.T, sig string, err error) {
	t.Helper()
	prev := fetchComposerSig
	fetchComposerSig = func(_ context.Context) (string, error) { return sig, err }
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

func TestComposerApplyInstallsOnMatchingHash(t *testing.T) {
	const sig = "abc123def456" // stand-in for the run-time SHA-384
	stubComposerSig(t, sig, nil)

	hashCmd := fmt.Sprintf("php -r \"echo hash_file('sha384', '%s');\"", composerSetupPath)
	installCmd := fmt.Sprintf("php %s --install-dir=/usr/local/bin --filename=composer", composerSetupPath)

	f := bssh.NewFakeRunner()
	f.On(fmt.Sprintf("php -r \"copy('%s', '%s');\"", composerInstallerURL, composerSetupPath), bssh.Result{})
	f.On(hashCmd, bssh.Result{Stdout: sig})
	f.On(installCmd, bssh.Result{})
	f.On("rm -f "+composerSetupPath, bssh.Result{})

	if err := Composer().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{installCmd, "rm -f " + composerSetupPath} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

func TestComposerApplyAbortsOnHashMismatch(t *testing.T) {
	stubComposerSig(t, "the-expected-hash", nil)

	hashCmd := fmt.Sprintf("php -r \"echo hash_file('sha384', '%s');\"", composerSetupPath)
	installCmd := fmt.Sprintf("php %s --install-dir=/usr/local/bin --filename=composer", composerSetupPath)

	f := bssh.NewFakeRunner()
	f.On(fmt.Sprintf("php -r \"copy('%s', '%s');\"", composerInstallerURL, composerSetupPath), bssh.Result{})
	f.On(hashCmd, bssh.Result{Stdout: "a-different-hash"})
	f.On("rm -f "+composerSetupPath, bssh.Result{})

	err := Composer().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil {
		t.Fatal("expected error on checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("error should mention checksum mismatch; got %v", err)
	}
	// The installer must NOT have been executed when the hash does not match.
	for _, c := range f.Calls() {
		if c.Cmd == installCmd {
			t.Error("composer installer must not run when the checksum does not match")
		}
	}
}

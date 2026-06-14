package steps

import (
	"context"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestPreflightRejectsNonTrixie(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(". /etc/os-release && echo $VERSION_CODENAME", bssh.Result{Stdout: "bookworm\n"})
	_, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil {
		t.Fatal("expected rejection of non-trixie")
	}
}

func TestPreflightAcceptsTrixie(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(". /etc/os-release && echo $VERSION_CODENAME", bssh.Result{Stdout: "trixie\n"})
	cr, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("trixie should pass and report not-yet-satisfied; got cr=%+v err=%v", cr, err)
	}
}

func TestPreflightApplyRunsAptUpdate(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("sudo -n true", bssh.Result{})
	f.On("sudo DEBIAN_FRONTEND=noninteractive apt-get update -y", bssh.Result{})
	if err := Preflight().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	cmds := []string{f.Calls()[0].Cmd, f.Calls()[1].Cmd}
	if cmds[0] != "sudo -n true" || cmds[1] != "sudo DEBIAN_FRONTEND=noninteractive apt-get update -y" {
		t.Errorf("unexpected command sequence: %v", cmds)
	}
	// The dpkg-lock-wait config must be written before the apt-get update so a
	// boot-time apt-daily run cannot make the install steps fail on the lock.
	var wroteLockCfg bool
	for _, w := range f.Writes() {
		if w.Path == aptLockTimeoutPath {
			wroteLockCfg = true
			if string(w.Content) != aptLockTimeoutBody {
				t.Errorf("lock-timeout config body = %q, want %q", w.Content, aptLockTimeoutBody)
			}
		}
	}
	if !wroteLockCfg {
		t.Errorf("expected %s to be written", aptLockTimeoutPath)
	}
}

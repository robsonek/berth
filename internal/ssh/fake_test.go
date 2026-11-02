package ssh

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFakeRunnerMatchesAndRecords(t *testing.T) {
	f := NewFakeRunner()
	f.On("id -u deploy", Result{ExitCode: 1}) // user missing
	f.On("getent passwd deploy", Result{Stdout: "deploy:x:1001:", ExitCode: 0})

	r, err := f.Run(context.Background(), "id -u deploy", nil)
	if err != nil || r.ExitCode != 1 {
		t.Fatalf("Run() = %+v, %v; want exit 1", r, err)
	}
	if got := f.Calls()[0].Cmd; got != "id -u deploy" {
		t.Errorf("recorded cmd = %q", got)
	}
}

func TestFakeRunnerUnexpectedCmdErrors(t *testing.T) {
	f := NewFakeRunner()
	if _, err := f.Run(context.Background(), "rm -rf /", nil); err == nil {
		t.Error("expected error for unstubbed command")
	}
}

func TestFakeRunnerWriteFileRecorded(t *testing.T) {
	f := NewFakeRunner()
	err := f.WriteFile(context.Background(), FileSpec{Path: "/etc/x", Content: []byte("y"), Mode: 0o644, Sudo: true})
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if len(f.Writes()) != 1 || f.Writes()[0].Path != "/etc/x" {
		t.Errorf("writes = %+v", f.Writes())
	}
}

func TestFakeHolderReplaysStubs(t *testing.T) {
	lease := NewFakeLease()
	exit := &HoldExitError{Code: 75, Stdout: "berth v1.0.0 provision by ops@ws (pid 9) since 2026-11-02T09:00:00Z\n"}
	boom := errors.New("transport down")
	f := NewFakeHolder().
		OnHold("lock", lease).
		OnHoldExit("busy", exit).
		OnHoldError("broken", boom)
	ctx := context.Background()

	if l, err := f.Hold(ctx, "lock", "locked"); err != nil || l != Lease(lease) {
		t.Errorf("Hold(lock) = %v, %v; want the stubbed lease", l, err)
	}
	var he *HoldExitError
	if l, err := f.Hold(ctx, "busy", "locked"); l != nil || !errors.As(err, &he) || he != exit {
		t.Errorf("Hold(busy) = %v, %v; want nil lease and the stubbed *HoldExitError", l, err)
	}
	if l, err := f.Hold(ctx, "broken", "locked"); l != nil || !errors.Is(err, boom) {
		t.Errorf("Hold(broken) = %v, %v; want nil lease and the stubbed error", l, err)
	}
	l, err := f.Hold(ctx, "rm -rf /", "locked")
	if l != nil || err == nil || !strings.Contains(err.Error(), "rm -rf /") {
		t.Errorf("Hold(unstubbed) = %v, %v; want nil lease and an error naming the command", l, err)
	}
	want := []string{"lock", "busy", "broken", "rm -rf /"}
	if got := f.Calls(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("Calls() = %q, want %q", got, want)
	}
}

func TestFakeLeaseEndAndRelease(t *testing.T) {
	l := NewFakeLease()
	if err := l.Send("ping"); err != nil {
		t.Fatalf("Send on a live lease = %v", err)
	}
	if got := l.Sent(); len(got) != 1 || got[0] != "ping" {
		t.Errorf("Sent() = %q, want [\"ping\"]", got)
	}
	select {
	case <-l.Done():
		t.Fatal("Done() closed on a live lease")
	default:
	}

	l.End()
	select {
	case <-l.Done():
	default:
		t.Fatal("End() did not close Done()")
	}
	if l.Released() {
		t.Error("End() marked the lease released — it simulates the remote command ending on its own")
	}
	if err := l.Send("late"); err == nil {
		t.Error("Send after End = nil, want an error (the held command is gone)")
	}

	if err := l.Release(time.Second); err != nil {
		t.Errorf("Release after End = %v, want nil", err)
	}
	if !l.Released() {
		t.Error("Released() = false after Release")
	}
	if err := l.Release(time.Second); err != nil {
		t.Errorf("second Release = %v, want nil (idempotent)", err)
	}

	r := NewFakeLease()
	if err := r.Release(time.Second); err != nil {
		t.Errorf("Release = %v, want nil", err)
	}
	select {
	case <-r.Done():
	default:
		t.Error("Release did not close Done()")
	}
	if !r.Released() {
		t.Error("Released() = false after Release")
	}
	if got := r.Sent(); len(got) != 0 {
		t.Errorf("Sent() = %q, want none", got)
	}
}

package ssh

import (
	"bufio"
	"context"
	"errors"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

func TestHoldReturnsLeaseOnReadyLine(t *testing.T) {
	got := make(chan []string, 1)
	srv := startTestServer(t, func(_ *testServer, ch xssh.Channel, _ <-chan *xssh.Request) {
		_, _ = ch.Write([]byte("locked\n"))
		var lines []string
		sc := bufio.NewScanner(ch) // the client's stdin, until it sends EOF
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		got <- lines
		_, _ = ch.SendRequest("exit-status", false, xssh.Marshal(exitStatusMsg{Status: 0}))
	}, false)
	c := dialTest(t, srv)

	l, err := c.Hold(context.Background(), "x", "locked")
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if err := l.Send("ping"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := l.Release(2 * time.Second); err != nil {
		t.Fatalf("Release: %v", err)
	}
	select {
	case lines := <-got:
		if len(lines) != 1 || lines[0] != "ping" {
			t.Errorf("server read stdin lines %q, want [\"ping\"]", lines)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never saw stdin EOF — Release did not close stdin")
	}
	select {
	case <-l.Done():
	default:
		t.Error("Done() still open after Release returned nil")
	}
	if err := l.Release(2 * time.Second); err != nil {
		t.Errorf("second Release = %v, want nil (idempotent)", err)
	}
	if err := l.Send("late"); err == nil {
		t.Error("Send after Release = nil, want an error (stdin is closed)")
	}
}

func TestHoldExitBeforeReadyIsHoldExitError(t *testing.T) {
	const line = "berth v1.0.0 provision by ops@ws (pid 1) since 2026-11-02T09:32:00Z\n"
	srv := startTestServer(t, completeExec(line, 75), false)
	c := dialTest(t, srv)

	l, err := c.Hold(context.Background(), "x", "locked")
	if l != nil {
		t.Errorf("lease = %v, want nil when the command ended before ready", l)
	}
	var he *HoldExitError
	if !errors.As(err, &he) {
		t.Fatalf("err = %v (%T), want *HoldExitError", err, err)
	}
	if he.Code != 75 {
		t.Errorf("Code = %d, want 75", he.Code)
	}
	if he.Stdout != line {
		t.Errorf("Stdout = %q, want %q", he.Stdout, line)
	}
}

func TestHoldDoneClosesWhenRemoteEnds(t *testing.T) {
	// Ready, then exit-status and channel close straight away: the waiter may
	// see the end before the reader sees the ready line, which must still
	// yield a lease (readiness is decided by stdout, not by the race).
	srv := startTestServer(t, completeExec("locked\n", 0), false)
	c := dialTest(t, srv)

	l, err := c.Hold(context.Background(), "x", "locked")
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	select {
	case <-l.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done() did not close after the remote command ended")
	}
	if err := l.Release(time.Second); err != nil {
		t.Errorf("Release after the end = %v, want nil", err)
	}
}

func TestHoldCancelBeforeReadyReturnsPromptly(t *testing.T) {
	srv := startTestServer(t, hangExec, false)
	c := dialTest(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		l   Lease
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		l, err := c.Hold(ctx, "x", "locked")
		done <- outcome{l, err}
	}()
	select {
	case <-srv.execStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("exec request never reached the server")
	}
	cancel()

	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", got.err)
		}
		if got.l != nil {
			t.Errorf("lease = %v, want nil on cancel", got.l)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Hold did not return after cancel")
	}
	select {
	case sig := <-srv.signals:
		if sig != "TERM" {
			t.Errorf("signal = %q, want TERM", sig)
		}
	case <-time.After(2 * time.Second):
		t.Error("server never observed TERM — the held command would keep running")
	}
}

func TestHoldWrapsWithSudoForNonRoot(t *testing.T) {
	const cmd = `flock -n /x bash -c 'echo locked'`
	for _, tc := range []struct {
		name    string
		useSudo bool
		want    string
	}{
		{"root", false, cmd},
		{"non-root", true, "sudo -n -- /bin/sh -c " + shQuote(cmd)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startTestServer(t, completeExec("", 0), false)
			c := dialTest(t, srv)
			c.useSudo = tc.useSudo

			_, err := c.Hold(context.Background(), cmd, "locked")
			var he *HoldExitError
			if !errors.As(err, &he) || he.Code != 0 {
				t.Fatalf("err = %v, want *HoldExitError with code 0", err)
			}
			if got := srv.execCommands(); len(got) != 1 || got[0] != tc.want {
				t.Errorf("exec requests = %q, want [%q]", got, tc.want)
			}
		})
	}
}

func TestHoldReleaseTimeoutTerminatesHeldCommand(t *testing.T) {
	// The held command ignores stdin EOF: Release must stop waiting after its
	// budget, TERM the command and close the session instead of hanging.
	srv := startTestServer(t, func(srv *testServer, ch xssh.Channel, reqs <-chan *xssh.Request) {
		_, _ = ch.Write([]byte("locked\n"))
		hangExec(srv, ch, reqs)
	}, false)
	c := dialTest(t, srv)

	l, err := c.Hold(context.Background(), "x", "locked")
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	start := time.Now()
	if err := l.Release(100 * time.Millisecond); err == nil {
		t.Error("Release = nil, want an error when the command outlives the wait")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Release took %v, want about its 100ms wait", elapsed)
	}
	select {
	case sig := <-srv.signals:
		if sig != "TERM" {
			t.Errorf("signal = %q, want TERM", sig)
		}
	case <-time.After(2 * time.Second):
		t.Error("server never observed TERM after the release wait ran out")
	}
	select {
	case <-l.Done():
	case <-time.After(2 * time.Second):
		t.Error("Done() did not close after the session was torn down")
	}
}

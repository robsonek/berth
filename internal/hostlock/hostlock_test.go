package hostlock

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	bssh "github.com/robsonek/berth/internal/ssh"
)

// testConn is a Conn built from the two fakes: the FakeRunner answers Run and
// WriteFile, the FakeHolder answers Hold.
type testConn struct {
	*bssh.FakeRunner
	*bssh.FakeHolder
}

func newTestConn() *testConn {
	return &testConn{FakeRunner: bssh.NewFakeRunner(), FakeHolder: bssh.NewFakeHolder()}
}

// lockScript is the exact command Run holds for mode and command under the
// pinned seams.
func lockScript(mode Mode, command string) string {
	return Script(mode, HolderLine(command))
}

// waitDone fails the test if ch is not closed within a generous bound, so a
// broken implementation fails instead of hanging the suite.
func waitDone(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestRunHoldsLockAroundFn(t *testing.T) {
	fixSeams(t)
	conn := newTestConn()
	lease := bssh.NewFakeLease()
	conn.OnHold(lockScript(Mutating, "provision"), lease)

	calls := 0
	err := Run(context.Background(), conn, Mutating, "provision", func(_ context.Context, _ bssh.Runner) error {
		calls++
		if lease.Released() {
			t.Error("lease released before fn ran")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if calls != 1 {
		t.Fatalf("fn called %d times, want 1", calls)
	}
	if !lease.Released() {
		t.Fatal("lease not released after Run returned")
	}
	if got := conn.FakeHolder.Calls(); len(got) != 1 {
		t.Fatalf("Hold calls = %d, want 1", len(got))
	}
}

func TestRunReturnsFnError(t *testing.T) {
	fixSeams(t)
	conn := newTestConn()
	lease := bssh.NewFakeLease()
	conn.OnHold(lockScript(Mutating, "provision"), lease)
	boom := errors.New("boom")
	err := Run(context.Background(), conn, Mutating, "provision", func(context.Context, bssh.Runner) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("Run = %v, want fn's error", err)
	}
	if !lease.Released() {
		t.Fatal("lease not released")
	}
}

func TestRunBusyReportsHolder(t *testing.T) {
	fixSeams(t)
	for _, mode := range []Mode{Mutating, ReadOnly} {
		conn := newTestConn()
		conn.OnHoldExit(lockScript(mode, "provision"), &bssh.HoldExitError{
			Code:   75,
			Stdout: "\n  berth v1.0.0 provision by ops@ws (pid 9) since 2026-11-02T09:00:00Z  \nignored\n",
		})
		called := false
		err := Run(context.Background(), conn, mode, "provision", func(context.Context, bssh.Runner) error {
			called = true
			return nil
		})
		if called {
			t.Fatalf("mode %d: fn called on a busy host", mode)
		}
		var busy *BusyError
		if !errors.As(err, &busy) {
			t.Fatalf("mode %d: Run = %v (%T), want *BusyError", mode, err, err)
		}
		want := "host is busy: another berth session holds /var/lib/berth/session.lock — berth v1.0.0 provision by ops@ws (pid 9) since 2026-11-02T09:00:00Z; wait for it to finish"
		if err.Error() != want {
			t.Fatalf("mode %d: message =\n%s\nwant\n%s", mode, err.Error(), want)
		}
	}
}

func TestRunBusyWithoutHolderLine(t *testing.T) {
	fixSeams(t)
	for _, stdout := range []string{"", "\n \n"} {
		conn := newTestConn()
		conn.OnHoldExit(lockScript(Mutating, "provision"), &bssh.HoldExitError{Code: 75, Stdout: stdout})
		err := Run(context.Background(), conn, Mutating, "provision", func(context.Context, bssh.Runner) error {
			t.Fatal("fn called on a busy host")
			return nil
		})
		var busy *BusyError
		if !errors.As(err, &busy) {
			t.Fatalf("stdout %q: Run = %v, want *BusyError", stdout, err)
		}
		want := "host is busy: another berth session holds /var/lib/berth/session.lock; wait for it to finish"
		if err.Error() != want {
			t.Fatalf("stdout %q: message =\n%s\nwant\n%s", stdout, err.Error(), want)
		}
	}
}

func TestRunReadOnlyAbsentRunsWithoutLock(t *testing.T) {
	fixSeams(t)
	conn := newTestConn()
	conn.OnHoldExit(lockScript(ReadOnly, "status --drift"), &bssh.HoldExitError{Code: 0, Stdout: "absent\n"})
	sentinel := errors.New("fn result")
	var got bssh.Runner
	err := Run(context.Background(), conn, ReadOnly, "status --drift", func(_ context.Context, r bssh.Runner) error {
		got = r
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Run = %v, want fn's result", err)
	}
	if got != bssh.Runner(conn) {
		t.Fatalf("fn got runner %T %p, want the original connection", got, got)
	}
}

func TestRunMutatingNeverTreatsExitZeroAsAbsent(t *testing.T) {
	fixSeams(t)
	conn := newTestConn()
	conn.OnHoldExit(lockScript(Mutating, "provision"), &bssh.HoldExitError{Code: 0, Stdout: "absent\n"})
	err := Run(context.Background(), conn, Mutating, "provision", func(context.Context, bssh.Runner) error {
		t.Fatal("fn called without the lock in a mutating run")
		return nil
	})
	if err == nil {
		t.Fatal("Run = nil, want an error (fail closed)")
	}
	var busy *BusyError
	if errors.As(err, &busy) {
		t.Fatalf("Run = %v, want a lock failure, not busy", err)
	}
}

func TestRunOtherHoldFailureFailsClosed(t *testing.T) {
	fixSeams(t)
	cases := []struct {
		name  string
		mode  Mode
		stub  func(c *testConn, cmd string)
		check func(t *testing.T, err error)
	}{
		{
			name: "sudo refused",
			mode: Mutating,
			stub: func(c *testConn, cmd string) {
				c.OnHoldExit(cmd, &bssh.HoldExitError{Code: 1, Stderr: "sudo: a password is required"})
			},
			check: func(t *testing.T, err error) {
				t.Helper()
				if !strings.Contains(err.Error(), "sudo: a password is required") {
					t.Errorf("error %q lost the host's diagnostics", err)
				}
			},
		},
		{
			name: "transport error",
			mode: Mutating,
			stub: func(c *testConn, cmd string) { c.OnHoldError(cmd, io.EOF) },
			check: func(t *testing.T, err error) {
				t.Helper()
				if !errors.Is(err, io.EOF) {
					t.Errorf("error %v does not wrap io.EOF", err)
				}
			},
		},
		{
			name: "read-only exit 0 without absent",
			mode: ReadOnly,
			stub: func(c *testConn, cmd string) {
				c.OnHoldExit(cmd, &bssh.HoldExitError{Code: 0, Stdout: "something else\n"})
			},
			check: func(*testing.T, error) {},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := newTestConn()
			tc.stub(conn, lockScript(tc.mode, "provision"))
			err := Run(context.Background(), conn, tc.mode, "provision", func(context.Context, bssh.Runner) error {
				t.Fatal("fn called without the lock")
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), "host session lock") {
				t.Fatalf("Run = %v, want an error naming the host session lock", err)
			}
			var busy *BusyError
			if errors.As(err, &busy) {
				t.Fatalf("Run = %v, want a lock failure, not busy", err)
			}
			tc.check(t, err)
		})
	}
}

func TestRunLossCancelsAndGuardsRunner(t *testing.T) {
	fixSeams(t)
	conn := newTestConn()
	conn.On("true", bssh.Result{})
	lease := bssh.NewFakeLease()
	conn.OnHold(lockScript(Mutating, "provision"), lease)

	err := Run(context.Background(), conn, Mutating, "provision", func(ctx context.Context, r bssh.Runner) error {
		lease.End() // the held command ended on its own: lease expired or killed
		waitDone(t, ctx.Done(), "the run context to be cancelled")
		if cause := context.Cause(ctx); !errors.Is(cause, ErrLost) {
			t.Errorf("context.Cause = %v, want ErrLost", cause)
		}
		if _, err := r.Run(context.Background(), "true", nil); !errors.Is(err, ErrLost) {
			t.Errorf("guarded Run = %v, want ErrLost", err)
		}
		if err := r.WriteFile(context.Background(), bssh.FileSpec{Path: "/etc/x", Owner: "root", Group: "root", Mode: 0o644, Sudo: true}); !errors.Is(err, ErrLost) {
			t.Errorf("guarded WriteFile = %v, want ErrLost", err)
		}
		return ctx.Err()
	})
	if !errors.Is(err, ErrLost) {
		t.Fatalf("Run = %v, want ErrLost", err)
	}
	if got := conn.FakeRunner.Calls(); len(got) != 0 {
		t.Fatalf("FakeRunner recorded %v after the loss, want no calls", got)
	}
	if got := conn.Writes(); len(got) != 0 {
		t.Fatalf("FakeRunner recorded writes %v after the loss, want none", got)
	}
	if !lease.Released() {
		t.Fatal("lost lease not released")
	}
	want := "lost the host session lock /var/lib/berth/session.lock (the lease expired or the holding process ended); stopped before any further host change"
	if err.Error() != want {
		t.Fatalf("message =\n%s\nwant\n%s", err.Error(), want)
	}
}

// TestRunLossBeforeWatcherRunsIsStillLoss: a lease that ended before fn
// returned is lost even when fn returns before the watcher noticed.
func TestRunLossBeforeWatcherRunsIsStillLoss(t *testing.T) {
	fixSeams(t)
	for i := range 200 {
		conn := newTestConn()
		lease := bssh.NewFakeLease()
		conn.OnHold(lockScript(Mutating, "provision"), lease)
		err := Run(context.Background(), conn, Mutating, "provision", func(context.Context, bssh.Runner) error {
			lease.End()
			return nil
		})
		if !errors.Is(err, ErrLost) {
			t.Fatalf("iteration %d: Run = %v, want ErrLost", i, err)
		}
	}
}

func TestRunGuardedRunnerDelegatesWhileHeld(t *testing.T) {
	fixSeams(t)
	conn := newTestConn()
	conn.On("true", bssh.Result{Stdout: "ok"})
	conn.OnHold(lockScript(Mutating, "provision"), bssh.NewFakeLease())
	err := Run(context.Background(), conn, Mutating, "provision", func(ctx context.Context, r bssh.Runner) error {
		res, err := r.Run(ctx, "true", []byte("in"))
		if err != nil || res.Stdout != "ok" {
			t.Errorf("guarded Run = %+v, %v", res, err)
		}
		return r.WriteFile(ctx, bssh.FileSpec{Path: "/etc/x", Owner: "root", Group: "root", Mode: 0o644, Sudo: true})
	})
	if err != nil {
		t.Fatalf("Run = %v", err)
	}
	if got := conn.FakeRunner.Calls(); len(got) != 1 || got[0].Cmd != "true" || string(got[0].Stdin) != "in" {
		t.Fatalf("calls = %+v", got)
	}
	if got := conn.Writes(); len(got) != 1 || got[0].Path != "/etc/x" {
		t.Fatalf("writes = %+v", got)
	}
}

// TestRunNormalEndIsNotLoss: Release ends the held command, closing Done — a
// race between that and the watcher must never be reported as loss.
func TestRunNormalEndIsNotLoss(t *testing.T) {
	fixSeams(t)
	for i := range 200 {
		conn := newTestConn()
		lease := bssh.NewFakeLease()
		conn.OnHold(lockScript(Mutating, "provision"), lease)
		if err := Run(context.Background(), conn, Mutating, "provision", func(context.Context, bssh.Runner) error { return nil }); err != nil {
			t.Fatalf("iteration %d: Run = %v, want nil", i, err)
		}
		if !lease.Released() {
			t.Fatalf("iteration %d: lease not released", i)
		}
	}
}

// releaseProbe records whether fn's context was already cancelled when
// Release ran.
type releaseProbe struct {
	*bssh.FakeLease
	ctx              context.Context
	cancelledAtStart bool
}

func (p *releaseProbe) Release(wait time.Duration) error {
	p.cancelledAtStart = p.ctx.Err() != nil
	return p.FakeLease.Release(wait)
}

// TestRunCancelsRunContextBeforeRelease: whatever fn left running on its
// context stops before the lock goes, and a loss keeps ErrLost as the cause.
func TestRunCancelsRunContextBeforeRelease(t *testing.T) {
	for _, lost := range []bool{false, true} {
		probe := &releaseProbe{FakeLease: bssh.NewFakeLease()}
		err := holdWhile(context.Background(), probe, bssh.NewFakeRunner(), time.Hour, time.Second, func(ctx context.Context, _ bssh.Runner) error {
			probe.ctx = ctx
			if lost {
				probe.End()
			}
			return nil
		})
		if !probe.cancelledAtStart {
			t.Errorf("lost=%v: fn's context still live when Release ran", lost)
		}
		if got := context.Cause(probe.ctx); lost != errors.Is(got, ErrLost) {
			t.Errorf("lost=%v: cause = %v", lost, got)
		}
		if lost != errors.Is(err, ErrLost) {
			t.Errorf("lost=%v: holdWhile = %v", lost, err)
		}
	}
}

func TestRunParentCancelIsNotLoss(t *testing.T) {
	fixSeams(t)
	conn := newTestConn()
	lease := bssh.NewFakeLease()
	conn.OnHold(lockScript(Mutating, "provision"), lease)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := Run(parent, conn, Mutating, "provision", func(ctx context.Context, _ bssh.Runner) error {
		cancel()
		waitDone(t, ctx.Done(), "the run context to follow its parent")
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrLost) {
		t.Fatalf("Run = %v, want context.Canceled and not ErrLost", err)
	}
	if !lease.Released() {
		t.Fatal("lease not released after the parent was cancelled")
	}
}

// TestRunParentCancelThenLeaseEndIsNotLoss: a cancelled parent is the
// caller's shutdown, and the ssh layer's cancel paths close the whole
// connection, which also ends the held command. A lease that ends after the
// parent was cancelled is that teardown, never loss — whether the watcher or
// the backstop sees it.
func TestRunParentCancelThenLeaseEndIsNotLoss(t *testing.T) {
	fixSeams(t)
	for i := range 200 {
		conn := newTestConn()
		lease := bssh.NewFakeLease()
		conn.OnHold(lockScript(Mutating, "provision"), lease)
		parent, cancel := context.WithCancel(context.Background())
		err := Run(parent, conn, Mutating, "provision", func(ctx context.Context, _ bssh.Runner) error {
			cancel()
			<-ctx.Done()
			lease.End() // the shutdown closed the connection, and the held command with it
			return ctx.Err()
		})
		cancel()
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrLost) {
			t.Fatalf("iteration %d: Run = %v, want context.Canceled and not ErrLost", i, err)
		}
		if !lease.Released() {
			t.Fatalf("iteration %d: lease not released", i)
		}
	}
}

func TestRunReleasesOnPanic(t *testing.T) {
	fixSeams(t)
	conn := newTestConn()
	lease := bssh.NewFakeLease()
	conn.OnHold(lockScript(Mutating, "provision"), lease)
	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Fatalf("recovered %v, want the fn panic", r)
			}
		}()
		_ = Run(context.Background(), conn, Mutating, "provision", func(context.Context, bssh.Runner) error {
			panic("boom")
		})
	}()
	if !lease.Released() {
		t.Fatal("lease not released after fn panicked")
	}
}

// TestRunReleasesOnGoexit: t.Fatal inside fn (runtime.Goexit, as in the
// integration test) still releases the lease.
func TestRunReleasesOnGoexit(t *testing.T) {
	fixSeams(t)
	conn := newTestConn()
	lease := bssh.NewFakeLease()
	conn.OnHold(lockScript(Mutating, "provision"), lease)
	ok := t.Run("fatal inside fn", func(t *testing.T) {
		_ = Run(context.Background(), conn, Mutating, "provision", func(context.Context, bssh.Runner) error {
			t.SkipNow() // Goexit, like t.Fatal, without failing the parent
			return nil
		})
	})
	if !ok {
		t.Fatal("subtest failed")
	}
	if !lease.Released() {
		t.Fatal("lease not released after fn called runtime.Goexit")
	}
}

func TestRunSendsHeartbeats(t *testing.T) {
	fixSeams(t)
	heartbeatInterval = 10 * time.Millisecond
	conn := newTestConn()
	lease := bssh.NewFakeLease()
	conn.OnHold(lockScript(Mutating, "provision"), lease)
	err := Run(context.Background(), conn, Mutating, "provision", func(context.Context, bssh.Runner) error {
		// At least 60 ms; polled up to a generous bound so a loaded CI
		// runner does not flake.
		time.Sleep(60 * time.Millisecond)
		deadline := time.Now().Add(5 * time.Second)
		for len(lease.Sent()) < 3 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run = %v", err)
	}
	sent := lease.Sent()
	if len(sent) < 3 {
		t.Fatalf("heartbeats sent = %d, want >= 3", len(sent))
	}
	for _, s := range sent {
		if s != "" {
			t.Fatalf("heartbeat %q, want an empty line", s)
		}
	}
	// The heartbeat goroutine is joined before Run returns: nothing more is
	// sent afterwards.
	n := len(lease.Sent())
	time.Sleep(30 * time.Millisecond)
	if got := len(lease.Sent()); got != n {
		t.Fatalf("heartbeats after Run returned: %d -> %d", n, got)
	}
}

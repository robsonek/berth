package ssh

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// The live Client both runs and holds commands.
var _ Conn = (*Client)(nil)

// errLeaseReleased is Send's answer once Release has started: the held
// command's stdin is closed (or closing) and nothing more may reach it.
var errLeaseReleased = errors.New("ssh: lease released")

// heldCmd is one remote command kept running on its own session. It becomes
// the Lease once the command has printed its ready line.
type heldCmd struct {
	c     *Client
	sess  *xssh.Session
	stdin io.WriteCloser
	errb  bytes.Buffer  // stderr; complete (and safe to read) once done is closed
	done  chan struct{} // closed when the command has ended (or never started)

	// Written by the waiter goroutine before it closes done.
	startErr error
	waitErr  error

	// mu serializes stdin writes with stdin's close: x/crypto/ssh's channel
	// is not safe for a concurrent Write and CloseWrite.
	mu       sync.Mutex
	released atomic.Bool

	releaseOnce sync.Once
	releaseErr  error
}

// readResult is the stdout reader's verdict: the ready line was seen, or
// stdout ended without it (stdout then holds everything printed).
type readResult struct {
	ready  bool
	stdout string
}

// Hold starts cmd — wrapped exactly like Run (c.privileged: as root through
// sudo on a non-root connection) — on its own session with stdin kept open,
// and returns a Lease once the command prints a line exactly equal to ready.
//
// Before ready, a command that ends yields *HoldExitError (exit code, all of
// its stdout, its stderr) — exit 0 included, since a command may report a
// verdict by ending; a cancelled ctx returns ctx.Err() at once and tears the
// session down in the background (TERM, close, connection close past
// execTeardownBudget — the exec pattern). After ready the lease is independent
// of ctx: the caller ends it with Release, and Done reports an end of any
// other kind. Stdout after the ready line is read and discarded, so the
// channel window never fills.
func (c *Client) Hold(ctx context.Context, cmd, ready string) (Lease, error) {
	sess, err := c.openSession(ctx)
	if err != nil {
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	h := &heldCmd{c: c, sess: sess, stdin: stdin, done: make(chan struct{})}
	sess.Stderr = &h.errb

	readc := make(chan readResult, 1) // buffered: the reader never blocks on it
	go func() {
		br := bufio.NewReader(stdout)
		var seen strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err == nil && strings.TrimSuffix(line, "\n") == ready {
				readc <- readResult{ready: true}
				_, _ = io.Copy(io.Discard, br)
				return
			}
			seen.WriteString(line)
			if err != nil { // EOF (the channel ended) or a dead transport
				readc <- readResult{stdout: seen.String()}
				return
			}
		}
	}()
	// Start sits behind the waiter too: it waits for the peer's reply to the
	// exec request, which must not hang Hold past ctx either.
	go func() {
		defer close(h.done)
		if err := sess.Start(c.privileged(cmd)); err != nil {
			h.startErr = err
			_ = sess.Close() // the channel's end gives the reader its EOF
			return
		}
		h.waitErr = sess.Wait()
	}()

	// Readiness is decided by stdout alone: a command that prints ready and
	// ends at once may finish its Wait before the reader reaches the line.
	select {
	case r := <-readc:
		if r.ready {
			return h, nil
		}
		select {
		case <-h.done:
			_ = sess.Close()
			return nil, h.exitError(r.stdout)
		case <-ctx.Done():
			go c.teardownHeld(sess, h.done)
			return nil, ctx.Err()
		}
	case <-ctx.Done():
		go c.teardownHeld(sess, h.done)
		return nil, ctx.Err()
	}
}

// exitError maps a command that ended before ready. Only call once done is
// closed. A non-zero exit is data (*HoldExitError); a start failure or an end
// without an exit status is a transport error, returned as is (like exec).
func (h *heldCmd) exitError(stdout string) error {
	if h.startErr != nil {
		return h.startErr
	}
	code := 0
	if h.waitErr != nil {
		var ee *xssh.ExitError
		if !errors.As(h.waitErr, &ee) {
			return h.waitErr
		}
		code = ee.ExitStatus()
	}
	return &HoldExitError{Code: code, Stdout: stdout, Stderr: h.errb.String()}
}

// Send writes line+"\n" to the held command's stdin.
func (h *heldCmd) Send(line string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.released.Load() {
		return errLeaseReleased
	}
	_, err := io.WriteString(h.stdin, line+"\n")
	return err
}

// Done is closed once the held command has ended, for any reason.
func (h *heldCmd) Done() <-chan struct{} { return h.done }

// Release closes stdin, waits up to wait for the command to end and closes
// the session. A command still running after wait is TERMed and its session
// closed in the background, and Release reports it. Later calls return the
// first call's result.
func (h *heldCmd) Release(wait time.Duration) error {
	h.releaseOnce.Do(func() { h.releaseErr = h.release(wait) })
	return h.releaseErr
}

func (h *heldCmd) release(wait time.Duration) error {
	h.released.Store(true)
	// The close waits for an in-flight Send and, like it, writes to the
	// transport: on a wedged peer it blocks, so it never holds up Release.
	// The teardown below closes the connection, which unblocks both.
	go func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		_ = h.stdin.Close()
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-h.done:
	case <-timer.C:
		select {
		case <-h.done: // ended right at the deadline: still a clean release
		default:
			go h.c.teardownHeld(h.sess, h.done)
			return fmt.Errorf("held command still running %s after release; sent it TERM and closed its session", wait)
		}
	}
	_ = h.sess.Close()
	return nil
}

// teardownHeld TERMs a held command and closes its session. Signal and Close
// both WRITE to the transport and block on a wedged peer, so they run in
// their own goroutine; if the command has not ended within
// execTeardownBudget the connection is closed, which unblocks everything.
// Callers run it in its own goroutine, as exec does.
func (c *Client) teardownHeld(sess *xssh.Session, ended <-chan struct{}) {
	go func() {
		_ = sess.Signal(xssh.SIGTERM)
		_ = sess.Close()
	}()
	select {
	case <-ended:
	case <-time.After(execTeardownBudget):
		_ = c.conn.Close()
	}
}

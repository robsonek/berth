// Package hostlock keeps one berth session per host: a run that changes the
// host (or reads it to compare against the config) holds an exclusive
// flock(2) on Path for its whole duration, so two workstations — or two
// terminals — never interleave on one server. The lock lives in a held SSH
// command (bssh.Holder): it is released when berth closes the command's
// stdin, and the host frees it on its own if berth disappears (the command
// reads EOF, or the lease runs out without a heartbeat).
//
// Pipeline steps never import this package: callers wrap the whole engine run
// in Run, and steps only ever see the Runner Run hands them.
package hostlock

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	bssh "github.com/robsonek/berth/internal/ssh"
)

// Mode says whether the session may prepare the lock file.
type Mode int

const (
	// Mutating is a run that changes the host (`provision`): it creates
	// /var/lib/berth and the lock file when missing, then takes the lock.
	Mutating Mode = iota
	// ReadOnly is a run that only reads (`provision --dry-run`,
	// `status --drift`): it never creates anything; with no lock file (a
	// fresh or pre-lock host, nothing of berth's to protect) it runs without
	// a lock. It still writes its holder line into an existing file.
	ReadOnly
)

// BusyError reports that another berth session holds the host. Holder is the
// first non-empty line of the lock file (host-supplied free text, trimmed —
// callers sanitize it for display like any other host output); "" when the
// file was empty — a new holder had not written its line yet, or the holder
// ended and cleared it just before the read — or it was unreadable.
type BusyError struct{ Holder string }

func (e *BusyError) Error() string {
	if e.Holder == "" {
		return "host is busy: another berth session holds " + Path + "; wait for it to finish"
	}
	return "host is busy: another berth session holds " + Path + " — " + e.Holder + "; wait for it to finish"
}

// ErrLost reports that the held lock ended while the session was still
// running (the lease expired after a network stall, or the holding process
// was killed on the host). Run cancels the session's context with it as the
// cause, refuses every later command through the Runner it handed out, and
// returns it.
var ErrLost = errors.New("lost the host session lock " + Path + " (the lease expired or the holding process ended); stopped before any further host change")

// Seams for Run's timing; tests shorten them.
var (
	// heartbeatInterval paces the empty lines that keep the held command's
	// `read -t` lease (leaseSeconds) from running out.
	heartbeatInterval = 20 * time.Second
	// releaseWait bounds how long Release waits for the held command to end,
	// so the next run from this workstation does not find the host busy.
	releaseWait = 5 * time.Second
)

// Run takes the host session lock on conn for mode, runs fn while holding it
// and releases it when fn returns — also when fn panics or calls
// runtime.Goexit (t.Fatal). command names the session in the holder line
// (e.g. "provision --only site").
//
// fn receives a context cancelled with cause ErrLost if the lock is lost, and
// a Runner that, from the moment the loss is observed, refuses every command
// with ErrLost without sending it. A ReadOnly run on a host without the lock
// file calls fn(ctx, conn) unlocked.
//
// The result is a *BusyError when another session holds the lock, an error
// naming the host session lock when it could not be taken (fail closed: fn
// does not run), ErrLost when the lock ended before fn returned while ctx was
// still live, and fn's own error otherwise.
//
// Shutdown contract: callers signal shutdown (an operator interrupt, a
// deadline, a renderer that stopped early) by cancelling ctx — the context
// passed to Run, or one of its parents — never only a context derived inside
// fn. The ssh layer's cancel paths may close the whole connection, which ends
// the held command too; a lease that ends once ctx is cancelled is that
// teardown, never loss. Cancelling ctx before fn returns therefore also
// waives the verdict on a loss Run had not yet observed.
func Run(ctx context.Context, conn bssh.Conn, mode Mode, command string, fn func(ctx context.Context, r bssh.Runner) error) error {
	lease, err := conn.Hold(ctx, Script(mode, HolderLine(command)), readyLine)
	if err != nil {
		var exit *bssh.HoldExitError
		if errors.As(err, &exit) {
			switch {
			case exit.Code == busyCode:
				return &BusyError{Holder: firstLine(exit.Stdout)}
			case mode == ReadOnly && exit.Code == 0 && firstLine(exit.Stdout) == absentLine:
				return fn(ctx, conn)
			}
		}
		return fmt.Errorf("host session lock: %w", err)
	}
	return holdWhile(ctx, lease, conn, heartbeatInterval, releaseWait, fn)
}

// holdWhile runs fn under lease. The loss verdict is decided only by Done
// and the caller's ctx: the lease is lost iff it ended before release started
// while ctx was still live. A cancelled ctx is the caller's shutdown (see Run),
// and the connection teardown it may cause ends the lease without losing
// anything. Both goroutines are joined before the result is computed, so the
// verdict is final and nothing touches the lease or the context after
// holdWhile returns.
func holdWhile(ctx context.Context, lease bssh.Lease, conn bssh.Runner, beat, wait time.Duration, fn func(ctx context.Context, r bssh.Runner) error) (err error) {
	lctx, cancel := context.WithCancelCause(ctx)
	guard := &guardedRunner{next: conn}
	// lose flags the Runner first, so whoever sees lctx cancelled also finds
	// every further command refused. Idempotent. A no-op once the caller's
	// ctx (the parent, not lctx) is cancelled: the lease ending then is the
	// shutdown's teardown, not loss. Checked at both sites that observe Done.
	lose := func() {
		if ctx.Err() != nil {
			return
		}
		guard.lost.Store(true)
		cancel(ErrLost)
	}

	stop := make(chan struct{})      // closed when release starts
	watched := make(chan struct{})   // closed when the watcher has exited
	heartbeat := make(chan struct{}) // closed when the heartbeat has exited
	go func() {
		defer close(watched)
		select {
		case <-lease.Done():
			lose()
		case <-stop:
		}
	}()
	go func() {
		defer close(heartbeat)
		sendHeartbeats(lease, beat, stop)
	}()

	defer func() {
		close(stop)
		<-watched // prompt: the watcher only selects
		// A lease that ended before release started is lost even if the
		// watcher picked stop or had not run yet — unless the caller already
		// shut down (lose checks ctx). From here on Done closing is the
		// release itself, never loss.
		select {
		case <-lease.Done():
			lose()
		default:
		}
		// Anything fn left running on lctx stops before the lock goes (after
		// the check above, so a loss keeps ErrLost as the cause).
		cancel(nil)
		// A Release error (the command outlived wait and was torn down) is
		// not loss: fn already ran under the lock. Its consequence: on a
		// wedged transport the host may not have seen the release, and
		// keeps the lock until it notices the closed channel or the lease
		// runs out (up to leaseSeconds), so a run started right after from
		// the same terminal can find the host busy.
		_ = lease.Release(wait)
		// Joined after Release: a heartbeat stuck in Send on a wedged
		// transport is unblocked by Release's teardown, never the reverse.
		<-heartbeat
		if guard.lost.Load() {
			err = ErrLost
		}
	}()
	return fn(lctx, guard)
}

// sendHeartbeats writes an empty line to the held command every beat until
// stop closes or the lease ends. Send errors are expected near the end and
// ignored: loss is decided by Done and the caller's ctx alone (holdWhile).
func sendHeartbeats(lease bssh.Lease, beat time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(beat)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-lease.Done():
			return
		case <-t.C:
			_ = lease.Send("")
		}
	}
}

// guardedRunner delegates to next until the loss is observed, then refuses
// every command with ErrLost without sending it: the engine checks its
// context only between steps, and one step sends many commands.
type guardedRunner struct {
	next bssh.Runner
	lost atomic.Bool
}

func (g *guardedRunner) Run(ctx context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	if g.lost.Load() {
		return bssh.Result{}, ErrLost
	}
	return g.next.Run(ctx, cmd, stdin)
}

func (g *guardedRunner) WriteFile(ctx context.Context, f bssh.FileSpec) error {
	if g.lost.Load() {
		return ErrLost
	}
	return g.next.WriteFile(ctx, f)
}

// firstLine is the first non-empty line of s, trimmed.
func firstLine(s string) string {
	for line := range strings.SplitSeq(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

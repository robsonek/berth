// Package ssh abstracts remote command execution and file writes.
package ssh

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"time"
)

// Result is the outcome of a remote command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// FileSpec describes an atomic remote file write.
type FileSpec struct {
	Path    string
	Content []byte
	Owner   string
	Group   string
	Mode    fs.FileMode
	Sudo    bool
}

// Runner executes commands and writes files on a target host.
// Implementations must pass secrets via stdin, never via the command string.
type Runner interface {
	Run(ctx context.Context, cmd string, stdin []byte) (Result, error)
	WriteFile(ctx context.Context, f FileSpec) error
}

// Lease is a remote command held running on its own SSH channel (see Holder).
type Lease interface {
	// Send writes line+"\n" to the held command's stdin.
	Send(line string) error
	// Done is closed once the remote command has ended, for any reason.
	Done() <-chan struct{}
	// Release closes the held command's stdin, waits up to wait for it to
	// end and closes the session. Idempotent: later calls return the first
	// call's result.
	Release(wait time.Duration) error
}

// Holder starts a remote command and keeps it running until released. Hold
// returns a Lease once the command prints a line exactly equal to ready; a
// command that ends first yields a *HoldExitError. Deliberately not part of
// Runner: steps never hold anything.
type Holder interface {
	Hold(ctx context.Context, cmd, ready string) (Lease, error)
}

// Conn is a connection that both runs commands and holds them (the live
// Client).
type Conn interface {
	Runner
	Holder
}

// HoldExitError reports a held command that ended before printing its ready
// line. Like a Run exit code it is data about the command, not a transport
// failure: Stdout is everything it printed (raw), Stderr its diagnostics.
type HoldExitError struct {
	Code           int
	Stdout, Stderr string
}

func (e *HoldExitError) Error() string {
	msg := fmt.Sprintf("held command exited with status %d before it was ready", e.Code)
	if s := strings.TrimSpace(e.Stderr); s != "" {
		msg += ": " + s
	}
	return msg
}

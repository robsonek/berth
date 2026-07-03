package ssh

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	xssh "golang.org/x/crypto/ssh"
)

// execTeardownBudget bounds the cancel-path session teardown. Signal and Close
// themselves WRITE to the SSH transport, so on a half-open peer they block; if
// the session has not unwound within this budget the connection is closed,
// which force-unblocks everything. Package var so tests could shrink it.
var execTeardownBudget = 5 * time.Second

// Client is the production Runner over a single SSH connection.
type Client struct {
	conn          *xssh.Client
	sftp          *sftp.Client
	useSudo       bool // true when connected as a non-root account
	stopKeepalive chan struct{}
	stopOnce      sync.Once
}

// Keepalive tuning. Package vars (not consts) so tests can shrink them — the
// resolveA stub pattern. Three 30s-spaced probes with a 10s reply budget give
// a worst-case dead-transport detection of ~2 minutes.
var (
	keepaliveInterval    = 30 * time.Second
	keepaliveReplyBudget = 10 * time.Second
	keepaliveMaxMissed   = 3
)

// keepalive probes the server with keepalive@openssh.com (the probe OpenSSH's
// ServerAliveInterval uses; ANY reply — even a failure — proves the transport
// is live) and closes the connection after keepaliveMaxMissed consecutive
// silent probes. Closing errors out every in-flight session and SFTP call,
// which is what unblocks a Run/WriteFile stuck on a half-open TCP connection.
// SendRequest itself can block forever on such a connection, so each probe
// gets its own reply budget; blocked probe goroutines (at most maxMissed) are
// freed when the connection closes.
func keepalive(conn *xssh.Client, stop <-chan struct{}) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	missed := 0
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			replied := make(chan struct{}, 1)
			go func() {
				_, _, _ = conn.SendRequest("keepalive@openssh.com", true, nil)
				replied <- struct{}{}
			}()
			select {
			case <-replied:
				missed = 0
			case <-time.After(keepaliveReplyBudget):
				missed++
				if missed >= keepaliveMaxMissed {
					conn.Close()
					return
				}
			case <-stop:
				return
			}
		}
	}
}

// Dial opens an SSH connection and SFTP subsystem. The keepalive loop starts
// before SFTP setup so a transport that dies mid-setup is detected and closed;
// ctx cancellation during setup closes the connection and returns ctx.Err().
// The TCP dial and the SSH handshake/auth both honor ctx too — cfg.Timeout
// covers only the TCP connect, so an SSH-deaf peer would otherwise hang the
// handshake forever.
func Dial(ctx context.Context, addr string, cfg *xssh.ClientConfig, useSudo bool) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: cfg.Timeout}
	netConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	type connResult struct {
		conn *xssh.Client
		err  error
	}
	cr := make(chan connResult, 1) // buffered: the goroutine never leaks
	go func() {
		// NewClientConn owns netConn on success; on error it closes it.
		cc, chans, reqs, err := xssh.NewClientConn(netConn, addr, cfg)
		if err != nil {
			cr <- connResult{nil, err}
			return
		}
		cr <- connResult{xssh.NewClient(cc, chans, reqs), nil}
	}()
	var conn *xssh.Client
	select {
	case r := <-cr:
		if r.err != nil {
			return nil, fmt.Errorf("dial %s: %w", addr, r.err)
		}
		conn = r.conn
	case <-ctx.Done():
		netConn.Close() // unblocks the handshake goroutine; its result is reaped below
		go func() {
			if r := <-cr; r.err == nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
	stop := make(chan struct{})
	go keepalive(conn, stop)

	type sftpResult struct {
		sc  *sftp.Client
		err error
	}
	res := make(chan sftpResult, 1) // buffered: the goroutine never leaks
	go func() {
		sc, err := sftp.NewClient(conn)
		res <- sftpResult{sc, err}
	}()
	select {
	case r := <-res:
		if r.err != nil {
			close(stop)
			conn.Close()
			return nil, fmt.Errorf("sftp: %w", r.err)
		}
		return &Client{conn: conn, sftp: r.sc, useSudo: useSudo, stopKeepalive: stop}, nil
	case <-ctx.Done():
		close(stop)
		conn.Close() // unblocks the NewClient goroutine; its result is discarded
		return nil, ctx.Err()
	}
}

// Close stops the keepalive loop and shuts down the connection. The
// connection closes FIRST: pkg/sftp's Close can block behind the conn
// mutex on a wedged transport, and berth never reuses a Client after
// Close, so the graceful SFTP shutdown buys nothing — after conn.Close
// the sftp.Close below returns immediately. Nil guards keep it safe on
// test-constructed Clients that skipped Dial.
func (c *Client) Close() error {
	if c.stopKeepalive != nil {
		c.stopOnce.Do(func() { close(c.stopKeepalive) })
	}
	err := c.conn.Close()
	if c.sftp != nil {
		c.sftp.Close()
	}
	return err
}

// Run executes cmd, feeding stdin, and returns stdout/stderr/exit code. When the
// connection is to a non-root account (useSudo), the command is run as root via
// sudo so privileged provisioning steps work without a root SSH login.
func (c *Client) Run(ctx context.Context, cmd string, stdin []byte) (Result, error) {
	return c.exec(ctx, c.privileged(cmd), stdin)
}

// privileged wraps cmd to run as root via sudo when connected as a non-root
// account; for a root connection it returns cmd unchanged. The original command
// is single-quoted and handed to `sh -c`, so its environment prefixes, pipes and
// redirections are preserved and the outer shell performs no expansion.
func (c *Client) privileged(cmd string) string {
	if !c.useSudo {
		return cmd
	}
	return "sudo -n -- /bin/sh -c " + shQuote(cmd)
}

// exec runs cmd verbatim over a new SSH session, with no sudo wrapping. WriteFile
// uses it directly so the temp file is created as the connecting (SFTP) user,
// while the privileged install carries its own sudo (see installCmd).
//
// Cancellation: sess.Run runs in a goroutine; ctx.Done() returns ctx.Err()
// IMMEDIATELY with a ZERO Result (the session's copy goroutines may still be
// writing the buffers — reading them would race). Teardown is asynchronous
// because Signal/Close write to the transport and would block on a half-open
// peer: best-effort SIGTERM (sshd delivers the signal request via killpg, so
// sudo/sh/apt all get TERM and apt releases its dpkg lock), session close,
// then — if the session hasn't unwound within execTeardownBudget — connection
// close as the escalation. The Client stays usable only on the normal unwind
// path; a wedged transport costs the whole connection, which is correct.
// The session open itself (NewSession) runs behind the same goroutine+select,
// so a peer that stalls channel opens cannot hang exec before the ctx-aware
// select either; with no session yet to TERM, cancellation there closes the
// connection and reaps a late-materializing session.
func (c *Client) exec(ctx context.Context, cmd string, stdin []byte) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	type sessResult struct {
		sess *xssh.Session
		err  error
	}
	sr := make(chan sessResult, 1) // buffered: the goroutine never leaks
	go func() {
		s, err := c.conn.NewSession()
		sr <- sessResult{s, err}
	}()
	var sess *xssh.Session
	select {
	case r := <-sr:
		if r.err != nil {
			return Result{}, r.err
		}
		sess = r.sess
	case <-ctx.Done():
		// No session yet to TERM: close the connection to unblock the open,
		// and reap the session if the open wins the race after all.
		go func() {
			if r := <-sr; r.err == nil {
				r.sess.Close()
			}
		}()
		c.conn.Close()
		return Result{}, ctx.Err()
	}
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	done := make(chan error, 1) // buffered: the goroutine never leaks
	go func() { done <- sess.Run(cmd) }()
	select {
	case runErr := <-done:
		sess.Close()
		res := Result{Stdout: out.String(), Stderr: errb.String()}
		if ee, ok := runErr.(*xssh.ExitError); ok {
			res.ExitCode = ee.ExitStatus()
			return res, nil // non-zero exit is a signal, not a transport error
		}
		return res, runErr
	case <-ctx.Done():
		go func() {
			// Signal/Close both WRITE to the transport — on a byte-dead peer
			// (saturated send buffer) they block too, so they live in their
			// own goroutine and the budget below covers them as well.
			go func() {
				_ = sess.Signal(xssh.SIGTERM)
				sess.Close()
			}()
			select {
			case <-done: // session unwound: connection stays usable
			case <-time.After(execTeardownBudget):
				c.conn.Close() // wedged transport: force-unblock everything, incl. the writes above
			}
		}()
		return Result{}, ctx.Err()
	}
}

// WriteFile writes content with ownership/mode via an unpredictable temp file
// and a privileged `install` (which copies + sets owner/group/mode in one step).
func (c *Client) WriteFile(ctx context.Context, f FileSpec) error {
	// Unpredictable temp path (avoids /tmp symlink/predictable-name races). Uses
	// exec (not Run) so the temp file is owned by the connecting user and the
	// subsequent SFTP upload can write to it.
	mk, err := c.exec(ctx, "mktemp", nil)
	if err != nil {
		return err
	}
	if mk.ExitCode != 0 {
		return fmt.Errorf("mktemp: %s", mk.Stderr)
	}
	tmp := strings.TrimSpace(mk.Stdout)

	if err := c.sftpPut(ctx, tmp, f.Content); err != nil {
		return err
	}

	// installCmd carries its own sudo when needed, so run it raw via exec.
	cmd, _ := installCmd(f, tmp, c.useSudo)
	if r, err := c.exec(ctx, cmd, nil); err != nil {
		return err
	} else if r.ExitCode != 0 {
		return fmt.Errorf("install %s failed: %s", f.Path, r.Stderr)
	}
	return nil
}

// sftpPut uploads content to remotePath over SFTP. The SFTP client has no context
// support, so the upload runs in a goroutine; on cancellation the UNDERLYING
// CONNECTION is closed — a non-blocking net-level close that unblocks the
// in-flight SFTP call. Deliberately not c.sftp.Close(): pkg/sftp's Close can
// itself block behind the connection mutex / recv goroutine. Losing the whole
// connection is fine — a cancelled ctx means the run is shutting down, and
// any later call fails cleanly on the closed connection. The staged temp file
// may survive on the host (unpredictable mktemp name, 0600 — the same
// exposure as today's failure paths).
func (c *Client) sftpPut(ctx context.Context, remotePath string, content []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1) // buffered: the goroutine never leaks
	go func() {
		w, err := c.sftp.OpenFile(remotePath, os.O_WRONLY|os.O_TRUNC)
		if err != nil {
			done <- fmt.Errorf("open temp %s: %w", remotePath, err)
			return
		}
		if _, err := w.Write(content); err != nil {
			w.Close()
			done <- err
			return
		}
		if err := w.Close(); err != nil { // Close flushes; surface deferred write errors
			done <- fmt.Errorf("flush temp %s: %w", remotePath, err)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		c.conn.Close()
		return ctx.Err()
	}
}

// installCmd builds the privileged install command; all path/owner values are
// shell-quoted (defence-in-depth on top of config validation). The staged copy
// is mktemp'd in the DESTINATION directory — unpredictable name (no
// symlink-plant window in tenant-writable dirs) on the same filesystem — so
// the final `mv -f` is an atomic rename(2): a failure anywhere in the chain
// leaves the old destination intact, never a partial file. Because the chain
// starts with a variable assignment, the privileged form wraps it whole in
// `sudo -n sh -c`. It is a pure function so it can be unit-tested without an
// SSH connection.
func installCmd(f FileSpec, tmp string, useSudo bool) (cmd, tmpOut string) {
	mode := f.Mode
	if mode == 0 {
		mode = 0o644
	}
	owner, group := f.Owner, f.Group
	if owner == "" {
		owner = "root"
	}
	if group == "" {
		group = owner
	}
	cmd = fmt.Sprintf(`t=$(mktemp %s) && install -o %s -g %s -m %o %s "$t" && mv -f "$t" %s && rm -f %s`,
		shQuote(path.Dir(f.Path)+"/.berth.XXXXXX"),
		shQuote(owner), shQuote(group), mode.Perm(), shQuote(tmp), shQuote(f.Path), shQuote(tmp))
	if f.Sudo && useSudo {
		cmd = "sudo -n sh -c " + shQuote(cmd)
	}
	return cmd, tmp
}

// shQuote single-quotes s for safe shell use.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

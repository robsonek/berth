package ssh

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/sftp"
	xssh "golang.org/x/crypto/ssh"
)

// Client is the production Runner over a single SSH connection.
type Client struct {
	conn    *xssh.Client
	sftp    *sftp.Client
	useSudo bool // true when connected as a non-root account
}

// Dial opens an SSH connection and SFTP subsystem.
func Dial(ctx context.Context, addr string, cfg *xssh.ClientConfig, useSudo bool) (*Client, error) {
	conn, err := xssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	sc, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("sftp: %w", err)
	}
	return &Client{conn: conn, sftp: sc, useSudo: useSudo}, nil
}

// Close shuts down the SFTP subsystem and the underlying connection.
func (c *Client) Close() error { c.sftp.Close(); return c.conn.Close() }

// Run executes cmd, feeding stdin, and returns stdout/stderr/exit code.
func (c *Client) Run(ctx context.Context, cmd string, stdin []byte) (Result, error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return Result{}, err
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	runErr := sess.Run(cmd)
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	if ee, ok := runErr.(*xssh.ExitError); ok {
		res.ExitCode = ee.ExitStatus()
		return res, nil // non-zero exit is a signal, not a transport error
	}
	return res, runErr
}

// WriteFile writes content with ownership/mode via an unpredictable temp file
// and a privileged `install` (which copies + sets owner/group/mode in one step).
func (c *Client) WriteFile(ctx context.Context, f FileSpec) error {
	// Unpredictable temp path (avoids /tmp symlink/predictable-name races).
	mk, err := c.Run(ctx, "mktemp", nil)
	if err != nil {
		return err
	}
	if mk.ExitCode != 0 {
		return fmt.Errorf("mktemp: %s", mk.Stderr)
	}
	tmp := strings.TrimSpace(mk.Stdout)

	w, err := c.sftp.OpenFile(tmp, os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("open temp %s: %w", tmp, err)
	}
	if _, err := w.Write(f.Content); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil { // Close flushes; surface deferred write errors
		return fmt.Errorf("flush temp %s: %w", tmp, err)
	}

	cmd, _ := installCmd(f, tmp, c.useSudo)
	if r, err := c.Run(ctx, cmd, nil); err != nil {
		return err
	} else if r.ExitCode != 0 {
		return fmt.Errorf("install %s failed: %s", f.Path, r.Stderr)
	}
	return nil
}

// installCmd builds the privileged install command; all path/owner values are
// shell-quoted (defence-in-depth on top of config validation). It is a pure
// function so it can be unit-tested without an SSH connection.
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
	cmd = fmt.Sprintf("install -o %s -g %s -m %o %s %s && rm -f %s",
		shQuote(owner), shQuote(group), mode.Perm(), shQuote(tmp), shQuote(f.Path), shQuote(tmp))
	if f.Sudo && useSudo {
		cmd = "sudo " + cmd
	}
	return cmd, tmp
}

// shQuote single-quotes s for safe shell use.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

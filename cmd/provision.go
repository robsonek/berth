package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/hostlock"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/provision/steps"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/ui"
)

type provisionFlags struct {
	dryRun         bool
	skipSSL        bool
	sslStaging     bool
	only           string
	force          bool
	allowDowngrade bool
	verbose        bool
	noTTY          bool
}

func newProvisionCmd() *cobra.Command {
	f := &provisionFlags{}
	c := &cobra.Command{
		Use:   "provision <server>",
		Short: "Provision a server from its config file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProvision(cmd, args[0], f)
		},
	}
	c.Flags().BoolVar(&f.dryRun, "dry-run", false, "report changes without applying them")
	c.Flags().BoolVar(&f.skipSSL, "skip-ssl", false, "skip the TLS phase")
	c.Flags().BoolVar(&f.sslStaging, "ssl-staging", false, "use Let's Encrypt staging")
	c.Flags().StringVar(&f.only, "only", "", "run only the named phase or step")
	c.Flags().BoolVar(&f.force, "force", false, "overwrite resources not managed by berth; also re-bind the local secret cache after a deliberate endpoint (host/port) change; with --only it applies to the target step alone")
	c.Flags().BoolVar(&f.allowDowngrade, "allow-downgrade", false, "run even though a newer berth version already changed this host (deliberate rollback); --force does not imply this")
	c.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "plain output with reasons for satisfied steps and changes for applied ones")
	c.Flags().BoolVar(&f.noTTY, "no-tty", false, "force plain output (no live TUI)")
	return c
}

// wantTUI reports whether the live TUI should render this run. Dry-run always
// uses the plain renderer: a plan is a report to read or pipe, and the TUI has
// no planned-changes view.
func wantTUI(stdoutIsTTY bool, f *provisionFlags) bool {
	return stdoutIsTTY && !f.verbose && !f.noTTY && !f.dryRun
}

// provisionConn is the connection `berth provision` drives: remote commands,
// the held session-lock command, and Close when the run ends.
type provisionConn interface {
	bssh.Conn
	Close() error
}

// connectProvision dials the server for `berth provision`. A seam: tests
// substitute a connection without a host.
var connectProvision = func(ctx context.Context, srv *config.Server, p bssh.HostKeyPolicy) (provisionConn, error) {
	c, err := bssh.Connect(ctx, srv, p)
	if err != nil {
		return nil, err // never a nil *Client inside a non-nil interface
	}
	return c, nil
}

// renderRun renders the engine's events for this run and returns the run's
// failure. A seam: tests substitute a renderer that stops before the engine
// finishes, as a TUI interrupt does.
var renderRun = func(cmd *cobra.Command, f *provisionFlags, events <-chan provision.Event) error {
	return ui.New(cmd.OutOrStdout(), wantTUI(ui.IsTTY(os.Stdout), f), f.verbose).Render(events)
}

// engineStopped reports, without blocking, whether the engine has closed its
// event channel — true after a renderer that read it to the end. It may
// consume one pending event; the caller drains the rest anyway.
func engineStopped(events <-chan provision.Event) bool {
	select {
	case _, ok := <-events:
		return !ok
	default:
		return false
	}
}

// sessionMode is the host session lock this run takes and the command its
// holder line names. A dry-run only reads (ReadOnly never creates the lock
// file); every other run changes the host. No other flag matters: --force,
// --allow-downgrade and --skip-ssl never bypass or weaken the lock, and
// --only merely names the target in the holder line.
func sessionMode(f *provisionFlags) (hostlock.Mode, string) {
	mode, command := hostlock.Mutating, "provision"
	if f.dryRun {
		mode, command = hostlock.ReadOnly, command+" --dry-run"
	}
	if f.only != "" {
		command += " --only " + f.only
	}
	return mode, command
}

func runProvision(cmd *cobra.Command, serverPath string, f *provisionFlags) error {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	srv, err := config.Load(serverPath)
	if err != nil {
		return err
	}
	red := secret.NewRedactor()
	client, err := connectProvision(ctx, srv, bssh.HostKeyPolicy{
		Pinned: srv.SSH.Fingerprint, KnownHosts: defaultKnownHosts(),
		AllowTOFU: ui.IsTTY(os.Stdin), ConfirmTOFU: confirmFingerprint(cmd),
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	// One berth session per host: the lock is taken right after connecting,
	// before the engine's first step (identity, preflight), and held until the
	// run ends. A busy host stops here — no pipeline command reaches it.
	mode, command := sessionMode(f)
	err = hostlock.Run(ctx, client, mode, command, func(lctx context.Context, r bssh.Runner) error {
		// The whole run happens in here, on the lock's context and guarded
		// Runner: neither may be used once this function returns.
		//
		// The SAME redactor instance feeds the steps (they register secrets
		// on acquisition) and the engine's output policy (it masks every
		// event and the pre-flight error).
		eng := provision.New(steps.Pipeline(srv, red, f.skipSSL)...)
		events, err := eng.Run(lctx, srv, r, provision.Options{
			DryRun: f.dryRun, Only: f.only, Force: f.force, SSLStaging: f.sslStaging, Redact: red,
			AllowDowngrade: f.allowDowngrade,
		})
		if err != nil {
			return err
		}
		rerr := renderRun(cmd, f, events)
		// A renderer that returned before the engine finished (a TUI
		// interrupt, a renderer error) is a shutdown: cancel explicitly,
		// BEFORE the lock's release and the deferred client.Close (LIFO would
		// close the SSH connection first), so the engine starts no further
		// step. The ssh layer TERMs and abandons an in-flight remote command
		// on cancellation, and may close the whole connection — which also
		// ends the held lock command. Cancelling ctx, the parent hostlock.Run
		// was given (never a context derived inside this function), is what
		// makes that teardown a shutdown rather than a lost lock. After a
		// renderer that read to the end the engine has already stopped and
		// nothing is cancelled here, so a loss the lock had not yet observed
		// is still reported.
		if !engineStopped(events) {
			cancel()
		}
		// Then wait for the engine to stop (it closes the channel when its
		// goroutine ends; a no-op after a renderer that read to the end), so
		// nothing still holds the lock's Runner when the lock is released.
		for range events {
		}
		return rerr
	})
	// err is the busy error (nothing ran), ErrLost when the lock ended
	// mid-run while the run was live (it outranks the renderer's
	// "interrupted" symptom; an operator interrupt or SIGINT cancels ctx
	// first, so its connection teardown is never reported as a lost lock),
	// or the run's own error. Defence in depth at the command boundary: cobra
	// prints this error again, and renderer-internal errors never passed
	// through the engine's masking.
	return provision.RedactError(red, err)
}

// defaultKnownHosts returns the conventional path to the user's known_hosts file.
func defaultKnownHosts() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

// confirmFingerprint returns a TOFU confirmation callback that prints the host
// key type + fingerprint and reads a y/N answer from stdin. Showing the key's
// type matters: this exact fingerprint is what the operator will pin as
// ssh.fingerprint, and ssh-keyscan prints one line per key type.
func confirmFingerprint(cmd *cobra.Command) func(host, fingerprint, keyType string) bool {
	return func(host, fingerprint, keyType string) bool {
		out := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(out, "The authenticity of host %q can't be established.\n", host)
		_, _ = fmt.Fprintf(out, "Key fingerprint is %s (%s)\n", fingerprint, keyType)
		_, _ = fmt.Fprint(out, "Are you sure you want to continue connecting (y/N)? ")
		reader := bufio.NewReader(cmd.InOrStdin())
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return false
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		return answer == "y" || answer == "yes"
	}
}

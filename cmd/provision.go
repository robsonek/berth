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
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/provision/steps"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/ui"
)

type provisionFlags struct {
	dryRun     bool
	skipSSL    bool
	sslStaging bool
	only       string
	force      bool
	verbose    bool
	noTTY      bool
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
	c.Flags().BoolVar(&f.force, "force", false, "overwrite resources not managed by berth")
	c.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "verbose output")
	c.Flags().BoolVar(&f.noTTY, "no-tty", false, "force plain output (no live TUI)")
	return c
}

// wantTUI reports whether the live TUI should render this run. Dry-run always
// uses the plain renderer: a plan is a report to read or pipe, and the TUI has
// no planned-changes view.
func wantTUI(stdoutIsTTY bool, f *provisionFlags) bool {
	return stdoutIsTTY && !f.verbose && !f.noTTY && !f.dryRun
}

func runProvision(cmd *cobra.Command, serverPath string, f *provisionFlags) error {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	srv, err := config.Load(serverPath)
	if err != nil {
		return err
	}
	red := secret.NewRedactor()
	client, err := bssh.Connect(ctx, srv, bssh.HostKeyPolicy{
		Pinned: srv.SSH.Fingerprint, KnownHosts: defaultKnownHosts(),
		AllowTOFU: ui.IsTTY(os.Stdin), ConfirmTOFU: confirmFingerprint(cmd),
	})
	if err != nil {
		return err
	}
	defer client.Close()

	eng := provision.New(steps.Pipeline(srv, red, f.skipSSL)...)
	events, err := eng.Run(ctx, srv, client, provision.Options{
		DryRun: f.dryRun, Only: f.only, Force: f.force, SSLStaging: f.sslStaging,
	})
	if err != nil {
		return err
	}
	r := ui.New(cmd.OutOrStdout(), wantTUI(ui.IsTTY(os.Stdout), f))
	rerr := r.Render(events)
	// Cancel explicitly BEFORE the deferred client.Close (LIFO would close the
	// SSH connection first): the engine must not start another step once the
	// renderer has returned, e.g. after a TUI interrupt. A step already in
	// flight is not cancelled (ssh.Runner ignores ctx — documented limitation).
	cancel()
	return rerr
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
// key fingerprint and reads a y/N answer from stdin.
func confirmFingerprint(cmd *cobra.Command) func(host, fingerprint string) bool {
	return func(host, fingerprint string) bool {
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "The authenticity of host %q can't be established.\n", host)
		fmt.Fprintf(out, "Key fingerprint is %s\n", fingerprint)
		fmt.Fprint(out, "Are you sure you want to continue connecting (y/N)? ")
		reader := bufio.NewReader(cmd.InOrStdin())
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return false
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		return answer == "y" || answer == "yes"
	}
}

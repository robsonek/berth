package cmd

import (
	"github.com/spf13/cobra"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
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

// steps returns the ordered pipeline. Empty in Plan 1; Plan 2 fills it.
func steps(_ *config.Server) []provision.Step { return nil }

func runProvision(cmd *cobra.Command, serverPath string, f *provisionFlags) error {
	srv, err := config.Load(serverPath)
	if err != nil {
		return err
	}
	// Plan 1 ships no real ssh connection; the engine runs against a config-only
	// pipeline. Plan 2 introduces the live ssh.Runner and the connection model.
	eng := provision.New(steps(srv)...)
	events, err := eng.Run(cmd.Context(), srv, nil, provision.Options{
		DryRun: f.dryRun,
		Only:   f.only,
	})
	if err != nil {
		return err
	}
	r := ui.NewPlainRenderer(cmd.OutOrStdout())
	return r.Render(events)
}

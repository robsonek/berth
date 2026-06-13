package cmd

import (
	"github.com/spf13/cobra"
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
			// Wiring to the engine lands in Plan 1 Task 11.
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

func runProvision(cmd *cobra.Command, server string, f *provisionFlags) error {
	return errNotImplemented("provision (engine wiring lands in Task 11)")
}

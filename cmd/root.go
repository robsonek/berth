// Package cmd wires the berth command-line interface.
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/robsonek/berth/internal/version"
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "berth",
		Short:         "Provision a fresh Debian 13 server for Laravel apps",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
	}
	root.SetVersionTemplate(version.String() + "\n")
	root.AddCommand(newInitCmd(), newProvisionCmd(), newSiteCmd())
	return root
}

func errNotImplemented(what string) error {
	return errors.New(what + " is not implemented yet")
}

// Execute runs the root command and exits non-zero on error.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

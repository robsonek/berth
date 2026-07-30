// Package cmd wires the berth command-line interface.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/robsonek/berth/internal/ui"
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
	root.AddCommand(newInitCmd(), newProvisionCmd(), newSiteCmd(), newSecretCmd(), newStatusCmd())
	return root
}

func errNotImplemented(what string) error {
	return errors.New(what + " is not implemented yet")
}

// Execute runs the root command and exits non-zero on error. SIGINT/SIGTERM
// cancel the command context: the ssh layer best-effort-SIGTERMs the
// in-flight remote command and returns immediately, and the engine stops.
// After the first signal default handling is restored, so a second ctrl+c
// force-kills the CLI if anything still refuses to die.
func Execute() {
	if err := run(); err != nil {
		// Error text can embed remote-derived strings (probe stderr, drift
		// reasons); sanitize this final print like the renderers do — keeping
		// the deliberate multi-line remedies — so a hostile host cannot drive
		// the terminal through the exit message either.
		fmt.Fprintln(os.Stderr, "error:", ui.SanitizeBlock(err.Error()))
		os.Exit(1)
	}
}

// run is split from Execute so its deferred signal cleanup runs before
// Execute's os.Exit.
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	return newRootCmd().ExecuteContext(ctx)
}

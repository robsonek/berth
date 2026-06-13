package cmd

import "github.com/spf13/cobra"

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Interactive wizard that writes a server config",
		RunE: func(cmd *cobra.Command, args []string) error {
			// The huh wizard is implemented in Plan 3.
			return errNotImplemented("init wizard")
		},
	}
}

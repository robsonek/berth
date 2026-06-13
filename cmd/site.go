package cmd

import "github.com/spf13/cobra"

func newSiteCmd() *cobra.Command {
	c := &cobra.Command{Use: "site", Short: "Manage sites on a server"}
	c.AddCommand(&cobra.Command{
		Use:   "add <server>",
		Short: "Add another site to an existing server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errNotImplemented("site:add") // post-v1
		},
	})
	return c
}

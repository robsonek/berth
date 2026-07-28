package cmd

import (
	"fmt"

	"github.com/robsonek/berth/internal/wizard"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Interactive wizard that writes a server config",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := wizard.Run()
			if err != nil {
				return err
			}
			path, err := a.Write()
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s — run: berth provision %s\n", path, path)
			return nil
		},
	}
}

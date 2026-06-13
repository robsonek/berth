package cmd

import (
	"fmt"
	"os"
	"strings"

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
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s — run: berth provision %s\n", path, path)
			return ensureGitignore()
		},
	}
}

// ensureGitignore appends berth's local-state ignore rules to .gitignore if
// they are absent, creating the file when needed. It is idempotent.
func ensureGitignore() error {
	const path = ".gitignore"
	want := []string{".berth/", "*.secrets*"}

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	have := map[string]bool{}
	for _, line := range strings.Split(string(existing), "\n") {
		have[strings.TrimSpace(line)] = true
	}

	var add []string
	for _, w := range want {
		if !have[w] {
			add = append(add, w)
		}
	}
	if len(add) == 0 {
		return nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}
	for _, line := range add {
		if _, err := f.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return nil
}

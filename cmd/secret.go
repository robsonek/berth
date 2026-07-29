package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/secret"
	"github.com/spf13/cobra"
)

func newSecretCmd() *cobra.Command {
	c := &cobra.Command{Use: "secret", Short: "Manage the local secret cache for a server"}
	c.AddCommand(newSecretSetCmd())
	return c
}

// maxSecretLen bounds one secret value; longest real-world offsite credential
// classes (S3 secret keys, session-token-free) sit far below it.
const maxSecretLen = 4096

func newSecretSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <server> <name>",
		Short: "Store one named secret in the local cache (value read from stdin)",
		Long: "Reads the secret VALUE from stdin (never from argv - shell history),\n" +
			"validates it, and stores it in the server's local secret cache\n" +
			"(~/.berth/<id>.secrets.json). Settable names: " + strings.Join(secret.SettableNames(), ", "),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			srv, err := config.Load(args[0])
			if err != nil {
				return err
			}
			name := args[1]
			settable := false
			for _, n := range secret.SettableNames() {
				if n == name {
					settable = true
					break
				}
			}
			if !settable {
				return fmt.Errorf("secret %q is not settable (settable: %s)", name, strings.Join(secret.SettableNames(), ", "))
			}
			// +3 headroom: a full-length value may still carry ONE
			// terminal CRLF from the shell pipe; anything beyond that is
			// oversize or multi-line and gets rejected by the validator.
			raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxSecretLen+3))
			if err != nil {
				return fmt.Errorf("read secret value from stdin: %w", err)
			}
			// Strip at most ONE terminal newline (LF or CRLF) — the one the
			// shell adds. Any remaining CR/LF means multi-line input and is
			// the validator's job to reject, never silently trimmed.
			value := strings.TrimSuffix(string(raw), "\n")
			value = strings.TrimSuffix(value, "\r")
			if err := secret.ValidateSecretValue(value); err != nil {
				return err
			}
			release, err := secret.LockCache(srv.CacheKey())
			if err != nil {
				return err
			}
			defer release()
			env, err := secret.LoadEnvelope(srv.CacheKey())
			if err != nil {
				return err
			}
			if err := secret.VerifyEnvelope(env, srv.Host, srv.SSH.Port); err != nil {
				return err
			}
			secrets := map[string]string{}
			if env != nil {
				secrets = env.Secrets
			}
			secrets[name] = value
			if err := secret.SaveEnvelope(srv.CacheKey(), secret.Envelope{
				Endpoint: &secret.Endpoint{Host: srv.Host, Port: srv.SSH.Port},
				Secrets:  secrets,
			}); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "stored %s in the local cache for %s\n", name, srv.CacheKey())
			return nil
		},
	}
}

package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/robsonek/berth/internal/config"
	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Connect returns a Client, preferring the 'berth' provisioning account and
// falling back to the configured bootstrap user (typically root).
func Connect(ctx context.Context, s *config.Server, policy HostKeyPolicy) (*Client, error) {
	auth, err := authMethods(s.SSH.Key)
	if err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("%s:%d", s.Host, s.SSH.Port)

	// Try the steady-state provisioning account first.
	if c, err := Dial(ctx, addr, clientConfig("berth", auth, policy), true); err == nil {
		if r, e := c.Run(ctx, "sudo -n true", nil); e == nil && r.ExitCode == 0 {
			return c, nil
		}
		c.Close()
	}
	// Bootstrap: connect as the configured user (root on a fresh box).
	return Dial(ctx, addr, clientConfig(s.SSH.User, auth, policy), s.SSH.User != "root")
}

func clientConfig(user string, auth []xssh.AuthMethod, policy HostKeyPolicy) *xssh.ClientConfig {
	return &xssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: HostKeyChecker(policy),
		Timeout:         15 * time.Second,
	}
}

// ClientConfig is the exported form of clientConfig; callers that need to dial a
// specific account directly (e.g. the hardening anti-lockout gate, which must
// connect as berth without the Connect auto-detect/root fallback) use it.
func ClientConfig(user string, auth []xssh.AuthMethod, policy HostKeyPolicy) *xssh.ClientConfig {
	return clientConfig(user, auth, policy)
}

// AuthMethods is the exported form of authMethods (ssh-agent then key file).
func AuthMethods(keyPath string) ([]xssh.AuthMethod, error) { return authMethods(keyPath) }

// authMethods prefers ssh-agent (SSH_AUTH_SOCK), then the configured key file.
// Passphrase-protected keys are supported by loading them into the agent.
func authMethods(keyPath string) ([]xssh.AuthMethod, error) {
	var methods []xssh.AuthMethod
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			methods = append(methods, xssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	if keyPath != "" {
		if b, err := os.ReadFile(expandHome(keyPath)); err == nil {
			signer, perr := xssh.ParsePrivateKey(b)
			if perr != nil {
				return nil, fmt.Errorf("parse ssh key %s: %w (for passphrase-protected keys, use ssh-agent)", keyPath, perr)
			}
			methods = append(methods, xssh.PublicKeys(signer))
		}
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH auth available: set ssh.key to a readable key or load one into ssh-agent")
	}
	return methods, nil
}

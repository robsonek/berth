package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyPolicy configures how a server's host key is verified.
type HostKeyPolicy struct {
	Pinned      string                              // optional "SHA256:..." fingerprint; if set, must match
	KnownHosts  string                              // path to known_hosts (default ~/.ssh/known_hosts)
	AllowTOFU   bool                                // prompt + pin on first contact when not pinned/known
	ConfirmTOFU func(host, fingerprint string) bool // interactive confirm
}

// Fingerprint returns the SHA256 fingerprint of a public key ("SHA256:...").
func Fingerprint(k xssh.PublicKey) string { return xssh.FingerprintSHA256(k) }

// HostKeyChecker builds a HostKeyCallback. It never returns InsecureIgnoreHostKey.
// Order: pinned fingerprint (if set) -> known_hosts -> TOFU confirmation.
func HostKeyChecker(p HostKeyPolicy) xssh.HostKeyCallback {
	var known xssh.HostKeyCallback
	if p.KnownHosts != "" {
		if cb, err := knownhosts.New(expandHome(p.KnownHosts)); err == nil {
			known = cb
		}
	}
	return func(hostname string, remote net.Addr, key xssh.PublicKey) error {
		fp := Fingerprint(key)
		// 1) Explicit pin wins.
		if p.Pinned != "" {
			if fp != p.Pinned {
				return fmt.Errorf("host key fingerprint %s does not match pinned %s", fp, p.Pinned)
			}
			return nil
		}
		// 2) known_hosts.
		if known != nil {
			switch err := known(hostname, remote, key); {
			case err == nil:
				return nil // recognized host + key
			case isKnownHostsMismatch(err):
				return fmt.Errorf("host key mismatch for %s (%s) — refusing (possible MITM)", hostname, fp)
				// default: unknown host → fall through to TOFU
			}
		}
		// 3) TOFU with explicit confirmation, then pin to known_hosts.
		if p.AllowTOFU && p.ConfirmTOFU != nil && p.ConfirmTOFU(hostname, fp) {
			return appendKnownHost(p.KnownHosts, hostname, key)
		}
		return fmt.Errorf("unknown host key for %s (%s); pin via ssh.fingerprint or confirm interactively", hostname, fp)
	}
}

// isKnownHostsMismatch is true when the host is present with a different key.
func isKnownHostsMismatch(err error) bool {
	var ke *knownhosts.KeyError
	return errors.As(err, &ke) && len(ke.Want) > 0
}

// appendKnownHost pins a confirmed host key to the known_hosts file (0600).
func appendKnownHost(path, hostname string, key xssh.PublicKey) error {
	f, err := os.OpenFile(expandHome(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, knownhosts.Line([]string{hostname}, key))
	return err
}

// expandHome replaces a leading "~" with the user's home directory. It is the
// single shared path-expansion helper for the ssh package (reused by connect.go).
func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

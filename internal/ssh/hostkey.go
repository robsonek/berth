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
	Pinned      string                                       // optional "SHA256:..." fingerprint; if set, must match
	KnownHosts  string                                       // path to known_hosts (default ~/.ssh/known_hosts)
	AllowTOFU   bool                                         // prompt + pin on first contact when not pinned/known
	ConfirmTOFU func(host, fingerprint, keyType string) bool // interactive confirm; keyType is the presented key's type (e.g. ecdsa-sha2-nistp256)
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
		// Every message names the presented key's TYPE (key.Type() — the label
		// ssh-keyscan/ssh-keygen print per line, e.g. ssh-rsa even when the
		// signature algorithm negotiated for it is rsa-sha2-*): a server offers
		// one key per type, so a pin taken from the wrong scan line (e.g. its
		// ed25519 output when this client selects ECDSA) mismatches even though
		// the server is genuine — the type is what disambiguates.
		// 1) Explicit pin wins.
		if p.Pinned != "" {
			if fp != p.Pinned {
				return fmt.Errorf("host key (%s) fingerprint %s does not match pinned %s — a server has one key per type; compare all with: ssh-keyscan HOST | ssh-keygen -lf -", key.Type(), fp, p.Pinned)
			}
			return nil
		}
		// 2) known_hosts.
		if known != nil {
			switch err := known(hostname, remote, key); {
			case err == nil:
				return nil // recognized host + key
			case isKnownHostsMismatch(err):
				return fmt.Errorf("host key mismatch for %s (%s %s) — refusing (possible MITM)", hostname, key.Type(), fp)
				// default: unknown host → fall through to TOFU
			}
		}
		// 3) TOFU with explicit confirmation, then pin to known_hosts.
		if p.AllowTOFU && p.ConfirmTOFU != nil && p.ConfirmTOFU(hostname, fp, key.Type()) {
			return appendKnownHost(p.KnownHosts, hostname, key)
		}
		return fmt.Errorf("unknown host key for %s (%s %s); pin via ssh.fingerprint or confirm interactively", hostname, key.Type(), fp)
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
	if _, err := fmt.Fprintln(f, knownhosts.Line([]string{hostname}, key)); err != nil {
		_ = f.Close()
		return err
	}
	// A swallowed close error could report the key as pinned while the write
	// never became durable — the next connect would then fail as unknown host.
	return f.Close()
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

//go:build !integration

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xssh "golang.org/x/crypto/ssh"
)

func TestClientConfigUsesCallbackNotInsecure(t *testing.T) {
	cfg := clientConfig("berth", nil, HostKeyPolicy{Pinned: "SHA256:x"})
	if cfg.User != "berth" {
		t.Errorf("user = %q", cfg.User)
	}
	if cfg.HostKeyCallback == nil {
		t.Error("HostKeyCallback must be set (never InsecureIgnoreHostKey)")
	}
}

// writeKey marshals an ed25519 private key to a temp PEM file, optionally
// passphrase-protected, and returns its path.
func writeKey(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = xssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = xssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKeyFileAuth(t *testing.T) {
	plain := writeKey(t, "")
	protected := writeKey(t, "s3cret")
	missing := filepath.Join(t.TempDir(), "nope")

	// Empty path: no method, no error.
	if m, err := keyFileAuth("", false); m != nil || err != nil {
		t.Errorf(`keyFileAuth("",false) = %v,%v; want nil,nil`, m, err)
	}
	// Missing/unreadable file: non-fatal (the agent may cover it).
	if m, err := keyFileAuth(missing, false); m != nil || err != nil {
		t.Errorf("keyFileAuth(missing,false) = %v,%v; want nil,nil", m, err)
	}
	// A plain (unencrypted) key always yields a usable method.
	if m, err := keyFileAuth(plain, false); m == nil || err != nil {
		t.Errorf("keyFileAuth(plain,false) = %v,%v; want method,nil", m, err)
	}
	// A passphrase-protected key with NO other auth is a clear, fatal error.
	if m, err := keyFileAuth(protected, false); m != nil || err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("keyFileAuth(protected,false) = %v,%v; want nil + passphrase error", m, err)
	}
	// A passphrase-protected key is skipped (non-fatal) when another method
	// (e.g. ssh-agent) is already available — this is the documented contract.
	if m, err := keyFileAuth(protected, true); m != nil || err != nil {
		t.Errorf("keyFileAuth(protected,true) = %v,%v; want nil,nil (agent covers it)", m, err)
	}
}

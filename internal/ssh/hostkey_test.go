package ssh

import (
	"crypto/ed25519"
	"net"
	"os"
	"path/filepath"
	"testing"

	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// newTestKey generates a deterministic-shape ed25519 SSH public key for tests.
func newTestKey(t *testing.T) xssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer.PublicKey()
}

// testAddr is a fixed remote address for callbacks that parse host:port.
var testAddr = &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}

func TestPinnedFingerprintMismatchFails(t *testing.T) {
	hk := newTestKey(t)
	cb := HostKeyChecker(HostKeyPolicy{Pinned: "SHA256:doesnotmatch"})
	if err := cb("host:22", testAddr, hk); err == nil {
		t.Fatal("expected mismatch error for wrong pinned fingerprint")
	}
}

func TestPinnedFingerprintMatchPasses(t *testing.T) {
	hk := newTestKey(t)
	want := Fingerprint(hk)
	cb := HostKeyChecker(HostKeyPolicy{Pinned: want})
	if err := cb("host:22", testAddr, hk); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}

func TestKnownHostsMatchPasses(t *testing.T) {
	hk := newTestKey(t)
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, []byte(knownhosts.Line([]string{"host:22"}, hk)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cb := HostKeyChecker(HostKeyPolicy{KnownHosts: kh})
	if err := cb("host:22", testAddr, hk); err != nil {
		t.Fatalf("expected known_hosts match, got %v", err)
	}
}

func TestKnownHostsMismatchHardFails(t *testing.T) {
	known := newTestKey(t)
	attacker := newTestKey(t)
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, []byte(knownhosts.Line([]string{"host:22"}, known)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cb := HostKeyChecker(HostKeyPolicy{KnownHosts: kh})
	// A different key for a known host must hard-fail (possible MITM) and never
	// fall through to TOFU.
	if err := cb("host:22", testAddr, attacker); err == nil {
		t.Fatal("expected hard failure on known_hosts key mismatch (MITM)")
	}
}

func TestUnknownHostTOFUConfirmsAndPins(t *testing.T) {
	hk := newTestKey(t)
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts") // does not exist yet
	var confirmed string
	cb := HostKeyChecker(HostKeyPolicy{
		KnownHosts: kh,
		AllowTOFU:  true,
		ConfirmTOFU: func(host, fingerprint string) bool {
			confirmed = fingerprint
			return true
		},
	})
	if err := cb("host:22", testAddr, hk); err != nil {
		t.Fatalf("expected TOFU acceptance, got %v", err)
	}
	if confirmed != Fingerprint(hk) {
		t.Errorf("ConfirmTOFU got fingerprint %q, want %q", confirmed, Fingerprint(hk))
	}
	// The host key must have been pinned to known_hosts (0600), so a second
	// check now succeeds via known_hosts without prompting.
	fi, err := os.Stat(kh)
	if err != nil {
		t.Fatalf("known_hosts not created: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("known_hosts mode = %v, want 0600", fi.Mode().Perm())
	}
	cb2 := HostKeyChecker(HostKeyPolicy{KnownHosts: kh})
	if err := cb2("host:22", testAddr, hk); err != nil {
		t.Fatalf("pinned host should now match via known_hosts, got %v", err)
	}
}

func TestUnknownHostWithoutTOFUFails(t *testing.T) {
	hk := newTestKey(t)
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	cb := HostKeyChecker(HostKeyPolicy{KnownHosts: kh}) // AllowTOFU false
	if err := cb("host:22", testAddr, hk); err == nil {
		t.Fatal("expected failure for unknown host without TOFU")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	if got := expandHome("~/.ssh/known_hosts"); got != filepath.Join(home, ".ssh/known_hosts") {
		t.Errorf("expandHome(~/...) = %q, want %q", got, filepath.Join(home, ".ssh/known_hosts"))
	}
	if got := expandHome("/etc/ssh/known_hosts"); got != "/etc/ssh/known_hosts" {
		t.Errorf("expandHome(absolute) = %q, want unchanged", got)
	}
}

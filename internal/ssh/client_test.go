//go:build !integration

package ssh

import (
	"strings"
	"testing"
)

// contains reports whether substr is within s (small local helper for assertions).
func contains(s, substr string) bool { return strings.Contains(s, substr) }

func TestInstallCmdSudoAndOwnership(t *testing.T) {
	cmd, _ := installCmd(FileSpec{Path: "/etc/nginx/sites-available/app", Owner: "root", Group: "root", Mode: 0o644, Sudo: true}, "/tmp/berth.tmp", true)
	for _, want := range []string{"sudo install", "-o 'root'", "-g 'root'", "-m 644", "'/etc/nginx/sites-available/app'"} {
		if !contains(cmd, want) {
			t.Errorf("installCmd missing %q in %q", want, cmd)
		}
	}
}

func TestInstallCmdNoSudoDefaults(t *testing.T) {
	// No Sudo requested: command must not be prefixed with sudo.
	cmd, tmp := installCmd(FileSpec{Path: "/home/deploy/app/shared/.env", Owner: "deploy"}, "/tmp/berth.tmp", true)
	if strings.HasPrefix(cmd, "sudo ") {
		t.Errorf("non-sudo spec must not start with sudo: %q", cmd)
	}
	if tmp != "/tmp/berth.tmp" {
		t.Errorf("tmpOut = %q, want the supplied temp path", tmp)
	}
	// Group defaults to Owner when empty; Mode defaults to 0644 when zero.
	for _, want := range []string{"-o 'deploy'", "-g 'deploy'", "-m 644", "rm -f '/tmp/berth.tmp'"} {
		if !contains(cmd, want) {
			t.Errorf("installCmd missing %q in %q", want, cmd)
		}
	}
}

func TestInstallCmdSudoRequestedButNotAvailable(t *testing.T) {
	// f.Sudo set but the connection is already root (useSudo=false): no sudo prefix.
	cmd, _ := installCmd(FileSpec{Path: "/etc/x", Sudo: true}, "/tmp/t", false)
	if strings.HasPrefix(cmd, "sudo ") {
		t.Errorf("sudo must be omitted when useSudo is false: %q", cmd)
	}
	// Owner/Group default to root.
	for _, want := range []string{"-o 'root'", "-g 'root'"} {
		if !contains(cmd, want) {
			t.Errorf("installCmd missing %q in %q", want, cmd)
		}
	}
}

func TestShQuoteEscapesSingleQuotes(t *testing.T) {
	got := shQuote("a'b")
	want := `'a'\''b'`
	if got != want {
		t.Errorf("shQuote(%q) = %q, want %q", "a'b", got, want)
	}
}

func TestPrivilegedWrapsOnlyForNonRoot(t *testing.T) {
	// Root connection: command passes through untouched.
	root := &Client{useSudo: false}
	if got := root.privileged("apt-get update"); got != "apt-get update" {
		t.Errorf("root privileged() = %q, want unchanged", got)
	}

	// Non-root connection: command is wrapped to run as root via `sudo sh -c`,
	// single-quoted so env prefixes/redirections survive without outer expansion.
	nonRoot := &Client{useSudo: true}
	got := nonRoot.privileged("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx")
	for _, want := range []string{"sudo -n -- /bin/sh -c ", "'DEBIAN_FRONTEND=noninteractive apt-get install -y nginx'"} {
		if !contains(got, want) {
			t.Errorf("non-root privileged() missing %q in %q", want, got)
		}
	}

	// Embedded single quotes are escaped so the wrapper stays a valid single
	// argument (e.g. accounts' `sudo -u deploy sh -c '...'`).
	if q := nonRoot.privileged("sh -c 'echo hi'"); !contains(q, `'\''`) {
		t.Errorf("embedded single quotes not escaped: %q", q)
	}
}

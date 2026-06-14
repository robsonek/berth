package steps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/robsonek/berth/internal/apt"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// managedMarker / managedMarkerINI are the first line berth writes into every
// config file it owns (templates.Render / RenderINI prepend one of them). Their
// presence distinguishes a berth-managed file from a pre-existing, unmanaged one
// (drift policy, §6.5). Two variants exist because '#' starts a comment in most
// configs but PHP-FPM's INI parser only accepts ';'.
const (
	managedMarker    = "# managed by berth"
	managedMarkerINI = "; managed by berth"
)

// hasManagedMarker reports whether content begins with either marker variant.
func hasManagedMarker(content string) bool {
	return strings.HasPrefix(content, managedMarker) || strings.HasPrefix(content, managedMarkerINI)
}

// contentHash returns the hex SHA-256 of b; used to detect out-of-band drift in
// a managed file (a Check compares the live file's hash against the desired one).
func contentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// aptInstall installs Debian packages non-interactively via the apt helper.
func aptInstall(ctx context.Context, r bssh.Runner, pkgs ...string) error {
	return apt.New(r).EnsurePackages(ctx, nil, pkgs...)
}

// pkgInstalled reports whether a Debian package is installed (dpkg -s exit 0).
func pkgInstalled(ctx context.Context, r bssh.Runner, pkg string) (bool, error) {
	res, err := r.Run(ctx, "dpkg -s "+pkg, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// serviceUp reports whether a systemd unit is both active and enabled.
func serviceUp(ctx context.Context, r bssh.Runner, unit string) (bool, error) {
	active, err := r.Run(ctx, "systemctl is-active "+unit, nil)
	if err != nil {
		return false, err
	}
	enabled, err := r.Run(ctx, "systemctl is-enabled "+unit, nil)
	if err != nil {
		return false, err
	}
	return active.ExitCode == 0 && enabled.ExitCode == 0, nil
}

// fileExists reports whether a path exists on the host (test -e exit 0).
func fileExists(ctx context.Context, r bssh.Runner, path string) (bool, error) {
	res, err := r.Run(ctx, "test -e "+shQuote(path), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// managedFileState classifies the live state of a path berth wants to manage.
type managedFileState int

const (
	fileAbsent    managedFileState = iota // not present
	fileUnmanaged                         // present but lacks the berth marker
	fileDrifted                           // managed by berth but content differs
	fileUpToDate                          // managed and content matches
)

// checkManagedFile reads path and classifies it against the desired content.
func checkManagedFile(ctx context.Context, r bssh.Runner, path string, desired []byte) (managedFileState, error) {
	res, err := r.Run(ctx, "cat "+shQuote(path), nil)
	if err != nil {
		return fileAbsent, err
	}
	if res.ExitCode != 0 {
		return fileAbsent, nil
	}
	if !hasManagedMarker(res.Stdout) {
		return fileUnmanaged, nil
	}
	if contentHash([]byte(res.Stdout)) == contentHash(desired) {
		return fileUpToDate, nil
	}
	return fileDrifted, nil
}

// managedFileSatisfied applies the drift policy (§6.5) to a managed-file state:
// up-to-date is satisfied; absent/drifted are reconciled by Apply (not
// satisfied, no error); an unmanaged conflicting file aborts unless force.
func managedFileSatisfied(state managedFileState, path string, force bool) (satisfied bool, err error) {
	switch state {
	case fileUpToDate:
		return true, nil
	case fileUnmanaged:
		if force {
			return false, nil
		}
		return false, fmt.Errorf("%s exists but is not managed by berth; re-run with --force to overwrite", path)
	default: // fileAbsent, fileDrifted
		return false, nil
	}
}

// shQuote single-quotes s for safe shell use (mirrors the ssh package helper,
// kept local so steps can build remote command strings without exporting it).
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// expandHomeLocal replaces a leading "~" with the local home directory; used to
// locate the operator's public key file referenced by ssh.key.
func expandHomeLocal(path string) string {
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

// operatorPublicKey returns the operator's SSH public key, read from the public
// companion of the configured private key (ssh.key + ".pub"). This is the key
// that authorizes the berth and deploy accounts (design §6.3, §7).
func operatorPublicKey(keyPath string) (string, error) {
	if keyPath == "" {
		return "", fmt.Errorf("ssh.key is not set; cannot determine the operator public key for authorized_keys")
	}
	pubPath := expandHomeLocal(keyPath) + ".pub"
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return "", fmt.Errorf("read operator public key %s: %w", pubPath, err)
	}
	return strings.TrimSpace(string(b)), nil
}

package steps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	gopath "path"
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

// hasManagedMarker reports whether the FIRST LINE of content is exactly one
// of the marker variants. Exact-line on purpose: the marker guards
// destructive paths (overwrite-without---force, drift-removal rm), and a
// prefix match would accept a foreign tool's "# managed by berth-backup"
// as berth's own file.
func hasManagedMarker(content string) bool {
	line, _, _ := strings.Cut(content, "\n")
	return line == managedMarker || line == managedMarkerINI
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

// pkgInstalled reports whether a Debian package is actually installed.
// dpkg -s exits 0 for a package that was REMOVED but not purged (state "rc":
// only conffiles remain), so the Status line decides. Its format is
// "Status: <want> <eflag> <status>" — only the trailing "<eflag> <status>"
// matters here: "install ok installed" and "hold ok installed" are both
// installed (reconciling an operator's hold is apt's business, not
// provisioning drift), while "deinstall ok config-files" is not.
// Line-anchored on purpose: a package description merely CONTAINING the
// phrase (continuation lines start with a space) must not spoof the verdict.
func pkgInstalled(ctx context.Context, r bssh.Runner, pkg string) (bool, error) {
	res, err := r.Run(ctx, "dpkg -s "+pkg, nil)
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, nil
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if rest, ok := strings.CutPrefix(line, "Status: "); ok {
			return strings.HasSuffix(strings.TrimSpace(rest), " ok installed"), nil
		}
	}
	return false, nil
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

// serviceActive reports whether a systemd unit is currently active (running),
// regardless of whether it is enabled at boot. The tuning step uses this rather
// than serviceUp because enablement is owned by the service's own step; requiring
// enabled here would never converge (tuning's Apply restarts but does not enable).
func serviceActive(ctx context.Context, r bssh.Runner, unit string) (bool, error) {
	res, err := r.Run(ctx, "systemctl is-active "+unit, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
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
	fileDrifted                           // Apply should rewrite: managed content differs, or allowlisted stock content is being adopted
	fileUpToDate                          // managed and content matches
)

// checkManagedFile reads path and classifies it against the desired content.
func checkManagedFile(ctx context.Context, r bssh.Runner, path string, desired []byte) (managedFileState, error) {
	return checkManagedFileAdopt(ctx, r, path, desired, nil)
}

// checkManagedFileAdopt is checkManagedFile plus an adoption allowlist: an
// unmanaged file whose EXACT content equals an entry of knownStock classifies
// as fileDrifted (adoptable — Apply overwrites it without --force) instead of
// fileUnmanaged. Image-shipped stock files carry no operator intent, so
// silently replacing them is safe; every other unmanaged content keeps the
// abort-unless---force contract. Exact-bytes match on purpose: a near-miss is
// precisely the case where a human should look.
func checkManagedFileAdopt(ctx context.Context, r bssh.Runner, path string, desired []byte, knownStock []string) (managedFileState, error) {
	res, err := r.Run(ctx, "cat "+shQuote(path), nil)
	if err != nil {
		return fileAbsent, err
	}
	if res.ExitCode != 0 {
		return fileAbsent, nil
	}
	if !hasManagedMarker(res.Stdout) {
		for _, stock := range knownStock {
			if res.Stdout == stock {
				return fileDrifted, nil // adoptable stock content
			}
		}
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

// assertManagedWritable enforces the drift policy on the WRITE path: a
// pre-existing file that lacks the berth marker is refused unless force. Shared
// by writeManagedFile (root writes) and writeManagedFileAsUser (account
// writes), so both mechanisms obey exactly one policy.
func assertManagedWritable(ctx context.Context, r bssh.Runner, force bool, path string) error {
	res, err := r.Run(ctx, "cat "+shQuote(path), nil)
	if err != nil {
		return err
	}
	if res.ExitCode == 0 && !hasManagedMarker(res.Stdout) && !force {
		return fmt.Errorf("%s exists but is not managed by berth; re-run with --force to overwrite", path)
	}
	return nil
}

// writeFileAsUser atomically writes content to path AS user.
//
// Use it for every file whose DIRECTORY component the user controls. The root
// write path (ssh.installCmd) stages its temp file inside the destination
// directory and gives the result the target owner, so a user who can replace
// that directory with a symlink gets root to create a user-OWNED file anywhere
// — e.g. /etc/apt/apt.conf.d/authorized_keys, which APT honors (extensionless
// fragments are read) and whose content the user may then rewrite into a shell
// hook that the next root apt-get executes. Running the whole sequence as the
// user removes that privilege: the worst a swapped symlink achieves is a file
// the user could have written anyway.
//
// Content rides on stdin, never in the command string, so secrets stay out of
// logs and out of -v output. mktemp stages a sibling of the target, so the
// closing rename is atomic on the same filesystem — a reader never sees a
// half-written file (the property ssh.WriteFile gives root writes).
//
// Two details are load-bearing. `mv -fT` (--no-target-directory) is required
// because a plain `mv` whose destination resolves to a DIRECTORY moves the
// source inside it instead of replacing it, so a symlinked leaf would relocate
// the file into a directory of the attacker's choosing. The trap removes the
// staged temp file if any later step fails; without it a failing run leaves a
// credential-bearing .berth.* behind, and repeated failures accumulate them
// (after a successful mv the path is gone, so the trap is a no-op).
func writeFileAsUser(ctx context.Context, r bssh.Runner, user, path string, mode os.FileMode, content []byte) error {
	dir := gopath.Dir(path)
	inner := fmt.Sprintf(`umask 077; t=$(mktemp %s) && trap 'rm -f "$t"' EXIT INT TERM && cat > "$t" && chmod %o "$t" && mv -fT -- "$t" %s`,
		shQuote(dir+"/.berth.XXXXXX"), mode.Perm(), shQuote(path))
	cmd := fmt.Sprintf("sudo -u %s sh -c %s", user, shQuote(inner))
	res, err := r.Run(ctx, cmd, content)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("write %s as %s: %s", path, user, res.Stderr)
	}
	return nil
}

// writeManagedFileAsUser is writeManagedFile for a path inside territory the
// user owns: identical drift policy, but the write runs as the user.
func writeManagedFileAsUser(ctx context.Context, r bssh.Runner, force bool, user string, spec bssh.FileSpec) error {
	if err := assertManagedWritable(ctx, r, force, spec.Path); err != nil {
		return err
	}
	return writeFileAsUser(ctx, r, user, spec.Path, spec.Mode, spec.Content)
}

// writeManagedFile enforces the drift policy (§6.5) on the WRITE path, then
// writes: a pre-existing file at spec.Path that lacks the berth marker is
// refused unless force. Check normally reports such conflicts first, but its
// per-file loops return at the FIRST unsatisfied entry, so a foreign file
// later in the list reaches Apply unclassified — the write path must enforce
// the abort-unless---force contract itself. Steps write managed configs
// through this helper, never bare r.WriteFile.
func writeManagedFile(ctx context.Context, r bssh.Runner, force bool, spec bssh.FileSpec) error {
	if err := assertManagedWritable(ctx, r, force, spec.Path); err != nil {
		return err
	}
	return r.WriteFile(ctx, spec)
}

// managedFilePresent reports whether a berth-managed file currently exists at
// path. Used for drift-removal: an absent or unmanaged (non-berth) file is left
// untouched, so disabling a feature never clobbers a foreign file.
func managedFilePresent(ctx context.Context, r bssh.Runner, path string) (bool, error) {
	res, err := r.Run(ctx, "cat "+shQuote(path), nil)
	if err != nil {
		return false, err
	}
	if res.ExitCode != 0 {
		return false, nil // absent
	}
	return hasManagedMarker(res.Stdout), nil
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

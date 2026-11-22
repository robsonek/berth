package steps

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

// composerInstallerURL is the canonical Composer installer download.
const composerInstallerURL = "https://getcomposer.org/installer"

// composerSigURL serves the expected SHA-384 of the current installer. Composer
// rotates the installer (and thus this hash), so it is fetched at run time and
// never hardcoded (design decision: compare against the live signature).
const composerSigURL = "https://composer.github.io/installer.sig"

// fetchComposerSig retrieves the expected installer SHA-384 from Composer. It is
// a package-level var so tests can stub the network without a real HTTP call.
var fetchComposerSig = func(ctx context.Context) (string, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, composerSigURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch composer installer signature: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch composer installer signature: unexpected status %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read composer installer signature: %w", err)
	}
	sig := strings.TrimSpace(string(b))
	if sig == "" {
		return "", fmt.Errorf("composer installer signature is empty")
	}
	return sig, nil
}

// composerBin is where berth's installer puts Composer. The self-update cron
// names it by absolute path, so a Composer berth did not install (a distro
// package in /usr/bin, say) is never touched by it.
const composerBin = "/usr/local/bin/composer"

// composerUpdateCronPath is the managed daily self-update cron the composer
// step owns while composer.auto_update is on (the default): it keeps the host
// on the newest stable Composer between provisions. Written under the
// managed-marker drift policy, drift-removed when the knob is off (guarded: a
// foreign file at this path is never deleted).
const composerUpdateCronPath = "/etc/cron.d/berth-composer-update"

// renderComposerUpdateCron renders the cron file. It takes no data: the
// schedule, the binary path and the stable channel are fixed.
func renderComposerUpdateCron() ([]byte, error) {
	return templates.Render("composer_update.cron.tmpl", nil)
}

// checkComposerCron classifies the cron against the knob. On: the rendered
// content must be present (a foreign file refuses unless --force — the
// standard managed-file policy). Off: a lingering berth-managed file is drift
// for Apply to remove; a foreign file or none is converged.
func checkComposerCron(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (bool, error) {
	if !s.Composer.AutoUpdateEnabled() {
		present, err := managedFilePresent(ctx, r, composerUpdateCronPath)
		if err != nil {
			return false, err
		}
		return !present, nil
	}
	want, err := renderComposerUpdateCron()
	if err != nil {
		return false, err
	}
	state, err := checkManagedFile(ctx, r, composerUpdateCronPath, want)
	if err != nil {
		return false, err
	}
	return managedFileSatisfied(state, composerUpdateCronPath, rc.Force)
}

// ensureComposerCron is checkComposerCron's write path: render-and-write
// under the drift policy when the knob is on, guarded removal of a
// berth-managed file when it is off.
func ensureComposerCron(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if !s.Composer.AutoUpdateEnabled() {
		present, err := managedFilePresent(ctx, r, composerUpdateCronPath)
		if err != nil {
			return err
		}
		if !present {
			return nil
		}
		if res, err := r.Run(ctx, "rm -f "+shQuote(composerUpdateCronPath), nil); err != nil {
			return err
		} else if res.ExitCode != 0 {
			return fmt.Errorf("remove %s: %s", composerUpdateCronPath, res.Stderr)
		}
		return nil
	}
	// A cron.d file is inert without the daemon, and no other step
	// guarantees one here (site ensures it only for scheduler crons, backups
	// only when enabled): ensure it before writing the file that needs it.
	if err := ensureCron(ctx, r); err != nil {
		return err
	}
	want, err := renderComposerUpdateCron()
	if err != nil {
		return err
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
		Path: composerUpdateCronPath, Content: want,
		Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write composer self-update cron: %w", err)
	}
	return nil
}

type composer struct{}

func Composer() provision.Step { return composer{} }

func (composer) Name() string       { return "composer" }
func (composer) Requires() []string { return []string{"php"} }

// composerOnPath reports whether a composer binary resolves on PATH.
func composerOnPath(ctx context.Context, r bssh.Runner) (bool, error) {
	res, err := r.Run(ctx, "command -v composer", nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

func (composer) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	// The cron is classified FIRST and unconditionally — ahead of the
	// install probe — so a foreign file at its path refuses on a fresh host
	// too instead of surfacing only after the install (the nginx gzip
	// drop-in's order). Check stays local: no network, so a new Composer
	// release is never drift.
	cronOK, err := checkComposerCron(ctx, rc, s, r)
	if err != nil {
		return provision.CheckResult{}, err
	}
	installed, err := composerOnPath(ctx, r)
	if err != nil {
		return provision.CheckResult{}, err
	}
	// The cron is inert without a running cron daemon; the auto-update
	// promise depends on it, so probe it (Apply heals via ensureCron).
	daemonOK := true
	if s.Composer.AutoUpdateEnabled() {
		if daemonOK, err = serviceUp(ctx, r, "cron"); err != nil {
			return provision.CheckResult{}, err
		}
	}
	if installed && cronOK && daemonOK {
		reason := "composer installed; daily self-update cron in place"
		if !s.Composer.AutoUpdateEnabled() {
			reason = "composer installed; auto-update not managed (composer.auto_update: false)"
		}
		return provision.CheckResult{Satisfied: true, Reason: reason}, nil
	}
	var changes []string
	if !installed {
		changes = append(changes, "install composer (verified by SHA-384)")
	}
	if !cronOK {
		if s.Composer.AutoUpdateEnabled() {
			changes = append(changes, "write "+composerUpdateCronPath+" (daily composer self-update)")
		} else {
			changes = append(changes, "remove "+composerUpdateCronPath+" (composer.auto_update: false)")
		}
	}
	if !daemonOK {
		changes = append(changes, "install and enable the cron daemon (the self-update cron is inert without it)")
	}
	return provision.CheckResult{Satisfied: false, Changes: changes}, nil
}

func (composer) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	// Apply also runs for the cron alone (every host provisioned before the
	// cron existed), so the install is gated on its own probe: an installed
	// Composer is never re-installed — updating it is the cron's job.
	installed, err := composerOnPath(ctx, r)
	if err != nil {
		return err
	}
	if !installed {
		if err := installComposer(ctx, r); err != nil {
			return err
		}
	}
	// After the install, never before: no cron for a Composer that failed
	// to install.
	return ensureComposerCron(ctx, rc, s, r)
}

// installComposer downloads the official installer, verifies it against the
// live SHA-384 signature and installs Composer system-wide.
func installComposer(ctx context.Context, r bssh.Runner) error {
	// Download, verify and run the installer from a private, unpredictable
	// root-only directory rather than a fixed world-writable /tmp path —
	// closing the predictable-path + hash-check→exec TOCTOU window.
	mk, err := r.Run(ctx, "mktemp -d /tmp/berth-composer.XXXXXXXXXX", nil)
	if err != nil {
		return err
	}
	if mk.ExitCode != 0 {
		return fmt.Errorf("create composer temp dir: %s", mk.Stderr)
	}
	dir := strings.TrimSpace(mk.Stdout)
	if dir == "" || !strings.HasPrefix(dir, "/") {
		return fmt.Errorf("mktemp -d returned an unexpected path %q", dir)
	}
	setup := dir + "/composer-setup.php"
	// Best-effort cleanup that survives an already-cancelled ctx (the live
	// runner rejects a cancelled context immediately, so reusing ctx here would
	// skip the remote rm on Ctrl-C) yet stays bounded: WithoutCancel also
	// strips the parent's deadline, and without one a wedged transport or a
	// hung remote rm would block Apply indefinitely.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = r.Run(cleanupCtx, "rm -rf "+shQuote(dir), nil)
	}()

	// Download the installer onto the host.
	dl := fmt.Sprintf("php -r \"copy('%s', '%s');\"", composerInstallerURL, setup)
	if res, err := r.Run(ctx, dl, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("download composer installer: %s", res.Stderr)
	}

	// Fetch the expected SHA-384 at run time (never hardcoded) and compare it
	// against the hash of the downloaded installer. Abort on any mismatch before
	// executing the installer.
	expected, err := fetchComposerSig(ctx)
	if err != nil {
		return err
	}
	hashRes, err := r.Run(ctx, fmt.Sprintf("php -r \"echo hash_file('sha384', '%s');\"", setup), nil)
	if err != nil {
		return err
	}
	if hashRes.ExitCode != 0 {
		return fmt.Errorf("hash composer installer: %s", hashRes.Stderr)
	}
	actual := strings.TrimSpace(hashRes.Stdout)
	if actual != expected {
		return fmt.Errorf("composer installer checksum mismatch: got %q, expected %q", actual, expected)
	}

	// Install composer system-wide; the deferred rm -rf removes the setup dir.
	install := fmt.Sprintf("php %s --install-dir=/usr/local/bin --filename=composer", setup)
	if res, err := r.Run(ctx, install, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("install composer: %s", res.Stderr)
	}
	return nil
}

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
)

// composerInstallerURL is the canonical Composer installer download.
const composerInstallerURL = "https://getcomposer.org/installer"

// composerSigURL serves the expected SHA-384 of the current installer. Composer
// rotates the installer (and thus this hash), so it is fetched at run time and
// never hardcoded (design decision: compare against the live signature).
const composerSigURL = "https://composer.github.io/installer.sig"

// composerSetupPath is the temporary on-host path for the downloaded installer.
const composerSetupPath = "/tmp/composer-setup.php"

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
	defer resp.Body.Close()
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

type composer struct{}

func Composer() provision.Step { return composer{} }

func (composer) Name() string       { return "composer" }
func (composer) Requires() []string { return []string{"php"} }

func (composer) Check(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	res, err := r.Run(ctx, "command -v composer", nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if res.ExitCode == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "composer installed"}, nil
	}
	return provision.CheckResult{Satisfied: false, Changes: []string{"install composer (verified by SHA-384)"}}, nil
}

func (composer) Apply(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	// Download the installer onto the host.
	dl := fmt.Sprintf("php -r \"copy('%s', '%s');\"", composerInstallerURL, composerSetupPath)
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
	hashRes, err := r.Run(ctx, fmt.Sprintf("php -r \"echo hash_file('sha384', '%s');\"", composerSetupPath), nil)
	if err != nil {
		return err
	}
	if hashRes.ExitCode != 0 {
		return fmt.Errorf("hash composer installer: %s", hashRes.Stderr)
	}
	actual := strings.TrimSpace(hashRes.Stdout)
	if actual != expected {
		// Remove the corrupt installer, then abort.
		_, _ = r.Run(ctx, "rm -f "+composerSetupPath, nil)
		return fmt.Errorf("composer installer checksum mismatch: got %q, expected %q", actual, expected)
	}

	// Install composer system-wide, then remove the setup file.
	install := fmt.Sprintf("php %s --install-dir=/usr/local/bin --filename=composer", composerSetupPath)
	if res, err := r.Run(ctx, install, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("install composer: %s", res.Stderr)
	}
	if res, err := r.Run(ctx, "rm -f "+composerSetupPath, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("remove composer installer: %s", res.Stderr)
	}
	return nil
}

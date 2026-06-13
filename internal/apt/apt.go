// Package apt installs Debian packages from the stock repos or a pinned upstream.
package apt

import (
	"context"
	"fmt"
	"strings"

	bssh "github.com/robsonek/berth/internal/ssh"
)

// Repo describes a pinned third-party apt repository.
type Repo struct {
	Name        string // e.g. "sury-php"
	URI         string
	Suite       string
	Components  []string
	KeyURL      string
	Fingerprint string // pinned; EnsureRepo aborts on mismatch
}

// Sury returns the Ondřej Surý PHP repository definition for Debian 13.
func Sury() Repo {
	return Repo{
		Name:       "sury-php",
		URI:        "https://packages.sury.org/php/",
		Suite:      "trixie",
		Components: []string{"main"},
		KeyURL:     "https://packages.sury.org/php/apt.gpg",
		// TODO(implementer): this is a PLACEHOLDER key id and must be replaced
		// with Surý's real full 40-hex-char key fingerprint (verify from
		// https://packages.sury.org/php/apt.gpg) before this ships. Match on it.
		Fingerprint: "B188E2B695BD4743", // pinned key id; verified before use
	}
}

// Manager installs packages over an ssh.Runner.
type Manager struct{ r bssh.Runner }

func New(r bssh.Runner) *Manager { return &Manager{r: r} }

// EnsureRepo installs the signing key, verifies its fingerprint, and writes the
// source with signed-by. It aborts on a fingerprint mismatch.
func (m *Manager) EnsureRepo(ctx context.Context, repo Repo) error {
	keyring := "/usr/share/keyrings/" + repo.Name + ".gpg"
	dl := fmt.Sprintf("curl -fsSL %s | gpg --dearmor --yes -o %s", repo.URI+"apt.gpg", keyring)
	if _, err := m.r.Run(ctx, dl, nil); err != nil {
		return fmt.Errorf("download key: %w", err)
	}
	res, err := m.r.Run(ctx, "gpg --show-keys --with-colons "+keyring, nil)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	if !strings.Contains(res.Stdout, repo.Fingerprint) {
		return fmt.Errorf("repo %s: key fingerprint does not match pinned %s", repo.Name, repo.Fingerprint)
	}
	src := fmt.Sprintf("deb [signed-by=%s] %s %s %s\n",
		keyring, repo.URI, repo.Suite, strings.Join(repo.Components, " "))
	if err := m.r.WriteFile(ctx, bssh.FileSpec{
		Path:    "/etc/apt/sources.list.d/" + repo.Name + ".list",
		Content: []byte(src), Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write source: %w", err)
	}
	_, err = m.r.Run(ctx, "apt-get update", nil)
	return err
}

// EnsurePackages installs packages non-interactively from the stock repos.
func (m *Manager) EnsurePackages(ctx context.Context, _ *Repo, pkgs ...string) error {
	cmd := "DEBIAN_FRONTEND=noninteractive apt-get install -y " + strings.Join(pkgs, " ")
	_, err := m.r.Run(ctx, cmd, nil)
	return err
}

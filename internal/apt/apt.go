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

// Sury returns the Ondřej Surý PHP repository definition for Debian 13 (used by
// the php step when php.source selects it, e.g. for PHP versions Debian does not
// ship). Fingerprint is the full 40-hex DEB.SURY.ORG signing key.
func Sury() Repo {
	return Repo{
		Name:        "sury-php",
		URI:         "https://packages.sury.org/php/",
		Suite:       "trixie",
		Components:  []string{"main"},
		KeyURL:      "https://packages.sury.org/php/apt.gpg",
		Fingerprint: "15058500A0235D97F5D10063B188E2B695BD4743",
	}
}

// NginxOrg returns the official nginx.org mainline repository for Debian 13,
// used by the nginx step when nginx.source is "nginx". Fingerprint is the full
// 40-hex nginx signing key.
func NginxOrg() Repo {
	return Repo{
		Name:        "nginx-org",
		URI:         "https://nginx.org/packages/mainline/debian/",
		Suite:       "trixie",
		Components:  []string{"nginx"},
		KeyURL:      "https://nginx.org/keys/nginx_signing.key",
		Fingerprint: "8540A6F18833A80E9C1653A42FD21310B49F6B46",
	}
}

// PostgresPGDG returns the official PostgreSQL Global Development Group (PGDG)
// repository for Debian 13, used by the database step when database.source is
// "pgdg". Fingerprint is the full 40-hex PGDG signing key.
func PostgresPGDG() Repo {
	return Repo{
		Name:        "pgdg",
		URI:         "https://apt.postgresql.org/pub/repos/apt/",
		Suite:       "trixie-pgdg",
		Components:  []string{"main"},
		KeyURL:      "https://www.postgresql.org/media/keys/ACCC4CF8.asc",
		Fingerprint: "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8",
	}
}

// MariaDBOrg returns the official mariadb.org 11.8 LTS repository for Debian 13,
// used by the database step when database.source is "mariadb". Fingerprint is the
// full 40-hex MariaDB release signing key.
func MariaDBOrg() Repo {
	return Repo{
		Name:        "mariadb-org",
		URI:         "https://deb.mariadb.org/11.8/debian/",
		Suite:       "trixie",
		Components:  []string{"main"},
		KeyURL:      "https://mariadb.org/mariadb_release_signing_key.asc",
		Fingerprint: "177F4010FE56CA3336300305F1656F24C74CD1D8",
	}
}

// Manager installs packages over an ssh.Runner.
type Manager struct{ r bssh.Runner }

func New(r bssh.Runner) *Manager { return &Manager{r: r} }

// EnsureRepo installs the signing key, verifies its fingerprint, and writes the
// source with signed-by. It aborts on a fingerprint mismatch.
func (m *Manager) EnsureRepo(ctx context.Context, repo Repo) error {
	keyring := "/usr/share/keyrings/" + repo.Name + ".gpg"
	// Fetch the signing key from its published URL and dearmor it into a keyring.
	dl := fmt.Sprintf("curl -fsSL %s | gpg --dearmor --yes -o %s", repo.KeyURL, keyring)
	if res, err := m.r.Run(ctx, dl, nil); err != nil {
		return fmt.Errorf("download key for %s: %w", repo.Name, err)
	} else if res.ExitCode != 0 {
		return fmt.Errorf("download key for %s: %s", repo.Name, res.Stderr)
	}
	res, err := m.r.Run(ctx, "gpg --show-keys --with-colons "+keyring, nil)
	if err != nil {
		return fmt.Errorf("read key for %s: %w", repo.Name, err)
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
	if res, err := m.r.Run(ctx, "apt-get update", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("apt-get update after adding %s: %s", repo.Name, res.Stderr)
	}
	return nil
}

// EnsurePackages installs packages non-interactively from the stock repos (or
// from any upstream repo already registered via EnsureRepo). The non-interactive
// frontend keeps existing conffiles, so an upstream-repo upgrade of a stock
// package does not hang on a prompt. A non-zero apt exit is surfaced as an error.
func (m *Manager) EnsurePackages(ctx context.Context, _ *Repo, pkgs ...string) error {
	cmd := "DEBIAN_FRONTEND=noninteractive apt-get install -y " + strings.Join(pkgs, " ")
	res, err := m.r.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("apt-get install %s: %s", strings.Join(pkgs, " "), res.Stderr)
	}
	return nil
}

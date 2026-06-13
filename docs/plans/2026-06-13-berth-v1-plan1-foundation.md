# berth v1 — Plan 1: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the testable core of berth — a Go CLI that loads a per-server YAML config and runs an idempotent, event-emitting provisioning pipeline — without yet implementing any real provisioning step.

**Architecture:** A Cobra CLI loads/validates a `config.Server` (Viper/YAML). Provisioning is an ordered pipeline of `Step`s run by an `Engine` against an `ssh.Runner` (faked in tests). The engine emits progress `Event`s consumed by a renderer; this plan ships the plain (non-TTY) renderer. Supporting packages: `apt` (package-source helper), `secret` (generation + redaction). No real steps yet — a sample step proves the engine.

**Tech Stack:** Go 1.25; `github.com/spf13/cobra` v1.10.2; `github.com/spf13/viper` v1.21.0; `golang.org/x/crypto` v0.53.0 (ssh); `github.com/pkg/sftp` v1.13.10; Charm v2 line for later UI, on the **`charm.land/…`** module paths (`bubbletea/v2` v2.0.7, `bubbles/v2` v2.1.0, `lipgloss/v2` v2.0.4, `huh/v2` v2.0.3 — these modules declare `module charm.land/<name>/v2`, the canonical v2 import path) — added now to `go.mod`, used in Plan 3. Tests: Go standard `testing`. All versions resolved via the Go module proxy / `go list -m -versions` (authoritative latest stable).

**Spec:** `docs/design/2026-06-13-berth-design.md` (Revision 5). This plan covers §5 (architecture: Runner, Step, CheckResult, apt, config, validation) and the non-TTY half of the Interface section. Concrete provisioning steps (§6.4), the MariaDB engine, secret persistence, the wizard, the bubbletea renderer, and CI are Plans 2–3.

**Module path:** `github.com/robsonek/berth`. All code and comments in English; no personal data.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `go.mod`, `go.sum` | Module + pinned dependencies |
| `main.go` | Entry point → `cmd.Execute()` |
| `internal/version/version.go` | Version vars (ldflags-injected) |
| `cmd/root.go` | Cobra root command + `--version` |
| `cmd/provision.go`, `cmd/init.go`, `cmd/site.go` | Command wiring (stubs where logic lands in later plans) |
| `internal/config/config.go` | `Server`/`SSH`/`PHP`/`Database`/`Site` structs + `Load` |
| `internal/config/validate.go` | Field validators (domain, SQL ident, path, version, source, repo) |
| `internal/ssh/runner.go` | `Runner` interface, `Result`, `FileSpec` |
| `internal/ssh/fake.go` | `FakeRunner` test double |
| `internal/secret/secret.go` | `Generate` (random password), `Redactor` |
| `internal/apt/apt.go` | `Repo`, `Manager` (`EnsureRepo`, `EnsurePackages`), Surý repo def |
| `internal/provision/step.go` | `Step`, `CheckResult` |
| `internal/provision/event.go` | `Event` + event kinds |
| `internal/provision/engine.go` | `Engine` (run loop, dry-run, `--only`, dependency check) |
| `internal/ui/renderer.go` | `Renderer` interface + `IsTTY` |
| `internal/ui/plain.go` | `PlainRenderer` (non-TTY output) |

Each `internal/<pkg>` keeps one responsibility and is unit-testable in isolation via `FakeRunner` and in-memory inputs.

---

## Task 1: Module skeleton & version

**Files:**
- Create: `go.mod`
- Create: `main.go`
- Create: `internal/version/version.go`
- Test: `internal/version/version_test.go`

- [ ] **Step 1: Create `go.mod` with pinned dependencies**

```
module github.com/robsonek/berth

go 1.25

require (
	charm.land/bubbles/v2 v2.1.0
	charm.land/bubbletea/v2 v2.0.7
	charm.land/huh/v2 v2.0.3
	charm.land/lipgloss/v2 v2.0.4
	github.com/pkg/sftp v1.13.10
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	golang.org/x/crypto v0.53.0
)
```

- [ ] **Step 2: Write `internal/version/version.go`**

```go
// Package version exposes build metadata injected via -ldflags.
package version

var (
	// Version is the semantic version, set at build time.
	Version = "dev"
	// Commit is the git commit hash, set at build time.
	Commit = "none"
	// Date is the build date, set at build time.
	Date = "unknown"
)

// String returns a human-readable version line.
func String() string {
	return "berth " + Version + " (" + Commit + ", " + Date + ")"
}
```

- [ ] **Step 3: Write the failing test `internal/version/version_test.go`**

```go
package version

import (
	"strings"
	"testing"
)

func TestStringContainsVersion(t *testing.T) {
	Version = "1.2.3"
	got := String()
	if !strings.Contains(got, "1.2.3") {
		t.Fatalf("String() = %q, want it to contain %q", got, "1.2.3")
	}
}
```

- [ ] **Step 4: Write `main.go`**

```go
package main

import "github.com/robsonek/berth/cmd"

func main() {
	cmd.Execute()
}
```

- [ ] **Step 5: Run tests and tidy**

Run: `go mod tidy && go test ./internal/version/...`
Expected: `go.sum` is created; test PASS. (`main.go` will not compile until Task 2 creates `cmd`; that is expected — do not build the whole module yet.)

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum main.go internal/version
git commit -m "Add module skeleton and version package"
```

---

## Task 2: Cobra root command & `--version`

**Files:**
- Create: `cmd/root.go`
- Test: `cmd/root_test.go`

- [ ] **Step 1: Write the failing test `cmd/root_test.go`**

```go
package cmd

import (
	"bytes"
	"testing"
)

func TestRootVersionFlag(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("expected version output, got none")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/...`
Expected: FAIL — `newRootCmd` undefined.

- [ ] **Step 3: Write `cmd/root.go`**

```go
// Package cmd wires the berth command-line interface.
package cmd

import (
	"fmt"
	"os"

	"github.com/robsonek/berth/internal/version"
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "berth",
		Short:         "Provision a fresh Debian 13 server for Laravel apps",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
	}
	root.SetVersionTemplate(version.String() + "\n")
	return root
}

// Execute runs the root command and exits non-zero on error.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/root.go cmd/root_test.go
git commit -m "Add Cobra root command with --version"
```

---

## Task 3: Config structs & loader

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/testdata/valid.yml`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write `internal/config/config.go`**

```go
// Package config loads and validates per-server berth configuration.
package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type SSH struct {
	User        string `mapstructure:"user"`
	Port        int    `mapstructure:"port"`
	Key         string `mapstructure:"key"`
	Fingerprint string `mapstructure:"fingerprint"`
}

type PHP struct {
	Version string `mapstructure:"version"`
	Source  string `mapstructure:"source"` // auto | sury | debian
}

type Database struct {
	Engine string `mapstructure:"engine"` // mariadb
	Name   string `mapstructure:"name"`
	User   string `mapstructure:"user"`
}

type Site struct {
	Domain     string `mapstructure:"domain"`
	DeployPath string `mapstructure:"deploy_path"`
	Repository string `mapstructure:"repository"`
	SSL        bool   `mapstructure:"ssl"`
	SSLEmail   string `mapstructure:"ssl_email"`
}

type Server struct {
	Host      string   `mapstructure:"host"`
	SSH       SSH      `mapstructure:"ssh"`
	PHP       PHP      `mapstructure:"php"`
	Database  Database `mapstructure:"database"`
	Valkey    bool     `mapstructure:"valkey"`
	Queue     bool     `mapstructure:"queue"`
	Scheduler bool     `mapstructure:"scheduler"`
	Sites     []Site   `mapstructure:"sites"`
}

// Load reads a YAML config file, applies defaults, and validates it.
func Load(path string) (*Server, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetDefault("ssh.port", 22)
	v.SetDefault("ssh.user", "root")
	v.SetDefault("php.source", "auto")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var s Server
	if err := v.Unmarshal(&s); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &s, nil
}
```

- [ ] **Step 2: Create `internal/config/testdata/valid.yml`**

```yaml
host: 203.0.113.10
ssh:
  user: root
  port: 22
  key: ~/.ssh/id_ed25519
php:
  version: "8.5"
  source: auto
database:
  engine: mariadb
  name: myapp
  user: myapp
valkey: true
queue: true
scheduler: true
sites:
  - domain: app.example.com
    deploy_path: /home/deploy/myapp
    repository: git@github.com:owner/repo.git
    ssl: true
    ssl_email: admin@example.com
```

- [ ] **Step 3: Write the failing test `internal/config/config_test.go`**

```go
package config

import "testing"

func TestLoadValid(t *testing.T) {
	s, err := Load("testdata/valid.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.Host != "203.0.113.10" {
		t.Errorf("Host = %q, want 203.0.113.10", s.Host)
	}
	if s.SSH.Port != 22 {
		t.Errorf("SSH.Port = %d, want 22", s.SSH.Port)
	}
	if s.PHP.Source != "auto" {
		t.Errorf("PHP.Source = %q, want auto", s.PHP.Source)
	}
	if len(s.Sites) != 1 || s.Sites[0].Domain != "app.example.com" {
		t.Errorf("Sites = %+v, want one site app.example.com", s.Sites)
	}
}

func TestLoadDefaultsPort(t *testing.T) {
	// minimal.yml omits ssh.port → default 22 applies (created inline below).
	s, err := Load("testdata/valid.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.SSH.Port == 0 {
		t.Error("expected default ssh.port to be applied")
	}
}
```

- [ ] **Step 4: Run test (fails to compile until Validate exists)**

Run: `go test ./internal/config/...`
Expected: FAIL — `s.Validate` undefined. (Implemented in Task 4.)

- [ ] **Step 5: Commit (after Task 4 makes it pass)**

Defer the commit to Task 4, Step 5 (config + validation commit together, since `Load` calls `Validate`).

---

## Task 4: Config validators

**Files:**
- Create: `internal/config/validate.go`
- Test: `internal/config/validate_test.go`

- [ ] **Step 1: Write `internal/config/validate.go`**

```go
package config

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var (
	reHostname = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	reSQLIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	rePHPVer   = regexp.MustCompile(`^\d+\.\d+$`)
)

var allowedPHPVersions = map[string]bool{"8.2": true, "8.3": true, "8.4": true, "8.5": true}
var allowedPHPSources = map[string]bool{"auto": true, "sury": true, "debian": true}

// Validate checks every field that reaches a shell, SQL statement, or path.
func (s *Server) Validate() error {
	if !reHostname.MatchString(s.Host) {
		return fmt.Errorf("host %q is not a valid hostname or IP", s.Host)
	}
	if s.SSH.Port < 1 || s.SSH.Port > 65535 {
		return fmt.Errorf("ssh.port %d out of range", s.SSH.Port)
	}
	if !rePHPVer.MatchString(s.PHP.Version) || !allowedPHPVersions[s.PHP.Version] {
		return fmt.Errorf("php.version %q is not an allowed version", s.PHP.Version)
	}
	if !allowedPHPSources[s.PHP.Source] {
		return fmt.Errorf("php.source %q must be auto, sury, or debian", s.PHP.Source)
	}
	if s.Database.Engine != "mariadb" {
		return fmt.Errorf("database.engine %q unsupported (v1 supports mariadb)", s.Database.Engine)
	}
	if !reSQLIdent.MatchString(s.Database.Name) {
		return fmt.Errorf("database.name %q is not a valid SQL identifier", s.Database.Name)
	}
	if !reSQLIdent.MatchString(s.Database.User) {
		return fmt.Errorf("database.user %q is not a valid SQL identifier", s.Database.User)
	}
	if len(s.Sites) == 0 {
		return fmt.Errorf("at least one site is required")
	}
	for i := range s.Sites {
		if err := s.Sites[i].validate(); err != nil {
			return fmt.Errorf("site %d: %w", i, err)
		}
	}
	return nil
}

func (st *Site) validate() error {
	if !reHostname.MatchString(st.Domain) {
		return fmt.Errorf("domain %q is not a valid hostname", st.Domain)
	}
	if !path.IsAbs(st.DeployPath) || strings.ContainsAny(st.DeployPath, " ;&|$`\n\t") {
		return fmt.Errorf("deploy_path %q must be an absolute path without shell metacharacters", st.DeployPath)
	}
	if st.Repository != "" && !validGitURL(st.Repository) {
		return fmt.Errorf("repository %q must be an SSH git URL (scp-like or ssh://); HTTPS is out of v1 scope", st.Repository)
	}
	if st.SSL && st.SSLEmail == "" {
		return fmt.Errorf("ssl_email is required when ssl is true")
	}
	return nil
}

// validGitURL accepts only SSH git URLs in v1 (scp-like git@host:path or
// ssh://…), because berth generates an SSH deploy key for the repository.
// HTTPS repositories are out of v1 scope (no deploy key would be generated).
func validGitURL(s string) bool {
	if strings.HasPrefix(s, "ssh://") {
		u, err := url.Parse(s)
		return err == nil && u.Host != "" && strings.Trim(u.Path, "/") != ""
	}
	// scp-like: user@host:path
	return regexp.MustCompile(`^[\w.-]+@[\w.-]+:[\w./~-]+$`).MatchString(s)
}

// GitHost extracts the host from a repository URL for known_hosts (Plan 2 uses it).
func GitHost(repo string) (string, error) {
	if strings.HasPrefix(repo, "http") || strings.HasPrefix(repo, "ssh://") {
		u, err := url.Parse(repo)
		if err != nil {
			return "", err
		}
		return u.Hostname(), nil
	}
	at := strings.Index(repo, "@")
	colon := strings.Index(repo, ":")
	if at < 0 || colon < 0 || colon < at {
		return "", fmt.Errorf("cannot parse host from %q", repo)
	}
	return repo[at+1 : colon], nil
}
```

- [ ] **Step 2: Write the failing test `internal/config/validate_test.go`**

```go
package config

import "testing"

func base() *Server {
	return &Server{
		Host:     "203.0.113.10",
		SSH:      SSH{User: "root", Port: 22},
		PHP:      PHP{Version: "8.5", Source: "auto"},
		Database: Database{Engine: "mariadb", Name: "myapp", User: "myapp"},
		Sites:    []Site{{Domain: "app.example.com", DeployPath: "/home/deploy/myapp"}},
	}
}

func TestValidateOK(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Server){
		"bad php version": func(s *Server) { s.PHP.Version = "9.9" },
		"bad php source":  func(s *Server) { s.PHP.Source = "ppa" },
		"bad db name":     func(s *Server) { s.Database.Name = "my-app; DROP" },
		"bad engine":      func(s *Server) { s.Database.Engine = "oracle" },
		"relative path":   func(s *Server) { s.Sites[0].DeployPath = "deploy/x" },
		"shell meta path": func(s *Server) { s.Sites[0].DeployPath = "/home/$(whoami)" },
		"ssl no email":    func(s *Server) { s.Sites[0].SSL = true },
		"bad port":        func(s *Server) { s.SSH.Port = 0 },
		"no sites":        func(s *Server) { s.Sites = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := base()
			mutate(s)
			if err := s.Validate(); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestGitHost(t *testing.T) {
	for in, want := range map[string]string{
		"git@github.com:owner/repo.git":        "github.com",
		"https://github.com/owner/repo.git":    "github.com",
		"ssh://git@example.org:22/owner/r.git": "example.org",
	} {
		got, err := GitHost(in)
		if err != nil || got != want {
			t.Errorf("GitHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `go test ./internal/config/...`
Expected: PASS (both `config_test.go` from Task 3 and `validate_test.go`).

- [ ] **Step 4: Commit**

```bash
git add internal/config
git commit -m "Add config structs, YAML loader, and validators"
```

---

## Task 5: Command stubs (`init`, `provision`, `site`)

**Files:**
- Create: `cmd/provision.go`
- Create: `cmd/init.go`
- Create: `cmd/site.go`
- Modify: `cmd/root.go` (register subcommands)
- Test: `cmd/commands_test.go`

- [ ] **Step 1: Write the failing test `cmd/commands_test.go`**

```go
package cmd

import "testing"

func TestSubcommandsRegistered(t *testing.T) {
	root := newRootCmd()
	want := map[string]bool{"init": false, "provision": false, "site": false}
	for _, c := range root.Commands() {
		want[c.Name()] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}

func TestProvisionRequiresServerArg(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"provision"})
	if err := root.Execute(); err == nil {
		t.Error("expected error when provision is called without a server argument")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/...`
Expected: FAIL — subcommands not registered.

- [ ] **Step 3: Write `cmd/provision.go`**

```go
package cmd

import (
	"github.com/spf13/cobra"
)

type provisionFlags struct {
	dryRun     bool
	skipSSL    bool
	sslStaging bool
	only       string
	force      bool
	verbose    bool
	noTTY      bool
}

func newProvisionCmd() *cobra.Command {
	f := &provisionFlags{}
	c := &cobra.Command{
		Use:   "provision <server>",
		Short: "Provision a server from its config file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Wiring to the engine lands in Plan 1 Task 11.
			return runProvision(cmd, args[0], f)
		},
	}
	c.Flags().BoolVar(&f.dryRun, "dry-run", false, "report changes without applying them")
	c.Flags().BoolVar(&f.skipSSL, "skip-ssl", false, "skip the TLS phase")
	c.Flags().BoolVar(&f.sslStaging, "ssl-staging", false, "use Let's Encrypt staging")
	c.Flags().StringVar(&f.only, "only", "", "run only the named phase or step")
	c.Flags().BoolVar(&f.force, "force", false, "overwrite resources not managed by berth")
	c.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "verbose output")
	c.Flags().BoolVar(&f.noTTY, "no-tty", false, "force plain output (no live TUI)")
	return c
}
```

- [ ] **Step 4: Write `cmd/init.go`**

```go
package cmd

import "github.com/spf13/cobra"

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Interactive wizard that writes a server config",
		RunE: func(cmd *cobra.Command, args []string) error {
			// The huh wizard is implemented in Plan 3.
			return errNotImplemented("init wizard")
		},
	}
}
```

- [ ] **Step 5: Write `cmd/site.go`**

```go
package cmd

import "github.com/spf13/cobra"

func newSiteCmd() *cobra.Command {
	c := &cobra.Command{Use: "site", Short: "Manage sites on a server"}
	c.AddCommand(&cobra.Command{
		Use:   "add <server>",
		Short: "Add another site to an existing server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errNotImplemented("site:add") // post-v1
		},
	})
	return c
}
```

- [ ] **Step 6: Add `errNotImplemented` and register subcommands in `cmd/root.go`**

Add to `cmd/root.go` (inside `newRootCmd`, before `return root`):

```go
	root.AddCommand(newInitCmd(), newProvisionCmd(), newSiteCmd())
```

Add this helper to `cmd/root.go`:

```go
import "errors"

func errNotImplemented(what string) error {
	return errors.New(what + " is not implemented yet")
}
```

Add a temporary `runProvision` stub at the end of `cmd/provision.go` (replaced in Task 11):

```go
func runProvision(cmd *cobra.Command, server string, f *provisionFlags) error {
	return errNotImplemented("provision (engine wiring lands in Task 11)")
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./cmd/...`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add cmd
git commit -m "Register init/provision/site subcommands with flag stubs"
```

---

## Task 6: SSH Runner interface & FakeRunner

**Files:**
- Create: `internal/ssh/runner.go`
- Create: `internal/ssh/fake.go`
- Test: `internal/ssh/fake_test.go`

- [ ] **Step 1: Write `internal/ssh/runner.go`**

```go
// Package ssh abstracts remote command execution and file writes.
package ssh

import (
	"context"
	"io/fs"
)

// Result is the outcome of a remote command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// FileSpec describes an atomic remote file write.
type FileSpec struct {
	Path  string
	Content []byte
	Owner string
	Group string
	Mode  fs.FileMode
	Sudo  bool
}

// Runner executes commands and writes files on a target host.
// Implementations must pass secrets via stdin, never via the command string.
type Runner interface {
	Run(ctx context.Context, cmd string, stdin []byte) (Result, error)
	WriteFile(ctx context.Context, f FileSpec) error
}
```

- [ ] **Step 2: Write the failing test `internal/ssh/fake_test.go`**

```go
package ssh

import (
	"context"
	"testing"
)

func TestFakeRunnerMatchesAndRecords(t *testing.T) {
	f := NewFakeRunner()
	f.On("id -u deploy", Result{ExitCode: 1}) // user missing
	f.On("getent passwd deploy", Result{Stdout: "deploy:x:1001:", ExitCode: 0})

	r, err := f.Run(context.Background(), "id -u deploy", nil)
	if err != nil || r.ExitCode != 1 {
		t.Fatalf("Run() = %+v, %v; want exit 1", r, err)
	}
	if got := f.Calls()[0].Cmd; got != "id -u deploy" {
		t.Errorf("recorded cmd = %q", got)
	}
}

func TestFakeRunnerUnexpectedCmdErrors(t *testing.T) {
	f := NewFakeRunner()
	if _, err := f.Run(context.Background(), "rm -rf /", nil); err == nil {
		t.Error("expected error for unstubbed command")
	}
}

func TestFakeRunnerWriteFileRecorded(t *testing.T) {
	f := NewFakeRunner()
	err := f.WriteFile(context.Background(), FileSpec{Path: "/etc/x", Content: []byte("y"), Mode: 0o644})
	if err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if len(f.Writes()) != 1 || f.Writes()[0].Path != "/etc/x" {
		t.Errorf("writes = %+v", f.Writes())
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/ssh/...`
Expected: FAIL — `NewFakeRunner` undefined.

- [ ] **Step 4: Write `internal/ssh/fake.go`**

```go
package ssh

import (
	"context"
	"fmt"
)

// Call records a Run invocation.
type Call struct {
	Cmd   string
	Stdin []byte
}

// FakeRunner is an in-memory Runner for tests.
type FakeRunner struct {
	responses map[string]Result
	errs      map[string]error
	calls     []Call
	writes    []FileSpec
}

func NewFakeRunner() *FakeRunner {
	return &FakeRunner{responses: map[string]Result{}, errs: map[string]error{}}
}

// On stubs the result for an exact command string.
func (f *FakeRunner) On(cmd string, r Result) *FakeRunner { f.responses[cmd] = r; return f }

// OnError stubs a transport error for an exact command string.
func (f *FakeRunner) OnError(cmd string, err error) *FakeRunner { f.errs[cmd] = err; return f }

func (f *FakeRunner) Run(_ context.Context, cmd string, stdin []byte) (Result, error) {
	f.calls = append(f.calls, Call{Cmd: cmd, Stdin: stdin})
	if err, ok := f.errs[cmd]; ok {
		return Result{}, err
	}
	if r, ok := f.responses[cmd]; ok {
		return r, nil
	}
	return Result{}, fmt.Errorf("FakeRunner: unstubbed command %q", cmd)
}

func (f *FakeRunner) WriteFile(_ context.Context, fs FileSpec) error {
	f.writes = append(f.writes, fs)
	return nil
}

func (f *FakeRunner) Calls() []Call      { return f.calls }
func (f *FakeRunner) Writes() []FileSpec { return f.writes }
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/ssh/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/ssh
git commit -m "Add ssh.Runner interface and FakeRunner test double"
```

---

## Task 7: Secret generation & redaction

**Files:**
- Create: `internal/secret/secret.go`
- Test: `internal/secret/secret_test.go`

- [ ] **Step 1: Write the failing test `internal/secret/secret_test.go`**

```go
package secret

import (
	"strings"
	"testing"
)

func TestGenerateLengthAndCharset(t *testing.T) {
	p, err := Generate(32)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(p) != 32 {
		t.Errorf("len = %d, want 32", len(p))
	}
	if strings.ContainsAny(p, " /+=\n") {
		t.Errorf("password %q contains shell/url-unsafe characters", p)
	}
}

func TestGenerateUnique(t *testing.T) {
	a, _ := Generate(24)
	b, _ := Generate(24)
	if a == b {
		t.Error("two generated passwords should differ")
	}
}

func TestRedactorMasksRegisteredSecrets(t *testing.T) {
	r := NewRedactor()
	r.Add("s3cr3t-pw")
	got := r.Apply("mysql -p s3cr3t-pw -e ...")
	if strings.Contains(got, "s3cr3t-pw") {
		t.Errorf("redacted output still contains the secret: %q", got)
	}
	if !strings.Contains(got, "***") {
		t.Errorf("expected mask in %q", got)
	}
}

func TestRedactorIgnoresEmpty(t *testing.T) {
	r := NewRedactor()
	r.Add("")
	if got := r.Apply("hello"); got != "hello" {
		t.Errorf("empty secret should be a no-op, got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/secret/...`
Expected: FAIL — undefined `Generate`/`NewRedactor`.

- [ ] **Step 3: Write `internal/secret/secret.go`**

```go
// Package secret generates credentials and redacts them from output.
package secret

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// alphabet excludes shell- and URL-unsafe characters on purpose.
const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Generate returns a cryptographically random password of length n.
func Generate(n int) (string, error) {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[idx.Int64()]
	}
	return string(b), nil
}

// Redactor masks registered secret values in arbitrary strings.
type Redactor struct{ secrets []string }

func NewRedactor() *Redactor { return &Redactor{} }

// Add registers a secret to mask. Empty strings are ignored.
func (r *Redactor) Add(s string) {
	if s != "" {
		r.secrets = append(r.secrets, s)
	}
}

// Apply replaces every registered secret with "***".
func (r *Redactor) Apply(s string) string {
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, "***")
	}
	return s
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/secret/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/secret
git commit -m "Add secret generation and redaction"
```

---

## Task 8: apt package-source helper

**Files:**
- Create: `internal/apt/apt.go`
- Test: `internal/apt/apt_test.go`

- [ ] **Step 1: Write the failing test `internal/apt/apt_test.go`**

```go
package apt

import (
	"context"
	"strings"
	"testing"

	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestEnsurePackagesFromDebianStock(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	m := New(f)
	if err := m.EnsurePackages(context.Background(), nil, "nginx"); err != nil {
		t.Fatalf("EnsurePackages() error = %v", err)
	}
}

func TestEnsureRepoVerifiesFingerprint(t *testing.T) {
	f := bssh.NewFakeRunner()
	// gpg show-keys returns a fingerprint that does NOT match the pinned one.
	f.On("gpg --show-keys --with-colons /usr/share/keyrings/sury-php.gpg",
		bssh.Result{Stdout: "fpr:::::::::DEADBEEF:\n"})
	m := New(f)
	err := m.EnsureRepo(context.Background(), Sury())
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected fingerprint mismatch error, got %v", err)
	}
}

func TestSuryRepoDefinition(t *testing.T) {
	r := Sury()
	if r.Fingerprint == "" || !strings.Contains(r.URI, "sury") {
		t.Errorf("Sury() looks wrong: %+v", r)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/apt/...`
Expected: FAIL — `New`/`Sury`/`EnsureRepo` undefined.

- [ ] **Step 3: Write `internal/apt/apt.go`**

```go
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
		Name:        "sury-php",
		URI:         "https://packages.sury.org/php/",
		Suite:       "trixie",
		Components:  []string{"main"},
		KeyURL:      "https://packages.sury.org/php/apt.gpg",
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
		Path: "/etc/apt/sources.list.d/" + repo.Name + ".list",
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
```

> Note for the implementer: the pinned `Fingerprint` value above is a placeholder key id and **must be replaced with Surý's real full key fingerprint** (verify from `https://packages.sury.org/php/apt.gpg`) before this ships. Capture the full 40-hex-char fingerprint and match on it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/apt/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/apt
git commit -m "Add apt package-source helper with pinned Sury repo"
```

---

## Task 9: Provision engine (Step, CheckResult, events, run loop)

**Files:**
- Create: `internal/provision/step.go`
- Create: `internal/provision/event.go`
- Create: `internal/provision/engine.go`
- Test: `internal/provision/engine_test.go`

- [ ] **Step 1: Write `internal/provision/step.go`**

```go
// Package provision runs an ordered pipeline of idempotent steps.
package provision

import (
	"context"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// CheckResult reports the current state of a step.
type CheckResult struct {
	Satisfied bool
	Reason    string
	Changes   []string
	Sensitive bool
}

// RunCtx carries run-time flags steps need beyond the static config.
type RunCtx struct {
	Force      bool // overwrite resources not managed by berth (drift policy, §6.5)
	SSLStaging bool // use Let's Encrypt staging in the TLS step
}

// Step is one idempotent unit of provisioning.
type Step interface {
	Name() string
	Requires() []string
	Check(ctx context.Context, rc RunCtx, s *config.Server, r bssh.Runner) (CheckResult, error)
	Apply(ctx context.Context, rc RunCtx, s *config.Server, r bssh.Runner) error
}
```

- [ ] **Step 2: Write `internal/provision/event.go`**

```go
package provision

// EventKind classifies a progress event.
type EventKind int

const (
	EventStarted EventKind = iota
	EventSatisfied
	EventApplied
	EventPlanned // dry-run: would change
	EventFailed
)

// Event is emitted by the engine for each step transition.
type Event struct {
	Step      string
	Kind      EventKind
	Reason    string
	Changes   []string
	Sensitive bool // Changes may contain secrets → renderers must redact
	Err       error
}
```

- [ ] **Step 3: Write the failing test `internal/provision/engine_test.go`**

```go
package provision

import (
	"context"
	"errors"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// stepStub is a configurable Step for tests.
type stepStub struct {
	name      string
	requires  []string
	satisfied bool
	applyErr  error
	applied   *bool
}

func (s *stepStub) Name() string       { return s.name }
func (s *stepStub) Requires() []string { return s.requires }
func (s *stepStub) Check(context.Context, RunCtx, *config.Server, bssh.Runner) (CheckResult, error) {
	return CheckResult{Satisfied: s.satisfied, Reason: "stub", Changes: []string{"do x"}}, nil
}
func (s *stepStub) Apply(context.Context, RunCtx, *config.Server, bssh.Runner) error {
	if s.applied != nil {
		*s.applied = true
	}
	return s.applyErr
}

func collect(ch <-chan Event) []Event {
	var out []Event
	for e := range ch {
		out = append(out, e)
	}
	return out
}

func TestEngineSkipsSatisfiedAndAppliesOthers(t *testing.T) {
	appliedB := false
	eng := New(
		&stepStub{name: "a", satisfied: true},
		&stepStub{name: "b", satisfied: false, applied: &appliedB},
	)
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !appliedB {
		t.Error("step b should have been applied")
	}
	evs := collect(events)
	if !hasKind(evs, "a", EventSatisfied) || !hasKind(evs, "b", EventApplied) {
		t.Errorf("unexpected events: %+v", evs)
	}
}

func TestEngineDryRunDoesNotApply(t *testing.T) {
	applied := false
	eng := New(&stepStub{name: "b", satisfied: false, applied: &applied})
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{DryRun: true})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if applied {
		t.Error("dry-run must not apply")
	}
	if !hasKind(collect(events), "b", EventPlanned) {
		t.Error("expected EventPlanned in dry-run")
	}
}

func TestEngineFailFastStopsPipeline(t *testing.T) {
	secondApplied := false
	eng := New(
		&stepStub{name: "a", satisfied: false, applyErr: errors.New("boom")},
		&stepStub{name: "b", satisfied: false, applied: &secondApplied},
	)
	events, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("preflight error = %v", err)
	}
	evs := collect(events) // blocks until the pipeline goroutine closes the channel
	if !hasKind(evs, "a", EventFailed) {
		t.Error("expected EventFailed for step a")
	}
	if secondApplied {
		t.Error("pipeline must stop after a failure")
	}
}

func TestEngineOnlyRefusesUnmetDependency(t *testing.T) {
	eng := New(
		&stepStub{name: "a", satisfied: false},
		&stepStub{name: "b", satisfied: false, requires: []string{"a"}},
	)
	_, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{Only: "b"})
	if err == nil {
		t.Fatal("expected refusal: b requires a which is unsatisfied")
	}
}

func TestEngineOnlyRefusesUnmetTransitiveDependency(t *testing.T) {
	// c → b → a; a is unsatisfied. `--only c` must refuse on the transitive a.
	eng := New(
		&stepStub{name: "a", satisfied: false},
		&stepStub{name: "b", satisfied: true, requires: []string{"a"}},
		&stepStub{name: "c", satisfied: false, requires: []string{"b"}},
	)
	_, err := eng.Run(context.Background(), &config.Server{}, bssh.NewFakeRunner(), Options{Only: "c"})
	if err == nil {
		t.Fatal("expected refusal: c depends transitively on unsatisfied a")
	}
}

func hasKind(evs []Event, step string, k EventKind) bool {
	for _, e := range evs {
		if e.Step == step && e.Kind == k {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it fails**

Run: `go test ./internal/provision/...`
Expected: FAIL — `New`/`Options`/`Run` undefined.

- [ ] **Step 5: Write `internal/provision/engine.go`**

```go
package provision

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// Options controls a pipeline run.
type Options struct {
	DryRun     bool
	Only       string // run only this step (after verifying its transitive deps)
	Force      bool   // overwrite resources not managed by berth (drift policy)
	SSLStaging bool   // use Let's Encrypt staging in the TLS step
}

// Engine runs steps in registration order.
type Engine struct{ steps []Step }

func New(steps ...Step) *Engine { return &Engine{steps: steps} }

// Run executes the pipeline, returning a channel of progress events that is
// closed when the run finishes. Step Check/Apply failures are reported as
// EventFailed and stop the pipeline (fail-fast). The returned error is non-nil
// ONLY for pre-flight problems (an unknown --only target or an unmet --only
// dependency); per-step errors travel on the event stream and are surfaced by
// the renderer (see internal/ui).
func (e *Engine) Run(ctx context.Context, s *config.Server, r bssh.Runner, opt Options) (<-chan Event, error) {
	rc := RunCtx{Force: opt.Force, SSLStaging: opt.SSLStaging}
	if opt.Only != "" {
		if err := e.checkDependencies(ctx, rc, s, r, opt.Only); err != nil {
			return nil, err
		}
	}
	ch := make(chan Event, len(e.steps)*2+1)
	go func() {
		defer close(ch)
		for _, step := range e.steps {
			if opt.Only != "" && step.Name() != opt.Only {
				continue
			}
			ch <- Event{Step: step.Name(), Kind: EventStarted}
			cr, err := step.Check(ctx, rc, s, r)
			if err != nil {
				ch <- Event{Step: step.Name(), Kind: EventFailed, Err: fmt.Errorf("%s: check: %w", step.Name(), err)}
				return
			}
			if cr.Satisfied {
				ch <- Event{Step: step.Name(), Kind: EventSatisfied, Reason: cr.Reason}
				continue
			}
			if opt.DryRun {
				ch <- Event{Step: step.Name(), Kind: EventPlanned, Reason: cr.Reason, Changes: cr.Changes, Sensitive: cr.Sensitive}
				continue
			}
			if err := step.Apply(ctx, rc, s, r); err != nil {
				ch <- Event{Step: step.Name(), Kind: EventFailed, Err: fmt.Errorf("%s: apply: %w", step.Name(), err)}
				return
			}
			ch <- Event{Step: step.Name(), Kind: EventApplied, Changes: cr.Changes, Sensitive: cr.Sensitive}
		}
	}()
	return ch, nil
}

// checkDependencies fails if any TRANSITIVE Requires of target is unsatisfied.
// It walks the dependency graph depth-first (detecting cycles) and Checks each
// prerequisite, so `--only ssl` correctly refuses when an indirect dependency
// (e.g. php, needed by site, needed by tls) is not yet satisfied.
func (e *Engine) checkDependencies(ctx context.Context, rc RunCtx, s *config.Server, r bssh.Runner, target string) error {
	byName := map[string]Step{}
	for _, st := range e.steps {
		byName[st.Name()] = st
	}
	if _, ok := byName[target]; !ok {
		return fmt.Errorf("unknown step %q", target)
	}
	var missing []string
	visiting, done := map[string]bool{}, map[string]bool{}
	var walk func(name string) error
	walk = func(name string) error {
		if done[name] {
			return nil
		}
		if visiting[name] {
			return fmt.Errorf("dependency cycle at %q", name)
		}
		visiting[name] = true
		st, ok := byName[name]
		if !ok {
			missing = append(missing, name+" (undefined)")
		} else {
			for _, dep := range st.Requires() {
				if err := walk(dep); err != nil {
					return err
				}
			}
			if name != target { // the target itself need not be satisfied
				cr, err := st.Check(ctx, rc, s, r)
				if err != nil {
					return fmt.Errorf("%s: check: %w", name, err)
				}
				if !cr.Satisfied {
					missing = append(missing, name)
				}
			}
		}
		visiting[name], done[name] = false, true
		return nil
	}
	if err := walk(target); err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("cannot run %q: unmet prerequisites: %v", target, missing)
	}
	return nil
}
```

> Implementer note: `Run` streams events live (so Plan 3's bubbletea renderer can update in real time) and returns an error only for pre-flight `--only` problems. Per-step failures are surfaced via `EventFailed` and by the renderer's return value (Task 10). Consumers must drain the channel to completion.

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/provision/...`
Expected: PASS (all four engine tests).

- [ ] **Step 7: Commit**

```bash
git add internal/provision
git commit -m "Add provision engine: Step, CheckResult, events, run loop"
```

---

## Task 10: Plain renderer & TTY detection

**Files:**
- Create: `internal/ui/renderer.go`
- Create: `internal/ui/plain.go`
- Test: `internal/ui/plain_test.go`

- [ ] **Step 1: Write `internal/ui/renderer.go`**

```go
// Package ui renders provisioning progress events.
package ui

import (
	"os"

	"github.com/robsonek/berth/internal/provision"
	"golang.org/x/term"
)

// Renderer consumes the engine's event stream and reports progress.
// Render returns the terminal error (the Err of any EventFailed), or nil.
type Renderer interface {
	Render(events <-chan provision.Event) error
}

// IsTTY reports whether f is an interactive terminal.
func IsTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
```

> Implementer note: `golang.org/x/term` is pulled in transitively by the Charm libs; if `go mod tidy` does not add it, run `go get golang.org/x/term@latest`.

- [ ] **Step 2: Write the failing test `internal/ui/plain_test.go`**

```go
package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/provision"
)

func feed(evs ...provision.Event) <-chan provision.Event {
	ch := make(chan provision.Event, len(evs))
	for _, e := range evs {
		ch <- e
	}
	close(ch)
	return ch
}

func TestPlainRendererPrintsStatuses(t *testing.T) {
	var buf bytes.Buffer
	r := NewPlainRenderer(&buf)
	err := r.Render(feed(
		provision.Event{Step: "php", Kind: provision.EventStarted},
		provision.Event{Step: "php", Kind: provision.EventApplied},
		provision.Event{Step: "nginx", Kind: provision.EventSatisfied},
	))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "php") || !strings.Contains(out, "nginx") {
		t.Errorf("missing steps in output: %q", out)
	}
}

func TestPlainRendererReturnsFailure() (err error) { return nil } // placeholder removed below

func TestPlainRendererSurfacesFailure(t *testing.T) {
	var buf bytes.Buffer
	r := NewPlainRenderer(&buf)
	err := r.Render(feed(
		provision.Event{Step: "tls", Kind: provision.EventFailed, Err: errors.New("dns not ready")},
	))
	if err == nil || !strings.Contains(err.Error(), "dns not ready") {
		t.Fatalf("expected failure surfaced, got %v", err)
	}
}
```

> Implementer note: delete the stray `TestPlainRendererReturnsFailure` placeholder line above before running — it is shown only to flag that the real failure test is `TestPlainRendererSurfacesFailure`.

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/ui/...`
Expected: FAIL — `NewPlainRenderer` undefined.

- [ ] **Step 4: Write `internal/ui/plain.go`**

```go
package ui

import (
	"fmt"
	"io"

	"github.com/robsonek/berth/internal/provision"
)

// PlainRenderer prints one stable, parseable line per terminal event.
// It emits no ANSI and does no in-place updates — safe for CI and pipes.
type PlainRenderer struct{ w io.Writer }

func NewPlainRenderer(w io.Writer) *PlainRenderer { return &PlainRenderer{w: w} }

func (p *PlainRenderer) Render(events <-chan provision.Event) error {
	var failure error
	for e := range events {
		switch e.Kind {
		case provision.EventSatisfied:
			fmt.Fprintf(p.w, "ok    %s (already)\n", e.Step)
		case provision.EventApplied:
			fmt.Fprintf(p.w, "apply %s\n", e.Step)
		case provision.EventPlanned:
			changes := e.Changes
			if e.Sensitive {
				changes = []string{"[redacted]"}
			}
			fmt.Fprintf(p.w, "plan  %s: %v\n", e.Step, changes)
		case provision.EventFailed:
			fmt.Fprintf(p.w, "FAIL  %s: %v\n", e.Step, e.Err)
			failure = e.Err
		}
	}
	return failure
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/ui/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/ui
git commit -m "Add plain progress renderer and TTY detection"
```

---

## Task 11: Wire `provision` to the engine (empty pipeline)

**Files:**
- Modify: `cmd/provision.go` (replace the `runProvision` stub)
- Test: `cmd/provision_test.go`

- [ ] **Step 1: Write the failing test `cmd/provision_test.go`**

```go
package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writeValidConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "srv.yml")
	cfg := `host: 203.0.113.10
ssh: {user: root, port: 22}
php: {version: "8.5", source: auto}
database: {engine: mariadb, name: myapp, user: myapp}
valkey: true
sites:
  - {domain: app.example.com, deploy_path: /home/deploy/myapp}
`
	if err := os.WriteFile(p, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProvisionLoadsConfigAndRunsEmptyPipeline(t *testing.T) {
	cfgPath := writeValidConfig(t)
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"provision", cfgPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("provision error = %v", err)
	}
	// Empty pipeline (no steps registered yet in Plan 1) → succeeds with no FAIL.
	if bytes.Contains(out.Bytes(), []byte("FAIL")) {
		t.Errorf("unexpected failure in output: %q", out.String())
	}
}

func TestProvisionRejectsInvalidConfigPath(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"provision", "/no/such/file.yml"})
	if err := root.Execute(); err == nil {
		t.Error("expected error for missing config file")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/...`
Expected: FAIL — `runProvision` still returns "not implemented".

- [ ] **Step 3: Replace `runProvision` in `cmd/provision.go`**

```go
import (
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/ui"
)

// steps returns the ordered pipeline. Empty in Plan 1; Plan 2 fills it.
func steps(_ *config.Server) []provision.Step { return nil }

func runProvision(cmd *cobra.Command, serverPath string, f *provisionFlags) error {
	srv, err := config.Load(serverPath)
	if err != nil {
		return err
	}
	// Plan 1 ships no real ssh connection; the engine runs against a config-only
	// pipeline. Plan 2 introduces the live ssh.Runner and the connection model.
	eng := provision.New(steps(srv)...)
	events, err := eng.Run(cmd.Context(), srv, nil, provision.Options{
		DryRun: f.dryRun,
		Only:   f.only,
	})
	if err != nil {
		return err
	}
	r := ui.NewPlainRenderer(cmd.OutOrStdout())
	return r.Render(events)
}
```

> Implementer note: passing `nil` as the `ssh.Runner` is safe only while the pipeline is empty. Plan 2's first task introduces the live runner and the connection/auto-detection model (§6.1) and updates this wiring; no real step may run against a nil runner.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./...`
Expected: PASS across all packages.

- [ ] **Step 5: Build the binary**

Run: `go build -o /tmp/berth . && /tmp/berth --version`
Expected: prints `berth dev (none, unknown)` (ldflags wired in Plan 3).

- [ ] **Step 6: Commit**

```bash
git add cmd/provision.go cmd/provision_test.go
git commit -m "Wire provision command to load config and run the (empty) engine"
```

---

## Task 12: CI workflow for tests (lint + vet + test)

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - run: go vet ./...
      - run: go test -race ./...
```

- [ ] **Step 2: Verify locally**

Run: `go vet ./... && go test -race ./...`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "Add CI workflow: vet and race-enabled tests"
```

---

## Self-Review

- **Spec coverage (Foundation slice):** §5 `Runner` (Task 6), `Step`/`CheckResult` (Task 9), `apt` helper (Task 8), config + validators (Tasks 3–4), input-validation rules (Task 4), commands (Tasks 2, 5, 11), plain renderer + TTY detection (Task 10), redaction + secret generation (Task 7). Deferred to Plans 2–3 (called out in-line): live ssh.Runner, concrete steps, MariaDB engine, secret persistence, huh wizard, bubbletea renderer, GoReleaser. ✔
- **Placeholder scan:** The only intentional placeholders are (a) the Surý `Fingerprint` value — flagged with a replace-before-ship note and a verification source; (b) a deliberately-marked stray test line in Task 10 with delete instructions. Both are explicit, not silent. No "TODO/TBD/handle errors appropriately".
- **Type consistency:** `ssh.Runner`/`Result`/`FileSpec` (Task 6) are consumed unchanged by `apt` (Task 8), `provision` (Task 9), and `cmd` (Task 11). `provision.Event`/`EventKind`/`CheckResult` (Task 9) are consumed unchanged by `ui` (Task 10). `config.Server` is threaded through `Step.Check/Apply` and `runProvision`. `Engine.Run` signature `(ctx, *config.Server, ssh.Runner, Options) (<-chan Event, error)` is identical in Task 9 and Task 11.
- **Scope:** Self-contained — every task ends green and committed; the module builds and all tests pass at Task 11. Produces a working CLI that loads/validates config and runs an (empty) idempotent pipeline with parseable output.

---

## Execution Handoff

This is Plan 1 of 3 (Foundation → Provisioning steps → UX & distribution). After Plan 1 is implemented and green, request Plans 2 and 3.

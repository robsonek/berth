# berth v1 — Plan 3: UX & Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish v1 — the interactive `berth init` wizard, the live bubbletea progress view (with TTY-aware fallback to the plain renderer), build-time version injection, and cross-platform release via GoReleaser + GitHub Actions.

**Architecture:** `internal/wizard` collects answers with **huh** and serializes a `config.Server` to `servers/<name>.yml`. `internal/ui` gains a **bubbletea** renderer whose pure state-reducer is unit-tested; `ui.New(w, isTTY)` returns the bubbletea renderer on a TTY and the Plan 1 plain renderer otherwise. `version` vars are injected via `-ldflags`. `.goreleaser.yaml` + a tag-triggered workflow build static binaries for Linux/macOS/Windows after the test + integration gate.

**Tech Stack:** Charm v2 — **import paths `charm.land/…/v2`** (the canonical v2 module path; `bubbletea/v2` v2.0.7, `bubbles/v2` v2.1.0, `lipgloss/v2` v2.0.4, `huh/v2` v2.0.3), already in `go.mod`. v2 API: `View()` returns **`tea.View`** (via `tea.NewView`), key events are `tea.KeyPressMsg`. GoReleaser v2 (`goreleaser/goreleaser-action@v6`).

**Spec:** `docs/design/2026-06-13-berth-design.md` (Rev 5) §2, §5 (Interface), §10. Builds on Plans 1–2.

**Prerequisite:** Plans 1 and 2 implemented and green.

**Module path:** `github.com/robsonek/berth`. English only; no personal data.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `internal/wizard/wizard.go` | huh forms → `config.Server`; serialize to YAML |
| `internal/ui/tui.go` | bubbletea renderer (live step list) + pure reducer |
| `internal/ui/factory.go` | `New(w, isTTY)` → bubbletea or plain renderer |
| `cmd/init.go` | Wire the wizard (replace Plan 1 stub) |
| `cmd/provision.go` | Use `ui.New` for TTY-aware rendering |
| `cmd/root.go` | Inject `version` into the binary |
| `.goreleaser.yaml` | Cross-platform static build + archives + checksums |
| `.github/workflows/release.yml` | Tag-triggered: test + integration gate + release |
| `README.md` | Install-from-Releases section |

---

## Task 1: Wizard answer model & YAML serialization

**Files:**
- Create: `internal/wizard/wizard.go`
- Test: `internal/wizard/wizard_test.go`

- [ ] **Step 1: Write `internal/wizard/wizard.go`**

```go
// Package wizard builds a server config interactively and serializes it.
package wizard

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/robsonek/berth/internal/config"
	"gopkg.in/yaml.v3"
)

// Answers is the flat set of values the huh form collects.
type Answers struct {
	Name       string
	Host       string
	Port       int
	Key        string
	PHPVersion string
	PHPSource  string
	DBName     string
	DBUser     string
	Valkey     bool
	Queue      bool
	Scheduler  bool
	Domain     string
	DeployPath string
	Repository string
	SSL        bool
	SSLEmail   string
}

// ToServer maps validated answers into a config.Server.
func (a Answers) ToServer() *config.Server {
	return &config.Server{
		Host: a.Host,
		SSH:  config.SSH{User: "root", Port: a.Port, Key: a.Key},
		PHP:  config.PHP{Version: a.PHPVersion, Source: a.PHPSource},
		Database: config.Database{Engine: "mariadb", Name: a.DBName, User: a.DBUser},
		Valkey: a.Valkey, Queue: a.Queue, Scheduler: a.Scheduler,
		Sites: []config.Site{{
			Domain: a.Domain, DeployPath: a.DeployPath, Repository: a.Repository,
			SSL: a.SSL, SSLEmail: a.SSLEmail,
		}},
	}
}

// Write validates the server and writes servers/<name>.yml (refusing to clobber).
func (a Answers) Write() (string, error) {
	srv := a.ToServer()
	if err := srv.Validate(); err != nil {
		return "", err
	}
	if err := os.MkdirAll("servers", 0o755); err != nil {
		return "", err
	}
	path := filepath.Join("servers", a.Name+".yml")
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists; refusing to overwrite", path)
	}
	b, err := yaml.Marshal(srv)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
```

> Implementer note: add `gopkg.in/yaml.v3` to `go.mod` (it is already an indirect dep via viper; promote it to direct). Ensure the `config` structs carry `yaml:"..."` tags matching the `mapstructure` tags so the written file round-trips through `config.Load`; add the tags in this task.

- [ ] **Step 2: Write the failing test `internal/wizard/wizard_test.go`**

```go
package wizard

import (
	"os"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

func valid() Answers {
	return Answers{
		Name: "example", Host: "203.0.113.10", Port: 22, Key: "~/.ssh/id_ed25519",
		PHPVersion: "8.5", PHPSource: "auto", DBName: "myapp", DBUser: "myapp",
		Valkey: true, Queue: true, Scheduler: true,
		Domain: "app.example.com", DeployPath: "/home/deploy/myapp",
	}
}

func TestWriteThenLoadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)

	path, err := valid().Write()
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load(%s) error = %v", path, err)
	}
	if got.PHP.Version != "8.5" || got.Sites[0].Domain != "app.example.com" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestWriteRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)
	if _, err := valid().Write(); err != nil {
		t.Fatal(err)
	}
	if _, err := valid().Write(); err == nil {
		t.Error("expected refusal to overwrite existing config")
	}
}

func TestWriteValidatesAnswers(t *testing.T) {
	a := valid()
	a.PHPVersion = "9.9"
	if _, err := a.Write(); err == nil {
		t.Error("expected validation error for bad php version")
	}
}
```

- [ ] **Step 3–5:** Run `go test ./internal/wizard/...` (fail → implement, incl. yaml tags on config structs → pass). Then commit:

```bash
git add internal/wizard internal/config/config.go
git commit -m "Add wizard answer model and config YAML serialization"
```

---

## Task 2: huh form & `berth init`

**Files:**
- Modify: `internal/wizard/wizard.go` (add `Run(ctx) (Answers, error)` using huh)
- Modify: `cmd/init.go`
- Test: covered by Task 1 (the interactive form itself is not unit-tested; its output path `Write` is)

- [ ] **Step 1: Add the huh form to `internal/wizard/wizard.go`**

```go
import "charm.land/huh/v2"

// Run presents the interactive form and returns the collected answers.
func Run() (Answers, error) {
	a := Answers{Port: 22, PHPVersion: "8.5", PHPSource: "auto", Key: "~/.ssh/id_ed25519"}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Config name").Value(&a.Name),
			huh.NewInput().Title("Host (IP)").Value(&a.Host),
			huh.NewInput().Title("SSH key path").Value(&a.Key),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("PHP version").
				Options(huh.NewOptions("8.5", "8.4", "8.3", "8.2")...).Value(&a.PHPVersion),
			huh.NewSelect[string]().Title("PHP source").
				Options(huh.NewOptions("auto", "sury", "debian")...).Value(&a.PHPSource),
		),
		huh.NewGroup(
			huh.NewInput().Title("Database name").Value(&a.DBName),
			huh.NewInput().Title("Database user").Value(&a.DBUser),
			huh.NewConfirm().Title("Install Valkey?").Value(&a.Valkey),
			huh.NewConfirm().Title("Queue worker (Supervisor)?").Value(&a.Queue),
			huh.NewConfirm().Title("Scheduler (cron)?").Value(&a.Scheduler),
		),
		huh.NewGroup(
			huh.NewInput().Title("Domain").Value(&a.Domain),
			huh.NewInput().Title("Deploy path").Value(&a.DeployPath),
			huh.NewInput().Title("Repository (optional)").Value(&a.Repository),
			huh.NewConfirm().Title("Enable TLS (Let's Encrypt)?").Value(&a.SSL),
			huh.NewInput().Title("TLS email").Value(&a.SSLEmail),
		),
	)
	if err := form.Run(); err != nil {
		return Answers{}, err
	}
	return a, nil
}
```

> Implementer note: confirm the huh v2 API against Context7 `/charmbracelet/huh` (v2.0.0) — group/field constructors and `Value` binding. Add per-field `.Validate(...)` using the same `config` validators for inline feedback. The TLS-email field can be conditionally shown via `huh` group hiding when `SSL` is false.

- [ ] **Step 2: Wire `cmd/init.go`**

```go
package cmd

import (
	"fmt"

	"github.com/robsonek/berth/internal/wizard"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Interactive wizard that writes a server config",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := wizard.Run()
			if err != nil {
				return err
			}
			path, err := a.Write()
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s — run: berth provision %s\n", path, path)
			return ensureGitignore()
		},
	}
}
```

> Implementer note: `ensureGitignore()` appends `.berth/` and `*.secrets*` to `.gitignore` if absent (scaffolds it per §7). It is also safe to call from `init`.

- [ ] **Step 3: Build & commit**

Run: `go build ./... && go test ./...`
Expected: PASS.

```bash
git add internal/wizard/wizard.go cmd/init.go
git commit -m "Add interactive huh wizard for berth init"
```

---

## Task 3: bubbletea live renderer + pure reducer

**Files:**
- Create: `internal/ui/tui.go`
- Test: `internal/ui/tui_test.go`

- [ ] **Step 1: Write the failing test `internal/ui/tui_test.go`** (tests the pure reducer, not the terminal)

```go
package ui

import (
	"testing"

	"github.com/robsonek/berth/internal/provision"
)

func TestReducerTracksStatusesAndFailure(t *testing.T) {
	m := newStepModel()
	m = m.apply(provision.Event{Step: "php", Kind: provision.EventStarted})
	m = m.apply(provision.Event{Step: "php", Kind: provision.EventApplied})
	m = m.apply(provision.Event{Step: "tls", Kind: provision.EventFailed, Err: errTest})

	if m.status("php") != "applied" {
		t.Errorf("php status = %q, want applied", m.status("php"))
	}
	if !m.failed() {
		t.Error("model should record failure")
	}
	if m.err == nil {
		t.Error("failure error must be retained for Render's return")
	}
}

var errTest = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }
```

- [ ] **Step 2: Write `internal/ui/tui.go`**

```go
package ui

import (
	"fmt"
	"io"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/robsonek/berth/internal/provision"
)

// stepModel is the pure, testable state behind the TUI.
type stepModel struct {
	order    []string
	statuses map[string]string // started|applied|already|planned|failed
	err      error
}

func newStepModel() stepModel {
	return stepModel{statuses: map[string]string{}}
}

func (m stepModel) apply(e provision.Event) stepModel {
	if _, seen := m.statuses[e.Step]; !seen && e.Step != "" {
		m.order = append(m.order, e.Step)
	}
	switch e.Kind {
	case provision.EventStarted:
		m.statuses[e.Step] = "started"
	case provision.EventSatisfied:
		m.statuses[e.Step] = "already"
	case provision.EventApplied:
		m.statuses[e.Step] = "applied"
	case provision.EventPlanned:
		m.statuses[e.Step] = "planned"
	case provision.EventFailed:
		m.statuses[e.Step] = "failed"
		m.err = e.Err
	}
	return m
}

func (m stepModel) status(step string) string { return m.statuses[step] }
func (m stepModel) failed() bool              { return m.err != nil }

var (
	okStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	failStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
)

func (m stepModel) view() string {
	out := ""
	for _, name := range m.order {
		switch m.statuses[name] {
		case "applied":
			out += okStyle.Render("⚙ "+name) + "\n"
		case "already":
			out += okStyle.Render("✔ "+name+" (already)") + "\n"
		case "failed":
			out += failStyle.Render("✗ "+name+": "+errText(m.err)) + "\n"
		default:
			out += "… " + name + "\n"
		}
	}
	return out
}

func errText(e error) string { if e == nil { return "" }; return e.Error() }

// TUIRenderer drives a bubbletea program from the engine's event stream.
type TUIRenderer struct{ w io.Writer }

func NewTUIRenderer(w io.Writer) *TUIRenderer { return &TUIRenderer{w: w} }

// Render consumes events live and returns the terminal failure error, if any.
func (t *TUIRenderer) Render(events <-chan provision.Event) error {
	p := tea.NewProgram(teaModel{m: newStepModel(), events: events}, tea.WithOutput(t.w))
	final, err := p.Run()
	if err != nil {
		return err
	}
	return final.(teaModel).m.err
}

// teaModel adapts stepModel to the bubbletea Model interface.
type teaModel struct {
	m      stepModel
	events <-chan provision.Event
}

type eventMsg provision.Event
type doneMsg struct{}

func (tm teaModel) waitForEvent() tea.Cmd {
	return func() tea.Msg {
		e, ok := <-tm.events
		if !ok {
			return doneMsg{}
		}
		return eventMsg(e)
	}
}

// Bubble Tea v2 Model interface (confirmed against the v2 upgrade guide):
// Init() tea.Cmd, Update(tea.Msg) (tea.Model, tea.Cmd), View() tea.View.
func (tm teaModel) Init() tea.Cmd { return tm.waitForEvent() }

func (tm teaModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case eventMsg:
		tm.m = tm.m.apply(provision.Event(m))
		return tm, tm.waitForEvent()
	case doneMsg:
		return tm, tea.Quit
	case tea.KeyPressMsg:
		if m.String() == "ctrl+c" {
			return tm, tea.Quit
		}
	}
	return tm, nil
}

func (tm teaModel) View() tea.View { return tea.NewView(tm.m.view()) }
```

> Implementer note: the v2 signatures above are confirmed — `View()` returns `tea.View` via `tea.NewView`, key events are `tea.KeyPressMsg`, and the import paths are `charm.land/…`. Optionally add a `bubbles/v2` spinner on the in-progress step. The pure `stepModel`/`apply`/`view` is the unit-tested core; the bubbletea glue is thin.

- [ ] **Step 3–5:** Run `go test ./internal/ui/...` (fail → implement → pass), then commit:

```bash
git add internal/ui/tui.go internal/ui/tui_test.go
git commit -m "Add bubbletea live renderer with a unit-tested pure reducer"
```

---

## Task 4: TTY-aware renderer factory

**Files:**
- Create: `internal/ui/factory.go`
- Modify: `cmd/provision.go`
- Test: `internal/ui/factory_test.go`

- [ ] **Step 1: Write the failing test `internal/ui/factory_test.go`**

```go
package ui

import (
	"bytes"
	"testing"
)

func TestNewPicksPlainWhenNotTTY(t *testing.T) {
	r := New(&bytes.Buffer{}, false)
	if _, ok := r.(*PlainRenderer); !ok {
		t.Errorf("non-TTY should yield PlainRenderer, got %T", r)
	}
}

func TestNewPicksTUIWhenTTY(t *testing.T) {
	r := New(&bytes.Buffer{}, true)
	if _, ok := r.(*TUIRenderer); !ok {
		t.Errorf("TTY should yield TUIRenderer, got %T", r)
	}
}
```

- [ ] **Step 2: Write `internal/ui/factory.go`**

```go
package ui

import "io"

// New returns the live TUI renderer on a TTY, or the plain renderer otherwise.
func New(w io.Writer, isTTY bool) Renderer {
	if isTTY {
		return NewTUIRenderer(w)
	}
	return NewPlainRenderer(w)
}
```

- [ ] **Step 3: Use it in `cmd/provision.go`**

Replace the renderer line from Plan 2:

```go
	r := ui.New(cmd.OutOrStdout(), ui.IsTTY(os.Stdout) && !f.verbose && !f.noTTY)
	return r.Render(events)
```

> Implementer note: `--verbose` forces the plain renderer (so the verbose, redacted command log is readable and scrollable). A `--no-tty` flag may be added for explicit control.

- [ ] **Step 4: Run & commit**

Run: `go test ./... && go build ./...`
Expected: PASS.

```bash
git add internal/ui/factory.go internal/ui/factory_test.go cmd/provision.go
git commit -m "Select renderer by TTY (bubbletea interactive, plain for CI/pipes)"
```

---

## Task 5: Version injection via ldflags

**Files:**
- Modify: `cmd/root.go` (use `version.Version` in `Version`, already wired in Plan 1)
- Create: `Makefile` (or document the build command)

- [ ] **Step 1: Create `Makefile`**

```makefile
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/robsonek/berth/internal/version.Version=$(VERSION) \
	-X github.com/robsonek/berth/internal/version.Commit=$(COMMIT) \
	-X github.com/robsonek/berth/internal/version.Date=$(DATE)

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o berth .

test:
	go test ./...
```

- [ ] **Step 2: Verify injection**

Run: `make build && ./berth --version`
Expected: prints a non-`dev` version when on a tag, with commit + date.

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "Add Makefile with ldflags version injection"
```

---

## Task 6: GoReleaser config

**Files:**
- Create: `.goreleaser.yaml`

- [ ] **Step 1: Write `.goreleaser.yaml`**

```yaml
version: 2
project_name: berth
before:
  hooks:
    - go mod tidy
builds:
  - id: berth
    main: .
    binary: berth
    env:
      - CGO_ENABLED=0
    goos: [linux, darwin, windows]
    goarch: [amd64, arm64]
    ignore:
      - goos: windows
        goarch: arm64
    ldflags:
      - -s -w
      - -X github.com/robsonek/berth/internal/version.Version={{.Version}}
      - -X github.com/robsonek/berth/internal/version.Commit={{.ShortCommit}}
      - -X github.com/robsonek/berth/internal/version.Date={{.Date}}
archives:
  - formats: [tar.gz]
    format_overrides:
      - goos: windows
        formats: [zip]
checksum:
  name_template: "checksums.txt"
release:
  draft: false
```

- [ ] **Step 2: Validate locally**

Run: `goreleaser check` (and, if GoReleaser is installed, `goreleaser build --snapshot --clean`)
Expected: config is valid; snapshot builds for all targets.

- [ ] **Step 3: Commit**

```bash
git add .goreleaser.yaml
git commit -m "Add GoReleaser config for cross-platform static binaries"
```

---

## Task 7: Release workflow (test + integration gate + release)

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Write `.github/workflows/release.yml`**

```yaml
name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - name: Unit tests
        run: go test -race ./...
      - name: Require integration target (fail-closed gate)
        env:
          BERTH_TEST_SERVER: ${{ secrets.BERTH_TEST_SERVER }}
        run: |
          if [ -z "${BERTH_TEST_SERVER}" ]; then
            echo "::error::BERTH_TEST_SERVER is not set; the release gate requires a Debian 13 target."
            exit 1
          fi
      - name: Integration smoke test (release gate)
        run: go test -tags integration ./test/integration/...
        env:
          BERTH_TEST_SERVER: ${{ secrets.BERTH_TEST_SERVER }}
      - uses: goreleaser/goreleaser-action@v6
        with:
          version: "~> v2"
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

> Implementer note: the gate is **fail-closed** — the `Require integration target` step fails the release when `BERTH_TEST_SERVER` is unset, so a release cannot be cut without a real Debian 13 smoke test. (The test's `t.Skip` on a missing target is for *local* dev only; CI enforces presence.) A robust alternative is to provision an ephemeral Debian 13 VPS / Incus container in a prior job and export its address as `BERTH_TEST_SERVER`.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "Add tag-triggered release workflow with test and integration gates"
```

---

## Task 8: README install section

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the "Status: early development" note's roadmap area with an install section**

```markdown
## Install

Download the binary for your OS from the [Releases](https://github.com/robsonek/berth/releases) page (Linux, macOS, Windows; amd64/arm64), make it executable, and put it on your `PATH`. No runtime is required.

```bash
# example (Linux amd64)
curl -fsSL -o berth https://github.com/robsonek/berth/releases/latest/download/berth_linux_amd64
chmod +x berth && sudo mv berth /usr/local/bin/
berth --version
```

## Usage

```bash
berth init                 # interactive wizard → servers/<name>.yml
berth provision servers/<name>.yml   # provision the server (idempotent)
berth provision servers/<name>.yml --dry-run
```
```

> Implementer note: align the exact asset filename with GoReleaser's `name_template` output (adjust the curl URL accordingly).

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "Document binary install and basic usage"
```

---

## Self-Review

- **Spec coverage:** huh wizard `init` (Tasks 1–2, §5 Interface); bubbletea live renderer + pure reducer (Task 3, §5/§8); TTY-aware selection with plain fallback (Task 4, §5); ldflags version (Task 5, §10); GoReleaser matrix Linux/macOS/Windows, CGO off, archives + checksums (Task 6, §10); tag-triggered workflow running unit tests **and the integration smoke gate** before release (Task 7, §9/§10); install docs (Task 8). ✔
- **Placeholder scan:** The bubbletea v2 `Init/Update/View` glue and the huh v2 field API carry explicit "verify against Context7 v2.0.0" notes — flagged, not silent — because v2 signatures must be confirmed at implementation time; the unit-tested core (`stepModel`/`apply`/`view`, `Answers.Write`) is fully specified. No "TODO/handle later".
- **Type consistency:** `ui.Renderer` (Plan 1) is implemented by `PlainRenderer` (Plan 1) and `TUIRenderer` (Task 3); `New` returns `Renderer`. `provision.Event`/`EventKind` consumed by the reducer match Plan 1. `config.Server`/`Validate` reused by the wizard. `version.Version/Commit/Date` (Plan 1) are the ldflags targets.
- **Scope:** Each task ends green + committed; after Task 8, `berth init` + `berth provision` are complete with an interactive TUI, and `git tag vX.Y.Z` produces cross-platform release binaries. v1 is shippable.

---

## Execution Handoff

Plan 3 of 3 — completes v1. With all three plans approved, the project takes its single clean initial commit (spec + the three plans + LICENSE/README/.gitignore), after which implementation can proceed via superpowers:subagent-driven-development (recommended) or superpowers:executing-plans, Plan 1 → 2 → 3.

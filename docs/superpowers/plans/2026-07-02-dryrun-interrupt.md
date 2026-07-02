# Dry-run Plain Renderer + Non-zero Exit on Interrupt — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `--dry-run` always renders the plan via the plain renderer, and any interrupt (ctrl+c key, SIGINT, SIGTERM) exits non-zero while the engine stops before starting another step.

**Architecture:** Renderer selection moves into a pure `wantTUI` helper that excludes dry-run from the TUI. Interrupt handling gets ONE owner — the root context (`signal.NotifyContext` in `cmd.Execute`); bubbletea's own signal handler is disabled (`tea.WithoutSignalHandler`), the TUI's raw-mode ctrl+c sets an exported `ui.ErrInterrupted` sentinel, and the engine emits an "interrupted" `EventFailed` between steps when the context is cancelled.

**Tech Stack:** Go 1.25, cobra, charm.land/bubbletea/v2 v2.0.7 (import path `charm.land/bubbletea/v2`, NOT github.com/charmbracelet).

**Spec:** `docs/superpowers/specs/2026-07-02-dryrun-interrupt-design.md` (approved; includes Codex design-review outcomes).

## Global Constraints

- Go 1.25; NEVER run `go mod tidy` (prunes pre-listed Charm v2 deps); no new dependencies needed.
- Charm v2 import path is `charm.land/bubbletea/v2` (already imported as `tea` in internal/ui/tui.go).
- Public MIT repo: code/comments/commits English-only, no personal data.
- Two-error-channels contract must hold: `Engine.Run`'s returned error stays --only-preflight-only; interruption travels as `EventFailed` on the event stream.
- Out of scope: cancelling a remote command in flight (`ssh.Client` ignores ctx — separate finding). Exit code on interrupt is 1, not 130.
- After each task: `gofmt -l .` must print nothing; `go test ./...` must pass.
- Branch: `fix/dryrun-interrupt` (already created; spec committed on it).

---

### Task 1: `wantTUI` helper — dry-run forces the plain renderer

**Files:**
- Modify: `cmd/provision.go` (add helper; change the `ui.New` call site at the end of `runProvision`)
- Test: `cmd/provision_test.go` (append a new test)

**Interfaces:**
- Produces: `func wantTUI(stdoutIsTTY bool, f *provisionFlags) bool` — pure, used only inside `cmd`. Task 4 keeps this call site when it touches `runProvision`.

- [ ] **Step 1: Write the failing test**

Append to `cmd/provision_test.go`:

```go
func TestWantTUIDisabledForDryRunVerboseNoTTY(t *testing.T) {
	cases := []struct {
		name string
		tty  bool
		f    provisionFlags
		want bool
	}{
		{"tty plain run", true, provisionFlags{}, true},
		{"not a tty", false, provisionFlags{}, false},
		{"dry-run forces plain", true, provisionFlags{dryRun: true}, false},
		{"verbose forces plain", true, provisionFlags{verbose: true}, false},
		{"no-tty forces plain", true, provisionFlags{noTTY: true}, false},
		{"dry-run without tty stays plain", false, provisionFlags{dryRun: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wantTUI(tc.tty, &tc.f); got != tc.want {
				t.Errorf("wantTUI(%v, %+v) = %v, want %v", tc.tty, tc.f, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run '^TestWantTUIDisabledForDryRunVerboseNoTTY$' ./cmd/`
Expected: FAIL to compile with `undefined: wantTUI`

- [ ] **Step 3: Write minimal implementation**

In `cmd/provision.go`, add above `runProvision`:

```go
// wantTUI reports whether the live TUI should render this run. Dry-run always
// uses the plain renderer: a plan is a report to read or pipe, and the TUI has
// no planned-changes view.
func wantTUI(stdoutIsTTY bool, f *provisionFlags) bool {
	return stdoutIsTTY && !f.verbose && !f.noTTY && !f.dryRun
}
```

and change the renderer line at the end of `runProvision` from:

```go
	r := ui.New(cmd.OutOrStdout(), ui.IsTTY(os.Stdout) && !f.verbose && !f.noTTY)
```

to:

```go
	r := ui.New(cmd.OutOrStdout(), wantTUI(ui.IsTTY(os.Stdout), f))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/`
Expected: PASS (all existing cmd tests plus the new one)

- [ ] **Step 5: Commit**

```bash
git add cmd/provision.go cmd/provision_test.go
git commit -m "fix(ui): --dry-run always uses the plain renderer

The TUI has no planned state and never renders CheckResult.Changes, so an
interactive dry-run showed nothing actionable. Renderer choice now lives in a
pure wantTUI helper that excludes dry-run (and keeps verbose/no-tty behavior)."
```

---

### Task 2: engine stops between steps on a cancelled context

**Files:**
- Modify: `internal/provision/engine.go` (ctx check inside `Run`'s step loop)
- Test: `internal/provision/engine_test.go` (extend `stepStub` with a `checked` flag; two new tests)

**Interfaces:**
- Consumes: existing `Engine.Run(ctx, s, r, opt)` signature — unchanged.
- Produces: on `ctx.Done()`, exactly one `Event{Kind: EventFailed, Err: fmt.Errorf("interrupted before %s: %w", step.Name(), ctx.Err())}` for the next step that would have run, then the channel closes. Task 4 relies on this event making both renderers return a non-nil error.

- [ ] **Step 1: Extend the stub and write the failing tests**

In `internal/provision/engine_test.go`, add a `checked` field to `stepStub` (after `applied *bool`):

```go
	checked   *bool
```

and set it at the top of `Check` (the method becomes):

```go
func (s *stepStub) Check(context.Context, RunCtx, *config.Server, bssh.Runner) (CheckResult, error) {
	if s.checked != nil {
		*s.checked = true
	}
	return CheckResult{Satisfied: s.satisfied, Reason: "stub", Changes: []string{"do x"}}, nil
}
```

Append the two tests:

```go
func TestEngineCancelledContextStopsBeforeNextStep(t *testing.T) {
	aChecked := false
	eng := New(
		&stepStub{name: "a", checked: &aChecked},
		&stepStub{name: "b"},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the pipeline starts
	events, err := eng.Run(ctx, &config.Server{}, bssh.NewFakeRunner(), Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	evs := collect(events)
	if len(evs) != 1 || evs[0].Kind != EventFailed || evs[0].Step != "a" {
		t.Fatalf("expected exactly one EventFailed for step a, got %+v", evs)
	}
	if evs[0].Err == nil || !strings.Contains(evs[0].Err.Error(), "interrupted") {
		t.Errorf("Err = %v, want it to mention interruption", evs[0].Err)
	}
	if aChecked {
		t.Error("no step Check may run after cancellation")
	}
}

func TestEngineCancelledContextWithOnlySkipsUnselectedSteps(t *testing.T) {
	eng := New(
		&stepStub{name: "a", satisfied: true},
		&stepStub{name: "b", requires: []string{"a"}},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	events, err := eng.Run(ctx, &config.Server{}, bssh.NewFakeRunner(), Options{Only: "b"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	evs := collect(events)
	if len(evs) != 1 || evs[0].Step != "b" || evs[0].Kind != EventFailed {
		t.Fatalf("expected one interrupted EventFailed for the --only target, got %+v", evs)
	}
}
```

Add `"strings"` to the test file's imports.

Note: in the second test the `--only` dependency gate runs `Check` on prerequisite "a" with the already-cancelled ctx — `stepStub.Check` ignores ctx, so the gate passes; the point under test is that the skipped step "a" gets NO "interrupted" event in the loop (the ctx check sits after the skip gate).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run 'TestEngineCancelledContext' ./internal/provision/`
Expected: FAIL — first test gets 2+ events (`a` Started/Applied, `b` Started/Applied) instead of a single EventFailed.

- [ ] **Step 3: Write minimal implementation**

In `internal/provision/engine.go`, inside `Run`'s goroutine loop, insert AFTER the `--only` skip gate (the `if opt.Only != "" && ... { continue }` block) and BEFORE `ch <- Event{Step: step.Name(), Kind: EventStarted}`:

```go
			// Interruption: stop before starting another step. Emitted as an
			// EventFailed so both renderers surface it as the run's error; the
			// two-error-channels contract is unchanged (Run's returned error
			// remains --only pre-flight only). Placed after the --only gate so
			// a skipped step is never reported as interrupted.
			select {
			case <-ctx.Done():
				ch <- Event{Step: step.Name(), Kind: EventFailed, Err: fmt.Errorf("interrupted before %s: %w", step.Name(), ctx.Err())}
				return
			default:
			}
```

(`fmt` is already imported.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/provision/...`
Expected: PASS (new tests plus all existing engine/registry/step tests)

- [ ] **Step 5: Commit**

```bash
git add internal/provision/engine.go internal/provision/engine_test.go
git commit -m "fix(engine): stop between steps when the run context is cancelled

On ctx.Done the engine emits one 'interrupted before <step>' EventFailed and
returns, so an interrupt surfaces as a non-nil renderer error instead of the
goroutine silently continuing to issue SSH commands. The check sits after the
--only skip gate so unselected steps are never reported as interrupted."
```

---

### Task 3: TUI interrupt — sentinel error, no bubbletea signal handler

**Files:**
- Modify: `internal/ui/tui.go`
- Test: `internal/ui/tui_test.go`

**Interfaces:**
- Produces: `ui.ErrInterrupted` (exported `var ErrInterrupted = errors.New("interrupted")`). `TUIRenderer.Render` returns it on ctrl+c / `tea.ErrInterrupted`. Task 4's `runProvision` does not branch on it (any non-nil error already exits 1) — it exists so tests and future callers can `errors.Is`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/ui/tui_test.go`:

```go
func TestUpdateCtrlCSetsInterruptedAndQuits(t *testing.T) {
	tm := teaModel{m: newStepModel()}
	next, cmd := tm.Update(tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
	got := next.(teaModel)
	if !errors.Is(got.m.err, ErrInterrupted) {
		t.Errorf("err = %v, want ErrInterrupted", got.m.err)
	}
	if cmd == nil {
		t.Error("ctrl+c must quit the program")
	}
}

func TestUpdateCtrlCKeepsStepFailure(t *testing.T) {
	m := newStepModel()
	m = m.apply(provision.Event{Step: "tls", Kind: provision.EventFailed, Err: errTest})
	tm := teaModel{m: m}
	next, _ := tm.Update(tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl}))
	if got := next.(teaModel).m.err; got != errTest {
		t.Errorf("err = %v, want the original step failure %v", got, errTest)
	}
}
```

Add to the test file's imports:

```go
	"errors"

	tea "charm.land/bubbletea/v2"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run 'TestUpdateCtrlC' ./internal/ui/`
Expected: FAIL to compile with `undefined: ErrInterrupted`

- [ ] **Step 3: Write minimal implementation**

In `internal/ui/tui.go`:

1. Add `"errors"` to the imports.
2. Below the imports, add:

```go
// ErrInterrupted is returned by Render when the operator interrupts the run
// (ctrl+c in the TUI, or a bubbletea-level interrupt). A non-nil return makes
// the CLI exit non-zero instead of reporting a half-finished provision as
// success.
var ErrInterrupted = errors.New("interrupted")
```

3. Replace the `tea.KeyPressMsg` case body in `Update`:

```go
	case tea.KeyPressMsg:
		if m.String() == "ctrl+c" {
			if tm.m.err == nil { // a step failure is more informative than "interrupted"
				tm.m.err = ErrInterrupted
			}
			return tm, tea.Quit
		}
```

4. In `Render`, disable bubbletea's own signal handler (the root context owns
   signals now — bubbletea would otherwise turn SIGTERM into a clean nil-error
   quit) and map its interrupt error:

```go
func (t *TUIRenderer) Render(events <-chan provision.Event) error {
	p := tea.NewProgram(teaModel{m: newStepModel(), events: events},
		tea.WithOutput(t.w), tea.WithoutSignalHandler())
	final, err := p.Run()
	if errors.Is(err, tea.ErrInterrupted) {
		return ErrInterrupted
	}
	if err != nil {
		return err
	}
	return final.(teaModel).m.err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/ui/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ui/tui.go internal/ui/tui_test.go
git commit -m "fix(tui): interrupt returns an error instead of a clean exit

ctrl+c now sets an exported ErrInterrupted sentinel (kept only when no step
failure is already recorded) so Render returns non-nil and the CLI exits 1.
The program runs WithoutSignalHandler: bubbletea v2 turned SIGTERM into a
clean QuitMsg (nil error) and SIGINT into its own ErrInterrupted — signal
ownership moves to the root context (see cmd.Execute)."
```

---

### Task 4: signal-bound root context + engine cancellation wiring in cmd

**Files:**
- Modify: `cmd/root.go` (`Execute`)
- Modify: `cmd/provision.go` (`runProvision`)

**Interfaces:**
- Consumes: Task 2's interrupted `EventFailed` (renderers return it), Task 3's `WithoutSignalHandler` TUI.
- Produces: `cmd.Execute()` signature unchanged (main.go untouched). `cmd.Context()` is now cancelled by SIGINT/SIGTERM.

No new unit test: this task is signal-plumbing glue — sending real signals to the
test process is flaky, and every behavioral piece (renderer selection, engine
cancellation, TUI sentinel) is unit-tested in Tasks 1-3. Verification is
compile + full suite + `go vet` + the manual check in Task 5.

- [ ] **Step 1: Rewrite `Execute` in `cmd/root.go`**

Replace the whole `Execute` function:

```go
// Execute runs the root command and exits non-zero on error. SIGINT/SIGTERM
// cancel the command context (the engine stops between steps); after the
// first signal default handling is restored, so a second ctrl+c force-kills
// a process stuck on a remote command that ignores cancellation.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
```

Update the imports of `cmd/root.go` to:

```go
import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/robsonek/berth/internal/version"
	"github.com/spf13/cobra"
)
```

- [ ] **Step 2: Wire the cancellable context through `runProvision` in `cmd/provision.go`**

Add `"context"` to the imports. At the top of `runProvision` (before `config.Load`), add:

```go
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
```

Replace `cmd.Context()` with `ctx` in the `bssh.Connect(...)` call and in `eng.Run(...)`. Replace the final two lines:

```go
	r := ui.New(cmd.OutOrStdout(), wantTUI(ui.IsTTY(os.Stdout), f))
	return r.Render(events)
```

with:

```go
	r := ui.New(cmd.OutOrStdout(), wantTUI(ui.IsTTY(os.Stdout), f))
	rerr := r.Render(events)
	// Cancel explicitly BEFORE the deferred client.Close (LIFO would close the
	// SSH connection first): the engine must not start another step once the
	// renderer has returned, e.g. after a TUI interrupt. A step already in
	// flight is not cancelled (ssh.Runner ignores ctx — documented limitation).
	cancel()
	return rerr
```

- [ ] **Step 3: Run the full suite and static checks**

Run: `go test ./... && go vet ./... && gofmt -l .`
Expected: all tests PASS, vet clean, gofmt prints nothing.

- [ ] **Step 4: Commit**

```bash
git add cmd/root.go cmd/provision.go
git commit -m "fix(cmd): SIGINT/SIGTERM cancel the run and exit non-zero

Execute now uses ExecuteContext with signal.NotifyContext; after the first
signal default handling is restored so a second ctrl+c force-kills. Interrupt
via the plain path: ctx cancels, the engine emits 'interrupted' EventFailed,
the renderer returns it, exit 1. runProvision cancels its context explicitly
when the renderer returns, before the deferred SSH close, so the engine never
starts another step after a TUI interrupt."
```

---

### Task 5: whole-branch verification

**Files:** none (verification only)

- [ ] **Step 1: Full suite with race detector (what CI runs)**

Run: `go test -race ./... && go vet ./...`
Expected: PASS, no vet findings.

- [ ] **Step 2: Build and eyeball the dry-run output path**

```bash
make build
./berth provision --dry-run servers/ovh.yml | head -20
```

Expected: `plan <step>: [...]`/`ok <step> (already)` lines from the PLAIN renderer
(no ANSI TUI frames), even on a TTY. (Connects to the test box read-only:
dry-run performs Checks only. If the box is unreachable, expect a clean
connection error — the renderer choice is still observable because no TUI
alt-screen is entered.)

- [ ] **Step 3: Interrupt behavior smoke check**

```bash
./berth provision servers/ovh.yml & sleep 2; kill -INT $!; wait $!; echo "exit=$?"
```

Expected: `exit=1` (not 0) and an `interrupted before <step>` line when the
signal lands between steps. (Only run against the disposable test box; a step
in flight finishes first — that is the documented contract.)

- [ ] **Step 4: Mark the roadmap items done**

In `docs/improvement-roadmap.md` § "Design-review findings — 2026-07-02",
prefix the two fixed bullets with `[FIXED <branch/PR>]` (the dry-run HIGH
bullet and the Ctrl-C MEDIUM bullet). Do not commit `docs/` (gitignored);
just edit the local file.

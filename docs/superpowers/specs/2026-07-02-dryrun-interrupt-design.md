# Design: usable `--dry-run` output + non-zero exit on interrupt

Date: 2026-07-02
Status: approved (user + Codex design review, 1 BLOCKER + 3 SHOULD-FIX incorporated)
Source: design-review findings H1 and "Ctrl-C exits 0" (docs/improvement-roadmap.md § Design-review findings — 2026-07-02)

## Problem

Two verified defects in the provision UX:

1. **`--dry-run` on a TTY renders no plan.** The TUI's `view()` (internal/ui/tui.go)
   has cases only for `applied`/`already`/`failed`; the `planned` status falls
   through to the same `… <step>` glyph as pending, and `CheckResult.Changes` is
   never rendered anywhere in the TUI. Renderer selection (cmd/provision.go)
   picks the TUI on a TTY regardless of dry-run, so the preview-before-mutating
   safety feature emits nothing actionable on the default path. The
   `PlainRenderer` already handles `EventPlanned` correctly (`plan <step>:
   [changes]`, with `Sensitive` redaction).

2. **Ctrl-C during a live provision exits 0.** The TUI maps `ctrl+c` to
   `tea.Quit`; `Render` returns `model.err`, which is nil unless a step already
   failed; cobra exits success on a half-configured server. The engine goroutine
   also keeps issuing SSH commands after the TUI quits (nothing cancels the
   context). Additionally (found in Codex design review, verified against
   bubbletea v2.0.7 source): bubbletea installs its own signal handler — SIGINT
   becomes `InterruptMsg` (`Run` returns `tea.ErrInterrupted`, tea.go:768) but
   **SIGTERM becomes `QuitMsg` and `Run` returns nil** (tea.go:765), so a
   SIGTERM'd provision also reports success.

## Scope

In scope: renderer selection for dry-run; interrupt/termination producing a
non-zero exit on both renderer paths; stopping the engine **between** steps on
interrupt.

Out of scope (separate finding, "dead ctx in ssh.Client"): cancelling a remote
command already in flight. A step in progress runs to completion (or the
process exits and the SSH connection drops; the remote command may survive
server-side). Exit code on interrupt is 1, like any other error — not 130.

## Design

### A. `--dry-run` forces the plain renderer

- cmd/provision.go: extract a pure helper
  `wantTUI(tty bool, f provisionFlags) bool` returning
  `tty && !f.verbose && !f.noTTY && !f.dryRun`, used at the `ui.New` call site.
- No TUI changes. A plan is a report to read or pipe, not a live view.

### B. Interrupt = error + engine stops between steps

One owner of signals: the root context. Four changes:

1. **internal/ui** — exported sentinel `var ErrInterrupted = errors.New("interrupted")`.
   - `teaModel.Update`, `ctrl+c` key (raw mode): set `m.err = ErrInterrupted`
     **only if `m.err == nil`** (a step failure is more informative), then
     `tea.Quit`.
   - `TUIRenderer.Render`: program constructed with
     `tea.WithoutSignalHandler()` (bubbletea no longer swallows SIGINT/SIGTERM);
     defensively map `tea.ErrInterrupted` from `p.Run()` to `ui.ErrInterrupted`.
2. **cmd/root.go `Execute`** — `newRootCmd().ExecuteContext(ctx)` with
   `ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)`.
   A goroutine `<-ctx.Done(); stop()` restores default signal handling after the
   first signal, so a **second** Ctrl-C force-kills a process stuck on a remote
   command that ignores ctx.
3. **internal/provision/engine.go `Run`** — in the step loop, **after** the
   `--only`/AlwaysRun skip gate and before `EventStarted`, non-blocking select
   on `ctx.Done()`: emit
   `Event{Step: step.Name(), Kind: EventFailed, Err: fmt.Errorf("interrupted before %s: %w", step.Name(), ctx.Err())}`
   and return. No new EventKind: both renderers already surface `EventFailed`
   as a non-nil error, and the two-error-channels contract is preserved
   (`Engine.Run`'s returned error stays --only-preflight-only).
4. **cmd/provision.go `runProvision`** —
   `ctx, cancel := context.WithCancel(cmd.Context())` passed to `Connect` and
   `eng.Run`; call `cancel()` **explicitly right after `Render` returns**
   (before the LIFO defers run `client.Close()`), keeping `defer cancel()` for
   early-error paths. This guarantees the engine does not start another step in
   the window before process exit.

### Flow after the change

- TUI + ctrl+c key: Update sets `ErrInterrupted`, quits; `runProvision` cancels
  ctx; exit 1.
- Either renderer + SIGINT/SIGTERM: NotifyContext cancels ctx; engine emits the
  interrupted `EventFailed` before its next step; renderer returns it; exit 1.
  If a long step is in flight, the event arrives when it finishes; a second
  Ctrl-C (post-`stop()`) force-kills.
- Engine goroutine never deadlocks post-quit: the events channel is buffered
  `len(steps)*2+1`, enough for every event even with no reader.

## Tests (TDD)

- `cmd`: table test for `wantTUI` (tty × verbose × noTTY × dryRun).
- `internal/ui/tui_test.go`: `Update` with
  `tea.KeyPressMsg(tea.Key{Code: 'c', Mod: tea.ModCtrl})` → model err is
  `ErrInterrupted` + quit; a pre-existing step-failure error is NOT overwritten.
- `internal/provision/engine_test.go`: cancelled ctx → exactly one
  `EventFailed` whose message contains "interrupted", and the following step's
  `Check` is never invoked (stepStub call counting); `--only` + cancelled ctx
  does not emit "interrupted" for a skipped step.
- Existing golden files, templates, and integration tests untouched.

## Codex design-review outcomes (2026-07-02)

- BLOCKER: bubbletea v2 signal handler (SIGTERM→QuitMsg→nil) — fixed via
  `WithoutSignalHandler` + root-context signal ownership (verified in
  bubbletea v2.0.7 source: tea.go:646-673, 765-769; options.go:64).
- SHOULD-FIX: `stop()` after first signal — adopted (Execute goroutine).
- SHOULD-FIX: ctx check placement after the `--only` gate — adopted.
- SHOULD-FIX: explicit `cancel()` before deferred `client.Close()` — adopted.
- OK: plain-renderer-for-dry-run; `EventFailed` for interruption; KeyPressMsg
  test construction.

# Design: declarative system timezone (`system.timezone`)

> Status: design approved in brainstorming; pending Codex review → writing-plans.
> Date: 2026-07-24.

## 1. Goal & scope

Operators change a fresh box's timezone right after install so system logs
(journald, nginx, fail2ban, cron mails) read in local time without mental
offset math. berth makes that declarative: one optional field, applied
idempotently by the existing `system` step.

Decisions locked during brainstorming:

- **Opt-in, no default.** Empty = berth never touches the timezone — the
  documented `System` contract (`Swap`/`Sysctl` default off the same way).
  Explicitly rejected: a `UTC` default (every admin wants their own zone; a
  forced default would mutate already-provisioned hosts on re-run).
- **Set via wizard AND yaml** — the wizard is just the interactive generator
  of the same field.
- **Unset ≠ drift-removal.** Unlike `swap` (a berth-created artifact that is
  removed when the knob is cleared), a timezone is plain system state with no
  berth-owned artifact: clearing the field means "stop managing", never
  "revert to UTC". Documented asymmetry.
- **System scope only.** PHP ignores the system zone without `date.timezone`,
  and Laravel apps carry their own `app.timezone` — both deliberately out of
  scope (the motivation is *system logs*; UTC app time is a Laravel best
  practice anyway). Noted in README.

## 2. Config surface (`internal/config`)

```yaml
system:
  timezone: Europe/Warsaw   # optional; empty/absent = berth leaves it untouched
```

```go
type System struct {
    Swap     string `mapstructure:"swap"     yaml:"swap,omitempty"`
    Sysctl   bool   `mapstructure:"sysctl"   yaml:"sysctl,omitempty"`
    Timezone string `mapstructure:"timezone" yaml:"timezone,omitempty"` // empty = don't touch
}
```

No `SetDefault`, no `*Eff` accessor — there is nothing to default to.

### 2.1 Validation (`validate.go`, lenient — empty passes)

The value reaches a command line, so the guard is config-injection defence:

```go
reTimezone = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
```

Covers the IANA shapes: `UTC`, `Europe/Warsaw`, `Etc/GMT+8`,
`America/Port-au-Prince`, `America/Argentina/Buenos_Aires` (max three
segments); rejects whitespace, `;`, `..`, leading `/`. **Existence is NOT
validated locally** — rejected alternative: `time.LoadLocation` needs a tzdb
that berth's Windows binaries don't ship (embedding `time/tzdata` costs
~450 KB); `timedatectl set-timezone` already rejects an unknown zone loudly
on the host, format-only guards being the repo's standard (MariaDB sizes).

## 3. `system` step changes (`internal/provision/steps/system.go`)

A third managed block next to swap and sysctl, gated on
`s.System.Timezone != ""`:

- **Check (read-only):** `timedatectl show -p Timezone --value`; trimmed
  output equal to the configured value ⇒ satisfied. Empty config ⇒ the block
  is skipped entirely (no remote call).
- **Apply:** capture the current zone, `timedatectl set-timezone <shQuote(tz)>`,
  then `systemctl restart cron`. The cron restart is the load-bearing detail:
  cron reads the local time at startup, and berth's own backup cron
  (`30 3 * * *`) is wall-clock-sensitive — without the restart the old zone's
  schedule would persist indefinitely. Plain `restart` (not `try-restart`,
  which the first draft used): berth ships cron-based features (scheduler,
  backups), so cron running is part of its promise — and `try-restart` would
  silently no-op on a cron left STOPPED by a previous half-failed restart,
  green-lighting a box whose scheduler is dead (Codex round-2 finding). A
  truly absent/masked cron makes `restart` fail loudly and the zone reverts.
  Both commands run under the client's standard sudo wrapping.
- **Cron-failure compensation (Codex HIGH, round 2 refined):** if the cron
  restart exits non-zero, Apply **reverts** to the captured previous zone
  before returning the error. Without this, the next run's Check would see
  the new zone already set and report Satisfied forever while cron still
  fires on the old zone's schedule — the exact falsely-Satisfied class the
  php step's drop-in-removal compensation closes, solved with the same shape.
  The revert's outcome is CHECKED and the error message branches honestly:
  "reverted … the next run retries" on success, versus an explicit
  "revert failed too — the zone is applied but cron still runs the old
  schedule; restart cron manually or re-run" on a double failure (never claim
  a revert that didn't happen). The double-failure residual (falsely
  Satisfied after it) is accepted and documented — a box where even
  `timedatectl` fails twice needs an operator anyway. A failed
  `set-timezone` needs no compensation (nothing changed). Rejected
  alternative: an mtime-vs-`ActiveEnterTimestamp` liveness probe in Check
  (the tuning-step machinery) — a per-Check remote probe for a
  failure-path-only scenario, and the zone comparison already reconciles
  out-of-band changes.
- **Convergence:** `set-timezone` atomically updates `/etc/localtime` +
  `/etc/timezone`; the next Check reads the new value (or, after a
  compensated failure, the reverted one — and retries both commands).
- **No foreign-file concerns:** nothing berth-managed is written, so the
  managed-marker machinery is not involved.

No registry change — `system` is already in the pipeline unconditionally.

## 4. Wizard (`internal/wizard`)

- `SystemAnswers.Timezone string`; `ServerOps` gains one input in the system
  group: `System timezone (e.g. Europe/Warsaw, blank=leave untouched)` with
  an `optionalTimezone` validator mirroring §2.1's regex (the established
  mirror-regex pattern; config validation stays authoritative and the domains
  are IDENTICAL — the fingerprint-era lesson: an inline validator narrower
  than config's traps the operator, wider ones let bad values reach the site
  retry loop it cannot fix. Same regex literal, both sides).
- `toserver.go`: map the field through.
- `matrix_test.go`: one valid case (loaded server carries the zone) + one
  invalid (`Europe;rm` → error names `system.timezone`).

## 5. README

`system:` block gains the field with two honest notes: (1) changing the zone
shifts when berth's cron jobs (backups schedule) fire — they run in local
time; (2) PHP/Laravel keep their own timezone settings — this field is about
system logs.

## 6. Testing (TDD, FakeRunner, exact-string `On(...)`)

- **config:** regex accepts `UTC`, `Europe/Warsaw`, `Etc/GMT+8`,
  `America/Argentina/Buenos_Aires`, `America/Port-au-Prince`; rejects
  `Europe/Warsaw; rm -rf /`, `../etc/passwd`, `Europe Warsaw`, `/Europe`,
  `A/B/C/D`; empty lenient-passes.
- **system step:** unset ⇒ NO timezone command in `Calls()` (**both** Check
  and Apply paths — Apply asserted too, an unstubbed probe errors the
  FakeRunner); set + drifted ⇒ Check unsatisfied, Apply runs **exactly one**
  `timedatectl set-timezone 'Europe/Warsaw'` then **exactly one**
  `systemctl restart cron`, in that order (occurrence counts, not just
  presence); set + matching ⇒ satisfied, Apply skips the block (re-entrant
  like swap/sysctl); `set-timezone` failure ⇒ error surfaces, NO cron
  restart, NO revert; cron-restart failure ⇒ error surfaces, names the
  successful revert, AND the revert `set-timezone '<previous>'` runs;
  cron-restart failure + revert failure ⇒ error explicitly says the revert
  failed and cron needs manual attention (never claims "reverted");
  trailing-newline handling of the `show` output.
- **wizard:** `optionalTimezone` accept/reject table; `ToServer` carries the
  field; matrix cases per §4.
- **integration (same PR, proven pattern):** `assert_system.go` gains a
  timezone assert gated on `srv.System.Timezone != ""` — `timedatectl show`
  exits 0 AND equals the configured zone. Runs live at the next box
  validation.

## 6.1 Codex CODE-review incorporation (post-implementation, gpt-5.6-sol)

| # | Severity | Verdict | Resolution |
|---|----------|---------|------------|
| 1 | high | **confirmed** — the v1 `base` step unconditionally ran `timedatectl set-timezone UTC` on every Apply (fire-and-forget; Check never probed it), contradicting "empty = never touch" and creating a no-cron-restart convergence trap for `timezone: UTC` | **UTC set removed from `base` entirely** — `system.timezone` is the sole timezone owner. DELIBERATE BEHAVIOR CHANGE: fresh provisions keep the image's zone unless the knob is set (flagged in the PR body). |
| 2 | high | accepted — an interruption/transport error between a successful `set-timezone` and the cron phase leaves the new zone with stale cron and a Satisfied next run (no revert was attempted) | Accepted residual, same class as every step's interrupted-Apply caveat (the php step's transport-error precedent): nothing can run on a dead connection, the run errors loudly, and any later zone change or cron restart heals it. |
| 3 | medium | confirmed — failure messages said "cron restart" for ensure failures, overclaimed "cron still runs the old schedule", and discarded the revert's own stderr | Neutral "ensuring/restarting cron" wording; double-failure message says "may be in effect without a cron restart" and includes the revert's error detail. |

## 7. Explicitly out of scope (YAGNI)

`php date.timezone` / Laravel `app.timezone`, per-site timezones, tzdata
existence validation, NTP/timesyncd management, reverting to a previous zone
when the field is cleared.

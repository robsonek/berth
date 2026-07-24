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
- **Apply:** `timedatectl set-timezone <shQuote(tz)>` followed by
  `systemctl try-restart cron`. The cron restart is the load-bearing detail:
  cron reads the local time at startup, and berth's own backup cron
  (`30 3 * * *`) is wall-clock-sensitive — without the restart the old zone's
  schedule would persist indefinitely. `try-restart` (not `restart`) is a
  no-op when cron isn't running, so the step never *starts* a service it
  doesn't own. Both commands run under the client's standard sudo wrapping.
- **Convergence:** `set-timezone` atomically updates `/etc/localtime` +
  `/etc/timezone`; the next Check reads the new value. No liveness gap.
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
- **system step:** unset ⇒ NO timezone command in `Calls()` (both Check and
  Apply paths); set + drifted ⇒ Check unsatisfied, Apply runs exactly
  `timedatectl set-timezone 'Europe/Warsaw'` then
  `systemctl try-restart cron`; set + matching ⇒ satisfied, Apply skips the
  block (re-entrant like swap/sysctl); trailing-newline handling of the
  `show` output.
- **wizard:** `optionalTimezone` accept/reject table; `ToServer` carries the
  field; matrix cases per §4.
- **integration (same PR, proven pattern):** `assert_system.go` gains a
  timezone assert gated on `srv.System.Timezone != ""` — `timedatectl show`
  equals the configured zone. Runs live at the next box validation.

## 7. Explicitly out of scope (YAGNI)

`php date.timezone` / Laravel `app.timezone`, per-site timezones, tzdata
existence validation, NTP/timesyncd management, reverting to a previous zone
when the field is cleared.

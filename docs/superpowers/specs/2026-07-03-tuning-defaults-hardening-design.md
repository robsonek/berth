# Design: tuning & defaults hardening (MEDIUM findings 1, 2, 4)

Date: 2026-07-03
Status: awaiting user spec review
Source: design-review findings, docs/improvement-roadmap.md § MEDIUM (items 1,
2 and 4): MariaDB restarted without validation; `--only tuning` passes the
dependency gate then fails mid-Apply; fail2ban defaults live only in `Load()`.

## Problem

**1. MariaDB restart without validation.** `tuning.Apply`
(internal/provision/steps/tuning.go) writes
`/etc/mysql/mariadb.conf.d/99-berth.cnf` and runs `systemctl restart mariadb`
with no validation — the only unvalidated reload path in the tree (nginx,
PHP-FPM, sudoers and fail2ban all validate first). MariaDB has no
`--validate-config` equivalent, and `tuning.mariadb_innodb_buffer_pool` is
already format-guarded by `reMariaDBSize` (`^[0-9]+[KMG]?$`), so the one
realistic killer is a value exceeding host RAM: config parsing cannot catch it
(the failure is allocation at startup), mariadbd goes down, and the poison
drop-in stays on disk — every later run sees "restart mariadb (not running)",
restarts, and fails identically.

**2. `--only tuning` and the conditional Valkey dependency.**
`tuning.Requires()` returns only `["database"]`; the Valkey block's real
prerequisite (the `valkey` step) is not expressed. With `valkey: true` on a
host where the valkey step never ran (flag flipped after the initial
provision), the `--only` gate passes — `database` is satisfied — and Apply
fails midway at `systemctl restart valkey-server.service` (unit absent). The
MariaDB block has no such gap: `database.Check` requires the engine's server
package installed, so a passed gate implies MariaDB is present.

**3. fail2ban defaults live only in `Load()`.**
`SetDefault("fail2ban.{bantime,findtime,maxretry}")` runs only in
`config.Load()`. A `Server` built by the wizard's `ToServer()` or as a struct
literal (tests, integration) renders `bantime = ` / `findtime = ` /
`maxretry = 0` into jail.local, and the deliberately lenient validator
(zero/empty skips) hides it. Tuning, Backups and System already solved this
with defaults in `*Eff()` accessors — fail2ban is the straggler.

## Decision

- **RAM-bound guard, no rollback** for MariaDB. Rejected:
  rollback-on-failed-restart (with the guard, the realistic self-inflicted
  failure is excluded before anything is written; if a fitting value still
  fails to restart, the drop-in is almost certainly not the cause and leaving
  it is correct) and parse-validation via `mariadbd --help --verbose` (cannot
  catch allocation failure; format is already regex-guarded upstream).
- **Dynamic `Requires()`** for the conditional Valkey dependency. Rejected:
  silent skip-when-absent inside each block (adds an SSH probe to every run
  and reports a lying "Satisfied" for tuning that was never applied).
- **`*Eff()` accessors as the single source of truth** for fail2ban defaults;
  the three `SetDefault` lines are removed. Rejected: keeping both (two
  sources for the same value drift apart on the next default change).

## Design

### 1. RAM guard for the MariaDB buffer pool (steps/tuning.go)

New helpers, all in tuning.go:

- `parseMariaDBSize(v string) (uint64, error)` — pure function converting the
  already-format-validated value to bytes (no suffix = bytes; `K`/`M`/`G` =
  1024-based). Overflow-checked (`strconv.ParseUint` + multiplier bound) so an
  absurd `99999999999G` errors instead of wrapping.
- `hostMemTotalBytes(ctx, r)` — runs the stable command
  `awk '/^MemTotal:/{print $2}' /proc/meminfo` (kB → bytes). Empty or
  unparsable output is an error ("cannot determine host RAM"), not zero.
- `checkMariaDBBufferPoolFits(ctx, r, s)` — errors when
  `pool > memTotal * mariadbBufferPoolMaxPercent / 100` with
  `const mariadbBufferPoolMaxPercent = 80` (integer arithmetic; memTotal is
  real RAM, so the multiplication cannot overflow uint64). The message names
  the configured value, the 80% limit and the host's MemTotal, e.g.
  `tuning.mariadb_innodb_buffer_pool 2G exceeds 80% of host RAM (MemTotal 1024 MiB)`.

Placement:

- **Check** runs the guard at the top of the MariaDB block. A violation is a
  step ERROR (`CheckResult{}, err`), not `Satisfied:false`: it is a
  config-vs-host mismatch Apply cannot fix, so the pipeline must stop with a
  pointed message. This also surfaces in `--dry-run`, and nothing is written.
- **Apply** re-runs the guard immediately before the WriteFile+restart pair,
  matching the repo convention that validate-before-reload lives in Apply.
  Costs one extra round-trip only when the MariaDB block actually applies.

Valkey stays unguarded on purpose: `maxmemory` is an eviction limit, not an
allocation — an oversized value does not prevent valkey from starting.

### 2. Dynamic Requires (tuning.go + registry.go)

```go
type tuning struct{ valkey bool }

func Tuning(valkey bool) provision.Step { return tuning{valkey: valkey} }

func (t tuning) Requires() []string {
	if t.valkey {
		return []string{"database", "valkey"}
	}
	return []string{"database"}
}
```

`Pipeline()` constructs `Tuning(s.Valkey)` (argument-taking constructors are
precedented: `Database(red)`). Effect: `--only tuning` with Valkey enabled but
not provisioned refuses pre-flight with `unmet prerequisites: [valkey]`
instead of failing mid-Apply. Full runs are unchanged — registration order
already places tuning after valkey, and `Requires()` never reorders anything.
The `valkey` step name is registered exactly when `s.Valkey` is set, so the
dependency name always resolves.

### 3. fail2ban `*Eff()` accessors (config.go, hardening.go)

- Constants `defaultFail2banBantime = "1h"`,
  `defaultFail2banFindtime = "10m"`, `defaultFail2banMaxretry = 5`; accessors
  `BantimeEff()` / `FindtimeEff()` (empty → default) and `MaxretryEff()`
  (`<= 0` → default, mirroring `RetentionDaysEff`).
- `renderFail2banJail` (steps/hardening.go) switches to the accessors. The
  template is untouched, so golden files are untouched.
- `Load()` drops the three `SetDefault("fail2ban.*")` lines; the `Fail2ban`
  struct comment is updated to the Tuning/Backups wording (defaults live in
  the accessors so `ToServer()`/literal callers render valid values).
- Compatibility: configs that went through `Load()` rendered `1h`/`10m`/`5`;
  the accessors return byte-identical values, so provisioned hosts see no
  drift. Servers that rendered the broken zero-value jail get a one-time
  HEALING drift (jail.local is a managed file, so it is rewritten in place).
- The lenient validator stays as-is — zero/empty now means "use the default"
  by design, so skipping it is correct, and non-empty values remain
  format-guarded (config-injection defence).

## Out of scope

- A RAM guard for Valkey `maxmemory` (not an allocation; does not kill the
  service).
- Stable `REDIS_DB` derivation, domain validation, apt trust chain (MEDIUM
  items 3, 5, 6, 7 — the follow-up package).
- Skip-when-absent unit probes inside tuning blocks (superseded by dynamic
  Requires).
- Any tightening of fail2ban validation ranges.

## Tests (TDD)

- `steps/tuning_test.go`:
  - `parseMariaDBSize` unit matrix: bare bytes, `K`, `M`, `G`, overflow →
    error (pure function, no runner).
  - Check errors when the pool exceeds 80% of the stubbed MemTotal (exact awk
    command on FakeRunner); Apply errors likewise BEFORE any write/restart
    (assert `Writes()` empty and no restart in `Calls()`).
  - Check/Apply proceed when the pool fits (existing MariaDB-block tests gain
    the MemTotal stub).
  - `TestTuningRequiresDatabase` extended: `Tuning(false)` →
    `["database"]`; `Tuning(true)` → `["database", "valkey"]`.
  - Existing gating test keeps proving a postgres+no-valkey server touches
    neither block.
- `steps/registry_test.go`: pipeline still includes tuning exactly when
  `s.Valkey || engine == mariadb` (construction now passes `s.Valkey`).
- `internal/config/config_test.go`: `TestLoadFail2banDefaults` becomes: Load
  leaves omitted fail2ban fields zero AND the `*Eff()` accessors return
  `1h`/`10m`/`5`; explicit values pass through untouched.
- `internal/wizard/matrix_test.go`: the comment referencing
  `SetDefault` fail2ban defaults is updated (behavioral assertions hold).
- `steps/hardening_test.go`: unchanged (its servers set explicit fail2ban
  values); one added case renders the jail from a zero-value `Fail2ban` and
  asserts the defaults appear (the exact bug scenario).
- Verification: `gofmt -l .`, `go vet ./...`, `go test -race ./...`; Codex
  foreground review of the diff; optional live `--only tuning` sanity on the
  disposable test box.

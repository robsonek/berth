# Design: managed PHP-FPM `memory_limit` (`tuning.php_memory_limit`)

> Status: design approved in brainstorming; pending spec review → writing-plans.
> Date: 2026-07-24. Scope: one global FPM `memory_limit` knob only.

## 1. Goal & scope

Close the last manual post-provision drop-in: Debian's stock `memory_limit = 128M`
OOMs heavy Laravel pages (Filament panels, server-side PDF generation). berth
promises a Laravel-ready box, so it should ship a managed, overridable limit.

Decisions locked during brainstorming:

- **Scope: global.** One server-wide value written as an FPM `conf.d` drop-in —
  **no** per-site override, **no** `php_admin_value` in the pool template
  (`php_admin_value` would lock the limit and break apps that legitimately
  `ini_set()` a higher value for a single PDF/export request).
- **Default: `256M`** — opinionated "Laravel-ready" default, conservative enough
  for small VPSes. Operators needing legacy parity set e.g. `768M` explicitly.
- **Owner step: `php`**, next to the existing OPcache drop-in — same managed-file
  flow, one shared `php-fpm<ver> -t` + one graceful `systemctl reload`. Not the
  `tuning` step: its `checkTuned` liveness machinery keys on
  `ActiveEnterTimestamp`, which only a full `restart` moves, and restarting the
  shared FPM master would kill in-flight requests across every site's pool.
- **FPM SAPI only** (`/etc/php/<ver>/fpm/conf.d/`). The CLI SAPI keeps Debian's
  stock `memory_limit = -1`, so supervisor queue workers and artisan runs are
  unaffected — the same deliberate FPM-only precedent as the OPcache drop-in.

## 2. Config surface (`internal/config`)

New field on the existing `Tuning` struct:

```yaml
tuning:
  php_memory_limit: 256M   # default; PHP shorthand: digits + optional K/M/G
```

```go
type Tuning struct {
    // ...existing fields...
    PHPMemoryLimit string `mapstructure:"php_memory_limit" yaml:"php_memory_limit,omitempty"`
}

const defaultPHPMemoryLimit = "256M"

// PHPMemoryLimitEff returns the configured FPM memory_limit or the default.
func (t Tuning) PHPMemoryLimitEff() string {
    if t.PHPMemoryLimit == "" {
        return defaultPHPMemoryLimit
    }
    return t.PHPMemoryLimit
}
```

Default lives in the accessor, **not** `SetDefault` in `Load()` — the documented
`Tuning` pattern: wizard `ToServer()` and literal-`Server` callers bypass `Load()`,
and an empty value would render a broken `memory_limit = ` directive.

### 2.1 Validation (`validate.go`, lenient — skips empty, mirrors the other Tuning fields)

- `php_memory_limit`: `^[0-9]+[KMGkmg]?$` (PHP ini shorthand — bare bytes or a
  K/M/G suffix; PHP parses the suffix case-insensitively).
- `-1` (unlimited) is rejected by the regex **on purpose**: an unbounded FPM
  worker is a tenant-isolation footgun; CLI already has `-1` where it matters.
- The regex intentionally does not police magnitude (`0`/`1` pass, as `1` does
  for `mariadb_innodb_buffer_pool`); format-only guards are config-injection
  defence, not sizing advice.

## 3. Template (`internal/templates/php_tuning.ini.tmpl`)

One directive, rendered via `RenderINI` (`;` marker — PHP-FPM's INI parser
rejects `#`):

```
; managed by berth
memory_limit = {{ .MemoryLimit }}
```

Golden file in `internal/templates/testdata/` (`-update`, diff, commit). The
render data struct is populated **only** through `PHPMemoryLimitEff()`; a unit
test renders from a literal `&config.Server{}` and asserts the default line is
non-empty (guards against an accidental raw-field read — same test shape as the
Valkey/MariaDB tuning spec §2.1).

## 4. `php` step changes (`internal/provision/steps/php.go`)

New managed drop-in alongside the OPcache one:

```go
// phpTuningDropInPath is the FPM-only berth tuning drop-in (memory_limit).
// FPM-only on purpose: the CLI SAPI keeps Debian's stock memory_limit=-1, so
// long-lived queue workers and artisan runs are never capped.
func phpTuningDropInPath(ver string) string {
    return "/etc/php/" + ver + "/fpm/conf.d/99-berth-tuning.ini"
}

func renderPHPTuning(s *config.Server) ([]byte, error) {
    return templates.RenderINI("php_tuning.ini.tmpl", struct{ MemoryLimit string }{
        MemoryLimit: s.Tuning.PHPMemoryLimitEff(),
    })
}
```

- **Check:** after the existing OPcache managed-file check, an identical
  `checkManagedFile` → `managedFileSatisfied` pass for the tuning drop-in
  (unsatisfied reason: `"PHP tuning drop-in not up to date"`). The static
  `changes` slice gains `"write PHP tuning drop-in (memory_limit)"`. A foreign
  (unmanaged) file at that path aborts unless `--force` — standard guard.
- **Apply:** `writeManagedFile` for the tuning drop-in right after the OPcache
  one, then the **existing single** `php-fpm<ver> -t` and the **existing single**
  graceful `systemctl reload php<ver>-fpm` cover both files (FPM reload
  re-parses all `conf.d` INI files; no restart needed).
- No registry change: `php` is already in the pipeline unconditionally, and its
  `Requires()` is untouched.

### 4.1 Accepted limitation: no liveness probe

If Apply is interrupted between `WriteFile` and `reload`, a re-run's Check sees
the file up to date and reports Satisfied while the running master still has the
old limit. This exact window already exists for the OPcache drop-in and is
accepted for the same reasons: the mtime-vs-`ActiveEnterTimestamp` liveness
trick from the `tuning` step does not work with `reload` (it never moves
`ActiveEnterTimestamp`), the crash window is sub-second, and the very next
deploy reloads FPM anyway (the deployer's post-deploy
`sudo systemctl reload php<ver>-fpm` grant).

## 5. Wizard (`internal/wizard`)

- `prompter.go`: one input in the existing tuning group —
  `PHP memory_limit (e.g. 256M, blank=default)` — with an optional-value
  validator matching §2.1's regex (empty passes).
- `toserver.go`: map `a.Tuning.PHPMemoryLimit` through, like the sibling fields.

## 6. Testing (TDD, FakeRunner, exact-string `On(...)`)

- **config:** accessor (empty→`256M`, set→override); validation (valid `256M`,
  `768M`, `1G`, bare `134217728` pass; `-1`, `256MB`, `abc`, `1.5G` reject;
  empty lenient-pass).
- **templates:** golden render (default + override); literal-`Server{}`
  default-render test (§3).
- **php step:** Check unsatisfied when the tuning drop-in is absent / drifted;
  Satisfied only when packages + OPcache + tuning drop-in + log dir + PDO all
  hold; Apply writes both drop-ins then runs one `-t` and one `reload` (assert
  `Writes()` / `Calls()`); foreign-file refusal without `--force` (mirror
  `TestPHPApplyRefusesForeignOpcacheDropIn`).
- **wizard:** `ToServer()` carries the field (extend the existing mapping test).
- **Integration (follow-up, behind the `integration` tag, not a PR gate):**
  assert the effective FPM `memory_limit` reflects the configured value and a
  second run is all-Satisfied.

## 7. README

Document `tuning.php_memory_limit` in the config reference (default `256M`,
FPM-only, CLI keeps `-1`) alongside the other tuning knobs.

## 8. Explicitly out of scope (YAGNI)

Per-site overrides (`sites[].php_memory_limit`), `-1`/unlimited, other ini keys
(`upload_max_filesize`, `post_max_size`, `max_execution_time`), `pm.*` pool
sizing, a generic `tuning.php_ini` map, RAM-based sanity guards
(`memory_limit` is a per-request cap, not an allocation — unlike
`innodb_buffer_pool_size`), and a runtime liveness probe (§4.1).

## 9. Migration note (existing hosts with a manual drop-in)

Set `tuning: {php_memory_limit: "768M"}` in the server yaml and delete the
manual drop-in file. If the manual file happens to live exactly at
`99-berth-tuning.ini`, berth refuses it as unmanaged; `--force` overwrites it
with the managed rendering.

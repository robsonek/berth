# Design: managed PHP-FPM tuning drop-in (`tuning.php_*`)

> Status: design approved in brainstorming (scope widened on review from
> memory_limit-only to the full FPM tuning set); pending spec review →
> writing-plans. Date: 2026-07-24.

## 1. Goal & scope

Close the last manual post-provision drop-in: Debian's stock FPM limits are
wrong for any real Laravel app — `memory_limit = 128M` OOMs heavy pages
(Filament panels, server-side PDF generation) and `upload_max_filesize = 2M` /
`post_max_size = 8M` reject ordinary file uploads that nginx (berth's own
vhost: `client_max_body_size 32m`) would happily pass through. berth promises
a Laravel-ready box, so it ships one managed, overridable FPM tuning drop-in.

Decisions locked during brainstorming:

- **Scope: global.** Server-wide values written as one FPM `conf.d` drop-in —
  **no** per-site override, **no** `php_admin_value` in the pool template
  (`php_admin_value` would lock the values and break apps that legitimately
  `ini_set()` a higher limit for a single PDF/export request).
- **Knobs (all on the existing `Tuning` struct):**
  - `php_memory_limit`, default **`256M`** — opinionated "Laravel-ready"
    default, conservative enough for small VPSes.
  - `php_upload_max`, default **`32M`** — ONE knob driving three directives:
    `upload_max_filesize`, `post_max_size`, **and** nginx
    `client_max_body_size` (§5). One source of truth for the whole upload
    path; the default matches the value already hardcoded in the vhost
    templates, so default nginx behavior is unchanged.
  - `php_max_execution_time`, default **`30`** (stock) — nginx's existing
    `fastcgi_read_timeout 300` gives headroom up to 300 s with no nginx change.
  - `php_max_input_vars`, default **`1000`** (stock) — large Filament forms
    (repeaters, relation managers) can exceed it.
  - `expose_php = Off` — unconditional line, no knob. Defense-in-depth only:
    nginx already strips `X-Powered-By` via `fastcgi_hide_header`.
- **Owner step: `php`**, next to the existing OPcache drop-in — same managed-file
  flow, one shared `php-fpm<ver> -t` + one graceful `systemctl reload`. Not the
  `tuning` step: its `checkTuned` liveness machinery keys on
  `ActiveEnterTimestamp`, which only a full `restart` moves, and restarting the
  shared FPM master would kill in-flight requests across every site's pool.
  (The nginx side of `php_upload_max` is owned by the `site` step, which
  already owns the vhosts — §5.)
- **FPM SAPI only** (`/etc/php/<ver>/fpm/conf.d/`). The CLI SAPI keeps Debian's
  stock php.ini (`memory_limit = -1`, `max_execution_time = 0`), so supervisor
  queue workers and artisan runs are unaffected — the same deliberate FPM-only
  precedent as the OPcache drop-in.

## 2. Config surface (`internal/config`)

New fields on the existing `Tuning` struct:

```yaml
tuning:
  php_memory_limit: 256M       # default; PHP shorthand: digits + optional K/M/G
  php_upload_max: 32M          # default; also becomes nginx client_max_body_size
  php_max_execution_time: 30   # default; seconds, 1..300 (nginx fastcgi ceiling)
  php_max_input_vars: 1000     # default
```

```go
type Tuning struct {
    // ...existing fields...
    PHPMemoryLimit      string `mapstructure:"php_memory_limit" yaml:"php_memory_limit,omitempty"`
    PHPUploadMax        string `mapstructure:"php_upload_max" yaml:"php_upload_max,omitempty"`
    PHPMaxExecutionTime int    `mapstructure:"php_max_execution_time" yaml:"php_max_execution_time,omitempty"`
    PHPMaxInputVars     int    `mapstructure:"php_max_input_vars" yaml:"php_max_input_vars,omitempty"`
}

const (
    defaultPHPMemoryLimit      = "256M"
    defaultPHPUploadMax        = "32M"
    defaultPHPMaxExecutionTime = 30
    defaultPHPMaxInputVars     = 1000
)
```

Each field gets a `*Eff()` accessor returning the default when the field is
empty (strings) or `<= 0` (ints — the `Fail2ban.MaxretryEff` precedent).
Defaults live in the accessors, **not** `SetDefault` in `Load()` — the
documented `Tuning` pattern: wizard `ToServer()` and literal-`Server` callers
bypass `Load()`, and an empty value would render a broken directive.

### 2.1 Validation (`validate.go`, lenient — skips empty/zero, mirrors the other Tuning fields)

- `php_memory_limit`, `php_upload_max`: `^[0-9]+[KMGkmg]?$` (PHP ini
  shorthand — bare bytes or a K/M/G suffix, parsed case-insensitively by PHP;
  the same token is valid nginx size syntax, so one value serves both renders).
- `-1` (unlimited) is rejected by the regex **on purpose**: an unbounded FPM
  worker is a tenant-isolation footgun; CLI already has `-1` where it matters.
- `php_max_execution_time`: when `> 0`, must be `<= 300` — beyond that nginx's
  `fastcgi_read_timeout 300` times out first and the knob would silently lie.
  The error message names the nginx ceiling. (`<= 0` = unset → default, per
  the lenient int pattern; PHP's `0 = unlimited` is deliberately not settable.)
- `php_max_input_vars`: no range check beyond the lenient `<= 0` = unset
  (harmless upward, can't inject).
- The string regexes intentionally do not police magnitude (`1` passes, as it
  does for `mariadb_innodb_buffer_pool`); format guards are config-injection
  defence, not sizing advice.

## 3. Template (`internal/templates/php_tuning.ini.tmpl`)

Rendered via `RenderINI` (`;` marker — PHP-FPM's INI parser rejects `#`):

```
; managed by berth
memory_limit = {{ .MemoryLimit }}
upload_max_filesize = {{ .UploadMax }}
post_max_size = {{ .UploadMax }}
max_execution_time = {{ .MaxExecutionTime }}
max_input_vars = {{ .MaxInputVars }}
expose_php = Off
```

`post_max_size = upload_max_filesize` (same knob) is the standard pairing; the
multipart-overhead edge case (a file at exactly the limit) is accepted — one
knob beats two coupled ones.

Golden file in `internal/templates/testdata/` (`-update`, diff, commit). The
render data struct is populated **only** through the `*Eff()` accessors; a unit
test renders from a literal `&config.Server{}` and asserts every directive line
is non-empty/non-zero (guards against an accidental raw-field read — same test
shape as the Valkey/MariaDB tuning spec §2.1).

## 4. `php` step changes (`internal/provision/steps/php.go`)

New managed drop-in alongside the OPcache one:

```go
// phpTuningDropInPath is the FPM-only berth tuning drop-in (memory_limit,
// upload sizing, execution limits). FPM-only on purpose: the CLI SAPI keeps
// Debian's stock php.ini (memory_limit=-1, max_execution_time=0), so
// long-lived queue workers and artisan runs are never capped.
func phpTuningDropInPath(ver string) string {
    return "/etc/php/" + ver + "/fpm/conf.d/99-berth-tuning.ini"
}

func renderPHPTuning(s *config.Server) ([]byte, error) {
    return templates.RenderINI("php_tuning.ini.tmpl", struct {
        MemoryLimit, UploadMax        string
        MaxExecutionTime, MaxInputVars int
    }{
        MemoryLimit:      s.Tuning.PHPMemoryLimitEff(),
        UploadMax:        s.Tuning.PHPUploadMaxEff(),
        MaxExecutionTime: s.Tuning.PHPMaxExecutionTimeEff(),
        MaxInputVars:     s.Tuning.PHPMaxInputVarsEff(),
    })
}
```

- **Check:** after the existing OPcache managed-file check, an identical
  `checkManagedFile` → `managedFileSatisfied` pass for the tuning drop-in
  (unsatisfied reason: `"PHP tuning drop-in not up to date"`). The static
  `changes` slice gains `"write PHP tuning drop-in (memory_limit, upload, limits)"`.
  A foreign (unmanaged) file at that path aborts unless `--force` — standard guard.
- **Apply:** `writeManagedFile` for the tuning drop-in right after the OPcache
  one, then the **existing single** `php-fpm<ver> -t` and the **existing single**
  graceful `systemctl reload php<ver>-fpm` cover both files (FPM reload
  re-parses all `conf.d` INI files; no restart needed).
- No registry change: `php` is already in the pipeline unconditionally, and its
  `Requires()` is untouched.

### 4.1 Accepted limitation: no liveness probe

If Apply is interrupted between `WriteFile` and `reload`, a re-run's Check sees
the file up to date and reports Satisfied while the running master still has the
old limits. This exact window already exists for the OPcache drop-in and is
accepted for the same reasons: the mtime-vs-`ActiveEnterTimestamp` liveness
trick from the `tuning` step does not work with `reload` (it never moves
`ActiveEnterTimestamp`), the crash window is sub-second, and the very next
deploy reloads FPM anyway (the deployer's post-deploy
`sudo systemctl reload php<ver>-fpm` grant).

## 5. nginx coordination (`site` step + vhost templates)

`php_upload_max` also renders as `client_max_body_size` so the upload path has
one source of truth (without this, any value above 32M would silently die at
nginx with a 413 before PHP ever sees it):

- `nginxData` (site.go) gains `UploadMax string`, populated in
  `nginxRenderData` via `s.Tuning.PHPUploadMaxEff()`.
- `nginx_http.conf.tmpl` and `nginx_https.conf.tmpl` (443 block only; the
  port-80 redirect block takes no bodies): `client_max_body_size 32m;` →
  `client_max_body_size {{ .UploadMax }};`.
- **site ↔ tls byte-identical invariant holds:** the value derives only from
  static config (accessor), never from remote state — exactly the HSTS
  precedent. Both `site` first-render and `tls` re-render consume the same
  `nginxRenderData`.
- Mirror the new field in the **test-local `nginxData` copy** in
  `templates_test.go` (documented trap), regenerate nginx goldens (`-update`,
  diff, commit).
- Drift semantics: changing `php_upload_max` makes **both** the `php` step
  (drop-in) and the `site` step (every vhost) report drift; each re-applies its
  own files. No cross-step coupling in code — they just read the same knob.

## 6. Wizard (`internal/wizard`)

- `prompter.go`, existing tuning group: four inputs —
  `PHP memory_limit (e.g. 256M, blank=default)`,
  `PHP upload limit (e.g. 32M, blank=default)` (noted as also setting nginx
  body size), `PHP max_execution_time (seconds, blank=default)`,
  `PHP max_input_vars (blank=default)` — string knobs with optional-value
  validators matching §2.1; int knobs mirror the existing `Fail2ban.Maxretry`
  input pattern.
- `toserver.go`: map all four fields through, like the sibling fields.

## 7. Testing (TDD, FakeRunner, exact-string `On(...)`)

- **config:** accessors (empty/zero→default, set→override, negative int→default);
  validation (valid `256M`, `768M`, `1G`, bare `134217728` pass; `-1`, `256MB`,
  `abc`, `1.5G` reject; `php_max_execution_time` 300 passes, 301 rejects,
  0/unset lenient-passes; `php_max_input_vars` 0/unset lenient-passes).
- **templates:** golden render of the drop-in (default + override); nginx
  goldens regenerated with `client_max_body_size` templated (default input
  keeps `32M`); literal-`Server{}` default-render test (§3).
- **php step:** Check unsatisfied when the tuning drop-in is absent / drifted;
  Satisfied only when packages + OPcache + tuning drop-in + log dir + PDO all
  hold; Apply writes both drop-ins then runs one `-t` and one `reload` (assert
  `Writes()` / `Calls()`); foreign-file refusal without `--force` (mirror
  `TestPHPApplyRefusesForeignOpcacheDropIn`).
- **site step:** vhost render includes the configured `client_max_body_size`;
  existing site↔tls identical-render tests still pass with the new field.
- **wizard:** `ToServer()` carries all four fields (extend the existing
  mapping test).
- **Integration (follow-up, behind the `integration` tag, not a PR gate):**
  assert the effective FPM values reflect the config and a second run is
  all-Satisfied.

## 8. README

Document the four `tuning.php_*` knobs in the config reference (defaults,
FPM-only, CLI keeps stock limits, `php_upload_max` drives nginx
`client_max_body_size` too, `php_max_execution_time` capped at 300 by the
nginx fastcgi timeout) alongside the other tuning knobs.

## 9. Explicitly out of scope (YAGNI)

Per-site overrides (`sites[].php_*`), `-1`/unlimited values, further ini keys
(`realpath_cache_size`, `max_input_time`), `pm.*` pool sizing, a generic
`tuning.php_ini` map, making nginx `fastcgi_read_timeout` configurable,
RAM-based sanity guards (`memory_limit` is a per-request cap, not an
allocation — unlike `innodb_buffer_pool_size`), and a runtime liveness probe
(§4.1).

## 10. Migration note (existing hosts with a manual drop-in)

Set the desired values in the server yaml (e.g.
`tuning: {php_memory_limit: "768M"}`) and delete the manual drop-in file. If
the manual file happens to live exactly at `99-berth-tuning.ini`, berth
refuses it as unmanaged; `--force` overwrites it with the managed rendering.

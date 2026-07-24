# Design: managed PHP-FPM tuning drop-in (`tuning.php_*`)

> Status: design approved in brainstorming (scope widened on review from
> memory_limit-only to the full FPM tuning set); revised after an adversarial
> Codex (gpt-5.6-sol) review — see §11. Pending re-review → writing-plans.
> Date: 2026-07-24.

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
  - `php_upload_max`, default **`32M`** — ONE knob, semantically **the largest
    single file an app must accept**. It renders as `upload_max_filesize`
    verbatim, and *derives* `post_max_size` and nginx `client_max_body_size`
    with multipart headroom (§2.2) so a file of exactly this size actually
    uploads. One source of truth for the whole upload path.
  - `php_max_execution_time`, default **`30`** (stock) — capped at 300 s (§2.1).
  - `php_max_input_vars`, default **`1000`** (stock) — large Filament forms
    (repeaters, relation managers) can exceed it. Capped at 1 000 000 (§2.1).
  - `expose_php = Off` — unconditional line, no knob. Defense-in-depth only:
    nginx already strips `X-Powered-By` via `fastcgi_hide_header`.
- **These are operational defaults, NOT an isolation boundary** (Codex #5):
  `memory_limit`/`max_execution_time` are `INI_ALL`, and the pools deliberately
  avoid `php_admin_value`, so tenant code can always `ini_set()` past them. The
  knobs keep FPM *bounded by default*; a tenant raising its own limits at
  runtime is accepted (the per-site OS user / open_basedir / socket isolation
  is unaffected). Config validation still rejects `-1`/`0` so berth never
  *ships* an unbounded default.
- **Owner step: `php`**, next to the existing OPcache drop-in — same managed-file
  flow, and *within the step* one shared `php-fpm<ver> -t` + one graceful
  `systemctl reload` covers both drop-ins. Not the `tuning` step: its
  `checkTuned` liveness machinery keys on `ActiveEnterTimestamp`, which only a
  full `restart` moves, and restarting the shared FPM master would kill
  in-flight requests across every site's pool. (The nginx side of
  `php_upload_max` is owned by the `site` step, which already owns the
  vhosts — §5.)
- **FPM SAPI only** (`/etc/php/<ver>/fpm/conf.d/`). The CLI SAPI keeps Debian's
  stock php.ini (`memory_limit = -1`, `max_execution_time = 0`), so supervisor
  queue workers and artisan runs are unaffected — the same deliberate FPM-only
  precedent as the OPcache drop-in.

## 2. Config surface (`internal/config`)

New fields on the existing `Tuning` struct:

```yaml
tuning:
  php_memory_limit: 256M       # default; digits + optional K/M/G, no leading zeros
  php_upload_max: 32M          # default; max single-file upload — post_max_size
                               # and nginx client_max_body_size are derived (§2.2)
  php_max_execution_time: 30   # default; seconds, 1..300
  php_max_input_vars: 1000     # default; 1..1000000
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

- `php_memory_limit`, `php_upload_max`: regex
  `^[1-9][0-9]*[KMGkmg]?$` **plus** a parse-and-bound check (`phpSizeBytes`,
  1024-based) requiring the value be ≤ 64 GiB. The tightened grammar
  (Codex #1) closes three real holes the naive `[0-9]+` version had:
  - **`0` rejected** — PHP treats `post_max_size 0` as unlimited and nginx
    treats `client_max_body_size 0` as "no checking"; a zero knob would have
    silently removed the request-size limit everywhere.
  - **Leading zeros rejected** — PHP's ini shorthand parses `010M` as octal
    (8 MiB) and warns on `08M` (→ 0), while nginx parses the same tokens as
    decimal; the two sides would diverge.
  - **Overflow rejected** — values past PHP's signed 64-bit parse wrap to the
    `-1` unlimited sentinel; the ≤ 64 GiB bound (far above any sane VPS value)
    makes overflow unrepresentable in both parsers.
- `-1` (unlimited) never parses (the regex has no sign) — deliberate: berth
  never ships an unbounded FPM default (see §1's honest framing — a sane
  default posture, not an isolation boundary).
- `php_max_execution_time`: when `> 0`, must be `<= 300`. This is an
  **opinionated sanity cap** — long-running web requests belong in queue
  workers, and berth's stack is tuned around short requests. (It is *not*
  claimed that nginx would 504 at exactly 300 s: `fastcgi_read_timeout 300` is
  a between-reads timeout and PHP's limit excludes I/O wait, so the two are
  not a common wall clock — Codex #6.)
- `php_max_input_vars`: when `> 0`, must be `<= 1000000` — the same domain the
  wizard input enforces, so both public config paths accept the same values
  (Codex #8).
- The bounds are injection/foot-gun defence, not sizing advice: `1` (byte) and
  `1` (second) still pass, as `1` does for `mariadb_innodb_buffer_pool`.

### 2.2 Derived request-body cap (`PHPPostBodyMaxEff`)

`post_max_size == upload_max_filesize` would NOT let a file of the configured
size upload: PHP requires `post_max_size` to be larger (multipart boundaries,
form fields and metadata all count toward it), and nginx's
`client_max_body_size` limits the same total body (Codex #2). So the knob is
defined as **max single-file size**, and the two body caps are derived:

```go
// bytes(PHPUploadMaxEff) + max(2 MiB, 5%) — rendered as an exact byte count,
// which is valid size syntax for both PHP ini shorthand and nginx.
func (t Tuning) PHPPostBodyMaxEff() string
```

- Default `32M` → `33554432 + 2097152` = `"35651584"`.
- Unparsable field (possible only for literal-`Server` callers that bypass
  validation) falls back to deriving from the default — the accessor stays
  total and deterministic.
- Consequence: the derived nginx cap is slightly *above* today's hardcoded
  `32m` — intentional, that gap is exactly why a 32 MiB file currently fails.
- Known accepted limit: several files in ONE multipart request share the
  derived total; per-request totals are what `post_max_size` fundamentally
  limits. Documented in README.

## 3. Template (`internal/templates/php_tuning.ini.tmpl`)

Rendered via `RenderINI` (`;` marker — PHP-FPM's INI parser rejects `#`):

```
; managed by berth
memory_limit = {{ .MemoryLimit }}
upload_max_filesize = {{ .UploadMax }}
post_max_size = {{ .PostMax }}
max_execution_time = {{ .MaxExecutionTime }}
max_input_vars = {{ .MaxInputVars }}
expose_php = Off
```

`PostMax` is the derived byte count from §2.2. Golden file in
`internal/templates/testdata/` (`-update`, diff, commit). The render data
struct is populated **only** through the `*Eff()` accessors; a unit test
renders from a literal `&config.Server{}` and asserts every directive line is
non-empty/non-zero (guards against an accidental raw-field read — same test
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

func renderPHPTuning(s *config.Server) ([]byte, error) // RenderINI, accessors only
```

- **Check:** after the existing OPcache managed-file check, an identical
  `checkManagedFile` → `managedFileSatisfied` pass for the tuning drop-in
  (unsatisfied reason: `"PHP tuning drop-in not up to date"`). The static
  `changes` slice gains `"write PHP tuning drop-in (memory_limit, upload, limits)"`.
  A foreign (unmanaged) file at that path aborts unless `--force` — standard guard.
- **Apply:** `writeManagedFile` for the tuning drop-in right after the OPcache
  one, then the step's **single** `php-fpm<ver> -t` and **single** graceful
  `systemctl reload php<ver>-fpm` cover both files (FPM reload re-parses all
  `conf.d` INI files; no restart needed).
- No registry change: `php` is already in the pipeline unconditionally, and its
  `Requires()` is untouched.

### 4.1 Validate/reload failure compensation (replaces the old "accepted limitation")

The naive flow had a real falsely-Satisfied trap (Codex #3, not just the
sub-second crash window): if `php-fpm -t` or `systemctl reload` fails *after*
the drop-ins are written, the run errors — but the re-run's Check sees the
files byte-perfect on disk and reports Satisfied forever, while the running
master never loaded them. Unlike the static OPcache drop-in, tuning values
change, so this matters.

Fix: on a non-zero `-t` or `reload` exit, Apply best-effort removes **both**
managed drop-ins (`rm -f`) before returning the error. Disk state then honestly
reflects runtime state (the master never loaded the new content), and the next
run re-applies write → `-t` → `reload`. Convergent, no liveness probe needed.
A *transport* error (SSH died) skips the cleanup — nothing can be run — and is
surfaced as the step error; the same interrupted-Apply caveat as every other
step. The pre-existing identical window in the `site` step (pools/vhosts) is
out of scope here.

## 5. nginx coordination (`site` step + vhost templates)

The derived body cap (§2.2) renders as `client_max_body_size` so the upload
path has one source of truth (without this, any PHP-side value above 32M would
silently die at nginx with a 413 before PHP ever sees it):

- `nginxData` (site.go) gains `BodyMax string`, populated in
  `nginxRenderData` via `s.Tuning.PHPPostBodyMaxEff()`.
- `nginx_http.conf.tmpl` and `nginx_https.conf.tmpl` (443 block only; the
  port-80 redirect block takes no bodies): `client_max_body_size 32m;` →
  `client_max_body_size {{ .BodyMax }};`.
- **site ↔ tls byte-identical invariant holds:** the value derives only from
  static config (accessor), never from remote state — exactly the HSTS
  precedent. Both `site` first-render and `tls` re-render consume the same
  `nginxRenderData`.
- Mirror the new field in the **test-local `nginxData` copy** in
  `templates_test.go` (documented trap), regenerate nginx goldens (`-update`,
  diff, commit).
- **Drift semantics (Codex #4, accepted + documented):** changing
  `php_upload_max` drifts **both** the `php` step (drop-in → one graceful FPM
  reload) and the `site` step (vhosts; its Apply also re-renders every FPM
  pool and reloads FPM again). An upload-only change therefore gracefully
  recycles the shared FPM master **twice** in one run. Accepted: reloads are
  graceful, tuning changes are rare, and cross-step reload deduplication would
  break the pipeline's step-isolation contract. No code coupling — the steps
  just read the same knob.

## 6. Wizard (`internal/wizard`)

- `prompter.go`, existing tuning group: four inputs —
  `PHP memory_limit (e.g. 256M, blank=default)`,
  `PHP upload limit, also nginx body size (e.g. 32M, blank=default)`,
  `PHP max_execution_time (1-300 s, blank/0=default)`,
  `PHP max_input_vars (1-1000000, blank/0=default)` — string knobs with an
  `optionalPHPSize` validator mirroring §2.1's regex (empty passes; the
  parse-and-bound check stays in config, which `Answers.Write()` always runs);
  int knobs mirror the existing `Fail2ban.Maxretry` input pattern with the
  same 1..300 / 1..1000000 domains as config.
- `toserver.go`: map all four fields through, like the sibling fields.
- `matrix_test.go`: extend the `tuning-all-fields-set-valid` subtest with the
  php fields and add an invalid-php-size subtest (Codex #7).

## 7. Testing (TDD, FakeRunner, exact-string `On(...)`)

- **config:** accessors (empty/zero→default, set→override, negative int→default,
  `PHPPostBodyMaxEff` default/override/unparsable-fallback); `phpSizeBytes`
  (K/M/G, bare bytes, error case); validation (valid `256M`, `768M`, `1G`,
  `512k`, bare `134217728` pass; **`0`, `08M`, `010M`**, `-1`, `256MB`, `abc`,
  `1.5G`, `65G`, `18446744073709551615` reject; exec time 300 passes / 301
  rejects; input vars 1000000 passes / 1000001 rejects; 0/unset lenient-passes).
- **templates:** golden render of the drop-in (default + override); nginx
  goldens regenerated with the derived `client_max_body_size`; literal-`Server{}`
  default-render test (§3).
- **php step:** Check unsatisfied when the tuning drop-in is absent / drifted;
  Satisfied only when packages + OPcache + tuning drop-in + log dir + PDO all
  hold; Apply writes both drop-ins then runs **exactly one** `-t` and
  **exactly one** `reload` (count the FakeRunner calls — Codex #7);
  foreign-file refusal without `--force`; **compensation tests**: `-t` failure
  and `reload` failure each remove both drop-ins and surface the error (§4.1).
- **site step:** vhost render includes the derived `client_max_body_size`
  (assert via `PHPPostBodyMaxEff()`, both HTTP and HTTPS renders); existing
  site↔tls identical-render tests still pass with the new field.
- **wizard:** `optionalPHPSize` accept/reject table; `ToServer()` carries all
  four fields; matrix subtests per §6.
- **Integration (follow-up, behind the `integration` tag, not a PR gate):**
  assert the effective FPM values and the nginx body cap reflect the config
  and a second run is all-Satisfied (the harness already checks FPM service
  health and re-run idempotency — extend, don't duplicate).

## 8. README

Document the four `tuning.php_*` knobs in the config reference: defaults;
FPM-only (CLI keeps stock limits); `php_upload_max` = max single-file size,
with `post_max_size`/nginx `client_max_body_size` derived slightly larger
(and shared by all files in one request); the 300 s execution cap as berth's
opinionated bound (queue long work); the 1 000 000 input-vars cap.

## 9. Explicitly out of scope (YAGNI)

Per-site overrides (`sites[].php_*`), `-1`/unlimited values, further ini keys
(`realpath_cache_size`, `max_input_time`), `pm.*` pool sizing, a generic
`tuning.php_ini` map, making nginx `fastcgi_read_timeout` configurable,
RAM-based sanity guards (`memory_limit` is a per-request cap, not an
allocation — unlike `innodb_buffer_pool_size`), cross-step FPM-reload
deduplication (§5), a runtime liveness probe beyond §4.1's compensation, and
fixing the pre-existing analogous write-then-reload window in the `site` step.

## 10. Migration note (existing hosts with a manual drop-in)

Set the desired values in the server yaml (e.g.
`tuning: {php_memory_limit: "768M"}`) and delete the manual drop-in file. If
the manual file happens to live exactly at `99-berth-tuning.ini`, berth
refuses it as unmanaged; `--force` overwrites it with the managed rendering.

## 11. Codex review incorporation (gpt-5.6-sol, foreground, verified against code)

| # | Severity | Verdict | Resolution |
|---|----------|---------|------------|
| 1 | blocker | **confirmed** — `[0-9]+` grammar admits `0` (unlimited in both PHP and nginx), octal-divergent `010M`/`08M`, and overflow-to-`-1` values | Tightened regex `^[1-9][0-9]*[KMGkmg]?$` + `phpSizeBytes` parse with a ≤ 64 GiB bound (§2.1). |
| 2 | major | **confirmed** — `post_max_size == upload_max_filesize` cannot pass a file of the advertised size (multipart overhead; PHP manual requires post > upload) | Knob redefined as max single-file size; `post_max_size` + nginx cap derived as bytes + max(2 MiB, 5%) via `PHPPostBodyMaxEff` (§2.2, §5). |
| 3 | major | **confirmed** — a failed `-t`/`reload` after a successful write leaves Check falsely Satisfied forever (verified against `php.go` Check = bytes-only) | Apply removes both drop-ins on non-zero `-t`/`reload` exit → next run re-applies; convergent (§4.1). |
| 4 | major | **confirmed** — `site.Apply` unconditionally rewrites pools + reloads FPM (site.go), so an upload change reloads FPM twice per run | Accepted + documented (graceful, rare); cross-step dedup rejected as a step-isolation break (§5, §9). |
| 5 | major | **confirmed** — `memory_limit` is `INI_ALL` and pools avoid `php_admin_value` by design, so "-1 rejection = tenant isolation" was wrong framing | Reworded: bounded-by-default operational posture, not an isolation boundary (§1, §2.1). |
| 6 | minor | **confirmed** — `fastcgi_read_timeout` is between-reads, PHP exec time excludes I/O; "504 first" was false | Cap kept as an opinionated 300 s sanity bound with honest rationale (§2.1); README wording fixed (§8). |
| 7 | minor | valid | Added: exact `-t`/reload call-count asserts, compensation tests, `0`/octal/overflow validation cases, wizard matrix subtests (§6, §7). Integration remains an explicit follow-up. |
| 8 | minor | valid | Config now enforces the same 1..1000000 input-vars domain as the wizard (§2.1). |

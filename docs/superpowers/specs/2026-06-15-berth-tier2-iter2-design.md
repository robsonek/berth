# berth — Tier 2, Iteration 2: configurable queue workers + daemon abstraction (design)

> Status: approved design, pre-implementation
> Date: 2026-06-15
> Source: `docs/improvement-roadmap.md` "Borrow — Tier 2" items #9 (configurable queue workers) and #10 (daemon abstraction: Horizon/Reverb/custom)
> Decisions locked with the maintainer 2026-06-15 (brainstorming).

## Goal

Make berth leave a box **correctly deployer-ready for real Laravel queue topologies**. Today the
`site` step writes exactly one dormant `queue:work` worker per site (`numprocs=1`, fixed flags), so:
a high-throughput app cannot scale workers or tune them, and a **Horizon** app gets a *redundant*
`queue:work` worker **and no horizon process** (Horizon replaces `queue:work`). This iteration adds,
per site, a **configurable queue worker** (#9) and an **arbitrary daemon list** (#10, Horizon/Reverb/
custom), all rendered as managed Supervisor programs, idempotent via the existing drift mechanism,
and isolated per tenant by narrow sudoers — without disturbing the byte-identical default.

## Scope

**In scope:**

- Per-site `queue:` config — tune the worker (`driver`, `processes`, `connection`, `queue`, `sleep`,
  `tries`, `timeout`, `max_memory`) with a `queue: horizon` bare-string sugar.
- Per-site `daemons:` list — arbitrary long-running programs (name + full command + processes).
- Render each as a managed `/etc/supervisor/conf.d/berth-<pool>[-<name>].conf` in the `site` step.
- Per-program narrow sudoers so a site user controls only its own programs (tenant isolation).
- Include the `supervisor` step when any site has a queue worker (`QueueEnabled`) or daemons.
- Drift-removal of orphaned berth-managed program files (removed daemon / disabled worker).
- Config validation; golden-template updates; unit + isolation + drift tests; live assertions.

**Out of scope (later Tier 2 / not now):**

- nginx cluster (basic-auth/real-IP/rate-limit/FPM tuning), system cluster (swap/sysctl/DB-Valkey
  tuning), backups, per-site PHP version, DNS-01 — separate iterations.
- Starting/enabling the programs: they stay **dormant** (`autostart=false`); the deployer enables
  them. berth is a provisioner, not a process manager.
- Supervisor groups, per-daemon log rotation beyond the existing global logrotate globs (the
  logrotate fragment already globs `/var/log/supervisor/berth-*.log`, which covers daemon logs).

## Locked decisions (brainstorming 2026-06-15)

1. **Config shape — separate `queue` + `daemons`** (mirrors Forge's "Queue Workers" vs "Daemons"),
   not a unified list. `queue` tunes the worker; `daemons` is everything else.
2. **`queue: horizon` sugar via a mapstructure DecodeHook** — a bare string decodes to
   `QueueConfig{Driver: "<string>"}`, composed with Viper's default hooks. Ergonomic; a small,
   contained extension to the otherwise mapstructure-pure `Load()`.
3. **Daemon/worker removal → auto drift-removal via a GLOBAL list+diff** — `Check`/`Apply` list
   *all* `berth-*.conf` program files once and diff against the **union of the desired program set
   across every site**, `rm -f`-ing only berth-managed orphans (guarded by `managedFilePresent`).
   The list is intentionally GLOBAL, never a per-pool `berth-<pool>*` glob: pool names can be
   prefixes of one another (same hazard as decision 4 — e.g. `a.example.com`→`a_example_com` is a
   prefix of `a.example.computer`→`a_example_computer`), so a per-site glob could match and delete a
   *sibling tenant's* files. An orphan = a managed program file desired by **no** current site, so
   removing it is collision-free. Fully declarative.
4. **Tenant isolation via per-program narrow sudoers lines**, never a broadened `berth-<pool>-*`
   glob (a sibling whose pool is a prefix — `app.example.com` vs `app.example.com.x` →
   `app_example_com` vs `app_example_com_x` — would otherwise be reachable).
5. **Byte-identical default** — `Server.Queue: true` with no per-site `queue`/`daemons` renders the
   exact current `berth-<pool>.conf`. The template is parametrized but the default render is
   unchanged; golden output stays identical (no drift on existing boxes).

## Config schema

New types in `internal/config/config.go` (each field both `mapstructure` and `yaml` tagged):

```go
// QueueConfig tunes a site's queue worker. nil => the server-default worker
// (when Server.Queue) or none. Driver "" / "work" => queue:work; "horizon" =>
// artisan horizon (Horizon manages its own workers; the queue:work-only knobs
// are ignored and numprocs is forced to 1).
type QueueConfig struct {
	Driver     string `mapstructure:"driver" yaml:"driver,omitempty"`         // work (default) | horizon
	Processes  int    `mapstructure:"processes" yaml:"processes,omitempty"`   // numprocs; default 1
	Connection string `mapstructure:"connection" yaml:"connection,omitempty"` // queue:work positional connection
	Queue      string `mapstructure:"queue" yaml:"queue,omitempty"`           // --queue
	Sleep      int    `mapstructure:"sleep" yaml:"sleep,omitempty"`           // --sleep; default 3
	Tries      int    `mapstructure:"tries" yaml:"tries,omitempty"`           // --tries; default 3
	Timeout    int    `mapstructure:"timeout" yaml:"timeout,omitempty"`       // --timeout (per-job)
	MaxMemory  int    `mapstructure:"max_memory" yaml:"max_memory,omitempty"` // --memory (MB)
}

// Daemon is an arbitrary long-running Supervisor program (Horizon/Reverb/custom).
type Daemon struct {
	Name      string `mapstructure:"name" yaml:"name"`                     // [a-z0-9-]; unique per site
	Command   string `mapstructure:"command" yaml:"command"`               // FULL command, run from <deploy_path>/current
	Processes int    `mapstructure:"processes" yaml:"processes,omitempty"` // numprocs; default 1
}
```

`Site` gains: `Queue *QueueConfig` (`mapstructure:"queue" yaml:"queue,omitempty"`) and
`Daemons []Daemon` (`mapstructure:"daemons" yaml:"daemons,omitempty"`). `Server.Queue bool` is
unchanged; it is the server-wide **default** (a `queue:work` worker on every site), **not** the
supervisor-step gate — the step is gated by `NeedsSupervisor()` and the worker is rendered per
`QueueEnabled(site)`.

**Daemon `command` is the FULL command** (e.g. `php artisan reverb:start`, or any binary), executed
with Supervisor `directory=<deploy_path>/current` — berth does **not** prefix `php …/current/`. This
generalizes beyond artisan (the brainstorming preview's `artisan reverb:start` was shorthand). The
*queue worker* (driver-based) is the opposite: berth builds the whole `php <path>/current/artisan …`
line; the user only sets knobs.

### Loader (`Load`)

Add a mapstructure `DecodeHookFunc` so a string source for a `QueueConfig` target yields
`QueueConfig{Driver: <string>}`, composed with Viper's existing defaults so nothing is lost:

```go
v.Unmarshal(&s, viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
	mapstructure.StringToTimeDurationHookFunc(),
	mapstructure.StringToSliceHookFunc(","),
	stringToQueueConfigHook, // string "horizon" -> QueueConfig{Driver:"horizon"}
)))
```

`stringToQueueConfigHook` fires when `from == string` and `to` is `QueueConfig` **or** `*QueueConfig`
(mapstructure may present either for a pointer field — handle both), and is composed **after** Viper's
duration/slice hooks so existing decodes (e.g. fail2ban string fields) are unaffected (Codex-confirmed).

### Helpers (config.go)

- `Server.QueueEnabled(site) bool` — does this site get a queue worker? `true` when `site.Queue != nil`
  OR `Server.Queue` (the server switch defaults a worker onto every site). `site.Queue` works
  **independently** of `Server.Queue` — a site can opt in even when the server switch is off. A
  per-site "off" switch (`queue: {processes: 0}` etc.) is **out of scope** (documented).
- `Server.NeedsSupervisor() bool` — `true` when **any** site is `QueueEnabled` OR has daemons. This
  (not the bare `Server.Queue`) gates the supervisor step, resolving the registry/`QueueEnabled`
  consistency: a site that enables a worker or a daemon without the server switch still gets
  supervisor installed.
- Queue defaults resolver returning effective driver/processes/sleep/tries (so the renderer and
  validator share one source of truth).

## Rendering, naming, ownership (`internal/provision/steps/site.go`)

All programs are owned by the **`site` step** via `managedSiteFiles` (same drift engine as the nginx
vhost / cron / logrotate), so Check/Apply stay in lock-step and the second-run idempotency holds.

- **Worker program** `berth-<pool>` → `/etc/supervisor/conf.d/berth-<pool>.conf` (path unchanged).
  - driver work: `command = php <deploy>/current/artisan queue:work[ <connection>] --sleep=N --tries=N --max-time=3600[ --queue=… --timeout=… --memory=…]`. **Default (no `queue:` block, `Server.Queue` true) renders byte-identically to today:** `php <deploy>/current/artisan queue:work --sleep=3 --tries=3 --max-time=3600`, `numprocs=1`.
  - driver horizon: `command = php <deploy>/current/artisan horizon`, `numprocs=1` (queue:work knobs ignored; validation rejects them combined with horizon to avoid silent no-ops).
- **Daemon programs** `berth-<pool>-<name>` → `/etc/supervisor/conf.d/berth-<pool>-<name>.conf`,
  `command = <daemon.command>`, `directory=<deploy>/current`, `user=<site user>`, `numprocs=<processes>`.
- All programs: `user=<site user>`, `autostart=false`, `autorestart=true`, `stopwaitsecs=3600`,
  `stopasgroup=true`, `killasgroup=true`, `stdout_logfile=/var/log/supervisor/<program>.log`.

**Template:** keep the single `supervisor.conf.tmpl`, parametrized with `ProgramName`, `Command`,
`Numprocs`, `User`, `DeployPath` (for `directory`), `LogFile`. The site step computes `Command`/
`Numprocs`; the default worker's computed values reproduce the current bytes exactly.

### Drift-removal of orphaned program files (decision 3)

A **global** reconciliation (not per-site, to avoid the pool-prefix collision of decision 3). A
helper `desiredProgramPaths(s)` returns the union, across **all** `s.Sites`, of the worker path
(`berth-<pool>.conf` when `QueueEnabled(site)`) and each daemon path (`berth-<pool>-<name>.conf`).
Then `site.Check`/`Apply`:

1. List every berth program file once: `ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null`.
2. Any listed path **not** in `desiredProgramPaths(s)` is an orphan: `Check` → unsatisfied if it
   carries the berth marker (`managedFilePresent`); `Apply` → `rm -f`, guarded so a foreign
   (non-berth) file is never clobbered.

Because the desired set spans every site, an orphan belongs to **no** current site — removing it
cannot touch a live tenant's program, so the global glob is collision-free (whereas a per-pool glob
would not be). This generalizes the scheduler-cron drift-removal (single fixed path) to a listed,
variable, server-wide set. A `supervisorctl reread && update` after changes is left to the deployer
(programs are dormant); berth does not start/stop them.

## Tenant isolation — sudoers (`accounts.go` + `sudoers_deploy.tmpl`)

The sudoers template currently grants `supervisorctl {start,stop,restart} berth-<pool>:*` for one
program. Generalize to **one explicit triple per program name** the site owns (worker + each daemon),
plus the shared `reread`/`update`:

```
{{ .User }} ALL=(root) NOPASSWD: /usr/bin/systemctl reload php{{ .PHPVersion }}-fpm
{{ .User }} ALL=(root) NOPASSWD: /usr/bin/supervisorctl reread
{{ .User }} ALL=(root) NOPASSWD: /usr/bin/supervisorctl update
{{- range .Programs }}
{{ $.User }} ALL=(root) NOPASSWD: /usr/bin/supervisorctl start {{ . }}\:*
{{ $.User }} ALL=(root) NOPASSWD: /usr/bin/supervisorctl stop {{ . }}\:*
{{ $.User }} ALL=(root) NOPASSWD: /usr/bin/supervisorctl restart {{ . }}\:*
{{- end }}
```

`accounts.go` computes `Programs` from a **single shared helper** `siteProgramNames(s, site)` (also
used by the `site` step's render + `desiredProgramPaths`): the worker `berth-<pool>` **iff**
`QueueEnabled(site)`, plus `berth-<pool>-<name>` for each daemon — i.e. **exactly** the programs the
`site` step renders, nothing more (a daemon-only site with no worker gets no `berth-<pool>` grant).
The shared helper guarantees the names match exactly, or a deployer's reload would be refused. Each line is an **exact** program name + `\:*`
(process-number glob only) — never a name-prefix glob — so site B can never reload site A's program.
Validated with `visudo -cf` before install (existing pattern). **Backward-compatible (byte-identical):**
a site with only the default worker must render **byte-for-byte** the same sudoers output as today
(one program: `berth-<pool>`) — enforce with template whitespace control (`{{- … }}`) and a golden/
`accounts` test, so the managed sudoers file does not drift on existing boxes.

**Convergence on existing hosts (REQUIRED fix, Codex):** today `accounts.Check` only verifies the
sudoers file *exists* and passes `visudo -cf` — it does **not** compare content, so a changed program
list would never trigger `accounts.Apply` on an already-provisioned box (the new daemon grants would
silently never appear). This iteration must make `accounts.Check` **content-drift-check** each managed
sudoers file via `checkManagedFile` + `managedFileSatisfied` (the file already carries the `#` marker
from `templates.Render`), keeping the `visudo -cf` validation in `Apply`.

## Registry (`registry.go`)

Include the `supervisor` step when `s.NeedsSupervisor()` (any site `QueueEnabled` or any daemons;
today the gate is only `s.Queue`). This keeps the registry consistent with `QueueEnabled`: a site
that enables/tunes a worker via `site.Queue` (or adds a daemon) **without** the server `queue:` switch
still gets supervisor installed (closes the contradiction Codex flagged). **Do NOT add
`supervisor` to `site.Requires()`:** the supervisor step is conditional (absent when queue/daemons
are off), so a hard requirement would make the `--only site` gate fail with "undefined" in that case.
`site` keeps its current `Requires()` {php, nginx, appdirs, database}; the registry just places
`site` after `supervisor` (as today). Writing program files when supervisor happens to be absent
under `--only site` is a pre-existing, accepted quirk — the full-run gate installs it.

## Validation (`validate.go`)

- **Global program-name/path uniqueness across ALL sites (REQUIRED, Codex):** compute every desired
  program name (`berth-<pool>` worker + each `berth-<pool>-<name>` daemon) over all `s.Sites` with the
  shared naming helper and reject any duplicate. Necessary because a daemon name can make one site's
  program equal another's: site A `app.example.com` + daemon `x` → `berth-app_example_com-x`, which
  equals site B `app.example.com-x`'s worker `berth-app_example_com-x` (`poolName` keeps `-`, maps
  `.`→`_`). A collision = two tenants fighting over one `/etc/supervisor/conf.d/*.conf` file and one
  site's sudoers controlling the other's program — reject at load time.
- `daemon.name`: non-empty, `^[a-z0-9-]+$`, unique within the site.
- `daemon.command`: non-empty AND **single-line-safe** — reject `\n`, `\r`, NUL and other control
  characters (it is rendered literally into a `command=` line; a newline would inject extra Supervisor
  directives — config injection).
- `queue.connection` / `queue.queue`: single-line-safe (same control-char rejection) — they go onto
  the `queue:work` command line.
- `queue.driver`: `""`/`work`/`horizon` only.
- `queue.processes` / `daemon.processes`: 0 means "default 1"; reject negatives; cap at a sane max
  (e.g. 64) to avoid fork-bombing a small VPS.
- `queue.sleep` / `queue.tries` / `queue.timeout` / `queue.max_memory`: reject negatives.
- horizon + any queue:work-only knob (connection/queue/sleep/tries/timeout/max_memory) **or**
  `processes > 1` → reject (Horizon manages its own workers and forces `numprocs=1`; the knobs would
  be silently ignored).
- Lenient where Load's defaults don't apply (literal `Server` callers, wizard `ToServer()`), matching
  the Fail2ban precedent.

## Error handling / edge cases

- **No supervisor, but daemons configured:** the registry gate installs supervisor; without it,
  `visudo`/render still succeed but programs can't run — the gate prevents that misconfiguration.
- **Switching driver work↔horizon:** same program name `berth-<pool>`, only the command changes →
  ordinary content drift (re-render), not a file add/remove.
- **Removing the last daemon / disabling the worker:** handled by the list+diff orphan removal.
- **Daemon name collisions across re-renders:** deterministic naming + uniqueness validation.
- **Foreign (unmanaged) program file at a berth path:** never removed (managedFilePresent guard),
  even with `--force`, consistent with berth's unmanaged-file policy.

## Testing

- **Golden** (`internal/templates`): `-update` then diff/commit. Assert the **default worker render
  is byte-identical** to the pre-change golden (a dedicated test), plus new goldens for tuned worker,
  horizon, and a daemon. Mirror any new template field in the test-local struct.
- **config**: `queue: horizon` bare-string decodes to `{Driver:"horizon"}`; `queue:` map decodes;
  `daemons` list decodes; validation rejects bad names/driver/horizon+knobs; defaults resolve.
- **site step**: `managedSiteFiles` enumerates worker + daemons; Check satisfied when all in place;
  drift-removal: an orphaned berth-managed `berth-<pool>-old.conf` (not in desired set) → Check
  unsatisfied, Apply `rm -f`; a foreign file → left untouched.
- **accounts/sudoers**: per-program lines for worker + daemons; **isolation test** — site B's grants
  never match site A's program names; `visudo -cf` validated.
- **registry**: `supervisor` included when only daemons (no `queue`) are set.
- **Live (integration, self-signed smoke + a daemon)**: `supervisorctl status` lists every program as
  STOPPED (dormant, not FATAL); the per-program config files exist; second run all-satisfied
  (idempotency, exempting preflight) — the #30 assertion already covers this once a daemon is in the
  smoke config.

## Out of scope / future

Per-site "queue off" switch, supervisor groups, non-dormant enablement, and the remaining Tier 2
features/tests follow in later iterations (each its own spec → plan → TDD → review → live → PR).

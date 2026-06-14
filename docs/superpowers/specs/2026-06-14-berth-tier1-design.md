# berth — Tier 1 improvements design

> Status: approved design, pre-implementation
> Date: 2026-06-14
> Source: `docs/improvement-roadmap.md` Tier 1 (items 1, 2, 4, 5, 11, 13, 20, 21, 22, 25)
> Decisions locked with the maintainer on 2026-06-14.

## Goal

Implement the six Tier-1 items from the improvement roadmap as idempotent, declarative
additions to the existing Step pipeline. Each change must respect berth's defining
contracts: side-effect-free `Check`, managed-marker drift detection, the byte-identical
`site`↔`tls` HTTPS render contract, and per-tenant isolation.

## Scope

**In scope (6 items):**

1. Auto security updates — write a managed `/etc/apt/apt.conf.d/20auto-upgrades` in the `base` step (roadmap 20).
2. IPv6 on port 80 — `listen [::]:80;` parity with the existing `[::]:443` (roadmap 5, 25).
3. HSTS + TLS tuning in the HTTPS vhost (roadmap 13).
4. Managed fail2ban jail in the `hardening` step (roadmap 1, 21) — **sshd + recidive only**.
5. Logrotate for FPM + supervisor logs (roadmap 2, 22) — **single global fragment**.
6. Honor the dead scheduler flag — per-site `Site.Scheduler` override + live server default (roadmap 4, 11).

**Out of scope (deferred to Tier 2, with rationale):**

- **nginx fail2ban web jails** — the roadmap keys them off *per-site nginx logs* (deferred) and
  pairs them with nginx rate limiting (Tier 2). They would also force a cross-step ordering hack
  (`hardening` runs before `nginx`). Defer until per-site nginx logs land.
- **Per-site nginx access/error logs** — bigger change touching the byte-identical contract; not
  needed for FPM/supervisor rotation. nginx keeps using the distro-rotated global logs.
- **OCSP stapling** — needs a `resolver` directive and self-signed gating; larger surface.
- **unattended-upgrades auto-reboot** and **managing `50unattended-upgrades`** — leave to Debian/debconf.
- Swap, sysctl tuning, DB/Valkey tuning, backups, daemons, per-site PHP — all Tier 2+.

## Cross-cutting mechanisms

### Managed-file / drift recap (invariant to preserve)

Every managed file is written via `templates.Render` (`#` marker) or `RenderINI` (`;` marker),
which prepend `# managed by berth` / `; managed by berth`. The marker line is **part of the
SHA-256-hashed content**. `checkManagedFile` (`steps/common.go:85`) classifies a remote file as
`absent` / `unmanaged` / `drifted` / `uptodate`; `managedFileSatisfied` maps that to
`(satisfied, err)` — `unmanaged` aborts unless `--force`. The marker string is duplicated in
`templates.go` (write side) and `steps/common.go` (read side); never hand-write managed files.

### New `siteFile.remove` intent (drift-removal)

The current drift state machine has **no "should be absent" state**, so disabling a feature
cannot be expressed as drift — a previously-written file would simply stop being re-checked and
linger. Required by the scheduler item. Add a `remove bool` field to the `siteFile` struct
(`site.go`):

- `managedSiteFiles` emits a normal entry when the feature is enabled, or an entry with
  `remove: true` (carrying the target path) when disabled.
- `site.Check`: a `remove` entry is **unsatisfied** iff the file exists *and* carries the berth
  marker (i.e. it is ours); absent or unmanaged ⇒ satisfied (never clobber a non-berth file).
- `site.Apply`: a `remove` entry triggers `rm -f` of the path (guarded to managed files only).

This keeps `managedSiteFiles` the single source of truth and converges in one run.

**Marker-policy tradeoff (explicit, per Codex review):** because a `remove` entry only acts on a
berth-marked file, `scheduler: false` removes only berth-managed crons. A hand-placed *unmanaged*
file at `/etc/cron.d/berth-<pool>` is left untouched **even with `--force`** — `scheduler: false`
is therefore not a hard guarantee that no cron exists at that path. This is deliberate and
consistent with berth's unmanaged-file policy elsewhere (an unmanaged file is never silently
clobbered). Documented so operators don't expect disablement to delete foreign files.

---

## Item 1 — Auto security updates (`base` step)

**Current:** `systembase.go` installs `unattended-upgrades` (in `basePackages`) and runs
`systemctl enable --now unattended-upgrades`, but never writes the APT Periodic config, so the
`apt-daily-upgrade` timer applies nothing — the feature is silently inert. `Check` only verifies
`dpkg -s` for each base package.

**Change:**

- New static template `internal/templates/apt_auto_upgrades.conf.tmpl` (rendered via `Render`, `#`
  comment valid in APT config):
  ```
  APT::Periodic::Update-Package-Lists "1";
  APT::Periodic::Download-Upgradeable-Packages "1";
  APT::Periodic::Unattended-Upgrade "1";
  APT::Periodic::AutocleanInterval "7";
  ```
- `systembase.go`: import `internal/templates`; add `autoUpgradesPath =
  "/etc/apt/apt.conf.d/20auto-upgrades"` and a `renderAutoUpgrades()` helper.
- `Check`: bind the `RunCtx` arg (currently `_`); after the package loop passes, render desired,
  `checkManagedFile` + `managedFileSatisfied(state, autoUpgradesPath, rc.Force)`. Return
  `Satisfied:true` only when packages present **and** the file up-to-date. Add the change to the
  `Changes` slice ("write 20auto-upgrades periodic config").
- `Apply`: after `EnsurePackages`, `WriteFile(FileSpec{Path: autoUpgradesPath, Owner:"root",
  Group:"root", Mode:0o644, Sudo:true})`; keep the existing `enable --now`.

**Pattern to mirror:** `php.Check`/`php.Apply` (canonical single-managed-file step).

**Risks/notes:** Debian's `unattended-upgrades` package may ship an unmanaged `20auto-upgrades`
via debconf → `fileUnmanaged` → abort unless `--force` (documented drift policy; add a code
comment). `systembase_test.go` must stub `cat '/etc/apt/apt.conf.d/20auto-upgrades'` and assert
the WriteFile.

## Item 2 — IPv6 on port 80

**Current:** `[::]:443` is already present in `nginx_https.conf.tmpl`, but both `nginx_http.conf.tmpl:2`
and the redirect server in `nginx_https.conf.tmpl:2` only `listen 80;` (IPv4 only).

**Change:** add `listen [::]:80;` directly under `listen 80;` in both places. **Unconditional**,
consistent with the existing `[::]:443`. No template data needed. Regenerate `nginx_http.golden`
and both `nginx_https*.golden`.

**Risk:** on an IPv6-less host `listen [::]:80;` would fail `nginx -t`/reload — but the existing
`[::]:443` already carries this exact risk, so behavior stays consistent.

## Item 3 — HSTS + TLS tuning (HTTPS vhost)

**Decision: HSTS auto-on for real (letsencrypt) certs.** No new config field.

**Change:**

- Add `HSTS bool` to the production `nginxData` struct (`site.go`) **and** the test-local
  `nginxData` (`templates_test.go:46`).
- In `nginxRenderData`: `HSTS: site.SSL && site.CertMode() != "selfsigned"`. Derived **purely
  from static config** (never cert presence) so `site` re-render and `tls` `swapToHTTPS` produce
  identical bytes.
- In `nginx_https.conf.tmpl`, alongside the existing always-headers, mirroring the
  `{{- if .HTTP3 }}` Alt-Svc pattern:
  ```
  {{- if .HSTS }}
  add_header Strict-Transport-Security "max-age=31536000" always;
  {{- end }}
  ```
  (1 year; **no** `includeSubDomains` — harmful on a multi-tenant box where tenants may be
  subdomains of each other; **no** `preload`.)
- Unconditional TLS tuning near the `ssl_certificate` lines (applies to both LE and self-signed):
  ```
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers off;
  ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off;
  ```
  (Mozilla-intermediate-style profile.)

**Goldens:** the main `nginx_https.golden` and `nginx_https_http3.golden` represent LE sites →
render with `HSTS:true`. Add one variant golden with `HSTS:false` (self-signed) to prove the gate.
Regenerate via `go test -update ./internal/templates/...`, diff, commit.

**Byte-identical contract:** HSTS/TLS directives live **only** in `nginx_https.conf.tmpl` (never
the HTTP block) and depend only on static config, so first-issuance (`tls`) and idempotent
re-render (`site`) stay byte-identical.

## Item 4 — Managed fail2ban jail (`hardening` step)

**Decision: sshd + recidive only; web jails deferred. Configurable knobs.**

**Current:** `hardening.go` installs fail2ban and only `serviceUp`-checks it; writes no jail, so
only Debian's stock defaults apply.

**Change:**

- New server-level config block `Fail2ban{ Bantime string; Findtime string; Maxretry int }` on
  `Server`. Defaults via `SetDefault("fail2ban.bantime","1h")`, `findtime "10m"`, `maxretry 5`.
- New template `internal/templates/fail2ban_jail.tmpl` (`Render`, `#`):
  ```
  [DEFAULT]
  bantime = {{ .Bantime }}
  findtime = {{ .Findtime }}
  maxretry = {{ .Maxretry }}

  [sshd]
  enabled = true
  port = {{ .SSHPort }}
  backend = systemd

  [recidive]
  enabled = true
  ```
  Render data `{Bantime, Findtime, Maxretry, SSHPort}`; `SSHPort` from `s.SSH.Port`.
- `hardening.Check`: add a `checkManagedFile` branch for `/etc/fail2ban/jail.local` mirroring the
  existing sshd-drop-in pattern (`hardening.go:75-82`).
- `hardening.Apply`: `WriteFile` the jail, validate `fail2ban-client -t`, then
  `systemctl reload fail2ban` (mirroring the `nginx -t`/`visudo -cf` validate-before-reload pattern).

**Notes:**
- `backend = systemd` for `[sshd]` reads journald (robust on Debian 13 regardless of rsyslog).
  The sshd jail has value even on a key-only sshd (bans scanners probing invalid users / closing
  connections before auth).
- `[recidive]` inherits its filter/logpath/longer-ban from Debian's stock `jail.conf` `[recidive]`
  section (section-specific values beat our `[DEFAULT]`); we only enable it. Validate exact merge
  behavior with `fail2ban-client -t` and integration.
- Validation: `bantime`/`findtime` match `^[0-9]+[smhdw]?$`; `maxretry` in `1..100`.

## Item 5 — Logrotate (FPM + supervisor)

**Decision: single global `/etc/logrotate.d/berth` with globs.**

**Current:** no logrotate config anywhere. FPM error log `/var/log/php/<pool>-fpm.error.log`,
supervisor worker log `/var/log/supervisor/berth-<pool>.log`. **`/var/log/php` is created by no
step** — the FPM error log is effectively broken today, independent of rotation.

**Change:**

- New template `internal/templates/logrotate.conf.tmpl` (`Render`, `#`), static, glob-based so one
  file covers all current and future sites:
  ```
  /var/log/php/*-fpm.error.log
  /var/log/supervisor/berth-*.log {
      daily
      rotate 14
      compress
      delaycompress
      missingok
      notifempty
      copytruncate
  }
  ```
  `copytruncate` avoids coupling to FPM pidfile / supervisorctl signalling.
- Written by the `site` step as a **single** entry in `managedSiteFiles` (not the per-site loop):
  path `/etc/logrotate.d/berth`, `WriteFile` root:root 0644.
- `site.Apply`: validate `logrotate -d /etc/logrotate.d/berth` (treat only non-zero exit as
  failure; `missingok` info lines are fine).
- New golden test `logrotate.golden`.

**`/var/log/php` directory gap — fixed in the `php` step, not `site` (per Codex review):** the FPM
error-log dir is created by no step today, so the FPM error log is already broken. Placing the
`install -d` in `site.Apply` is unsafe — on an already-converged box where the managed files are
up-to-date `site.Check` reports Satisfied and `Apply` never runs, so a deleted `/var/log/php`
would not be recreated. Instead the `php` step (owns the FPM runtime, runs before `site`) ensures
the directory: `php.Apply` runs `install -d -o root -g root -m 0755 /var/log/php` (idempotent), and
`php.Check` adds `test -d /var/log/php` to its satisfied condition so the directory converges
independently of any managed file.

**Risks:** logrotate refuses group/world-writable drop-ins (0644 root:root required). Do **not**
add an nginx stanza — the distro's `/etc/logrotate.d/nginx` already rotates `/var/log/nginx/*.log`
(double-rotation hazard); nginx per-site logs are deferred.

## Item 6 — Honor the scheduler flag

**Decision: per-site `Site.Scheduler *bool` override + live server default (default ON).**

**Current:** `Server.Scheduler` exists and the wizard collects it, but **no step reads it**; the
`site` step writes `/etc/cron.d/berth-<pool>` unconditionally for every site.

**Change:**

- `Load()`: `SetDefault("scheduler", true)` so the existing `Server.Scheduler` defaults ON,
  preserving today's always-installed behavior and finally making the flag meaningful (item 4).
- Add `Scheduler *bool` to the `Site` struct (both `mapstructure` + `yaml` tags). `*bool`
  distinguishes "unset" from "explicitly false".
- Helper `Server.SchedulerEnabled(site Site) bool`: `site.Scheduler != nil ? *site.Scheduler :
  s.Scheduler` (per-site override, else server default).
- `managedSiteFiles`: append the cron entry normally when `s.SchedulerEnabled(site)`, else append a
  `remove:true` entry on `cronPath(site.Domain)` (uses the new drift-removal mechanism above).
- Wizard unchanged (continues to set `Server.Scheduler`). The per-site override is config-only.
- Test: cron file absent / removed when scheduler disabled; present when enabled.

**Risk:** an explicit `scheduler: false` is now honored (previously ignored) — this is the intended
fix, not a regression for the common case (absent key → default true → cron installed, unchanged).

---

## Consolidated config schema changes

**Server (`config.go`):**
- `Scheduler bool` — keep; add `SetDefault("scheduler", true)` in `Load()`.
- New `Fail2ban Fail2ban` sub-block: `Bantime string`, `Findtime string`, `Maxretry int`
  (defaults via `SetDefault("fail2ban.bantime"/"findtime"/"maxretry", ...)`).

**Site (`config.go`):**
- `Scheduler *bool` — per-site scheduler override (nil = inherit server default).
- (No HSTS field — HSTS is auto-derived from `SSL` + `CertMode()`.)

**Validation (`validate.go`):**
- `fail2ban.bantime`/`findtime`: regex `^[0-9]+[smhdw]?$`.
- `fail2ban.maxretry`: integer range `1..100`.
- `Site.Scheduler` (`*bool`): no validation needed.

## Consolidated template & golden changes

| Template | Action | Golden |
|---|---|---|
| `apt_auto_upgrades.conf.tmpl` | new (static) | new `apt_auto_upgrades.golden` |
| `nginx_http.conf.tmpl` | add `listen [::]:80;` | regen `nginx_http.golden` |
| `nginx_https.conf.tmpl` | add `[::]:80` in redirect, HSTS gate, TLS tuning | regen `nginx_https.golden` + `nginx_https_http3.golden`; new HSTS-off variant |
| `fail2ban_jail.tmpl` | new (data: knobs + SSHPort) | new `fail2ban_jail.golden` |
| `logrotate.conf.tmpl` | new (static) | new `logrotate.golden` |

After any template edit: `go test -update ./internal/templates/...`, **diff** goldens, commit
template + test + golden together. The test-local `nginxData` struct must gain the `HSTS` field.

## Testing strategy

- **TDD per item.** Unit tests against `FakeRunner` stubbing exact command strings.
- **Golden tests** for every new/changed template (above).
- **Drift/removal:** unit test that a disabled scheduler produces a `remove` entry and `site.Apply`
  `rm -f`s the cron; that a re-run reports Satisfied.
- **HSTS gating:** assert `nginxData.HSTS` is false for a self-signed site and the rendered HTTPS
  vhost omits the HSTS header; true for an LE site.
- **Byte-identical contract:** assert `site`'s HTTPS render equals `tls` `swapToHTTPS` output for an
  LE site with the new HSTS/TLS directives (guards endless drift).
- **systembase:** stub `cat '/etc/apt/apt.conf.d/20auto-upgrades'`; assert WriteFile + Check
  satisfied/unsatisfied transitions.
- **php `/var/log/php`:** stub `test -d /var/log/php`; assert `php.Check` reports unsatisfied when
  absent and `php.Apply` runs `install -d ... /var/log/php`.
- **Integration (when wired, roadmap items 8/28):** `apt-config dump
  APT::Periodic::Unattended-Upgrade == "1"`; `fail2ban-client status sshd`; `logrotate -d
  /etc/logrotate.d/berth` parses clean; `swapon` n/a. Not part of the default unit gate.

## Sequencing & dependencies

No new pipeline steps; all changes are in-place edits to `base`, `hardening`, `site`, the templates
package, and config. Implementation order (dependency-safe, each independently testable):

1. Auto-upgrades (`base`) — isolated, highest impact/lowest risk; establishes the import + pattern.
2. IPv6 `[::]:80` — trivial template + goldens.
3. HSTS + TLS tuning — templates + `nginxData` + goldens; preserves the byte-identical contract.
4. fail2ban jail (`hardening`) — new config block + template + Check/Apply.
5. Logrotate — new template + single managed entry + `/var/log/php` dir + validation.
6. Scheduler — config (`*bool` + SetDefault) + `siteFile.remove` machinery + `managedSiteFiles`.

The `siteFile.remove` mechanism (item 6) is the only structural change to shared code; everything
else is additive.

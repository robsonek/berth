# Changelog

Notable changes to berth. Older releases are documented on the
[GitHub Releases](https://github.com/robsonek/berth/releases) page.

## [Unreleased]

### Added

- **Host provisioning manifest** — a new terminal `manifest` step records
  `/var/lib/berth/manifest` (`VERSION`, plus `PROVISIONED_AT` = when that
  version first fully provisioned the host), so future upgrades can branch
  on "last fully provisioned by" instead of probing the filesystem. Partial
  (`--only`) runs neither read nor write it, and a pipeline truncated by
  `--skip-ssl` does not attest at all.
- **Per-site backup manifest** — `/var/backups/berth/<pool>/manifest` records
  the berth version, engine, database/user names, site user and deploy path
  the archives were made under; the offsite copy of a backup directory is now
  self-describing. The recorded version makes the backups step re-apply once
  after every berth upgrade (byte-identical rewrites of its other files, no
  reload).

### Changed

- **BREAKING: the legacy top-level `database.name` / `database.user` spelling
  is gone.** Every site now carries its own `database: {name, user}` block
  (the wizard has always written it this way). A config still using the
  top-level spelling fails to load naming the unknown key — move the two
  values into the site's block.
- **BREAKING: pre-v0.22 (pre-envelope) local secret caches are no longer
  read.** The identity step no longer upgrades legacy flat caches; a flat
  file under `~/.berth/` is rejected with advice. No released berth wrote
  that format for a host that still exists. The legacy-format test writer
  (`secret.SaveCache`) is gone with it. A console password set by a
  pre-envelope berth loses its ownership marker with the discarded cache, so
  `break_glass: false` will leave it untouched — lock it manually with
  `passwd -l berth` or copy the `console:berth` entry into the new cache
  first.
- Removed the three on-host migration shims for artifacts renamed during
  pre-release development: the scheduler cron (`berth-<pool>` →
  `berth-site-<pool>`), the sshd drop-in (`berth.conf` → `00-berth.conf`)
  and the pre-per-site valkey tuning drop-in. The removed-site cron sweep
  now matches `berth-site-*` exactly. Every box berth has ever provisioned
  is disposable and is reset before the first real deployment; no surviving
  host carries any of these paths.
- Dropped two dead config decode hooks (`time.Duration`, comma-`[]string`) so
  no future field silently gains an alias spelling.

### Fixed

- **Restores are order-insensitive.** The `database` step now detects when
  the live `shared/.env` and the local secret cache hold DIFFERENT values for
  the DB password or `APP_KEY` (e.g. an older `.env` restored over a freshly
  provisioned host) and reconciles toward `.env`: the role's password is
  reset and the cache re-synced. Previously that state stayed green forever —
  the app locked out of its database and the cache permanently poisoned with
  a wrong `APP_KEY`. The README's Full-restore order now documents the
  reconciling second run. Reconciliation also refreshes a `~/.my.cnf` /
  `~/.pgpass` that provably held berth's previous credential (an
  operator-customized file is left alone).
- An operator-managed `APP_KEY` whose shape berth does not recognize no
  longer hard-errors the `database` step's apply — it is treated as "not
  berth's to back up" (previously any apply on such a host failed).
- A cached DB password or `APP_KEY` whose shape is corrupt (a hand-edited or
  tampered `~/.berth/` cache) now fails the `database` step's check loudly
  instead of riding into the value comparison or onto the host.

## [0.23.0] — 2026-07-27

### Fixed

- **Secret redaction is now real, not implied.** Steps have always registered
  generated credentials with a redactor, but nothing ever applied it to
  output — the masking a reader would assume from `redactor.Add(pw)` did not
  exist. The engine now masks every event field (reasons, change lists,
  warnings, errors — with `errors.Is`/`As` preserved through the wrapper) and
  its synchronous pre-flight error; the CLI masks returned errors again at
  the command boundary. Each database secret registers the moment it is
  acquired, before the next fallible operation, and the redactor itself is
  now concurrency-safe with longest-first matching (a short secret can no
  longer shred a longer one it prefixes).
- **Removing swap restores the pre-berth `vm.swappiness`.** berth records the
  live value into `/var/lib/berth/swappiness.pre-berth` before its first
  overwrite (never on re-applies, and never when the drop-in is already
  berth's — no fabricated baselines) and, on `system.swap` removal, restores
  exactly that value as the final sysctl operation of the step, dropping the
  state file only after a successful restore. Hosts provisioned before this
  version have no recorded baseline: removal warns and the value stays until
  reboot. Previously berth's `vm.swappiness=10` silently persisted forever.
- **Swap sizes are capped at 1 TiB at config validation.** An absurd
  `system.swap` used to overflow the byte conversion or fail remotely in
  `fallocate`; now `berth` rejects it locally, in the config, the wizard and
  the step alike.
- The wizard validates the raw config name (no path separators, `..`, or
  leading dot/dash — `servers/../x.yml` can no longer escape the directory)
  and creates the file exclusively (`O_EXCL`), removing a stat-then-write
  race; partial files are cleaned up on write errors.
- The secrets cache write is now crash-durable (fsync of file and directory
  before the promise "cached before the remote effect" is relied upon).

### Changed

- `.env` rendering validates keys (env-identifier grammar) and rejects
  CR/LF/NUL in values; the database dump command shell-quotes the database
  name. Both are defence in depth behind existing config validation; the
  backup script re-renders once on already-provisioned hosts (managed-file
  drift, quoted dump command).

## [0.22.0] — 2026-07-27

### Added

- **Declared server identity (`id:`) and a versioned secret cache.** The
  local cache under `~/.berth/` (database passwords, `APP_KEY` backups, the
  break-glass console password) used to be keyed by hostname alone, so two
  *different* machines reachable through one hostname (NAT / port forwards)
  silently shared — and clobbered — each other's credentials, while a lost
  cache entry could disown a still-usable root-equivalent console password.
  A new optional top-level `id` declares the machine's stable identity (the
  wizard generates one); the cache file is now a versioned envelope recording
  the endpoint it was bound to, and a new `identity` step — always executed,
  `--only` included, before any remote mutation — binds fresh caches,
  upgrades legacy files in place, migrates host-keyed files to the id
  (leaving a tombstone so a stale id-less config fails loudly instead of
  regenerating secrets), and hard-errors on an endpoint mismatch. A
  deliberate endpoint change is re-bound with `--force`; accidental id reuse
  across different servers is refused with both endpoints named. Downgrading
  below this version after an id/envelope exists is not supported.

### Changed

- **`valkey: false` now reconciles instead of abandoning.** The valkey step
  used to vanish from the pipeline when disabled, leaving previously
  provisioned per-site instances running forever. It now always runs: with
  `valkey: false` it stops, disables and removes every berth-managed
  instance (marker-guarded — foreign units are untouched; instance data
  under `/var/lib/berth-valkey/` is kept). Move each application's `.env`
  off the Valkey socket *before* flipping the knob — see the README.
- **Changing `php.version` on a provisioned host is refused loudly.** The
  per-site FPM sockets are version-independent, so the old version's master
  would fight the new one over them — a silent, non-deterministic
  half-state. Both the `accounts` and `php` steps now refuse (not
  bypassable with `--force`) while berth-marked pools of another version —
  or foreign pools bound to berth sockets — remain, with a manual
  maintenance-window migration recipe in the error and the README.

## [0.21.0] — 2026-07-27

### Fixed

- **A broken file owned by the `site` step no longer deadlocks the whole
  pipeline.** `php-fpm -t` and `nginx -t` validate the entire unit, and the
  `php`/`nginx` steps run before `site` — so a broken FPM pool or nginx vhost
  used to fail those earlier steps forever, while fail-fast never let `site`
  re-render the very file at fault (manual removal on the host was the only
  way out; `--only site` refused too because its prerequisites read
  unsatisfied). On a full run the two steps now hand the failure to `site`:
  `php` first proves the fault is outside its own drop-ins (removes them,
  re-validates, restores them — if the unit validates *without* them the
  failure is berth's own rendering and the step still fails loudly), `nginx`
  skips the check-by-removal entirely (removing its sites-include would
  unload every vhost and misattribute the fault), and both skip the reload
  and its stamp, emit a warning and let the pipeline continue. `site` then
  re-renders everything it owns, validates and reloads — one run heals a
  drifted pool/vhost end to end, and a genuinely foreign broken file now
  fails in `site` with the validator's message naming it. Under `--only`
  the old hard failure remains (there is no later `site` to defer to).
  Note the deliberate trade-off: because the run now continues past the
  warning, the steps between `nginx` and `site` (composer, valkey,
  supervisor, appdirs, database, tuning) apply their changes *before* a
  foreign-file failure surfaces at `site` — previously the run stopped
  before them. All of those steps are idempotent and independent of the
  broken unit, but the point at which the error is reported moves later.
- `nginx` is now enabled without being started until its config validates
  (`systemctl enable` + validate + start-or-reload, mirroring the FPM
  pattern): a dead nginx next to a broken vhost used to die in
  `enable --now` before validation could even assign blame.
- The "skipping TLS: domain does not resolve" notice goes through the
  renderers as a proper warning instead of a raw print that bypassed them.

### Added

- Warnings are now part of the provisioning output contract: plain mode
  prints stable `warn  <step>: <message>` lines, the TUI shows a yellow `⚠`
  list. Warnings never change the exit code — a run that healed itself exits
  0, a run that could not still fails at the failing step.

## [0.20.0] — 2026-07-27

### Changed

- **BREAKING: a config file with an unknown or misspelled key no longer
  loads.** `berth` used to ignore keys it did not recognise and quietly apply
  the default, so a typo in something safety-relevant — `cloudflare_only`, a
  backup setting, a per-site policy — left you convinced you had configured
  something berth never read. Unknown keys are now a parse error naming the
  offending key. If a config fails to load after upgrading, the message tells
  you which key to fix or remove.

### Fixed

- **The privileged write path now states and enforces its contract.** Writing
  a file as root is only sound when root controls the whole destination path:
  the temp file is staged next to the destination, so an account that can write
  any component of that path can substitute the staged file (via a hard link it
  keeps) or replace the final name afterwards. Ownership of the content does not
  help — a root-owned file is itself a capability, and an `authorized_keys`
  landing in `/root/.ssh` through a swapped symlink would grant root.

  Every privileged write therefore requires a `root:root` destination whose mode
  is not group- or other-writable, an absolute clean path, and an ancestry in
  which every existing component is a root-owned, non-writable real directory.
  Violations are refused before anything is staged, naming the component, its
  owner and the remedy. Files inside territory an account owns are not written
  this way at all; they are written by that account, as of the previous release.

## [0.19.1] — 2026-07-27

### Fixed

- **A symlink at an account's `~/.ssh` is now refused instead of failing
  mid-run.** The guard added in 0.19.0 checked only the owner, and it
  deliberately does not follow symlinks — so a symlink passed, because a
  symlink's own owner is the account that created it. Provisioning then died
  with a bare `Permission denied` from `install -d` whenever the link pointed
  at something the account cannot write. The guard now also requires the entry
  to be a real directory and names the type it found.

  The refusal deliberately does not offer a `chown`: for a symlink, `chown`
  acts on whatever the link points at, so that advice would re-own the target
  to the account. Removing or moving the entry aside is the fix, and the
  message says so.

  One arrangement that used to work is now refused: a `~/.ssh` symlinked to a
  directory the account can already write (a home on a separate mount, say)
  provisioned successfully before, because the account-run `install -d` simply
  followed the link. berth needs a real directory there, so such a host now
  gets the refusal too — replace the symlink with a directory, or point
  `sites[].user` at an account whose home layout berth manages.

## [0.19.0] — 2026-07-27

### Fixed

- **Closed privilege-escalation races in per-site provisioning.**
  Directories and files inside territory a site user owns — `shared/`,
  `shared/tmp`, `shared/.env`, each account's `~/.ssh`, its `authorized_keys`
  and its database client-auth file (`~/.my.cnf` / `~/.pgpass`) — were created
  and written by root. The safety probe and the mutation are separate
  commands, so a compromised site could swap a path component for a symlink in
  between, by either of two routes: `install -d` follows a directory symlink
  and applies ownership to its target, and the root write path stages its file
  inside the destination directory and hands the result the site user as
  owner. Both are enough to plant an account-owned file in a root-only
  directory and have root read or execute it later. All of these are now
  created and written by the owning account itself, so the operation carries no
  privilege the account does not already have.
- **Root file writes now target an exact path.** `mv` was invoked without
  `--no-target-directory`, so a destination that resolved to a directory moved
  the staged file inside it rather than replacing it. Every remaining root
  write now hits the named path or fails.
- **Root-run directory creation now requires a root-controlled ancestry.**
  berth still creates `deploy_path`, the ACME webroot and each account's
  `/home/<user>` as root; every existing component above them — including `/`,
  and `/home` itself for the account homes — must be a root-owned directory
  that is neither group- nor other-writable, and must be traversable by the
  site user and by `www-data`. Otherwise provisioning refuses, naming the path,
  its owner and its mode — a `/home` on a non-root-owned or group-writable
  mount is therefore refused too. Without this a `deploy_path` such as
  `/srv/apps/site` under a non-root `/srv/apps` remained redirectable, and an
  unsearchable ancestor would have made the step re-apply forever. Not
  bypassable with `--force`.
- Directory modes are now given as five octal digits, which clears any
  setuid/setgid bit. Shorter numeric modes leave those bits untouched on
  directories, so a site user could park its own `shared/` at mode `2700` and
  make the step re-apply on every run without ever converging.

### Changed

- **The ACME webroot is now owned by `root:root`** (previously `www-data`).
  certbot runs as root and writes the challenge files itself; nginx only reads
  and traverses the webroot, which mode `0755` already grants. An unprivileged
  owner could swap `.well-known` or `acme-challenge` for a symlink and
  redirect certbot's root-run writes. Existing hosts converge on the next
  provision — the step re-owns the directory automatically.
- Two states berth used to repair silently now refuse with the exact remedy,
  because the owning account — unlike root — cannot fix them itself:
  an account that is not a member of its own eponymous group
  (`usermod -aG <user> <user>`), and an existing `~/.ssh` owned by somebody
  else (`chown -R <user>:<user> /home/<user>/.ssh`). Both are reported before
  the `accounts` step touches any account home, key or sudoers file (earlier
  steps such as `preflight` and `base` still run first). Hosts provisioned by
  earlier versions are unaffected unless they were hand-edited into one of
  these states.

## [0.18.0] — 2026-07-27

### Changed

- **BREAKING: implicit site users are always derived from the domain** — a
  single-site config without `sites[].user` used to run the site as a shared
  `deploy` account; it now gets the same derived `b_<slug>_<hash>` account as
  multi-site configs, so identity no longer flips when a config grows to two
  sites or shrinks back to one. To keep an existing installation on the old
  account, pin it explicitly (`user: deploy`). On hosts already provisioned
  with the old identity, provisioning refuses loudly with that instruction
  instead of silently re-owning the tree.
- `berth init` always writes an explicit `user:` for every site (the derived
  name when the field was left blank), so the generated YAML shows the
  account your deployer connects as.
- nginx vhosts: dropped the dead `fastcgi_split_path_info` directive — the
  `location ~ \.php$` anchor can never yield PATH_INFO, and nothing read it.
- `-v/--verbose` is now a real verbose mode: plain output additionally shows
  each satisfied step's reason and each applied step's change list (it used
  to merely disable the TUI, exactly like `--no-tty`).

### Added

- **Owner guard for per-site directories** — when `deploy_path`, `shared/`
  or `shared/tmp` already exists but is owned by a different user than the
  configured/derived site user, the `accounts` and `appdirs` steps refuse
  loudly (even with `--force`) with remediation instructions, instead of
  re-owning the tree and orphaning the previous account, deploy key and
  sudoers entry.

### Fixed

- Hostname validation no longer accepts non-ASCII letters that merely
  case-fold into a-z (e.g. U+017F); uppercase site domains still get the
  dedicated "must be lowercase" hint (`host` and `system.hostname` accept
  uppercase as before).
- Package probes (`dpkg -s`) now parse the `Status:` line and require the
  package to be actually installed, so a package removed but not purged
  (dpkg state `rc`) no longer counts as installed and gets reinstalled
  instead of skipped; held-but-installed packages still count as installed.
- `berth init` no longer prints success and then possibly fails on
  `.gitignore`: the vestigial CWD `.gitignore` management was removed
  entirely — secret caches live under `~/.berth` (never in the working
  directory) and the generated YAML is secret-free by design.

## [0.17.0] — 2026-07-26

### Added

- **Five `tuning.*` parity knobs** — `mariadb_log_file_size`,
  `mariadb_tmp_table_size` (drives both `tmp_table_size` and
  `max_heap_table_size`), `mariadb_max_connections`,
  `mariadb_max_allowed_packet` (capped at MariaDB's 1G ceiling, which the
  server would otherwise enforce by silent truncation), and
  `php_fpm_max_children` (every site's pool, default 10). The MariaDB knobs
  are unset-by-default: an empty knob renders no directive and the engine's
  stock default stays in force — existing hosts see zero drift and no
  restart until a knob is set.

### Fixed

- **"Written but not reloaded" is now detected and healed** — a crash (or a
  lost SSH transport) between writing a config file and reloading its service
  used to leave the service running the OLD configuration forever while every
  later run reported green: fail2ban jailing port 22 instead of `ssh.port`,
  sshd on a stale drop-in, nginx without a just-enabled origin lockdown,
  PHP-FPM on old pools or tuning. berth now records a per-unit stamp under
  `/var/lib/berth/` after every successful reload and reports the step
  unsatisfied while a managed file is newer than the stamp. The first run
  after upgrading performs one graceful reload of nginx, PHP-FPM, fail2ban
  and ssh (the stamps do not exist yet); no restarts, no downtime.
- **A dead PHP-FPM is detected and started** — `php-fpm -t` validates syntax
  even with the daemon down, so every step reported green while the host
  served 502s. The `php` step now requires the unit active and starts it
  when it is not (boot enablement stays apt's business). A stopped sshd is
  likewise detected and started (validated first) by the `hardening` step —
  before its anti-lockout gate, which could never have healed it.
- **The scheduler crons are no longer silently inert** — the `site` step now
  installs/enables the cron daemon before writing scheduler entries (as
  `backups` already did) and reports unsatisfied while the daemon is down.
  The `site` step also verifies each vhost's `sites-enabled` symlink and
  that the stock FPM `www` pool stays disabled.
- **Tenant directory MODES are re-checked, not just ownership** — a drifted
  `deploy_path` mode (say 0755) silently broke tenant isolation while the
  ownership-only probe stayed green; owner, group and mode now all converge.
- **Deploy-key installations are verified for completeness** — a missing
  `.pub` is derived from the private key (never regenerated) and a missing
  `known_hosts` entry re-triggers the host scan; previously only the private
  key was probed and `berth site key` could send the operator to a no-op
  `berth provision`.
- **Spurious MariaDB/Valkey restarts in some timezones** — the config-loaded
  probe parsed `systemctl`'s human-readable timestamp with `date -d`, which
  fails on zone abbreviations like AEST/ACST and forced a restart on every
  run; it now uses `systemctl show --timestamp=unix` (no parsing at all).
- **A git repository on a nonstandard SSH port now works** — the known_hosts
  entry is stored and probed under the `[host]:port` token and the scan uses
  `ssh-keyscan -p`; previously the port was silently dropped and the first
  deploy failed host-key verification.
- **Removing a site from the YAML now removes its served artifacts** — the
  next run deletes the site's nginx vhost (+ enabled symlink), PHP-FPM pool
  and scheduler cron (marker-guarded, foreign files untouched) and reloads
  the services, closing the audit finding where a removed tenant stayed
  publicly served with every run green. `--dry-run` previews every planned
  removal. Data and access — database, DB user, OS account, sudoers, deploy
  key, `deploy_path`, certificates — are deliberately kept; the README
  documents the manual removal procedure. For Let's Encrypt sites
  `certbot delete --cert-name <domain>` is a required follow-up — the
  retained lineage keeps a webroot renewal job whose challenge now lands on
  the wrong vhost, so `certbot.timer` fails repeatedly until it runs. With
  implicit (derived) site users, pin `sites[].user` on every surviving site
  before shrinking to a single one — the lone survivor otherwise flips to
  the legacy `deploy` identity, and the next run re-owns its tree and mints
  a new deploy key.
- **Scheduler crons moved to `/etc/cron.d/berth-site-<pool>`** — the old
  `berth-<pool>` form of a domain literally named `backup-…` fell inside the
  backup-cron sweep's namespace and could be deleted or collide with another
  domain's backup cron. Existing crons migrate automatically on the next run
  via one atomic rename — at no instant do both the old and new file exist,
  so `schedule:run` never double-fires during the migration.
- **Removing the last Supervisor program now takes effect on an
  active-but-disabled supervisord** — the post-removal `reread`/`update` was
  gated on the unit being enabled too, letting a running worker keep
  executing removed code.
- **Overly long domains are rejected at validation, not mid-provision** — a
  still-RFC-valid domain longer than 77 characters overflows the kernel's
  107-byte unix-socket path budget for the per-site Valkey socket (the
  PHP-FPM socket follows at 88, cron/unit filenames much later at NAME_MAX),
  so provisioning failed at socket creation after nginx and PHP-FPM were
  already reloaded. `berth provision` now refuses the config up front,
  stating the limit and the reason; the cap includes the Valkey budget even
  while `valkey` is off, so a valid config never breaks the day the knob is
  switched on.
- **`cloudflare_only` now locks down every content location** — favicon.ico,
  robots.txt and `/build/assets/` were reachable directly from origin while the
  lockdown was on; they are now guarded like the app and PHP locations (the
  ACME challenge path stays open so certificate issuance/renewal still works).
- **The PHP location gates on file existence** (`try_files $uri =404;`) so only
  an existing PHP script is used as `SCRIPT_FILENAME`; a missing `.php` URI
  follows the existing front-controller 404 path. Both nginx fixes change the
  managed vhost template, so existing vhosts re-render once on the next run
  (detected as drift, validated with `nginx -t`, reloaded) and then stay
  stable.
- **The composer installer runs from a private temporary directory** instead of
  a fixed world-writable `/tmp` path, closing a predictable-path/TOCTOU window.

### Changed

- **berth now keeps per-unit reload stamps in `/var/lib/berth/`** (root-owned,
  0755) — the on-host state backing the written-but-not-reloaded detection.
  **After upgrading, run one full `berth provision` first**: the stamps do not
  exist yet, so `--only <step>` can refuse on an unsatisfied prerequisite
  until that first full run creates them.
- **CI supply-chain and coverage hardening** — GitHub Actions are pinned to
  commit SHAs (the release workflow holds `contents: write`, so a hijacked
  mutable action tag could have tampered with published binaries), the CI
  workflow can be started manually (`workflow_dispatch`) when the
  `pull_request` trigger fails to fire, the integration suite now proves
  per-site routing with Host-header/SNI probes for every configured site,
  and the `visudo -cf` sudoers gate is pinned by unit tests.
- **Removed the unused `env.tmpl` template** and its golden test (the `.env`
  file is built programmatically via `secret.EnvFile`, not from this template).

## [0.16.0] — 2026-07-26

### Changed

- **`deploy_path` validation is stricter** — the path must now be canonical
  (no trailing slash, no `.`/`..` segments), at least two components deep, and
  outside system trees: under `/var` only a subdirectory of `/var/www` is
  allowed, and `/home` is rejected outright. Two sites may no longer nest one
  `deploy_path` inside another. Previously `deploy_path: /etc` validated and
  the root-run `install -d` handed the tenant ownership of the existing
  directory (a path to full compromise); a `/home/<user>/…` path additionally
  could never be served (nginx cannot traverse the `0700` home) and let the
  tenant symlink-swap the directory to root. Conventional layouts
  (`/var/www/<domain>`, `/srv/…`, `/opt/…`) are unaffected.
- **`appdirs` refuses a symlinked deploy target** — before creating a site's
  directories, berth now verifies that no component of the deploy tree or the
  ACME webroot is a symlink. Without this, migrating a `deploy_path` to a
  descendant of the site's own prior (tenant-owned) directory let a tenant plant
  a symlink that root's `install -d` would follow and chown, reaching root. The
  path validation cannot catch this (the new path is valid and the old one has
  left the config), so the guard is a runtime check.
- **The local secret cache moved from `./.berth/` to `~/.berth/`** and is now
  guarded by a per-host lock. Anchoring it under `$HOME` means it is found
  regardless of the working directory (break-glass lock-back and the
  re-seed-after-`.env`-loss flow depend on this), and the lock stops two
  concurrent runs against the same host from lost-updating it. **There is no
  automatic migration:** an old `./.berth/` is simply ignored — berth re-seeds,
  reusing secrets from each host's live `shared/.env`. A console password set
  by a pre-move berth loses its ownership marker with the old cache, so
  `break_glass: false` will leave it untouched — lock it manually with
  `passwd -l berth` if needed.

### Fixed

- **Switching `database.engine` now fails loudly instead of reporting green**
  — when a site's seeded `shared/.env` carries a `DB_CONNECTION` that disagrees
  with the configured engine (or, on an existing `.env`, lacks the key
  entirely), both Check and Apply refuse with a pointed error before installing
  anything: the app would otherwise keep talking to the old engine while
  backups dump the empty new one. `--force` does not override; migrate the data
  and update the env, or revert the engine.
- **A staging certificate no longer survives production runs** — the TEST_CERT
  annotation in `certbot certificates` is now honored: a run without
  `--ssl-staging` that finds a staging certificate re-issues it against the
  production CA (explicit `--server` + `--force-renewal`) instead of reporting
  "valid certificates present" forever. Issuance pins `--cert-name <domain>` so
  the correct lineage is read and written. A staging run never replaces a
  production certificate, and a staging replacement blocked by a DNS mismatch
  fails loudly rather than drifting.
- **`certbot.timer` is now verified and enabled on every Let's Encrypt run** —
  previously the renewal timer was enabled only right after issuing a
  certificate, so a run that left an existing certificate untouched (e.g. a
  near-expiry production certificate under `--ssl-staging`) could report success
  while automatic renewal was disabled. Check now reports the inactive timer and
  Apply enables it whenever certbot is installed.
- **The Laravel `APP_KEY` is kept in sync with `shared/.env` instead of
  regenerated** — the DB password was synced to the local cache every run but
  the APP_KEY was only minted on first seed and never cached, so an existing
  install got no protection and a lost `.env` re-seeded with a NEW key,
  silently and permanently breaking decryption of encrypted-at-rest data. It is
  now read from the `.env` when present, recovered-or-generated when absent, and
  cached beside the password. The `database` step also verifies the local cache
  holds each site's credentials and APP_KEY backup and backfills them on
  existing installations.
- **The break-glass console password is validated before `chpasswd`** — a
  tampered cache value with a newline could otherwise inject a second `chpasswd`
  record and overwrite root's password.
- **Uppercase domains are rejected** — they passed the case-insensitive
  hostname check but broke the case-sensitive certificate lineage match and 443
  vhost file paths.

## [0.15.0] — 2026-07-25

### Changed

- **sshd hardening now enforces the effective configuration** — the managed
  drop-in moved to `/etc/ssh/sshd_config.d/00-berth.conf` so it wins OpenSSH's
  first-value-wins ordering against image drop-ins (e.g. cloud-init's
  `50-cloud-init.conf` re-enabling password auth), it additionally sets
  `KbdInteractiveAuthentication no`, and both Check and Apply verify via
  `sshd -T` that the global directives win in the configuration sshd loads —
  a foreign override fails the run loudly naming candidate files, as does a
  non-empty `SSHD_OPTS` in `/etc/default/ssh` (command-line options would
  bypass what berth verifies; `Match` blocks are out of scope). The legacy
  `berth.conf` drop-in is migrated away automatically.
- **Managed-file detection requires the exact marker line** — a foreign file
  whose first line merely starts with the marker (e.g.
  `# managed by berth-backup`) is no longer treated as berth-managed, so it
  can neither be overwritten without `--force` nor removed by drift cleanup.
- **Valkey is now one instance per site** — the shared, unauthenticated
  `valkey-server` on 127.0.0.1:6379 (a cross-tenant hole: logical DBs have no
  access control) is replaced by per-site instances running as each site's OS
  user, reachable only via a unix socket in a 0700 directory, with no TCP
  listener. The stock `valkey-server.service` is disabled, the legacy tuning
  drop-in migrated away, and instances for removed sites are swept (their
  `/var/lib/berth-valkey/<pool>` data directories are left in place —
  cache-class data, remove manually if desired). Fresh
  `.env` seeds point `REDIS_HOST` at the socket (`REDIS_PORT=0`, cache in its
  own logical DB); `REDIS_DB` allocation and `REDIS_PREFIX` are gone. The
  `tuning.valkey_maxmemory*` knobs now cap each instance. **Existing hosts:**
  the stock service gets disabled on the next provision, but `shared/.env` is
  seed-if-absent and never rewritten — update each site's `REDIS_*` values to
  the new socket manually (or remove `.env` to re-seed) before re-running.

## [0.14.0] — 2026-07-24

### Added

- **Break-glass console access** — opt-in `system.break_glass`: gives the
  `berth` account a generated password (stored locally in
  `.berth/<name>.secrets.json`) so the provider's console/VNC works when SSH
  is down; without it every berth-managed account is locked and only rescue
  mode remains. sshd keeps `PasswordAuthentication no`, so no network login
  path opens; the berth account has full sudo, so treat the cached password
  as a root credential. Turning the knob off locks back the password berth
  set (ownership is tracked via the local cache entry, which locking removes;
  a password berth did not set is left alone), and an existing usable
  password is reused, never rotated. Available in `berth init`.
- **Integration coverage for the v0.13 features and break-glass** — the live
  suite now asserts the static hostname + the exactly-one marked `127.0.1.1`
  alias, per-site client DB credentials by actually logging in with no inline
  credentials, deploy-key pairs for repository sites (including that the
  public half re-derives from the private one), the slow query log
  end-to-end (the variables alone read ON even on a host hit by the
  silent-off bug fixed in 0.13.0; with a threshold of at most 5 s a marker
  query must actually land in the log), and the berth account's
  console-password posture in both directions.

## [0.13.0] — 2026-07-24

### Added

- **Declarative static hostname** — opt-in `system.hostname`: sets the
  hostname via `hostnamectl` and maintains a berth-marked `127.0.1.1` alias
  line in `/etc/hosts` (Debian convention, so sudo resolves the name without
  DNS). Empty = berth never touches the hostname. Available in `berth init`.
- **Per-site DB client credentials** — the database step now seeds the site
  user's `~/.my.cnf` (MariaDB) / `~/.pgpass` (PostgreSQL) alongside
  `shared/.env` — seed-once, never rewritten — so `mariadb`, `mariadb-dump`,
  `psql` and `pg_dump` run as the site user without pasting the password.
  Already-provisioned hosts gain the file on their next apply.
- **MariaDB slow query log** — opt-in `tuning.mariadb_slow_query_log` with
  `tuning.mariadb_long_query_time` (default 2 s), rendered into the managed
  tuning drop-in; logs to `/var/log/mysql/mariadb-slow.log`. berth creates
  `/var/log/mysql` itself (Debian 13 logs to the journal and no longer ships
  the directory; when it is missing at startup mariadbd silently disables
  slow logging for the whole process) — the distro logrotate already covers
  `/var/log/mysql/*.log`. Off by default with a byte-identical render, so
  existing hosts see no drift. Available in `berth init`.
- **`berth site key <server> [domain]`** — prints each site's git deploy
  public key (generated at provision time for sites with `repository:`),
  ready to paste into the repo host's deploy-key settings. Read-only.

## [0.12.0] — 2026-07-24

### Added

- **PHP-FPM tuning** — new `tuning.php_*` knobs rendered into one managed,
  FPM-only drop-in (#36): `php_memory_limit` (default `256M`),
  `php_upload_max` (default `32M` — the max single-file upload;
  `post_max_size` and nginx `client_max_body_size` are derived slightly
  larger so a file of exactly that size actually uploads),
  `php_max_execution_time` (default `30`, capped at 300 s — long work belongs
  in queue workers) and `php_max_input_vars` (default `1000`), plus an
  unconditional `expose_php = Off`. The CLI SAPI keeps Debian's stock
  unlimited values, so queue workers and artisan runs are unaffected.
- **Declarative system timezone** — opt-in `system.timezone` (#39): empty
  means berth never touches (or probes) the zone; setting it runs
  `timedatectl set-timezone` and restarts cron — whose schedule is
  wall-clock-sensitive — installing cron first if the image lacks it, and
  reverting the zone automatically if the cron restart fails so re-runs
  retry. Available in the `berth init` wizard.
- **Live-harness coverage** for the new knobs (#38, #39): the integration
  suite now asserts the effective FPM values via `php-fpm -i`, the derived
  nginx body cap in every vhost, and the system timezone.

### Changed

- **berth no longer forces UTC.** The `base` step used to run
  `timedatectl set-timezone UTC` unconditionally on every apply (a v1
  leftover its own checks never verified). The timezone is now owned solely
  by `system.timezone`: fresh provisions keep the image's zone unless the
  knob is set. To keep the old behavior, set `system: { timezone: UTC }`
  explicitly (#39).

### Fixed

- Host-key verification errors and the TOFU prompt now name the presented
  key type (e.g. `ecdsa-sha2-nistp256`), and both `ssh.fingerprint` recipes
  (README and `examples/`) scan **all** key types instead of hardcoding
  ed25519 — a pin taken from the wrong `ssh-keyscan` line used to produce a
  confusing false mismatch against a genuine server (#37).

# Changelog

Notable changes to berth. Older releases are documented on the
[GitHub Releases](https://github.com/robsonek/berth/releases) page.

## [Unreleased]

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

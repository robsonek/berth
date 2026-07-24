# Changelog

Notable changes to berth. Older releases are documented on the
[GitHub Releases](https://github.com/robsonek/berth/releases) page.

## [Unreleased]

### Added

- **Break-glass console access** — opt-in `system.break_glass`: gives the
  `berth` account a generated password (stored locally in
  `.berth/<name>.secrets.json`) so the provider's console/VNC works when SSH
  is down; without it every berth-managed account is locked and only rescue
  mode remains. sshd keeps `PasswordAuthentication no`, so no network login
  path opens; the berth account has full sudo, so treat the cached password
  as a root credential. Both directions reconcile: turning the knob off locks
  the password again; an existing usable password is reused, never rotated.
  Available in `berth init`.
- **Integration coverage for the v0.13 features and break-glass** — the live
  suite now asserts the static hostname + the exactly-one marked `127.0.1.1`
  alias, per-site client DB credentials by actually logging in with no inline
  credentials, deploy-key presence for repository sites, the slow query log
  end-to-end (including a marker query landing in the log — the variables
  alone read ON even on a host hit by the silent-off bug fixed in 0.13.0),
  and the berth account's console-password posture in both directions.

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

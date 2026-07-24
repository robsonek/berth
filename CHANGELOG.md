# Changelog

Notable changes to berth. Older releases are documented on the
[GitHub Releases](https://github.com/robsonek/berth/releases) page.

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

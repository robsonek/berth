# feat: ops quick-wins — hostname, DB client credentials, slow query log, `site key`

Four small operational features in one iteration, each reusing an existing
berth pattern 1:1. All opt-in or additive; no defaults change and existing
hosts see no drift.

## What's included

### 1. `system.hostname` (opt-in)
- The `system` step sets the static hostname (`hostnamectl set-hostname`) and
  maintains exactly one berth-marked `127.0.1.1 <fqdn> <short> # managed by
  berth` alias line in `/etc/hosts` (Debian convention, so `sudo` resolves the
  name without DNS).
- **Deliberate deviation from the unmanaged-file guard:** a foreign
  `127.0.1.1` line is replaced **without** `--force`. That address exists
  solely to alias the local hostname, so once the operator declares
  `system.hostname` the image's old alias is stale by definition. Convergence
  requires the marked line exactly once AND no foreign `127.0.1.1` line.
- No removal branch (the `system.timezone` precedent): clearing the knob stops
  managing; the marked line stays (it still names the host).
- Validated as a hostname of ≤64 chars (kernel `HOST_NAME_MAX`); collected by
  `berth init`.

### 2. Per-site DB client credentials (`~/.my.cnf` / `~/.pgpass`)
- Two new `Engine` methods (`ClientAuthFileName`, `ClientAuthFile`) render the
  file; the `database` step seeds it right after `EnsureUser`, so the
  credential it holds is live. `mariadb`, `mariadb-dump`, `psql` and `pg_dump`
  now work as the site user without pasting the password (the deployer's
  `db:backup` relies on this).
- Semantics mirror `shared/.env` exactly: **seed-if-absent** (password is
  reused, never rotated; an operator-customized file is never rewritten),
  `0600` owned by the site user, no managed marker. `Check` adds an
  existence-only probe (exit-code only — Check stays secret-free), so a crash
  between `EnsureUser` and the seed heals, and already-provisioned hosts gain
  the file on their next apply.
- MariaDB: credential under `[client]`, database preselection under `[mysql]`
  only (`mariadb-dump` rejects a `database` option in `[client]`). Postgres:
  one full-wildcard `.pgpass` line (libpq requires 0600 — exactly what berth
  writes).

### 3. MariaDB slow query log (opt-in)
- `tuning.mariadb_slow_query_log: true` + `tuning.mariadb_long_query_time`
  (default 2 s) render into the managed `99-berth.cnf` drop-in; log at
  `/var/log/mysql/mariadb-slow.log`, a path the distro logrotate already
  rotates.
- The block is conditional, so the default (off) render is **byte-identical**
  to the previous template output — existing hosts see no drift and no MariaDB
  restart (verified: the base golden is unchanged in this diff).
- Setting the threshold without enabling the log is rejected at validation (a
  silently-ignored knob would be a config lie). Collected by `berth init`.

### 4. `berth site key <server> [domain]`
- The accounts step has always generated a per-site ed25519 deploy key for
  sites with `repository:`, but nothing surfaced the public half. This
  read-only command prints each selected site's key ready to paste into the
  repo host's deploy-key settings. A site without a repository is reported
  (not silently skipped); a missing key file points at provisioning first.

## Codex review (pre-PR), all three findings verified and fixed

- **HIGH** — `accounts.Check` never probed deploy keys, so adding
  `repository:` to an already-provisioned site never generated one (Apply is
  the only path calling `ensureDeployKey`), making `site key`'s "run provision
  first" advice loop forever. Check now probes the exact private-key-existence
  condition Apply gates on.
- **MEDIUM** — hosts-alias convergence accepted a stale foreign `127.0.1.1`
  line sitting beside the marked one; it now requires exactly-one-marked and
  no-foreign, re-triggering the normalization.
- **MEDIUM** — the slow-log pairing rule could trap the wizard user: the
  violation surfaced inside the site retry loop, which cannot edit server
  fields. `run()` now re-prompts `ServerAdvanced` itself.

## Testing

- Unit tests for every path: config validation, hostname Check/Apply (incl.
  foreign-alias takeover, duplicate marked lines, single-label hostnames,
  unset-never-probed), engine renderings, database seeding (fresh /
  never-rewrite / Check-heal / postgres), `printDeployKeys` (all-sites,
  domain filter, unknown domain, unprovisioned), wizard mapping + re-prompt.
- Golden templates regenerated; the pre-existing `mariadb_tuning.golden` is
  byte-identical (drift-neutrality proven), one new slow-log golden added.
- `gofmt` clean, `go vet ./...` clean, `go test -race ./...` green.
- Not yet live-validated on a real Debian 13 host — recommend the usual
  disposable-box provision (fresh run + all-Satisfied re-run + `site key`
  output + `mariadb` as the site user) before tagging a release.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

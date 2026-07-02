# berth

> Prepare a fresh Debian 13 server for your Laravel app — ready for Deployer PHP.

**berth** is a command-line tool that provisions a freshly installed Debian 13
(Trixie) VPS into a production-ready web server for Laravel applications. It
connects over SSH and applies an idempotent pipeline (nginx, PHP-FPM, MariaDB,
Valkey, Supervisor, firewall, TLS, hardening), leaving the server ready for a
separate deployer ([Deployer PHP](https://deployer.org)) to ship code.

A *berth* is the prepared place where a vessel docks: berth readies the server,
then the deployer brings the code alongside.

## Install

Prebuilt binaries are published for Linux, macOS, and Windows (amd64/arm64) on
the [Releases](https://github.com/robsonek/berth/releases) page. No runtime is
required. Download the archive that matches your OS and architecture, extract
the `berth` binary, and put it on your `PATH`.

```bash
# example (Linux amd64) — replace VERSION with the release you downloaded
tar -xzf berth_VERSION_linux_amd64.tar.gz
chmod +x berth && sudo mv berth /usr/local/bin/
berth --version
```

On Windows, download the `.zip` archive for your architecture, extract
`berth.exe`, and add its location to your `PATH`.

## Usage

```bash
berth init                            # interactive wizard → servers/<name>.yml
berth provision servers/<name>.yml    # provision the server (idempotent)
berth provision servers/<name>.yml --dry-run   # preview changes only
```

## Highlights

- **Single, dependency-free binary** for Linux, macOS, and Windows — no runtime
  to install on your machine or the server (beyond SSH).
- **Idempotent** — safe to re-run; it only fills in what is missing.
- **Declarative** — a server is described by a version-controllable, secret-free
  config file.
- **Safe by default** — anti-lockout SSH hardening, automatic security updates,
  a tuned fail2ban jail, HSTS, a least-privilege deploy account, secret
  redaction, and explicit host-key verification.

## How it works

`berth init` walks you through an interactive wizard and writes a per-server
config. `berth provision <server>` then connects over SSH and brings the host to
the desired state through an ordered pipeline of idempotent steps. Re-running is
always safe; `--dry-run` shows what would change.

## Configuration reference

A server is one YAML file in `servers/<name>.yml`. `berth init` can generate
**any** of the configs in this README interactively — the advanced sections
(fail2ban, tuning, swap/sysctl, Cloudflare-only lockdown, and backups, plus
per-site queue/daemons and scheduler/Cloudflare/backups overrides) sit behind
optional prompts, so the common path stays short — or you can write the file by
hand. Ready-to-copy
starting points live in [`examples/`](examples/) — e.g.
`cp examples/minimal.yml servers/myserver.yml`. Every field, with its default
and accepted values:

```yaml
host: 203.0.113.10             # required — server IP or DNS name

ssh:
  user: root                   # default root — the login user berth connects as
  port: 22                     # default 22
  key: ~/.ssh/id_ed25519       # path to your private SSH key
  fingerprint: ""              # optional host-key pin "SHA256:…"; empty = trust
                               # on first connect (TOFU, confirmed interactively).
                               # Pin it to defeat MITM — get the value with:
                               #   ssh-keyscan -t ed25519 HOST | ssh-keygen -lf - | awk '{print $2}'

php:
  version: "8.5"               # 8.2 | 8.3 | 8.4 | 8.5
  source: auto                 # auto | sury | debian  (Debian ships 8.4; Surý → 8.5)

nginx:
  source: debian               # debian | nginx  (nginx.org mainline; needed for HTTP/3)

database:
  engine: mariadb              # mariadb | postgres   (server-wide)
  source: debian               # debian | mariadb (MariaDB) | pgdg (PostgreSQL)
  # name / user: legacy single-site only — multi-site sites carry their own block

valkey: false                  # install Valkey as the cache/session/queue backend
                               # (multi-site is capped at 16 sites — one logical DB each)
queue: false                   # server-wide default: a queue:work worker on every site
scheduler: true                # install the Laravel scheduler cron (per site)
cloudflare_only: false         # opt-in: refuse non-Cloudflare requests (per site)

fail2ban:                      # optional — omit the block to use these defaults
  bantime: 1h
  findtime: 10m
  maxretry: 5

tuning:                        # optional — omit any field to keep its default
  valkey_maxmemory: 256mb
  valkey_maxmemory_policy: allkeys-lru   # any Valkey eviction policy
  mariadb_innodb_buffer_pool: 256M

system:                        # optional host-level OS provisioning — both default off
  swap: 2G                     # default off when absent; positive integer + M / G
                               # (e.g. 512M, 2G) → creates /swapfile + vm.swappiness=10
  sysctl: true                 # default false; writes a conservative web/DB sysctl drop-in

backups:                       # optional opt-in local backups — off by default
  enabled: true                # server-wide default (off unless set)
  retention_days: 7            # prune dumps older than N days (default 7; 1–3650)
  schedule: "30 3 * * *"       # 5-field cron, run as root (default 03:30 daily)

sites:                         # one or more
  - domain: app.example.com            # required
    deploy_path: /var/www/app          # required — absolute path
    user: app                          # optional — derived from the domain when
                                       # omitted (a lone site keeps the "deploy" user)
    repository: git@github.com:acme/app.git   # optional — SSH git URL only
    database: { name: app, user: app }        # per-site DB (required with 2+ sites)
    ssl: true
    ssl_mode: letsencrypt              # letsencrypt (default) | selfsigned
    ssl_email: admin@example.com       # required with letsencrypt
    http3: false                       # requires ssl: true + nginx.source: nginx
    scheduler: true                    # per-site override of the server default
    cloudflare_only: true              # per-site override of the server default
    backups: false                     # per-site override of the server default
                                       # (nil/absent = inherit backups.enabled)
    queue:                             # tune this site's worker (omit = server default)
      driver: work                     # work (default) | horizon
      processes: 4                     # numprocs
      connection: redis
      queue: default,emails
      tries: 3
      timeout: 90
      sleep: 3
      max_memory: 256                  # MB
    daemons:                           # arbitrary long-running Supervisor programs
      - { name: reverb, command: php artisan reverb:start, processes: 1 }
```

Generated passwords are cached in a gitignored `.berth/` directory (the secrets
file is mode 0600) and reused across runs — never rotated. The thematic sections
below explain each area in depth.

## Package sources

By default every component is installed from Debian 13's own repositories. Where
a newer version is wanted, a per-component `source` selects a trusted upstream
apt repository whose signing-key fingerprint is pinned in berth and scoped with
`signed-by`:

```yaml
php:
  version: "8.5"
  source: sury        # auto | sury | debian   (Debian ships 8.4; Surý provides 8.5)
nginx:
  source: nginx       # debian | nginx         (nginx.org mainline)
database:
  engine: mariadb     # mariadb | postgres
  source: mariadb     # mariadb engine: debian | mariadb (mariadb.org 12.3 LTS)
                      # postgres engine: debian | pgdg   (apt.postgresql.org / PGDG)
```

Each defaults to `debian`. `database.source` accepts `debian` or the chosen
engine's producer repo (`mariadb` for MariaDB, `pgdg` for PostgreSQL). An
upstream source aborts the run if the fetched key does not match the pinned
fingerprint.

## Performance

berth tunes the host for production Laravel out of the box:

- **OPcache** is configured for production (`opcache.validate_timestamps=0`, with
  sized memory / interned-strings / accelerated-files). FPM SAPI only, so
  long-running CLI workers never serve stale bytecode.
- **Valkey** (when `valkey: true`) is wired as the cache, session and queue
  backend in the seeded `.env`, each site isolated on its own Redis logical
  database. Without Valkey the app keeps the database driver. This wiring is
  written when berth first creates a site's `shared/.env`, so enable `valkey`
  before the initial provision (flipping it on later does not rewrite an
  existing `.env` — remove it or re-seed by hand).
- **HTTP/3 (QUIC)** is available per site with `http3: true` (requires `ssl` and
  `nginx.source: nginx`); berth also opens UDP/443.
- nginx serves fingerprinted Vite assets under `/build/assets/` with a one-year
  cache and gzip, and raises `client_max_body_size` for typical uploads.

### Service tuning (`tuning:`)

berth applies conservative, managed tuning drop-ins automatically:

- **Valkey** (when `valkey: true`) — a systemd drop-in sets `maxmemory` and
  `maxmemory-policy` so the cache evicts instead of returning OOM errors once
  full (Debian's default is `noeviction` with no `maxmemory`, so a full cache
  fails writes).
- **MariaDB** (when `database.engine: mariadb`) — a `mariadb.conf.d` drop-in
  sets `innodb_buffer_pool_size`.

Every value is overridable; omit a field to keep its default:

```yaml
tuning:
  valkey_maxmemory: 256mb              # default
  valkey_maxmemory_policy: allkeys-lru # default; any Valkey eviction policy
  mariadb_innodb_buffer_pool: 256M     # default
```

With one shared Valkey for cache, session and queue, `allkeys-lru` can evict
queued jobs under memory pressure; use `volatile-lru` to evict only keys that
carry a TTL.

### Deploy hook (required with OPcache)

Because `opcache.validate_timestamps=0`, new code is served only after PHP-FPM is
reloaded. berth does not deploy code, so after your deployer swaps the release
symlink it must reload FPM (and restart any running queue worker):

```php
// deploy.php (Deployer) — berth grants the site user exactly this reload, nothing more
after('deploy:publish', function () {
    run('sudo systemctl reload php{{php_version}}-fpm'); // clear OPcache -> serve new bytecode
});
// plus: php artisan queue:restart  (or horizon:terminate) so a running worker picks up the new code
```

## Security & hardening

Every provision hardens the host (in addition to the anti-lockout SSH drop-in,
which disables root login and password authentication only after verifying the
`berth` admin account can connect with a key and sudo):

- **Automatic security updates** — the APT periodic config is written so
  `unattended-upgrades` actually applies updates (the package alone is inert
  without it).
- **fail2ban** — a managed jail bans SSH brute-forcers (bound to your configured
  SSH port) and repeat offenders (`recidive`). Tunable, with safe defaults:

  ```yaml
  fail2ban:
    bantime: 1h       # ban duration
    findtime: 10m     # window failures are counted in
    maxretry: 5       # failures before a ban
  ```

- **TLS** — HTTPS sites with a real (Let's Encrypt) certificate send HSTS
  (`max-age` one year) and use a modern TLS profile (TLS 1.2/1.3, strong ciphers,
  session tickets off); self-signed sites deliberately omit HSTS.
- **Log rotation** — per-site PHP-FPM and Supervisor program (queue worker +
  daemon) logs are rotated so they never fill the disk.
- **Firewall** — `ufw` allows only SSH and 80/443 (plus UDP/443 with HTTP/3).

### Cloudflare origin lockdown (`cloudflare_only:`)

When a site sits behind Cloudflare's proxy, direct hits to the origin IP bypass
the edge entirely. Set `cloudflare_only: true` to lock the origin down to
Cloudflare's network. It is **opt-in** (default `false`), server-wide with a
per-site override:

```yaml
cloudflare_only: true          # server-wide default
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    ssl: true
    ssl_mode: selfsigned       # see the cert note below
    cloudflare_only: false     # per-site override of the server default
```

Enforcement is at the nginx layer: requests whose source IP is not in
Cloudflare's published edge ranges are dropped with a bare `444` (connection
closed, no response). berth also restores the real visitor IP from the
`CF-Connecting-IP` header (via `set_real_ip_from` / `real_ip_header`), so access
logs and fail2ban see the actual client rather than Cloudflare's edge.

**Certificate guidance:** pair a *proxied* `cloudflare_only` site with
`ssl_mode: selfsigned`. With the A record pointing at Cloudflare, the origin is
not publicly reachable on its own name, so a public CA cannot validate the
domain against the origin; berth rejects the pairing at validation. Use a
[Cloudflare Origin
Certificate](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/)
(or any self-signed cert) on the origin and set the Cloudflare SSL/TLS mode to
**Full** so the edge encrypts to the origin without validating its certificate
against a public CA.

`cloudflare_only` requires `ssl_mode: selfsigned` (or `ssl: false`) —
validation rejects Let's Encrypt because a proxied DNS record never points at
the origin.

## Scheduler, queue workers & daemons

berth installs Laravel's scheduler as a per-site cron running `php artisan
schedule:run` every minute as the site's own user. It is **on by default**; set
`scheduler: false` server-wide, or `scheduler: false` on an individual site, to
skip it (disabling it on a re-run removes the cron).

With `queue: true` berth installs a dormant Supervisor `queue:work` program per
site. Tune that worker — or replace it with **Horizon** — and add arbitrary
long-running processes, per site:

```yaml
queue: true                  # server-wide default: a queue:work worker on every site
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    queue:                   # tune this site's worker (omit to keep the default above)
      processes: 4           # numprocs
      connection: redis
      queue: default,emails
      tries: 3
      timeout: 90
      max_memory: 256        # MB
    # queue: horizon         # …or run Laravel Horizon instead of queue:work
    daemons:                 # arbitrary long-running programs (full command)
      - { name: reverb, command: php artisan reverb:start }
```

Every program is installed **dormant** (`autostart=false`) — your deployer starts
and restarts them; berth never runs them. `queue: horizon` emits an `artisan
horizon` program instead of `queue:work` (Horizon runs single-process and manages
its own workers, so the `queue:work` knobs don't apply; configure it in your app's
`config/horizon.php`, and note it needs the Redis/Valkey queue driver). Each site
user gets **narrow sudoers** to control only its own programs, and Supervisor is
installed whenever any site declares a worker or a daemon.

## Backups (opt-in, local)

```yaml
backups:
  enabled: true          # server-wide default (off unless set)
  retention_days: 7      # prune dumps older than N days (default 7)
  schedule: "30 3 * * *" # 5-field cron, run as root (default 03:30 daily)
sites:
  - domain: staging.example.com
    backups: false       # per-site override; nil/absent = inherit server default
```

When enabled, each site gets a managed root cron + `/usr/local/sbin/berth-backup-<pool>`
that writes, into `/var/backups/berth/<pool>/` (**`root:root`, mode 0700**):

- `<db>-<UTC-timestamp>.sql.gz` — passwordless engine dump (MariaDB socket-root / Postgres peer)
- `<pool>-files-<UTC-timestamp>.tar.gz` — a tar of the site's `shared/` (`.env` + `storage/`)

Old archives are pruned by age. Disabling backups (per site, or removing the site)
deletes the cron + script but **never** the existing archive files.

Backups are deliberately **root-owned** (directory and files): the dump cron runs as root,
and a root process must not create files in a directory a tenant can write to (a symlink
pre-planted at a predictable path would be a local-root privesc). Root ownership also means
a compromised *site* cannot read, tamper with, or delete its own backups. Restore is a root
operation (below).

**Restore** (run on the host as root):

```bash
# MariaDB
gunzip -c /var/backups/berth/<pool>/<db>-<ts>.sql.gz | mysql <db>
# PostgreSQL (plain-SQL dump — psql, not pg_restore)
gunzip -c /var/backups/berth/<pool>/<db>-<ts>.sql.gz | sudo -u postgres psql <db>
# Files
tar -xzf /var/backups/berth/<pool>/<pool>-files-<ts>.tar.gz -C <deploy_path>
```

The PostgreSQL dump carries ownership (`ALTER ... OWNER TO <approle>`), so the app
role and database must already exist before you restore for ownership to be
reestablished. For disaster recovery, re-run berth (it recreates the role/database)
before restoring.

**Limitations:** local only (no offsite copy) — backups are root-owned so they survive a
compromised *site*, but a lost *host* loses them; the DB dump and files tar are independent,
so a failed run may leave one without the other (match artifacts by UTC timestamp); the first
dump runs at the next scheduled time (provisioning never runs a backup itself).

## Multiple sites (isolated per domain)

List several `sites:` to host multiple domains on one server. Each site runs
under its **own dedicated OS user**, so a compromise of one site cannot read
another's files (its `deploy_path` is owned by that user, traversable only by
nginx; its PHP-FPM pool, queue worker and cron all run as that user), and each
site gets **its own database + user**:

```yaml
database:
  engine: postgres        # server-wide engine + source
  source: pgdg
sites:
  - domain: app-one.example.com
    deploy_path: /var/www/app-one
    user: app_one          # optional; derived from the domain when omitted
    database: { name: app_one, user: app_one }
    ssl: true
    ssl_email: admin@example.com
  - domain: app-two.example.com
    deploy_path: /var/www/app-two
    database: { name: app_two, user: app_two }
    ssl: true
    ssl_email: admin@example.com
```

A single-site config may keep the legacy top-level `database: { name, user }`
and the shared `deploy` user; with multiple sites each site needs its own
`database` block, and the OS users must be distinct.

Each TLS site uses Let's Encrypt by default; set `ssl_mode: selfsigned` on a site
to generate a self-signed certificate instead (no public DNS or `ssl_email`
needed — handy for staging or internal hosts).

## Beyond v1

`berth site:add` (incremental add) and package-manager distribution are planned
for later releases.

## License

[MIT](LICENSE) © 2026 robsonek

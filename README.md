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

### Deploy hook (required with OPcache)

Because `opcache.validate_timestamps=0`, new code is served only after PHP-FPM is
reloaded. berth does not deploy code, so after your deployer swaps the release
symlink it must reload FPM (and restart any running queue worker):

```php
// deploy.php (Deployer) — berth grants the site user exactly this reload, nothing more
after('deploy:publish', function () {
    run('sudo systemctl reload php{{php_version}}-fpm'); // clear OPcache -> serve new bytecode
});
// plus: php artisan queue:restart  (so a running worker picks up the new code)
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
- **Log rotation** — per-site PHP-FPM and queue-worker logs are rotated so they
  never fill the disk.
- **Firewall** — `ufw` allows only SSH and 80/443 (plus UDP/443 with HTTP/3).

## Scheduler & queue workers

berth installs Laravel's scheduler as a per-site cron running `php artisan
schedule:run` every minute as the site's own user. It is **on by default**; set
`scheduler: false` server-wide, or `scheduler: false` on an individual site, to
skip it (disabling it on a re-run removes the cron). With `queue: true` berth
also installs a dormant Supervisor `queue:work` program per site for your
deployer to start and restart.

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
for later releases. See the
[design specification](docs/design/2026-06-13-berth-design.md) for the full
scope.

## License

[MIT](LICENSE) © 2026 robsonek

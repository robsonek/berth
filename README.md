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
the [Releases](https://github.com/robsonek/berth/releases) page — notable
changes are summarized in [CHANGELOG.md](CHANGELOG.md). No runtime is
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
berth site key servers/<name>.yml [domain]     # print each site's git deploy public key
```

### Checking a fleet

`berth status` probes servers read-only and reports what is actually on them.
It never changes a server's configuration, data, packages, services or
certificates — repair is an explicit `berth provision <config>`.

```bash
berth status                      # every config in ./servers
berth status servers/prod.yml     # one host
berth status --drift              # add the full read-only Check sweep (slow)
berth status --offsite            # also query the offsite restic repository
berth status --timeout 5m         # per-host budget (default 1m, 10m with --drift)
berth status --json | jq '.hosts[] | select(any(.sites[]?; .cert.days_left < 30))'
```

`--drift` additionally runs the same validators provisioning runs. One of them,
`nginx -t`, opens the configured log files and can create a missing one. Beyond
that, status never changes a host's configuration, data, packages, service
state or certificates.

Host-key verification is strict: only a pinned `ssh.fingerprint` or an existing
`known_hosts` entry is accepted. There is no trust-on-first-use prompt, because
hosts are probed concurrently and a routine read-only command is the wrong
place to be asked to trust a new key.

The exit code reflects whether probing succeeded — an unreachable host, a
partial probe failure, or an aborted drift scan. It does **not** reflect
whether anything needs attention: an expiring certificate is data, so filter it
with `--json`.

One caveat: for PostgreSQL the service column reflects Debian's umbrella
`postgresql` unit, which can stay active while an individual cluster is down —
it is not a cluster health check.

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
always safe; `--dry-run` shows what would change. berth keeps per-unit reload
stamps under `/var/lib/berth/`, so a run interrupted between a config write and
the service reload heals on the next run.

## Configuration reference

A server is one YAML file in `servers/<name>.yml`. `berth init` can generate
**any** of the configs in this README interactively — the advanced sections
(fail2ban, tuning, swap/sysctl/timezone, Cloudflare-only lockdown, extra apt
repos/packages, and backups, plus per-site queue/daemons and
scheduler/Cloudflare/backups overrides) sit behind
optional prompts, so the common path stays short — or you can write the file by
hand. Ready-to-copy
starting points live in [`examples/`](examples/) — e.g.
`cp examples/minimal.yml servers/myserver.yml`. Every field, with its default
and accepted values:

```yaml
id: myserver-1a2b3c4d          # required — stable machine identity (see below)
host: 203.0.113.10             # required — server IP or DNS name

ssh:
  user: root                   # default root — the login user berth connects as
  port: 22                     # default 22
  key: ~/.ssh/id_ed25519       # path to your private SSH key
  fingerprint: ""              # optional host-key pin "SHA256:…"; empty = trust
                               # on first connect (TOFU, confirmed interactively).
                               # Pin it to defeat MITM — list ALL key types
                               # (add -p PORT when ssh.port is not 22; scan from
                               # a trusted network or use the provider console):
                               #   ssh-keyscan HOST | ssh-keygen -lf -
                               # and pin the type berth reports in its TOFU
                               # prompt / mismatch errors (e.g. ecdsa-sha2-nistp256).

php:
  version: "8.5"               # 8.2 | 8.3 | 8.4 | 8.5
  source: auto                 # auto | sury | debian  (Debian ships 8.4; Surý → 8.5)

nginx:
  source: debian               # debian | nginx  (nginx.org mainline; needed for HTTP/3)

database:
  engine: mariadb              # mariadb | postgres   (server-wide)
  source: debian               # debian | mariadb (MariaDB) | pgdg (PostgreSQL)

valkey: false                  # one Valkey instance per site (cache/session/queue)
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
  mariadb_slow_query_log: true # default off; log queries slower than the threshold
  mariadb_long_query_time: 2   # seconds (default 2); needs the slow log on
  mariadb_log_file_size: 1G    # innodb redo log, 4M-512G; omit = engine default (96M)
  mariadb_tmp_table_size: 128M # sets tmp_table_size AND max_heap_table_size; omit = engine default (16M)
  mariadb_max_connections: 256 # 10-100000; omit = engine default (151)
  mariadb_max_allowed_packet: 64M # max 1G; omit = engine default (16M)
  php_memory_limit: 256M
  php_upload_max: 32M          # max single-file upload; body caps derived
  php_max_execution_time: 30   # seconds, 1-300
  php_max_input_vars: 1000     # 1-1000000
  php_fpm_max_children: 16     # pm.max_children of every site pool, 4-10000 (default 10)

system:                        # optional host-level OS provisioning — all default off
  swap: 2G                     # default off when absent; positive integer + M / G
                               # (e.g. 512M, 2G) → creates /swapfile + vm.swappiness=10
  sysctl: true                 # default false; writes a conservative web/DB sysctl drop-in
  timezone: Europe/Warsaw      # default off when absent; sets the SYSTEM zone (logs,
                               # cron) via timedatectl and restarts cron — berth's cron
                               # jobs (e.g. the backups schedule) run in local time, so
                               # changing the zone shifts when they fire. PHP/Laravel
                               # keep their own timezone settings (date.timezone /
                               # app.timezone) — this field is about system logs.
  hostname: web-1.example.com  # default off when absent; sets the static hostname
                               # (hostnamectl) and keeps a 127.0.1.1 alias line in
                               # /etc/hosts so sudo resolves the name without DNS
  break_glass: true            # default off; give the berth account a console
                               # password (saved to ~/.berth/<name>.secrets.json) for
                               # provider console/VNC access when SSH is down —
                               # sshd keeps password logins disabled either way

backups:                       # optional opt-in local backups — off by default
  enabled: true                # server-wide default (off unless set)
  retention_days: 7            # prune dumps older than N days (default 7; 1–3650)
  schedule: "30 3 * * *"       # 5-field cron, run as root (default 03:30 daily)

apt:                           # optional extra third-party apt repos & packages
  repos:                       # (see "Extra apt repositories & packages" below)
    - name: signal-cli         # ^[a-z0-9][a-z0-9-]{0,31}$ — lands on the host as
                               # /etc/apt/sources.list.d/berth-<name>.list + keyring
      uri: https://packaging.gitlab.io/signal-cli    # https:// only
      suite: signalcli
      components: [main]       # optional, defaults to [main]
      key_url: https://packaging.gitlab.io/signal-cli/gpg.key   # https:// only
      fingerprint: 02BD5FB7BA4650D50ED69002797DFE3F4F80269B     # required — full
                               # 40-hex signing-key fingerprint, verified on fetch
  packages: [signal-cli-native, htop]   # extra packages — install-only, berth
                               # never uninstalls a name you remove from the list

sites:                         # one or more
  - domain: app.example.com            # required
    deploy_path: /var/www/app          # required — absolute path
    user: app                          # optional — derived from the domain when
                                       # omitted (pin it to choose the account name)
    repository: git@github.com:acme/app.git   # optional — SSH git URL only; berth
                                       # generates a per-site deploy key for it
                                       # (print it with `berth site key`)
    database: { name: app, user: app }        # per-site DB (required for every site)
    ssl: true
    ssl_mode: selfsigned               # letsencrypt (default) | selfsigned —
                                       # cloudflare_only requires selfsigned (or ssl: false)
    ssl_email: admin@example.com       # required with letsencrypt
    http3: false                       # requires ssl: true + nginx.source: nginx
    scheduler: true                    # per-site override of the server default
    cloudflare_only: true              # per-site override of the server default
    backups: false                     # per-site override of the server default
                                       # (nil/absent = inherit backups.enabled)
    queue:                             # tune this site's worker (omit = server default)
      driver: work                     # work (default) | horizon | none (opt out)
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

Generated passwords are cached in `~/.berth/` (the secrets file is mode 0600)
and reused across runs — never rotated. The `APP_KEY` backup covers
berth-seeded keys (`base64:` + 32 bytes); a live key in any other shape is
treated as operator-managed — left alone and simply not backed up — while a
malformed key already in the local cache makes berth refuse loudly rather
than propagate it. The thematic sections below explain each area in depth.

### Server identity (`id:`)

The local secret cache is keyed by `id` — a **required** field (`berth init`
has always generated one; a config predating this requirement keeps working
after you add the id it was implicitly using, i.e. one already recorded in a
tombstone, or a fresh one if the machine was only ever host-keyed). Two
*different* machines reachable through one hostname on different ports must
have *different* ids (or they would share database passwords, `APP_KEY`
backups and the break-glass console password), while one machine addressed by
several configs must use the *same* id in all of them — and, in this version,
the same current `host:port`. Rules:

- `id` is a stable, immutable machine identity, not a display name. Renaming
  it is refused: the host's tombstone records which id owns the cache, and a
  mismatch would orphan the old id's secrets (including the console-password
  ownership marker). Either restore the recorded id, or migrate deliberately
  by renaming `~/.berth/<old-id>.secrets.json` to `<new-id>.secrets.json` and
  updating the tombstone.
- Adding an `id` to an already-provisioned config migrates the cache file
  automatically and leaves a tombstone at the old host-keyed path, so any
  stale config still lacking the `id` fails loudly instead of silently
  regenerating (or disowning) secrets — add the same `id` there too.
- The cache records the endpoint it was bound to. A mismatch is a hard error:
  if it is a *different* server, give it its own `id`; if the endpoint really
  changed, update every config sharing the id first, then re-bind once with
  the narrow form `berth provision <config> --only identity --force`. Under
  `--only`, `--force` applies to the target step alone (the always-run steps
  ahead of it run unforced), so the narrow form authorizes exactly the
  re-bind and a forced run of any *other* step can never re-bind the cache as
  a side effect — while a bare `--force` (full run) would ALSO authorize
  overwriting unmanaged files in every other step. Endpoint metadata is an
  operator-error tripwire, not authentication — SSH host-key verification is
  unaffected and never bypassed.
- Downgrading berth below this version after an `id`/envelope exists is not
  supported (older binaries reject both the config key and the cache format).

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

### Changing `php.version` on a provisioned host

`php.version` is effectively immutable once sites are provisioned: the
per-site FPM sockets (`/run/php/berth-<pool>.sock`) are shared between PHP
versions, so an old master left running would fight the new one over them.
berth refuses loudly (in both the `accounts` and `php` steps, `--force`
included) while pools of another version remain. To migrate, in a maintenance
window: (1) inventory `/etc/php/<old>/fpm/pool.d/*.conf` — berth's pools carry
the exact first line `; managed by berth`; move anything else off that master
first; (2) `systemctl disable --now php<old>-fpm`; (3) remove only the
confirmed berth pool files; (4) re-run a full `berth provision`; (5) verify
only the new `php<ver>-fpm` holds the `/run/php/berth-*.sock` sockets.

Each defaults to `debian`. `database.source` accepts `debian` or the chosen
engine's producer repo (`mariadb` for MariaDB, `pgdg` for PostgreSQL). An
upstream source aborts the run if the fetched key does not match the pinned
fingerprint.

### Extra apt repositories & packages

Beyond the built-in upstreams (sury/nginx.org/MariaDB/PGDG), a server config
may declare extra third-party repositories and packages:

```yaml
apt:
  repos:
    - name: signal-cli
      uri: https://packaging.gitlab.io/signal-cli
      suite: signalcli
      components: [main]        # optional, defaults to [main]
      key_url: https://packaging.gitlab.io/signal-cli/gpg.key
      fingerprint: 02BD5FB7BA4650D50ED69002797DFE3F4F80269B
  packages: [signal-cli-native, htop]
```

Semantics:

- `fingerprint` (the full 40-hex signing-key fingerprint) is required — berth
  pins every repository key and refuses a bundle that does not contain
  exactly that key. `uri` and `key_url` must be `https://`.
- Repos are fully declarative: the source list lands at
  `/etc/apt/sources.list.d/berth-<name>.list` with a pinned keyring, and a
  repo REMOVED from the config is swept from the host (list + keyring) on the
  next run. A foreign file in the `berth-*` namespace is never touched.
- Packages are **install-only**: berth installs missing ones (after the
  declared repos are registered) but never uninstalls a package you remove
  from the list — uninstall manually with `apt-get remove`.
- Declare **concrete** package names, not virtual ones: convergence is probed
  with `dpkg -s <name>`, which never reports a virtual package as installed,
  so a virtual name would re-trigger installation on every run and the host
  would never report fully converged.
- Double-check names containing a dot: when no package matches the literal
  name, `apt-get install` falls back to treating it as a POSIX regex, so a
  typo'd dotted name (e.g. `python3.99`) can match — and install —
  unintended packages.
- Switching a built-in source back to stock (e.g. `nginx.source: nginx` →
  `debian`) now also removes the corresponding upstream repo. Installed
  packages KEEP their upstream versions — apt never auto-downgrades. To return
  to the Debian build: check `apt policy <pkg>`, then
  `apt-get install <pkg>=<debian-version>` (or remove and reinstall).

## Performance

berth tunes the host for production Laravel out of the box:

- **OPcache** is configured for production (`opcache.validate_timestamps=0`, with
  sized memory / interned-strings / accelerated-files). FPM SAPI only, so
  long-running CLI workers never serve stale bytecode.
- **Valkey (Redis-compatible), one instance per site** — with `valkey: true`
  every site gets its own Valkey instance running as that site's OS user,
  reachable only through a unix socket in a directory owned by that user
  (no TCP listener at all). Tenant isolation is enforced by the OS, not by
  passwords or key prefixes; `artisan cache:clear` flushes only that site's
  own cache DB. The `tuning.valkey_maxmemory` / `tuning.valkey_maxmemory_policy`
  knobs apply per instance. Valkey is wired as the cache, session and queue
  backend when berth first seeds a site's `shared/.env` (without Valkey the
  app keeps the database driver), so enable `valkey` before the initial
  provision — the `REDIS_*` lines are seed-time-only: flipping `valkey:` on
  an already-seeded host never rewrites the existing `.env`; update the
  site's `.env` by hand, or remove it so the next run re-seeds it (cached
  secrets are reused). Flipping `valkey: false` on a provisioned host makes the
  next full run (or `--only valkey`) stop and remove every berth-managed
  instance — **first** move each application's `.env` cache/session/queue off
  the Valkey socket, or the app breaks the moment the instance goes away.
  Instance data under `/var/lib/berth-valkey/` is kept; the package and the
  disabled stock service are left alone. Note `--only <other-step>` runs do
  not perform this cleanup.
- **HTTP/3 (QUIC)** is available per site with `http3: true` (requires `ssl` and
  `nginx.source: nginx`); berth also opens UDP/443.
- nginx serves fingerprinted Vite assets under `/build/assets/` with a one-year
  cache and gzip, and raises `client_max_body_size` for typical uploads.

### Service tuning (`tuning:`)

berth applies conservative, managed tuning automatically:

- **Valkey** (when `valkey: true`) — every per-site instance is started with
  `maxmemory` and `maxmemory-policy` so its cache evicts instead of returning
  OOM errors once full (Valkey's default is `noeviction` with no `maxmemory`,
  so a full cache fails writes). The limits apply to each instance separately.
- **MariaDB** (when `database.engine: mariadb`) — a `mariadb.conf.d` drop-in
  sets `innodb_buffer_pool_size`, and opt-in `mariadb_slow_query_log` logs
  queries slower than `mariadb_long_query_time` seconds (default 2) to
  `/var/log/mysql/mariadb-slow.log`. berth creates `/var/log/mysql` itself
  (Debian 13 logs to the journal and no longer ships it — a missing directory
  would silently disable slow logging for the whole server process); the
  distro logrotate already rotates `/var/log/mysql/*.log`. Four optional
  parity knobs — `mariadb_log_file_size` (innodb redo log),
  `mariadb_tmp_table_size` (sets `tmp_table_size` and `max_heap_table_size`
  together — the in-memory temp-table limit is the minimum of the two),
  `mariadb_max_connections`, and `mariadb_max_allowed_packet` (max 1G —
  MariaDB's hard ceiling) — render into the same drop-in only when set;
  omitted knobs leave the engine's stock defaults in force.
- **PHP-FPM** (always) — a managed FPM-only `conf.d` drop-in sets
  `memory_limit`, upload sizing, `max_execution_time`, `max_input_vars` and
  `expose_php = Off`. The CLI SAPI keeps Debian's stock unlimited values, so
  queue workers and artisan runs are unaffected. `php_upload_max` is the max
  single-file size: `post_max_size` and nginx `client_max_body_size` are
  derived slightly larger (multipart headroom), so a file of exactly that size
  uploads — note all files in one request share the derived total.
  `php_fpm_max_children` raises `pm.max_children` of every site's pool
  (default 10); the remaining `pm` settings stay fixed (`dynamic`, spares
  2/1/4), which is why the knob is floored at 4.

Every value is overridable; omit a field to keep its default:

```yaml
tuning:
  valkey_maxmemory: 256mb              # default
  valkey_maxmemory_policy: allkeys-lru # default; any Valkey eviction policy
  mariadb_innodb_buffer_pool: 256M     # default
  mariadb_slow_query_log: false        # default; opt-in slow query log
  mariadb_long_query_time: 2           # default; seconds, needs the slow log on
  mariadb_log_file_size: 1G            # 4M-512G; omit = engine default (96M)
  mariadb_tmp_table_size: 128M         # omit = engine default (16M)
  mariadb_max_connections: 256         # omit = engine default (151); 10-100000
  mariadb_max_allowed_packet: 64M      # omit = engine default (16M); max 1G
  php_memory_limit: 256M               # default
  php_upload_max: 32M                  # default; max single-file upload; body caps derived
  php_max_execution_time: 30           # default; seconds, 1-300
  php_max_input_vars: 1000             # default; 1-1000000
  php_fpm_max_children: 16             # default 10; 4-10000
```

Each site's Valkey instance serves its cache, session and queue together, so
`allkeys-lru` can evict queued jobs under memory pressure; use `volatile-lru`
to evict only keys that carry a TTL.

`php_max_execution_time` is capped at 300 s — berth's opinionated bound; work
that runs longer belongs in queue workers, not web requests.

### Deploy hook (required with OPcache)

Because `opcache.validate_timestamps=0`, new code is served only after PHP-FPM is
reloaded. berth does not deploy code, so after your deployer swaps the release
symlink it must reload FPM (and restart any running queue worker):

```php
// deploy.php (Deployer) — berth grants the site user exactly this reload, nothing more.
// The command is version-stable: the PHP version lives inside the berth-managed
// wrapper, so a future php version migration never touches your deploy pipeline.
// Note: it reloads the shared per-version FPM master, gracefully recycling every
// site's pool on the host (FPM has no per-pool reload).
after('deploy:publish', function () {
    run('sudo /bin/sh /usr/local/sbin/berth-reload-fpm'); // clear OPcache -> serve new bytecode
});
// plus: php artisan queue:restart  (or horizon:terminate) so a running worker picks up the new code
```

## Security & hardening

Every provision hardens the host (in addition to the anti-lockout SSH drop-in,
which disables root login, password and keyboard-interactive authentication
only after verifying the `berth` admin account can connect with a key and
sudo — and berth verifies via `sshd -T` that these global directives win in
the configuration sshd loads, so an image drop-in such as cloud-init's cannot
silently re-enable password logins; operator-added `Match` blocks are out of
scope):

- **Automatic security updates** — the APT periodic config is written so
  `unattended-upgrades` actually applies updates (the package alone is inert
  without it).
- **fail2ban** — a managed jail bans SSH brute-forcers (bound to your configured
  SSH port) and repeat offenders (`recidive`). berth writes it as
  `/etc/fail2ban/jail.d/99-berth.conf`, leaving `jail.local` — which loads
  after `jail.d/` and keeps final say — free for your own overrides. Tunable,
  with safe defaults:

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
- **Break-glass console access** (`system.break_glass`, opt-in) — every berth
  account is created with a locked password, which makes the provider's
  console/VNC useless when SSH is down (only rescue mode remains). Setting
  `break_glass: true` gives the `berth` account a generated password, stored
  locally in `~/.berth/<name>.secrets.json` (0600) so you can type
  it at the console. It never opens a network path — sshd keeps
  `PasswordAuthentication no` — but note the `berth` account has full sudo, so
  treat the cached password as a root credential. Setting the knob back to
  `false` locks the password berth set on the next provision (ownership is
  tracked via the cache entry, and locking removes the cached plaintext); a
  password berth did not set is left alone, and an existing usable password
  is reused, never rotated.

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
    # queue: none            # …or opt just this site out of the server-wide worker
    daemons:                 # arbitrary long-running programs (full command)
      - { name: reverb, command: php artisan reverb:start }
```

Every program is installed **dormant** (`autostart=false`) — your deployer starts
and restarts them; berth never runs them. `queue: horizon` emits an `artisan
horizon` program instead of `queue:work` (Horizon runs single-process and manages
its own workers, so the `queue:work` knobs don't apply; configure it in your app's
`config/horizon.php`, and note it needs the Redis/Valkey queue driver).
`queue: none` opts a single site out of the server-wide worker — the only
per-site off switch under `queue: true` (a shorthand like `horizon`; combining
it with the other worker knobs is rejected). Each site
user gets **narrow sudoers** to control only its own programs, and Supervisor is
installed whenever any site declares a worker or a daemon.

## Backups (opt-in)

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
- `<pool>-meta-<UTC-timestamp>.manifest` — a per-pair sidecar written by the
  same run as its two archives, recording the berth version, engine,
  database/user names, site user and `deploy_path` **as of that run**.
- `manifest` — written by `berth provision` itself (not the cron): the same
  facts for the site's **current** configuration, so a copy of the directory
  stays self-describing. Archives created before a config change may predate
  what it records — match dump/tar pairs by their UTC timestamp and trust
  the pair's own sidecar over the directory manifest.

Old archives (and their sidecars) are pruned by age; the prune matches only
berth's own artifact names, so an operator-parked file in the directory is
never deleted. Disabling backups (per site, or removing the site)
deletes the cron + script + manifest but **never** the existing archive files.

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

**Full-restore order (disaster recovery — host AND workstation lost):**

0. Recover the backup artifacts from offsite (skip if `/var/backups/berth`
   survived): on any machine with restic, export `RESTIC_REPOSITORY`,
   `RESTIC_PASSWORD` (and `AWS_*` for s3) from your local
   `~/.berth/<id>.secrets.json` and the config, then
   `restic restore latest --target /` — snapshots store absolute paths,
   recreating `/var/backups/berth` verbatim. For an `sftp` repository, use
   your **own** ssh access to the target (a plain `sftp:user@host:path`
   repository string with your default ssh setup) — berth's dedicated key
   and pinned command died with the host.

(1) run `berth provision servers/<name>.yml` — it rebuilds the stack and, with
no local cache, seeds `shared/.env` with FRESH secrets; (2) restore the files
tar (`tar -xzf <pool>-files-<ts>.tar.gz -C <deploy_path>` as root) — this
brings back the ORIGINAL `.env`; (3) pipe the SQL dump back in as above;
(4) run `berth provision` again — it detects that the restored `.env` disagrees
with the fresh cache and reconciles: the database role's password is reset to
the `.env` value and the local cache (including the `APP_KEY` backup) is
re-synced from the file the app actually reads. Without step (4) the app
cannot reach its database and the cache would poison any future re-seed with
a wrong `APP_KEY`. When `~/.berth/` survived, the same sequence simply makes
step (4) report everything satisfied. Each backup directory carries a
`manifest` file recording the engine, database/user names, site user and
`deploy_path` as of the last provision run — a useful starting point, but it
describes the current configuration, not necessarily the one an older archive
was made under; match the pair by its UTC timestamp and, for archives
predating a config change, trust the pair's own `<pool>-meta-<ts>.manifest`
sidecar over the directory manifest.

**Limitations:** local by default (offsite is the opt-in below) — backups are root-owned
so they survive a compromised *site*, but without `backups.offsite` a lost *host* loses
them; the DB dump and files tar are independent, so a failed run may leave one without the
other (match artifacts by UTC timestamp); the first dump runs at the next scheduled time
(provisioning never runs a backup itself).

### Offsite backups (restic)

`backups.offsite` ships the local artifacts to an encrypted restic
repository nightly (one snapshot of the whole `/var/backups/berth`,
04:15 by default — after the local backups), pruned by the `keep`
policy. Two backends: `s3` (any S3-compatible endpoint) and `sftp`
(a dedicated root ed25519 key; pin the target with `host_key` from
`ssh-keyscan`). The YAML stays secret-free: S3 credentials enter the
local cache once via `berth secret set <server.yml>
offsite_s3_access_key` / `offsite_s3_secret_key`, and the repository
password is generated automatically into the same cache.

To keep several copies **per day** offsite, set a sub-daily
`offsite.schedule` and a matching intra-day retention knob — `keep.daily`
alone collapses each day to its last snapshot:

    backups:
      offsite:
        schedule: "0 */6 * * *"   # push every 6 hours
        keep:
          last: 12                # keep the 12 most recent snapshots
          hourly: 48              # and one per hour for the last 48 hours that have a backup

`keep.last` and `keep.hourly` are additive to `daily`/`weekly`/`monthly`
(restic keeps a snapshot if any policy wants it) and default to off.
`hourly: N` counts the last N hours that contain a snapshot — not a fixed
N-hour window — so gaps in the schedule stretch the retained span.

**The restic password is the backup.** It lives in
`~/.berth/<id>.secrets.json` on the operator machine and in root-owned
`/etc/berth/offsite.env` on the host. Keep a third copy outside both
machines (password manager): losing it means losing every offsite
snapshot, by encryption design. Changing the offsite target later
initializes a NEW repository; snapshots on the old target remain yours
to keep or delete. Removing `backups.offsite` sweeps the script, cron,
env file and host-key pin from the host, but the dedicated sftp keypair
is kept — remove `/root/.ssh/berth_offsite*` manually if unwanted.

## Multiple sites (isolated per domain)

List several `sites:` to host multiple domains on one server. Each site runs
under its **own dedicated OS user**, so a compromise of one site cannot read
another's files (its `deploy_path` is owned by that user, traversable only by
nginx; its PHP-FPM pool, queue worker and cron all run as that user), and each
site gets **its own database + user**. Alongside the seeded `shared/.env`,
berth also seeds the site user's DB client-credentials file — `~/.my.cnf`
(MariaDB) or `~/.pgpass` (PostgreSQL), `0600`, written once and never
rewritten (single exception: when a provision run resets the database
password to a restored `.env`'s value and the file provably still holds
berth's previous credential, it is refreshed to match; an
operator-customized file is never touched) — so `mariadb`, `mariadb-dump`,
`psql` and `pg_dump` run as that user without pasting the password:

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

Every site carries its own `database: {name, user}` block, and the OS users
must be distinct. A site without `user:` always runs as its derived
`b_<slug>_<hash>` account, no matter how many sites the config lists.

Each TLS site uses Let's Encrypt by default; set `ssl_mode: selfsigned` on a site
to generate a self-signed certificate instead (no public DNS or `ssl_email`
needed — handy for staging or internal hosts). Renewals are automatic: berth
enables `certbot.timer` and installs a renewal deploy hook that validates and
reloads nginx after every successful renewal, so the renewed certificate is
actually served (not just written to disk). Provisioning with `--ssl-staging`
issues certificates against the Let's Encrypt staging CA; a later run without
the flag detects the staging certificate and automatically re-issues it
against production.

### Removing a site

Delete the site's entry from the YAML and re-run `berth provision`. The next
run removes everything that *serves* the site: its nginx vhost and enabled
symlink, its PHP-FPM pool (for the configured PHP version), its scheduler
cron, its Supervisor programs, its backup script + cron, and — while
`valkey: true` — its Valkey instance. Only files carrying the berth managed
marker are removed; anything foreign is left alone. nginx and PHP-FPM are
then reloaded. `--dry-run` previews every planned removal.

> **Note — site identity never depends on the site count.** A site's OS user
> is `sites[].user` when set, otherwise derived from the domain — growing or
> shrinking the config does not re-own anything. berth also refuses to adopt
> an existing tree silently: when `deploy_path`, `shared/` or `shared/tmp`
> is owned by a different user than the configured one, provisioning fails
> loudly. To keep the existing identity, pin `sites[].user` to the current
> owner (when that owner is a valid, non-reserved site user — otherwise
> migrate). To actually move a site to a new user: create the target account
> first (`useradd -m -s /bin/bash <user>` — the derived account does not
> exist yet at that point), stop the site's queue/daemon processes,
> `chown -R` the deploy tree, then move the deploy key pair and re-own it —
> `install -d -o <user> -g <user> -m 700 /home/<user>/.ssh`, move
> `id_ed25519` and `id_ed25519.pub` there and `chown <user>:<user>` both (a
> bare `mv` keeps the OLD owner, so the new user could not read its 0600
> key while every check stays green). Then run a FULL `berth provision`
> (not `--only`) and finally remove the old account, its sudoers file and
> its home once everything serves.

TLS artifacts are swept automatically: the next provision run deletes the
removed site's Let's Encrypt lineage (`certbot delete`, so the failing
renewal stops cleanly), its ACME webroot and any self-signed material
under `/etc/ssl/berth/`. Only lineages berth issued are touched — a
renewal config whose parameters do not point at berth's ACME webroot
namespace is left alone, as is any lineage still serving a configured
domain. Edges worth knowing: a site merely switched to `ssl: false`
(still in the config) is NOT swept — its certificate keeps renewing
silently and survives a later flip back; re-adding a REMOVED domain
re-issues from scratch, so mind the Let's Encrypt rate limit
(5 certificates per domain set per 168 h) when removing and re-adding a
site repeatedly; and if certbot itself was uninstalled, the lineage and
its webroot are kept with a warning until certbot returns or you remove
the lineage manually.

**Data and access are deliberately kept** — berth never deletes data
implicitly. Remove manually if you want them gone:

- database + DB user: `DROP DATABASE`/`DROP USER` (MariaDB) or
  `dropdb`/`dropuser` (PostgreSQL)
- the OS account (its home also holds the git deploy key) and its sudoers
  entry: `deluser --remove-home <user>`, `rm /etc/sudoers.d/berth-<user>`
- the application tree: `rm -rf <deploy_path>`
- Valkey state (`/var/lib/berth-valkey/<pool>`) and backup archives
  (`/var/backups/berth/<pool>/`) are likewise retained

Two related notes: the Valkey step always runs — while `valkey: true` a
removed site's instance is swept as an orphan, and `valkey: false` stops and
removes every berth-managed instance (data under `/var/lib/berth-valkey/` is
kept either way); and after changing `php.version`, the previous version's
FPM unit and pool files are no longer managed — clean them up manually.

## Beyond v1

`berth site:add` (incremental add) and package-manager distribution are planned
for later releases.

## License

[MIT](LICENSE) © 2026 robsonek

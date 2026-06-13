# berth — Design Specification

> Status: **Draft (design) · Revision 5** (three review rounds + package-source strategy + interface/progress UX) · Date: 2026-06-13 · License: MIT

## 1. Overview

**berth** is a command-line tool that turns a freshly installed **Debian 13
(Trixie)** VPS into a production-ready web server for **Laravel** applications,
leaving the server in a state where a separate deployer (**Deployer PHP**) only
needs to ship the code.

berth runs on the operator's machine and connects to the target server over
**SSH** (the same remote-provisioning model used by Laravel Forge and Ploi). It
applies an ordered pipeline of **idempotent steps**: each step first checks
whether the desired state already holds and only acts if it does not, so a run
can be safely repeated.

It is distributed as a **single, self-contained binary** for Linux, macOS, and
Windows. No runtime (PHP, Python, etc.) is required on the operator's machine or
on the target server beyond SSH access.

The name fits the model: a *berth* is the prepared place where a vessel docks —
berth readies the server, then the deployer brings the code alongside.

### Goals

- Take a clean Debian 13 host and produce a server ready for Deployer PHP.
- Be **idempotent**: re-running is safe and only fills in what is missing.
- Be **declarative**: a server is described by a version-controllable config file.
- Prefer **Debian's own repositories**, with a pluggable package-source mechanism
  ready for trusted upstream repos when a newer version is required.
- Be **safe**: never lock the operator out of SSH; least-privilege deploy account;
  never leak or commit secrets; never build remote commands from unvalidated input.
- Ship as a **dependency-free binary** for all major desktop platforms.

### Non-goals

- **Deploying application code** — that is the deployer's job (Deployer PHP).
- **Managing application-level secrets** such as `APP_KEY` — owned by the deployer.
- **Operating systems other than Debian 13** in v1.
- **A hosted control panel / web UI** — berth is a local CLI.

## 2. Technology stack & rationale

| Concern | Choice |
| --- | --- |
| Language | **Go** |
| CLI framework | **Cobra** |
| Config | **Viper** (YAML) |
| Interactive wizard | **charmbracelet/huh** |
| Live progress UI | **charmbracelet/bubbletea** + **lipgloss** (TTY-aware) |
| SSH | **golang.org/x/crypto/ssh** (file transfer via SCP/SFTP) |
| Templates | Go `text/template` embedded with `embed.FS` |
| Release | **GoReleaser** + GitHub Actions |

**Why Go.** The primary distribution requirement is that anyone can download a
binary for their own operating system — including **Windows** — and run it
without installing a language runtime. Go cross-compiles to every target from a
single CI runner, produces fully static binaries (CGO disabled), and has a
mature ecosystem for CLIs, SSH, and release automation.

**Alternatives considered.**

- **Laravel Zero (PHP)** — excellent CLI ergonomics, but producing a
  dependency-free binary for all platforms is fragile; the Windows target in
  particular is the least mature path. Rejected for the cross-platform
  distribution requirement.
- **Ansible** — purpose-built for provisioning with idempotency "for free", but
  it pushes the substantive logic into external playbooks and adds a runtime
  dependency. Rejected to keep all logic inside one self-contained tool.

## 3. Target end state — the "ready for Deployer PHP" contract

After a successful run, the server has:

- Two accounts (§6.3): a **`berth`** provisioning account (used only by berth
  over SSH) and a least-privilege **`deploy`** account used by Deployer PHP.
- The **`deploy_path`** (e.g. `/home/deploy/myapp`) **and `shared/`** directory,
  both owned by `deploy`, with a seeded **`shared/.env`**. berth creates these
  (before any secret is written); Deployer PHP creates `releases/` and the
  `current` symlink on the first deploy.
- `shared/.env` contains infrastructure credentials only (database, Valkey,
  `APP_ENV`, `APP_URL`). Deployer links this file into every release.
- A dedicated **ACME webroot** (`/var/www/berth-acme/<domain>`) used for TLS
  issuance, independent of the application's not-yet-existing `current/public`.
- When a site declares a `repository`: a generated **deploy key pair** (private
  key stays on the server under `deploy`; public key is printed to register on
  the Git host) and `known_hosts` for that Git host. Otherwise Git access is left
  to the deployer.
- **nginx** serving the site, document root at `{deploy_path}/current/public`,
  validated with `nginx -t`.
- A Supervisor `queue:work` program installed **but dormant** (`autostart=false`)
  and a `schedule:run` cron entry **guarded** so it is inert until the first
  deploy creates `current/artisan`. Activating the worker after the first deploy
  is a documented handoff to Deployer.

## 4. Provisioned stack

### Package sources

By default every component is installed from **Debian 13's own repositories**. A
pluggable **package-source** mechanism abstracts this: a component is installed
either from Debian stock or from a **trusted upstream apt repository** added
securely — the signing key is fetched into `/usr/share/keyrings/`, its
**fingerprint is verified against a value pinned in berth**, and the source is
written with `signed-by=` so the key is trusted only for that repository.

In **v1 the only upstream implemented is Ondřej Surý's PHP repository**
(`packages.sury.org`), because PHP 8.5 (targeted for Laravel 13) is not in Debian
13, which ships only PHP 8.4. The mechanism is built so additional trusted
upstreams (nginx.org, mariadb.org, …) are a localized addition later (§11).

### Components (version shipped by Debian 13)

- **Web:** **nginx** (Debian repo, 1.26.x) — one server block per domain.
- **PHP:** **PHP-FPM** with the extensions Laravel needs (`mbstring`, `xml`,
  `bcmath`, `curl`, `intl`, `zip`, `gd`, `redis`, and the database driver), plus
  **Composer 2** from its **official installer** (SHA-384 verified). The PHP
  **version** is set by `php.version` and the **source** by `php.source`
  (`auto` | `sury` | `debian`, default `auto`): `auto` uses Debian's repo for the
  stock version (8.4) and Surý otherwise (e.g. 8.5); `sury` always uses Surý;
  `debian` uses only the Debian repo and fails clearly for a non-stock version.
  The step fails clearly if a pinned fingerprint mismatches or the version is not
  installable from the chosen source.
- **Database:** **MariaDB** (Debian repo, 11.8 LTS) behind a pluggable engine,
  plus a dedicated database user with a generated password.
- **Cache / sessions / queues:** **Valkey** (Debian repo) — the BSD-licensed fork
  of Redis that Debian ships after Redis Ltd. relicensed Redis to SSPL/RSALv2 in
  2024. Valkey is wire-compatible, so Laravel uses it transparently through its
  `redis` driver (the `php*-redis` client extension talks to the `valkey-server`
  service; `REDIS_*` in `.env` points at the local Valkey).
- **App runtime:** **Supervisor** (queue workers, dormant until first deploy) and
  a guarded **cron** entry for the Laravel scheduler.
- **Assets:** built in **CI**, so **Node.js is not installed** on the server.
- **Security / network:** **ufw** (allows the actual SSH port plus 80/443),
  **Let's Encrypt** TLS via certbot (dedicated ACME webroot, automatic renewal),
  and hardening: least-privilege `deploy` user with key auth, `fail2ban`,
  `unattended-upgrades`, timezone/locale, and disabling SSH root login and
  password authentication.

In v1 everything except PHP comes from Debian's repositories (Composer from its
official installer); PHP may come from Surý when a non-stock version is requested.

### Site model

`Server (1) → Site (1..n)`. v1 provisions the server and its **first** site;
additional sites are added later via `berth site:add`. The schema already
allows multiple sites.

## 5. Architecture

### Commands (Cobra)

- `berth init` — interactive **wizard** (huh): host, SSH port, domain, PHP
  version, database, **repository**, SSL email, and toggles → writes
  `servers/<name>.yml`.
- `berth provision <server>` — full, idempotent provisioning of the server and
  its first site. Flags: `--dry-run`, `--skip-ssl`, `--ssl-staging`, `--only=<step>`,
  `--force` (overwrite resources not managed by berth), `--no-tty`, `-v`.
- `berth site:add <server>` — add another site to an existing server
  *(designed for, not in v1)*.

### Interface & progress output

berth is a **CLI**, not a full-screen TUI. `init` runs an interactive **huh**
wizard. The provisioning **engine is decoupled from rendering**: it emits
progress events (`step started / satisfied / applied / failed`) on a channel, and
a renderer consumes them. The renderer is chosen by **TTY detection**:

- **TTY (interactive):** a **bubbletea** live view renders the step list,
  updating in place with a spinner on the active step and lipgloss styling.
- **Non-TTY (CI, pipes, `--no-tty`):** a plain renderer prints one stable,
  parseable line per step — no ANSI, no in-place updates — so logs and the
  release-gate integration test stay clean.

This keeps the engine UI-agnostic and unit-testable, and the output usable both
interactively and in automation.

### Project layout

```
berth/
├── main.go
├── cmd/                    # Cobra commands: root, init, provision, site
├── internal/
│   ├── config/             # YAML structs + load/validate + input validators
│   ├── ssh/                # Runner interface + ssh impl + FakeRunner (tests)
│   ├── apt/                # package sources: Debian stock + pinned upstream repos (Surý in v1)
│   ├── provision/          # Step interface + engine (Check→Apply) + dependency graph
│   │   └── steps/          # concrete steps: accounts, php, nginx, valkey, …
│   ├── database/           # Engine interface + mariadb (mysql8/postgres later)
│   ├── secret/             # generation, local cache, redaction set
│   ├── wizard/             # huh forms → writes config
│   ├── ui/                 # progress renderers: bubbletea (TTY) + plain (CI); lipgloss styles
│   └── templates/          # embed.FS: nginx, fpm-pool, supervisor, .env, sudoers, cron
├── docs/design/            # this specification
├── .goreleaser.yaml
└── .github/workflows/release.yml
```

### Key interfaces

**`Runner` — abstraction over remote execution (the test seam).** It supports
stdin (so secrets never appear on the command line) and an atomic `WriteFile`
(so system files get correct ownership/mode without partial writes):

```go
type Result struct{ Stdout, Stderr string; ExitCode int }

type FileSpec struct {
    Path        string
    Content     []byte
    Owner, Group string
    Mode        os.FileMode
    Sudo        bool        // write via a privileged, atomic install
}

type Runner interface {
    Run(ctx context.Context, cmd string, stdin []byte) (Result, error)
    // WriteFile writes atomically: temp file in a writable dir → validate →
    // `install -o … -g … -m … tmp dest` (or `sudo` equivalent) → fsync/rename.
    WriteFile(ctx context.Context, f FileSpec) error
}
```

The production implementation runs over SSH; a `FakeRunner` is used in tests so
every step can be unit-tested without a server. Both `Run` arguments and
`WriteFile` content are passed through a **redaction set** before any logging.

**`Step` — a unit of work with idempotency and declared dependencies:**

```go
type CheckResult struct {
    Satisfied bool
    Reason    string   // human-readable current state
    Changes   []string // what Apply would do (drives --dry-run)
    Sensitive bool     // output may contain secrets → redact
}

type Step interface {
    Name() string
    Requires() []string  // names of steps that must be satisfied first
    Check(ctx context.Context, s *config.Server, r ssh.Runner) (CheckResult, error)
    Apply(ctx context.Context, s *config.Server, r ssh.Runner) error
}
```

`Check` validates **functional** state, not mere file presence: it inspects a
`# managed by berth` marker plus a content hash, runs validators
(`nginx -t`), and checks service health (`systemctl is-active` / `is-enabled`).
This prevents a re-run from falsely passing after a partial failure (e.g. a
written-but-not-reloaded nginx config).

**`apt` — package-source helper.** Installs a package set from Debian stock, or
registers a pinned upstream repository first:

```go
type Repo struct {
    Name        string   // e.g. "sury-php"
    URI         string   // e.g. "https://packages.sury.org/php/"
    Suite       string   // e.g. "trixie"
    Components  []string // e.g. ["main"]
    KeyURL      string   // armored signing key
    Fingerprint string   // pinned; install aborts on mismatch
}
// EnsureRepo writes the key to /usr/share/keyrings, verifies Fingerprint,
// writes the source with signed-by=, then apt update.
// EnsurePackages installs from Debian stock (no Repo) or after EnsureRepo.
```

v1 registers exactly one `Repo` (Surý, used by the PHP step when `php.source`
selects it). Adding nginx.org or mariadb.org later is a new `Repo` value plus a
per-component `source` field — no change to the mechanism.

**`Engine` — pluggable database backend.** Passwords are passed via stdin, never
as command arguments, and the engine can idempotently re-sync a password on a
re-run:

```go
type Engine interface {
    Name() string
    InstallSteps() []provision.Step
    EnsureDatabase(ctx context.Context, r ssh.Runner, name string) error
    EnsureUser(ctx context.Context, r ssh.Runner, user, password, database string) error // create or ALTER to match
}
```

A registry maps `"mariadb"` to the MariaDB implementation. Adding MySQL 8 or
PostgreSQL later means a new `Engine` implementation, without touching the rest
of the pipeline.

### Configuration (version-controllable, secret-free)

```yaml
# servers/example.yml
host: 203.0.113.10
ssh:
  user: root            # bootstrap only; berth creates the 'berth' and 'deploy' accounts and hardens
  port: 22
  key: ~/.ssh/id_ed25519
  fingerprint: ""       # optional pinned SHA256 host-key fingerprint (see §6.1)
php:
  version: "8.5"
  source: auto          # auto | sury | debian (auto: Debian repo for 8.4, Surý for 8.5)
database:
  engine: mariadb       # pluggable: mysql8 | postgres (future)
  name: myapp
  user: myapp
valkey: true            # install Valkey (Redis-compatible) for cache/sessions/queues
queue: true
scheduler: true
sites:
  - domain: app.example.com
    deploy_path: /home/deploy/myapp
    repository: git@github.com:owner/repo.git  # derives Git host for known_hosts + deploy key; omit to leave Git access to the deployer
    ssl: true
    ssl_email: admin@example.com               # Let's Encrypt account email (required when ssl: true)
```

Secrets never appear in this file (see §7). Per-component upstream `source` fields
(e.g. `nginx.source`, `database.source`) arrive with their upstream
implementations (§11); v1 ships `php.source`.

### Input validation & injection safety

All config values that reach a remote shell, SQL statement, or filesystem path
are validated before use, and commands are never built by loose string
concatenation:

- **Domains:** RFC-1123 hostname pattern.
- **SQL identifiers** (database name, user): `^[A-Za-z_][A-Za-z0-9_]*$`,
  length-limited, and quoted as identifiers in SQL.
- **`deploy_path`:** absolute, normalized, no shell metacharacters.
- **PHP version:** `^\d+\.\d+$`, checked against an allowlist.
- **PHP source:** one of `auto`, `sury`, `debian`.
- **`repository`:** a valid **SSH** Git URL (scp-like `git@host:path` or
  `ssh://…`); the host is parsed out for `known_hosts`. HTTPS repos are out of v1
  scope, since berth provisions an SSH deploy key for the repository.
- **Command construction:** secret-bearing values go through stdin; any value
  that must appear in a remote shell is passed via a vetted shell quoter.

## 6. Provisioning flow

### 6.1 Connection model, host-key verification & user auto-detection

A fresh VPS typically grants access as **root** on the configured `ssh.port`;
the steady state for provisioning is the **`berth`** account. On every run berth
first tries to connect as **`berth`** with the operator's key; on success it
proceeds via `sudo` (the server is already provisioned). On failure it falls back
to the **bootstrap `root`** user from the config. This makes the first run and
every subsequent run work even though root login is later removed.

**Host-key verification** uses an explicit `HostKeyCallback` (never
`InsecureIgnoreHostKey`):

- Default **strict** policy backed by the operator's `known_hosts`.
- On an unknown host, **TOFU with confirmation**: the SHA256 fingerprint is shown
  and must be accepted, then pinned to `known_hosts`.
- For non-interactive/CI use, `ssh.fingerprint` may pin the expected fingerprint;
  a mismatch aborts the run.

### 6.2 Anti-lockout safety gate

SSH hardening (disabling root login and password auth) runs **only after**:
(1) the `berth` account exists, (2) its `authorized_keys` is installed, and
(3) a **separate SSH session as `berth` confirms key auth and `sudo -n` work**.
If verification fails, the hardening step **aborts without modifying `sshd`**
(fail safe, not fail open). The firewall step **allows the actual SSH port
(`ssh.port`) plus 80/443 before enabling ufw**.

### 6.3 Privilege model — two accounts

To bound the impact of a compromise, provisioning rights and deployment rights
live in separate accounts (decided in the second design review):

- **`berth` (provisioning):** full `NOPASSWD` sudo via `/etc/sudoers.d/berth`.
  Used **only by berth** over SSH for provisioning and idempotent re-runs.
  Holds the operator's public key. Broad sudo is intentional and confined to this
  account; it is the account the anti-lockout gate validates before hardening.
- **`deploy` (deployment):** the account Deployer PHP uses. Owns `deploy_path`
  and `shared/`. Holds a **narrow** sudoers allowlist via `/etc/sudoers.d/deploy`
  (only what a deploy needs, e.g. reload PHP-FPM and restart its own Supervisor
  worker) — **not** general sudo. Holds the deploy/CI public key (defaults to the
  operator's key).

This makes the "least-privilege deploy account" real in v1, rather than a
deferred plan, and keeps the wording consistent: `deploy` is genuinely scoped.

### 6.4 Ordered phases

0. **Preflight** — connect (auto-detect user, verify host key), read
   `/etc/os-release` and require Debian 13 (trixie), confirm root/sudo,
   `apt update`, set `DEBIAN_FRONTEND=noninteractive`.
1. **System base** — timezone/locale, base packages (curl, git, unzip,
   ca-certificates, gnupg), `unattended-upgrades`.
2. **Users & access** — create the `berth` account (full sudoers) and the
   `deploy` account (narrow sudoers), install `authorized_keys`; when a site has
   a `repository`, generate the deploy key pair (under `deploy`) and add the Git
   host to `known_hosts`.
3. **Network & hardening** — ufw (allow `ssh.port`/80/443 → enable), `fail2ban`,
   then **[anti-lockout gate]** disable SSH root login and password auth, reload.
4. **Web / runtime** — install each component from its configured source via the
   `apt` helper: **nginx, Valkey, MariaDB, and Supervisor from Debian's
   repository**; **PHP-FPM + extensions from `php.source`** (Debian for the stock
   version, otherwise Surý with a pinned GPG fingerprint + `signed-by`); **Composer
   via its official installer**.
5. **Application directories** — create `deploy_path` and `shared/` (owned by
   `deploy`) and the ACME webroot `/var/www/berth-acme/<domain>`. This runs
   **before** any secret is written, so `shared/.env` always has a home.
6. **Database** — first **persist the generated password atomically** to
   `shared/.env` and the local secrets cache (the directory now exists), then
   `EnsureDatabase` / `EnsureUser` (create or `ALTER` to match the stored
   password). No window leaves a DB secret without a recoverable source.
7. **Site** — write the nginx server block (HTTP first), including a
   `location /.well-known/acme-challenge/` served from the ACME webroot, and
   validate with `nginx -t`; write the PHP-FPM pool; install the Supervisor
   `queue:work` program with `autostart=false`; install a cron entry guarded as
   `[ -f {deploy_path}/current/artisan ] && cd … && php artisan schedule:run`.
8. **TLS** — **DNS preflight** (resolve the domain and confirm it points at the
   server; otherwise skip with a warning, or honour `--skip-ssl`); obtain the
   certificate with `certbot certonly --webroot -w /var/www/berth-acme/<domain>`
   (berth retains ownership of all nginx config), using `ssl_email` for the
   account and `--ssl-staging` for tests; write the 443 server block with an
   80→443 redirect; enable the auto-renew timer. Idempotent: skip issuance if a
   valid, non-expiring cert already exists.
9. **Summary** — print the deploy **public key** to register on the Git host, the
   location of database credentials (`shared/.env`), the handoff step to activate
   the queue worker after the first deploy, and the next step (run Deployer PHP).

### 6.5 Conflict & drift policy

berth marks the files it manages (`# managed by berth` + content hash). On a
re-run:

- **Managed resource present** → reconcile to the desired state.
- **Resource present but unmanaged or conflicting** (e.g. a `deploy` user with a
  different shell, an unmanaged nginx block, a database with different
  parameters) → **abort with a clear drift message**, unless `--force` is given.

### 6.6 Modes & dependencies

- **Safe re-run** — every step is guarded by its functional `Check`.
- **`--dry-run`** — `Check` only; reports current state and the `Changes` each
  step would make.
- **`--only=<step>`** — runs a single step. In v1 each step *is* a phase (1:1),
  so a step name doubles as a phase name. berth first walks the step's
  **transitive** `Requires()`; if any prerequisite's `Check` is unsatisfied, it
  **refuses with the list of missing prerequisites** instead of failing
  cryptically.

## 7. Configuration, secrets & state

### Secret-free config

`servers/<name>.yml` holds only declarative, non-sensitive data and is safe to
commit (the operator may keep it in a private repository).

### Secrets

| Secret | Generated by | Lives in (source of truth) |
| --- | --- | --- |
| Database password (per app) | berth (cryptographically random) | server `shared/.env` (`DB_PASSWORD`) |
| Deploy key pair (Git clone) | `ssh-keygen` on the server | private key stays on the server under `deploy`; public key printed to register on the Git host |
| SSH access | the operator's existing key (from `ssh.key` / agent) | authorizes the `berth` account (provisioning) and `deploy` (deployment) |

- **Atomic, early persistence:** the application directories are created before
  the database phase, and the database password is written to its sources of
  truth **before** the database user is created; re-syncing on a re-run is
  idempotent (§6.4) — there is no orphaned-secret window.
- **Redaction everywhere:** a redaction set scrubs secret values from `-v`
  output, error messages, and any logs. Secret-bearing commands use stdin, not
  argv, so they never appear in the remote process list.
- **Local convenience cache:** an optional `./.berth/<name>.secrets.json`
  (mode 600, **gitignored**) plus a one-time summary at the end. `berth init`
  scaffolds a `.gitignore` (`.berth/`, `*.secrets*`).
- **Re-runs do not rotate secrets:** `Check` detects an existing `DB_PASSWORD` or
  key and reuses it.

### berth / deployer boundary

- **berth** seeds **infrastructure** values into `shared/.env`: `DB_*`,
  `REDIS_*` (pointing at the local Valkey), `APP_ENV=production`,
  `APP_DEBUG=false`, `APP_URL`.
- **`APP_KEY` and application-level secrets** belong to the **deploy** step
  (`artisan key:generate`); berth does not touch them.
- **Queue-worker activation** after the first deploy is a deploy-time handoff
  (Deployer runs `supervisorctl reread/update/start`).

### State

berth keeps **no "what was done" state file**. Idempotency comes from each
`Check` interrogating the real server, aided by `# managed by berth` markers and
content hashes for drift detection. The server is the source of truth; the only
local persistence is the config (desired state) and the optional secrets cache.

## 8. Error handling

- **Fail-fast with context:** a step failure stops the pipeline with
  `<phase>/<step>: check|apply: <cause>` plus captured remote `stderr` and exit
  code — **with secrets redacted**. No errors are swallowed.
- **Exit-code semantics:** in `Check`, a non-zero exit is a **signal** (e.g.
  `id deploy` failing means the user does not exist); in `Apply`, a non-zero exit
  is a **failure** unless the step explicitly tolerates it.
- **Functional Check** (§5) prevents a re-run from passing over a half-applied
  step.
- **Forward-only, no rollback (by design):** recovery is a **re-run** — completed
  steps `Check` as done and the pipeline resumes from the failure point.
- **One fail-safe exception:** the anti-lockout gate aborts rather than risk
  losing SSH access.
- **Cancellation & timeouts:** `context.Context` is threaded through `Runner`;
  Ctrl-C closes the SSH session cleanly; long operations (apt, certbot) get
  generous timeouts.
- **Preflight refuses** a non–Debian-13 host or missing sudo before any change.
- **Output:** the engine emits progress events to the renderer (§5) — a live
  **bubbletea** view on a TTY, otherwise a plain parseable line per step
  (`✔ already`, `⚙ applied`, `✗ failed`); `-v` shows the (redacted) remote
  commands and output.

## 9. Testing

- **Unit tests per `Step`** using `FakeRunner` (table-driven): program command →
  `(stdout, exit)` responses, assert correct commands and `CheckResult`
  interpretation (both branches), and `Apply` error handling. No server required.
- **Package-source tests:** the `apt` helper adds a pinned upstream repo correctly
  (key in `/usr/share/keyrings/`, `signed-by`, fingerprint verified) and **aborts
  on a fingerprint mismatch**; `php.source` + `php.version` select the right
  repository (and `debian` + a non-stock version is rejected).
- **Validator & redaction tests:** domains, SQL identifiers, paths, versions; and
  proof that secrets never appear in logged output.
- **Template golden-file tests:** nginx / fpm-pool / supervisor / `.env` /
  sudoers / cron rendered against checked-in expected output.
- **Config tests:** load/validate YAML; reject invalid input.
- **Engine tests:** the MariaDB engine issues the right (stdin-fed) SQL via
  `FakeRunner`; the interface contract is reusable for future engines.
- **Progress/UI tests:** the engine emits the expected event sequence (asserted
  via a fake renderer); the bubbletea model's update/view logic is unit-tested;
  the plain renderer is selected when stdout is not a TTY.
- **Minimal integration smoke test (v1, release gate):** provision a
  systemd-capable Debian 13 environment (an LXD/Incus container or an ephemeral
  VPS) and assert end state — services `is-active`, `nginx -t` passes, PHP-FPM
  responds, the database and Valkey are reachable, HTTP serves. Gated with
  `//go:build integration`, run nightly and **required before tagging a
  release**. (Firewall/SSH-hardening steps that are awkward in a container are
  exercised on the VPS variant.)

## 10. Distribution (CI/CD)

- **`.goreleaser.yaml`:** build matrix `linux/{amd64,arm64}`,
  `darwin/{amd64,arm64}`, `windows/amd64`; CGO disabled → fully static; `ldflags`
  inject version/commit/date (`berth --version`).
- **`.github/workflows/release.yml`:** on a `v*` tag, run unit tests **and the
  integration smoke test (release gate)**, then `goreleaser release` publishing a
  GitHub Release with archives (tar.gz / zip) and `checksums.txt`.
- **For users:** download a binary from the Releases page — including a Windows
  `.exe` — with no runtime to install. Homebrew tap and Scoop manifest are a
  nice-to-have (GoReleaser can generate them) and are out of v1.
- **Versioning:** SemVer tags.

## 11. Scope

**v1**

- `berth init` (wizard → config) and `berth provision` (one server + first
  site), MariaDB engine.
- Packages from **Debian 13's repositories** via a pluggable package-source
  mechanism; **Surý is the only upstream in v1** (for PHP 8.5). **Valkey** for
  cache/sessions/queues. `php.source` (`auto`/`sury`/`debian`) configurable.
- Idempotent pipeline with functional `Check`; `--dry-run` diff, `--only` with
  dependency checks, `--force`, `--skip-ssl`, `--ssl-staging`.
- Security: **separate `berth` (provisioning) and least-privilege `deploy`
  accounts**, explicit host-key verification, `ssh.port` handling, `sudo -n`
  gate, secret redaction + stdin, input validators, pinned-fingerprint
  package-source (Surý), dedicated ACME webroot.
- Atomic `WriteFile`; application directories created before secrets; idempotent
  DB secret handling; Supervisor/cron dormant-until-first-deploy; conflict/drift
  policy.
- Interface: Cobra CLI with a huh wizard (`init`) and a **bubbletea** live
  progress view (`provision`) that falls back to a plain, parseable renderer off
  a TTY.
- GoReleaser + GitHub Actions release for Linux/macOS/Windows, with a minimal
  integration smoke test as a release gate.

**Later**

- Trusted upstream package sources for other components (**nginx.org** mainline /
  HTTP-3, **mariadb.org**, …) with per-component `source` config; optional real
  Redis (SSPL) source if ever required.
- `berth site:add` (multiple sites per server).
- MySQL 8 and PostgreSQL engines.
- Homebrew tap / Scoop manifest.
- Full integration matrix.

## 12. License

Released under the **MIT License**.

## Appendix A — Design-review resolutions (first review, 16 findings)

| # | Finding | Resolution | Section |
| --- | --- | --- | --- |
| 1 | SSH host-key verification missing | Explicit `HostKeyCallback`: strict `known_hosts` + TOFU with fingerprint confirmation; optional pinned `ssh.fingerprint`; never insecure | §6.1, config |
| 2 | Firewall assumes port 22 | `ssh.port` field; ufw allows the actual SSH port before `enable` | §4, §6.2, config |
| 3 | Undefined sudo scope | **Separate `berth` (full sudo) and least-privilege `deploy` (narrow allowlist) accounts in v1**; `sudo -n` validated at the gate | §6.3 |
| 4 | Secret leakage in logs/commands | Redaction set on all output; secrets via stdin, not argv | §5, §7, §8 |
| 5 | `--dry-run` had no diff model | `Check` returns `CheckResult{Satisfied, Reason, Changes, Sensitive}` | §5, §6.6 |
| 6 | `Upload` insufficient for system files | Atomic `WriteFile(FileSpec{owner,group,mode,sudo})` | §5 |
| 7 | Partial-failure false pass | Functional `Check`: managed marker + content hash, `nginx -t`, `systemctl is-active/enabled` | §5, §8 |
| 8 | Orphaned DB password | Directories created before secrets; password persisted atomically before user creation; idempotent `ALTER` re-sync | §6.4 (5–6), §7 |
| 9 | No conflict/drift policy | Managed markers; reconcile managed, abort on unmanaged drift unless `--force` | §6.5 |
| 10 | `--only` may skip dependencies | `Step.Requires()`; refuse with missing-prerequisite list | §5, §6.6 |
| 11 | Supervisor/cron before first deploy | Supervisor `autostart=false`; cron guarded by `[ -f current/artisan ]`; activation is a deploy handoff | §3, §4, §6.4 (7) |
| 12 | Deploy key/`known_hosts` had no input | `repository` per site (+ wizard); deploy key + `known_hosts` only when set | §3, §5, §6.4 (2) |
| 13 | certbot underspecified | **Dedicated berth-managed ACME webroot** + challenge `location`; `ssl_email`, `certonly --webroot`, `--ssl-staging`, DNS preflight | §4, §6.4 (5,7,8), config |
| 14 | Input validation too generic | Explicit validators + no loose string concatenation | §5 |
| 15 | Upstream repo trust model | Key to `/usr/share/keyrings/`, verify pinned fingerprint, `signed-by` scoping — generalized into the `apt` package-source helper | §4, §5, §6.4 (4) |
| 16 | Integration testing deferred | Minimal integration smoke test promoted into v1 as a **release gate** | §9, §10, §11 |

## Appendix B — Second-review decisions

| Item | Verdict | Action taken |
| --- | --- | --- |
| #3 sudo | CHANGE | Split into a `berth` provisioning account (full sudo) and a least-privilege `deploy` account in v1 (separate-account option chosen because narrowing `deploy` after provisioning would break key-based re-runs once root is disabled) — §6.3 |
| #13 TLS | CHANGE | Dedicated berth-managed ACME webroot `/var/www/berth-acme/<domain>` + nginx challenge `location`, independent of the not-yet-existing `current/public` — §4, §6.4 |
| #11 workers | ACCEPT | Kept as designed |
| #16 tests | ACCEPT | Kept as designed |
| Ordering bug | FIXED | Application directories (incl. `shared/`) now created in phase 5, **before** the database phase writes `shared/.env` — §6.4 |
| "scoped sudoers" wording | FIXED | Now accurate: `deploy` is genuinely scoped; broad sudo is confined to the `berth` account — §6.3 |

## Appendix C — Package-source strategy

| Decision | Outcome |
| --- | --- |
| Install sources | Debian's repositories by default; a pluggable **package-source** mechanism (Debian stock or fingerprint-pinned upstream apt repo) is built in v1 — §4, §5 (`apt`) |
| v1 upstreams | **Only Surý for PHP** (required for 8.5; Debian 13 ships only 8.4). `php.source`: `auto`/`sury`/`debian` |
| Deferred upstreams | **nginx.org** (HTTP/3) and **mariadb.org** are architecturally ready but not implemented in v1; added later with per-component `source` config |
| Redis → Valkey | Debian ships **Valkey** (BSD) after Redis's 2024 SSPL/RSALv2 relicense; berth installs Valkey and Laravel uses it via the `redis` driver. Real Redis remains a possible future source |
| nginx / MariaDB in v1 | Debian stock only (nginx 1.26.x, MariaDB 11.8 LTS) |

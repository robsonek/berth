# berth

> Prepare a fresh Debian 13 server for your Laravel app — ready for Deployer PHP.

**berth** is a command-line tool that provisions a freshly installed Debian 13
(Trixie) VPS into a production-ready web server for Laravel applications. It
connects over SSH and applies an idempotent pipeline (nginx, PHP 8.5-FPM,
MariaDB, Redis, Supervisor, firewall, TLS, hardening), leaving the server ready
for a separate deployer ([Deployer PHP](https://deployer.org)) to ship code.

A *berth* is the prepared place where a vessel docks: berth readies the server,
then the deployer brings the code alongside.

> **Status: early development.** The full design is specified in
> [`docs/design`](docs/design/2026-06-13-berth-design.md); implementation is in
> progress.

## Highlights

- **Single, dependency-free binary** for Linux, macOS, and Windows — no runtime
  to install on your machine or the server (beyond SSH).
- **Idempotent** — safe to re-run; it only fills in what is missing.
- **Declarative** — a server is described by a version-controllable, secret-free
  config file.
- **Safe by default** — anti-lockout SSH hardening, a least-privilege deploy
  account, secret redaction, and explicit host-key verification.

## How it works

`berth init` walks you through an interactive wizard and writes a per-server
config. `berth provision <server>` then connects over SSH and brings the host to
the desired state through an ordered pipeline of idempotent steps. Re-running is
always safe; `--dry-run` shows what would change.

## Roadmap

v1 targets `berth init` and `berth provision` (one server and its first site,
MariaDB). MySQL 8 / PostgreSQL engines, multi-site (`berth site:add`), and
package-manager distribution come later. See the
[design specification](docs/design/2026-06-13-berth-design.md) for the full
scope.

## License

[MIT](LICENSE) © 2026 robsonek

# Integration smoke test (release gate)

`provision_test.go` runs berth's full provisioning pipeline against a **real**
Debian 13 (Trixie) host and asserts the end state. It is the v1 release gate.

The test is guarded by the `integration` build tag, so the normal
`go test ./...` never builds or runs it. It is also opt-in at runtime: it
`t.Skip`s unless `BERTH_TEST_SERVER` points at a server config.

## What it asserts

After running the pipeline with `--skip-ssl` (TLS needs real DNS and is
exercised separately), the test connects to the target and checks:

- `systemctl is-active` reports `active` for `nginx`, `php<version>-fpm`,
  `mariadb`, and `valkey-server` (the last only when `valkey: true`).
- `nginx -t` exits `0` (valid generated config).
- `mysql --protocol=socket -e 'SELECT 1'` exits `0` (socket-auth DB reachable).
- `GET http://<host>/` returns a response. A `502 Bad Gateway` is acceptable:
  nginx and PHP-FPM are up but no application is deployed yet.

## You need a systemd host, not plain Docker

The pipeline drives `systemctl`, `ufw`, and `sshd`. A stock Docker container has
no init system, so use one of the following.

### Option A — LXD / Incus container (fast, local)

LXD/Incus system containers run real systemd.

```bash
# Incus (or substitute `lxc` for LXD):
incus launch images:debian/13 berth-smoke
incus exec berth-smoke -- bash -c '
  apt-get update &&
  apt-get install -y openssh-server sudo ufw &&
  systemctl enable --now ssh'

# Get the container IP and allow root login with your key for bootstrap:
incus exec berth-smoke -- mkdir -p /root/.ssh
incus file push ~/.ssh/id_ed25519.pub berth-smoke/root/.ssh/authorized_keys
IP=$(incus list berth-smoke -f csv -c4 | cut -d' ' -f1)
echo "container IP: $IP"
```

Containers need `security.nesting`/privileges for `ufw` to manage nftables; if
`ufw` cannot load rules, launch with:

```bash
incus launch images:debian/13 berth-smoke -c security.privileged=true
```

### Option B — Ephemeral Debian 13 VPS (closest to production)

Provision a fresh Debian 13 droplet/instance at any cloud provider with SSH key
auth for `root`, then destroy it after the run. This is the most faithful target
(real kernel, real `ufw`, real `sshd`) and is recommended for release sign-off.

## Server config

Create a throwaway `servers/smoke.yml` pointing at the host (see the project's
`init` output for the schema). Minimal example:

```yaml
host: 10.0.0.42        # container IP or VPS address
ssh:
  user: root           # bootstrap user; berth creates the `berth` account
  port: 22
  key: ~/.ssh/id_ed25519
php:
  version: "8.4"
  source: auto
database:
  engine: mariadb
  name: app
  user: app
valkey: true
queue: true
scheduler: true
sites:
  - domain: smoke.example.test
    deploy_path: /var/www/smoke
    repository: https://github.com/example/app.git
    ssl: false
```

The test connects non-interactively, so the host key must already be trusted:
either pin it via `ssh.fingerprint` in the config, or add it to your
`~/.ssh/known_hosts` first (`ssh-keyscan -H <host> >> ~/.ssh/known_hosts`).

## Running

```bash
BERTH_TEST_SERVER=servers/smoke.yml go test -tags integration -v ./test/integration/...
```

Tear the host down afterwards (`incus delete -f berth-smoke`, or destroy the
VPS). Re-running against the same host is safe: every step is idempotent.

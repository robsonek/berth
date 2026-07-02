# Design: database.Check probes real state; Apply seeds .env only when absent

Date: 2026-07-03
Status: awaiting user spec review (approach chosen per the design-review
recommendation after an unanswered option prompt; the user can override here)
Source: design-review finding "database.Check treats .env presence as proof of
DB provisioning" (docs/improvement-roadmap.md § Design-review findings —
2026-07-02, "Fix first" list), plus the .env-clobber interaction noted there
and in the Tier-2 iteration-3 lesson.

## Problem

`database.Check` (internal/provision/steps/database.go) verifies only: server
package installed, upstream source registered, and each site's `shared/.env`
exists. It never verifies the database or role exist. `Apply` deliberately
writes `.env` FIRST (recoverable secret), then `EnsureDatabase`, then
`EnsureUser` — so a failure in that window (DB socket not ready right after
install, any SQL error) leaves a server that every later run reports
**Satisfied** and never heals; the app cannot connect until the operator
intervenes manually. This breaks the tool's core idempotent-convergence
contract.

Interacting hazard: when Apply does run, it unconditionally rewrites EVERY
site's `.env` (`seedSharedEnv` in a loop). A heal-run triggered by one broken
site would clobber healthy sites' `.env` files — wiping operator-added keys
and re-deriving the positional `REDIS_DB` index (finding M5).

## Decision

Existence probes (database + role) in Check; Apply seeds a site's `.env` only
when it is absent. Rejected: a full credential login-probe in Check (heavier;
covered live by the integration suite's app-user auth assertion) and any
change to `REDIS_DB` derivation (separate finding M5).

## Design

### 1. Engine interface (internal/database/engine.go)

Two new read-only methods on `Engine`, next to `EnsureDatabase`/`EnsureUser`:

```go
// DatabaseExists reports whether the application database exists. Read-only;
// a failing probe (server down, client binary absent) reports false, nil —
// Check treats "cannot confirm" as unsatisfied and Apply reconciles loudly.
DatabaseExists(ctx context.Context, r bssh.Runner, name string) (bool, error)
// UserExists reports whether the application user/role exists. Same
// read-only, false-on-unreachable semantics as DatabaseExists.
UserExists(ctx context.Context, r bssh.Runner, user string) (bool, error)
```

The `(bool, error)` split follows the repo's Runner convention: `error` is
transport-only (SSH failure); a non-zero client exit or empty result is data
(`false, nil`).

- **MariaDB** (root over the unix socket, matching `runSQL`): pipe the query
  via stdin to `mysql --protocol=socket -N`, then test stdout:
  - DatabaseExists: `SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='<name>';`
  - UserExists: `SELECT 1 FROM mysql.user WHERE User='<user>' AND Host='localhost';`
  Exists ⇔ exit 0 AND trimmed stdout == "1".
- **Postgres** (peer auth, matching its admin SQL):
  - DatabaseExists: `sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='<name>'"`
  - UserExists: `sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='<user>'"`
  Exists ⇔ exit 0 AND trimmed stdout == "1".

Names/users are `reSQLIdent`-validated identifiers (no quotes or shell
metacharacters — the same precondition `EnsureDatabase` already relies on), so
single-quoted interpolation is safe. No secrets are involved: probes use admin
socket/peer auth, never the app password.

### 2. database.Check (internal/provision/steps/database.go)

New sequence:
1. Engine lookup, `pkgInstalled`, `sourceOK` — unchanged.
2. If NOT installed or NOT sourceOK → unsatisfied (as today). Probes are
   skipped entirely when the package is missing (no server to ask).
3. Per site, in one pass: `.env` exists → else unsatisfied ("credential for
   <domain> not yet persisted"); `DatabaseExists` → else unsatisfied
   ("database for <domain> missing"); `UserExists` → else unsatisfied
   ("database user for <domain> missing").
4. All present → Satisfied.

Reasons keep `Sensitive: true` on unsatisfied results (unchanged convention).

### 3. database.Apply

One change: inside the per-site loop, `seedSharedEnv` runs only when the
site's `.env` is ABSENT (`fileExists`). Rationale:
- `ssh.WriteFile` is atomic (mktemp + SFTP + install), so an existing `.env`
  is complete — there is no torn-write state to repair.
- `resolvePassword`/`resolveAppKey` already read the live `.env` first, so on
  a heal-run `EnsureUser` re-syncs the SAME password the app already has; the
  file needs no rewrite.
- This removes the heal-run clobber hazard (operator-added keys, positional
  `REDIS_DB` renumbering) and matches today's EFFECTIVE behavior: with the
  old Check short-circuiting on `.env` existence, berth-derived `.env`
  changes never propagated to an existing file anyway.

Order stays seed → `EnsureDatabase` → `EnsureUser`; the persist-first
crash-recovery property is preserved for first provisioning.

`changes()` wording updates to reflect the conditional seed:
`"per site: persist DB credential to shared/.env (when absent), ensure database + user"`.

## Out of scope

- Credential login-probe in Check (integration suite asserts it live).
- `REDIS_DB` stable derivation (finding M5) — unchanged, though seeding only
  when absent already prevents renumbering of EXISTING sites.
- Password rotation, tls/site steps, wizard.

## Tests (TDD)

- `internal/database/mariadb_test.go` / `postgres_test.go`: exact probe
  command strings against FakeRunner; exists/absent/unreachable (non-zero
  exit → false, nil; transport error → error) for both methods.
- `internal/provision/steps/database_test.go`:
  - Check: env present + database probe false → unsatisfied (the exact gap:
    today this returns Satisfied);
  - Check: env present + db present + user probe false → unsatisfied;
  - Check: all probes true → Satisfied;
  - Check: package not installed → unsatisfied WITHOUT running any probe
    (assert no probe command in FakeRunner calls);
  - Apply heal path: `.env` exists → NO WriteFile for that path, Ensure SQL
    still runs, password taken from the live `.env`;
  - Apply fresh path: `.env` absent → seeded as before (existing test
    `TestDatabaseCheckSatisfiedDoesNotReseedExistingEnv` semantics move from
    Check-short-circuit to Apply-conditional; update as needed).
- Live validation on the test box (controller-run): full provision; then
  `DROP USER` the app role manually; re-run → `database` re-applies, role
  recreated, app-user login works (integration suite assertion), healthy
  site's `.env` byte-identical before/after (diff); second run all-Satisfied.

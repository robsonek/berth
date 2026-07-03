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

### 0. Prerequisite: WriteFile becomes genuinely atomic (internal/ssh/client.go)

The env-present path below treats an existing `.env` as complete — which is
only sound if the file can never be observed half-written. Today's
`installCmd` runs `install tmp dest`, which COPIES into the destination (the
SFTP temp lives in /tmp, a different filesystem, so no rename is possible) —
a connection drop mid-copy leaves a partial destination file. Fix at the
source, for every managed file: `installCmd` becomes

```
t=$(mktemp '<destdir>/.berth.XXXXXX') && install -o <o> -g <g> -m <m> <tmp> "$t" && mv -f "$t" <dest> && rm -f <tmp>
```

`mktemp` in the DESTINATION directory (unpredictable name — no symlink-plant
window in tenant-writable dirs) puts the staged copy on the same filesystem,
so `mv -f` is an atomic rename(2); a failure anywhere in the chain leaves the
old destination intact (plus a harmless random temp crumb). Because the chain
now starts with a variable assignment, the privileged form wraps the whole
chain: `sudo -n sh -c '<chain>'` (also aligning installCmd with the
`sudo -n` convention used by `privileged()` — a design-review LOW). The
`installCmd` unit tests pin the new command shape.

### 1. Engine interface (internal/database/engine.go)

Two new read-only methods on `Engine`, next to `EnsureDatabase`/`EnsureUser`:

```go
// DatabaseExists reports whether the application database exists. Read-only;
// a failing probe (server down, client binary absent) reports false, nil —
// Check treats "cannot confirm" as unsatisfied and Apply reconciles loudly.
DatabaseExists(ctx context.Context, r bssh.Runner, name string) (bool, error)
// UserGranted reports whether the application user/role exists AND holds its
// grant on (MariaDB) / ownership of (Postgres) the database — i.e. EnsureUser
// ran to its last meaningful statement, not merely CREATE. Same read-only,
// false-on-unreachable semantics as DatabaseExists.
UserGranted(ctx context.Context, r bssh.Runner, user, database string) (bool, error)
```

`UserGranted` (rather than a bare existence probe) closes the residual window
Codex flagged: a run dying inside `EnsureUser` after CREATE but before
GRANT/OWNER would otherwise read as satisfied. The remaining residual is
password drift only (role exists, granted, but with a different password than
`.env`) — explicitly out of scope with the login-probe rejection below.

The `(bool, error)` split follows the repo's Runner convention: `error` is
transport-only (SSH failure); a non-zero client exit or empty result is data
(`false, nil`).

- **MariaDB** (root over the unix socket, matching `runSQL`'s auth): the query
  is inlined via `-e` — probes carry no secrets, and inline queries give each
  probe a distinct command string, matching the repo's FakeRunner
  exact-command-string test convention:
  - DatabaseExists: `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='<name>'"`
  - UserGranted: `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='<db>' AND GRANTEE='''<user>''@''localhost''' LIMIT 1"`
    (GRANTEE stores the literal `'user'@'localhost'`; the embedded single
    quotes are doubled inside the SQL string literal — safe inside the
    double-quoted shell argument. Any privilege row qualifies: `EnsureUser`
    grants ALL, so at least one row exists once the GRANT ran.)
  Exists/granted ⇔ exit 0 AND trimmed stdout == "1".
- **Postgres** (peer auth, matching its admin SQL):
  - DatabaseExists: `sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='<name>'"`
  - UserGranted: `sudo -u postgres psql -tAc "SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba WHERE d.datname='<db>' AND r.rolname='<user>'"`
    (ownership is `EnsureUser`'s LAST statement — `ALTER DATABASE ... OWNER TO`
    — so a positive probe proves the whole batch completed).
  Exists/granted ⇔ exit 0 AND trimmed stdout == "1".

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
   ("database for <domain> missing"); `UserGranted` → else unsatisfied
   ("database user/grant for <domain> missing").
4. All present → Satisfied.

Reasons keep `Sensitive: true` on unsatisfied results (unchanged convention).

### 3. database.Apply

Inside the per-site loop, `fileExists(sharedEnvPath)` decides two paths:

- **`.env` absent (first provisioning):** seed as today — password from the
  local cache or freshly generated, `APP_KEY` freshly generated. With the
  file absent there is never an env value to reuse, so `resolveAppKey`
  collapses into the seed path (`secret.AppKey()` directly; the helper and
  its env-grep are deleted) and `resolvePassword`'s env-grep branch moves out
  of the shared helper into the env-present path below.
- **`.env` present (re-run / heal / operator-preseeded):** NO write — the
  file is never touched (§0 makes `WriteFile` genuinely atomic, so an
  existing file is complete by construction). The password for `EnsureUser`
  MUST come from the live `.env`:
  - `DB_PASSWORD` present → charset-validated (existing `reDBPassword`
    guard), then `EnsureUser` re-syncs that same value;
  - `DB_PASSWORD` missing/empty → **fail with a pointed error**
    ("shared/.env for <domain> exists but has no DB_PASSWORD; add one or
    remove the file to have berth re-seed it") — silently generating a new
    password would desync the role from the file the app reads.
  This also improves the operator-preseeded-restore scenario: a hand-written
  `.env` is now never overwritten.

Rationale for absent-only seeding:
- With §0, `ssh.WriteFile` stages in the destination directory and renames,
  so an existing `.env` is complete — there is no torn-write state to repair.
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

- Credential login-probe in Check (integration suite asserts it live). The
  accepted residual: a role that exists and is granted/owner but whose live
  password differs from `.env` reads as satisfied; only a triggered Apply
  re-syncs it (`EnsureUser`'s ALTER).
- `REDIS_DB` stable derivation (finding M5) — unchanged, though seeding only
  when absent already prevents renumbering of EXISTING sites.
- Password rotation, tls/site steps, wizard.

## Tests (TDD)

- `internal/ssh/client_test.go`: `installCmd` unit tests pin the new
  mktemp-in-destdir + install + `mv -f` chain and the `sudo -n sh -c`
  privileged wrapper (both sudo and non-sudo forms).
- `internal/database/mariadb_test.go` / `postgres_test.go`: exact probe
  command strings against FakeRunner; the FULL matrix for BOTH methods on
  BOTH engines: present ("1") / absent (empty) / unreachable (non-zero exit
  → false, nil) / transport error (→ error propagates).
- `internal/provision/steps/database_test.go`:
  - Check: env present + database probe false → unsatisfied (the exact gap:
    today this returns Satisfied);
  - Check: env present + db present + UserGranted false → unsatisfied;
  - Check: all probes true → Satisfied;
  - Check: package not installed → unsatisfied WITHOUT running any probe
    (assert no probe command in FakeRunner calls);
  - Apply heal path: `.env` exists → NO WriteFile for that path, Ensure SQL
    still runs, password taken from the live `.env` (adapts
    `TestDatabaseApplyReusesExistingPasswordWithoutRotating`);
  - Apply env-present-but-no-DB_PASSWORD → pointed error, no SQL run;
  - Apply fresh path: `.env` absent (stub `test -e` → exit 1 in every Apply
    test — FakeRunner's default exit 0 would otherwise mean "exists") →
    seeded as before; `TestDatabaseApplyReusesExistingAppKeyWithoutRotating`
    is deleted with `resolveAppKey` (an absent env has no key to reuse; a
    present env is never rewritten, which preserves the key trivially);
    `TestDatabaseCheckSatisfiedDoesNotReseedExistingEnv` gains probe stubs
    and its comment moves from Check-short-circuit to the probes+Apply story.
- Live validation on the test box (controller-run; the box runs MariaDB, so
  the live heal recipe is explicitly MariaDB-only — the Postgres heal path is
  pinned by the unit matrix, and a naive `DROP ROLE` would anyway fail on the
  owner role): full provision; then `DROP USER '<user>'@'localhost'`
  manually; re-run → `database` re-applies, role recreated with its grant,
  app-user login works (integration suite assertion), healthy site's `.env`
  byte-identical before/after (diff); second run all-Satisfied.

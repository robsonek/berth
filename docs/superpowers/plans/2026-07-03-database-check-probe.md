# database.Check Real-State Probes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `database.Check` verifies the database and role actually exist (not just that `shared/.env` does), so a provision that failed between the `.env` write and `EnsureUser` heals on the next run; `Apply` seeds `.env` only when absent, so a heal-run never clobbers a healthy site's file.

**Architecture:** Two new read-only `Engine` methods (`DatabaseExists`, `UserExists`) with admin socket/peer auth and false-on-unreachable semantics; `Check` gates on installed+source first, then per site: env → database → user; `Apply` splits per site on `fileExists(.env)`: absent → seed (cache/generated password, fresh APP_KEY), present → never write, password MUST come from the live `.env` (missing → pointed error).

**Tech Stack:** Go 1.25, stdlib only, FakeRunner exact-command-string tests.

**Spec:** `docs/superpowers/specs/2026-07-03-database-check-probe-design.md` (user-approved; Codex-consulted before implementation).

## Global Constraints

- Go 1.25; NEVER run `go mod tidy`; no new dependencies.
- Public MIT repo: code/comments/commits English-only.
- Probe semantics: `(bool, error)` — `error` is transport-only; non-zero client exit or non-"1" stdout is `false, nil` ("cannot confirm" → unsatisfied → Apply reconciles loudly).
- Identifiers passed to probes are `reSQLIdent`-validated (no quotes/shell metacharacters) — same precondition as `EnsureDatabase`. Probes carry NO secrets; queries are inlined in the command string (distinct, FakeRunner-matchable commands).
- Apply's persist-first order for FRESH sites is preserved: seed → `EnsureDatabase` → `EnsureUser`.
- An EXISTING `.env` is never written to. If it lacks `DB_PASSWORD`, Apply fails with: `<envpath> for <domain> exists but has no DB_PASSWORD; add one or remove the file to have berth re-seed it`.
- After each task: `gofmt -l .` prints nothing; `go test ./...` passes.
- Branch: `fix/database-check-probe` (created; spec committed).
- Commit messages end with: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

---

### Task 1: Engine probes (interface + MariaDB + Postgres)

**Files:**
- Modify: `internal/database/engine.go` (interface)
- Modify: `internal/database/mariadb.go`, `internal/database/postgres.go`
- Test: `internal/database/mariadb_test.go`, `internal/database/postgres_test.go` (append)

**Interfaces:**
- Produces (Tasks 2-3 consume):
  `DatabaseExists(ctx context.Context, r bssh.Runner, name string) (bool, error)` and
  `UserExists(ctx context.Context, r bssh.Runner, user string) (bool, error)` on `database.Engine`.
- Exact probe commands (tests stub these verbatim):
  - MariaDB: `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='<name>'"` and `mysql --protocol=socket -N -e "SELECT 1 FROM mysql.user WHERE User='<user>' AND Host='localhost'"`
  - Postgres: `sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='<name>'"` and `sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='<user>'"`

- [ ] **Step 1: Write the failing tests**

Append to `internal/database/mariadb_test.go`:

```go
func TestMariaDBProbes(t *testing.T) {
	dbCmd := `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='myapp'"`
	userCmd := `mysql --protocol=socket -N -e "SELECT 1 FROM mysql.user WHERE User='myapp' AND Host='localhost'"`
	cases := []struct {
		name   string
		result bssh.Result
		want   bool
	}{
		{"present", bssh.Result{Stdout: "1\n"}, true},
		{"absent", bssh.Result{Stdout: ""}, false},
		{"server unreachable", bssh.Result{ExitCode: 1, Stderr: "can't connect"}, false},
	}
	for _, tc := range cases {
		t.Run("database "+tc.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			f.On(dbCmd, tc.result)
			got, err := (MariaDB{}).DatabaseExists(context.Background(), f, "myapp")
			if err != nil || got != tc.want {
				t.Fatalf("DatabaseExists = %v, %v; want %v, nil", got, err, tc.want)
			}
			if f.Calls()[0].Cmd != dbCmd {
				t.Fatalf("probe command = %q, want %q", f.Calls()[0].Cmd, dbCmd)
			}
		})
		t.Run("user "+tc.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			f.On(userCmd, tc.result)
			got, err := (MariaDB{}).UserExists(context.Background(), f, "myapp")
			if err != nil || got != tc.want {
				t.Fatalf("UserExists = %v, %v; want %v, nil", got, err, tc.want)
			}
			if f.Calls()[0].Cmd != userCmd {
				t.Fatalf("probe command = %q, want %q", f.Calls()[0].Cmd, userCmd)
			}
		})
	}
}

func TestMariaDBProbeTransportError(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.OnError(`mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='myapp'"`, errTransport)
	if _, err := (MariaDB{}).DatabaseExists(context.Background(), f, "myapp"); err == nil {
		t.Fatal("transport error must propagate")
	}
}

var errTransport = errString("ssh: broken")

type errString string

func (e errString) Error() string { return string(e) }
```

Append to `internal/database/postgres_test.go` (mirror; if an `errString`/`errTransport` helper already exists in the package from the mariadb file, do not redeclare):

```go
func TestPostgresProbes(t *testing.T) {
	dbCmd := `sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='myapp'"`
	userCmd := `sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='myapp'"`
	cases := []struct {
		name   string
		result bssh.Result
		want   bool
	}{
		{"present", bssh.Result{Stdout: "1\n"}, true},
		{"absent", bssh.Result{Stdout: "\n"}, false},
		{"server unreachable", bssh.Result{ExitCode: 2, Stderr: "psql: could not connect"}, false},
	}
	for _, tc := range cases {
		t.Run("database "+tc.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			f.On(dbCmd, tc.result)
			got, err := (Postgres{}).DatabaseExists(context.Background(), f, "myapp")
			if err != nil || got != tc.want {
				t.Fatalf("DatabaseExists = %v, %v; want %v, nil", got, err, tc.want)
			}
		})
		t.Run("user "+tc.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			f.On(userCmd, tc.result)
			got, err := (Postgres{}).UserExists(context.Background(), f, "myapp")
			if err != nil || got != tc.want {
				t.Fatalf("UserExists = %v, %v; want %v, nil", got, err, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run 'Probe' ./internal/database/`
Expected: FAIL to compile — `DatabaseExists`/`UserExists` undefined.

- [ ] **Step 3: Implement**

`internal/database/engine.go` — add to the `Engine` interface after `EnsureUser`:

```go
	// DatabaseExists reports whether the application database exists. Read-only,
	// admin socket/peer auth (no app credentials). A failing probe (server down,
	// client binary absent) reports false, nil — Check treats "cannot confirm"
	// as unsatisfied and Apply reconciles loudly; error is transport-only.
	DatabaseExists(ctx context.Context, r bssh.Runner, name string) (bool, error)
	// UserExists reports whether the application user/role exists, with the
	// same read-only, false-on-unreachable semantics as DatabaseExists.
	UserExists(ctx context.Context, r bssh.Runner, user string) (bool, error)
```

`internal/database/mariadb.go` — add (plus `"strings"` import):

```go
// probeSQL runs a read-only scalar query inline (no secrets involved) and
// reports whether it returned "1". A non-zero exit is false, nil.
func probeSQL(ctx context.Context, r bssh.Runner, query string) (bool, error) {
	res, err := r.Run(ctx, `mysql --protocol=socket -N -e "`+query+`"`, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0 && strings.TrimSpace(res.Stdout) == "1", nil
}

// DatabaseExists probes information_schema for the database. name is a
// validated SQL identifier (config.Validate) — no quotes or metacharacters.
func (MariaDB) DatabaseExists(ctx context.Context, r bssh.Runner, name string) (bool, error) {
	return probeSQL(ctx, r, "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+name+"'")
}

// UserExists probes mysql.user for the '<user>'@'localhost' account EnsureUser creates.
func (MariaDB) UserExists(ctx context.Context, r bssh.Runner, user string) (bool, error) {
	return probeSQL(ctx, r, "SELECT 1 FROM mysql.user WHERE User='"+user+"' AND Host='localhost'")
}
```

`internal/database/postgres.go` — add (plus `"strings"` import):

```go
// probePSQL runs a read-only scalar query as the postgres superuser (peer
// auth) and reports whether it returned "1". A non-zero exit is false, nil.
func probePSQL(ctx context.Context, r bssh.Runner, query string) (bool, error) {
	res, err := r.Run(ctx, `sudo -u postgres psql -tAc "`+query+`"`, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0 && strings.TrimSpace(res.Stdout) == "1", nil
}

// DatabaseExists probes pg_database. name is a validated SQL identifier.
func (Postgres) DatabaseExists(ctx context.Context, r bssh.Runner, name string) (bool, error) {
	return probePSQL(ctx, r, "SELECT 1 FROM pg_database WHERE datname='"+name+"'")
}

// UserExists probes pg_roles for the login role EnsureUser creates.
func (Postgres) UserExists(ctx context.Context, r bssh.Runner, user string) (bool, error) {
	return probePSQL(ctx, r, "SELECT 1 FROM pg_roles WHERE rolname='"+user+"'")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/database/ && go build ./...`
Expected: PASS; the build confirms nothing else implements `Engine` (only MariaDB/Postgres register).

- [ ] **Step 5: Commit**

```bash
git add internal/database/engine.go internal/database/mariadb.go internal/database/postgres.go internal/database/mariadb_test.go internal/database/postgres_test.go
git commit -m "feat(database): read-only DatabaseExists/UserExists probes per engine

Both use the engine's admin transport (MariaDB root over the unix socket,
Postgres peer auth via sudo -u postgres), inline validated identifiers, and
report false on a non-zero exit so an unreachable server reads as
'cannot confirm' rather than an error.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Check probes real state

**Files:**
- Modify: `internal/provision/steps/database.go` (`Check` + `changes`)
- Test: `internal/provision/steps/database_test.go`

**Interfaces:**
- Consumes: Task 1's `eng.DatabaseExists` / `eng.UserExists`.
- Produces: Check unsatisfied-reasons Task 4's live validation greps for: `"database for <domain> missing"`, `"database user for <domain> missing"`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/provision/steps/database_test.go` (note: `databaseServer()` has legacy top-level `Database{Name: "myapp", User: "myapp"}`, so `SiteDBName`/`SiteDBUser` are both `myapp`):

```go
const (
	mariadbDBProbe   = `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='myapp'"`
	mariadbUserProbe = `mysql --protocol=socket -N -e "SELECT 1 FROM mysql.user WHERE User='myapp' AND Host='localhost'"`
)

func TestDatabaseCheckUnsatisfiedWhenDatabaseMissing(t *testing.T) {
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present
	f.On(mariadbDBProbe, bssh.Result{Stdout: ""}) // database absent
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("a present .env must not satisfy Check when the database is missing")
	}
	if !strings.Contains(cr.Reason, "database for app.example.com missing") {
		t.Errorf("Reason = %q", cr.Reason)
	}
}

func TestDatabaseCheckUnsatisfiedWhenUserMissing(t *testing.T) {
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
	f.On(mariadbUserProbe, bssh.Result{Stdout: ""}) // role absent
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("a present database must not satisfy Check when the user is missing")
	}
	if !strings.Contains(cr.Reason, "database user for app.example.com missing") {
		t.Errorf("Reason = %q", cr.Reason)
	}
}

func TestDatabaseCheckSkipsProbesWhenNotInstalled(t *testing.T) {
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 1}) // not installed
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("missing server package must be unsatisfied")
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "mysql") {
			t.Fatalf("no probe may run without an installed server; saw %q", c.Cmd)
		}
	}
}
```

Update `TestDatabaseCheckSatisfiedDoesNotReseedExistingEnv`: add the two probe stubs so it still describes the satisfied state, and reword its comment (the no-reseed guarantee now lives in Apply's absent-only seeding, Task 3):

```go
func TestDatabaseCheckSatisfiedDoesNotReseedExistingEnv(t *testing.T) {
	// Once installed + .env + database + user are all present the step is
	// satisfied, so flipping valkey: true on an already-provisioned host does
	// NOT re-seed the Redis keys (and Apply never rewrites an existing .env).
	s := databaseServer()
	s.Valkey = true
	f := bssh.NewFakeRunner()
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
	f.On(mariadbUserProbe, bssh.Result{Stdout: "1\n"})
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected Satisfied (installed + .env + db + user present); got %+v", cr)
	}
}
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `go test -run 'TestDatabaseCheck' ./internal/provision/steps/`
Expected: `UnsatisfiedWhenDatabaseMissing` and `UnsatisfiedWhenUserMissing` FAIL (Check reports Satisfied today); `SkipsProbesWhenNotInstalled` may already pass (no probes exist yet); the updated reseed test passes.

- [ ] **Step 3: Implement**

Replace `Check` and `changes` in `internal/provision/steps/database.go`:

```go
func (d database) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		return provision.CheckResult{}, err
	}
	installed, err := pkgInstalled(ctx, r, eng.ServerPackage())
	if err != nil {
		return provision.CheckResult{}, err
	}
	// When an upstream source is configured, the engine's producer repo must be
	// registered; this makes a source switch (debian -> upstream) re-trigger Apply.
	sourceOK := true
	if s.Database.Source != "debian" {
		if repo, ok := eng.UpstreamRepo(); ok {
			sourceOK, err = fileExists(ctx, r, upstreamSourceList(repo))
			if err != nil {
				return provision.CheckResult{}, err
			}
		}
	}
	if !installed || !sourceOK {
		// No server to probe yet (or the wrong source): Apply reconciles.
		return d.unsatisfied(eng, "database server or configured source not yet provisioned"), nil
	}
	// The server is installed: every site needs its credential persisted AND
	// its database + user actually present. Probing real state (not just the
	// .env file) lets a re-run heal a provision that failed between the .env
	// write and EnsureUser.
	for _, site := range s.Sites {
		envExists, err := fileExists(ctx, r, sharedEnvPath(site))
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !envExists {
			return d.unsatisfied(eng, "credential for "+site.Domain+" not yet persisted"), nil
		}
		dbExists, err := eng.DatabaseExists(ctx, r, s.SiteDBName(site))
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !dbExists {
			return d.unsatisfied(eng, "database for "+site.Domain+" missing"), nil
		}
		userExists, err := eng.UserExists(ctx, r, s.SiteDBUser(site))
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !userExists {
			return d.unsatisfied(eng, "database user for "+site.Domain+" missing"), nil
		}
	}
	return provision.CheckResult{Satisfied: true, Reason: eng.ServerPackage() + " installed (" + s.Database.Source + "); per-site databases, users and credentials present"}, nil
}

// unsatisfied builds this step's standard not-yet-converged result.
func (d database) unsatisfied(eng dbpkg.Engine, reason string) provision.CheckResult {
	return provision.CheckResult{Satisfied: false, Reason: reason, Changes: d.changes(eng), Sensitive: true}
}

func (database) changes(eng dbpkg.Engine) []string {
	return []string{
		"install " + eng.ServerPackage(),
		"per site: persist DB credential to shared/.env (when absent), ensure database + user",
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/provision/steps/`
Expected: PASS (including `TestDatabaseCheckSourceMariaDBRequiresRepo` — the missing-repo case now returns unsatisfied before any probe).

- [ ] **Step 5: Commit**

```bash
git add internal/provision/steps/database.go internal/provision/steps/database_test.go
git commit -m "fix(database): Check probes that the database and user actually exist

.env presence was treated as proof of provisioning, so a run that failed
between the .env write and EnsureUser left a server every later run
reported Satisfied and never healed. Check now gates on installed+source,
then per site verifies .env, database, and user via the engine probes.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Apply seeds .env only when absent

**Files:**
- Modify: `internal/provision/steps/database.go` (`Apply`; replace `resolvePassword`/`resolveAppKey` with `passwordFromEnv`/`newPassword`)
- Test: `internal/provision/steps/database_test.go`

**Interfaces:**
- Consumes: Task 1's probes are NOT used here; `fileExists`, `seedSharedEnv`, `secret.AppKey`, `secret.Generate`, `reDBPassword`, `dbPasswordKey` all exist.
- Produces: error text Task 4's tests/live validation rely on: `<envpath> for <domain> exists but has no DB_PASSWORD; add one or remove the file to have berth re-seed it`.

- [ ] **Step 1: Adapt and write the failing tests**

In `internal/provision/steps/database_test.go`:

1. Add to EVERY fresh-path Apply test an explicit absent-env stub — FakeRunner ERRORS on any un-stubbed command (`FakeRunner: unstubbed command %q`, internal/ssh/fake.go), and Apply now calls `test -e <env>` first thing in the loop. In `TestDatabaseApplyGeneratesPersistsAndEnsures`, `TestDatabaseApplySeedsRedisWhenValkey`, `TestDatabaseApplyKeepsDatabaseDriverWithoutValkey`, `TestDatabaseApplySourceMariaDBAddsRepo` add:

```go
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
```

   In `TestDatabaseApplyPostgresFromPGDG` add the same line using that test's own server value. Remove now-dead `grep -m1 '^APP_KEY=' ...` stubs from these tests (resolveAppKey is deleted; a fresh seed always generates).

2. Replace `TestDatabaseApplyReusesExistingPasswordWithoutRotating` with the heal-path test:

```go
func TestDatabaseApplyHealsFromExistingEnvWithoutRewriting(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env already present
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Reused123\n"})
	f.On("mysql --protocol=socket", bssh.Result{})

	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, w := range f.Writes() {
		if w.Path == envPath(s) {
			t.Fatal("an existing shared/.env must never be rewritten")
		}
	}
	var sawEnsureUser bool
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "mysql") && strings.Contains(string(c.Stdin), "Reused123") {
			sawEnsureUser = true
		}
	}
	if !sawEnsureUser {
		t.Fatal("EnsureUser must re-sync the password read from the live .env")
	}
}
```

3. Delete `TestDatabaseApplyReusesExistingAppKeyWithoutRotating` (an absent env has no key to reuse; a present env is never rewritten, which preserves the key trivially).

4. Update `TestDatabaseApplyRejectsTamperedPassword` to stub the env as PRESENT (`test -e` → exit 0) so the tampered `DB_PASSWORD` flows through the env-present path; the expected error is unchanged (charset refusal).

5. Add the missing-password guard test:

```go
func TestDatabaseApplyFailsWhenExistingEnvLacksPassword(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // key absent
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "has no DB_PASSWORD") {
		t.Fatalf("err = %v, want the pointed no-DB_PASSWORD error", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "mysql") {
			t.Fatal("no SQL may run when the existing .env cannot supply the password")
		}
	}
}
```

- [ ] **Step 2: Run tests to verify the intended failures**

Run: `go test -run 'TestDatabaseApply' ./internal/provision/steps/`
Expected: the heal test FAILS (env is rewritten today — the anti-rewrite assertion fires) and the no-password test FAILS (today a fresh password is silently generated and Apply proceeds to un-stubbed commands, so the error does not contain "has no DB_PASSWORD"); the adapted fresh-path tests still pass — today's Apply never runs `test -e`, and an unused stub is harmless.

- [ ] **Step 3: Implement**

In `internal/provision/steps/database.go`, replace the per-site loop body of `Apply` and swap the two helpers:

```go
	for i, site := range s.Sites {
		dbName, dbUser := s.SiteDBName(site), s.SiteDBUser(site)
		envExists, err := fileExists(ctx, r, sharedEnvPath(site))
		if err != nil {
			return err
		}
		var pw string
		if envExists {
			// An existing .env is never rewritten: WriteFile is atomic, so a
			// present file is complete, and rewriting would clobber
			// operator-added keys and re-derive the positional REDIS_DB index.
			// The role's password must therefore come from the file the app reads.
			pw, err = d.passwordFromEnv(ctx, r, site)
			if err != nil {
				return err
			}
		} else {
			pw, err = newPassword(dbUser, cache)
			if err != nil {
				return err
			}
			appKey, err := secret.AppKey()
			if err != nil {
				return err
			}
			d.redactor.Add(appKey)
			// Persist FIRST (atomic), so a crash before EnsureUser still leaves a
			// recoverable secret on the host. i is the site's per-site Redis logical
			// DB index when Valkey is enabled.
			if err := d.seedSharedEnv(ctx, r, s, site, i, dbName, dbUser, pw, appKey, driver, host, port, socket); err != nil {
				return err
			}
		}
		d.redactor.Add(pw)
		if err := eng.EnsureDatabase(ctx, r, dbName); err != nil {
			return err
		}
		if err := eng.EnsureUser(ctx, r, dbUser, pw, dbName); err != nil {
			return err
		}
		cache[dbUser] = pw
	}
```

Replace `resolvePassword` and `resolveAppKey` with:

```go
// passwordFromEnv reads DB_PASSWORD from a site's existing shared/.env. The
// file is authoritative once present: a missing value is a hard error, because
// silently generating a new password would desync the role from the file the
// app reads. A reused password is re-validated against the allowed charset
// (defence-in-depth against a tampered env injecting SQL metacharacters).
func (d database) passwordFromEnv(ctx context.Context, r bssh.Runner, site config.Site) (string, error) {
	env := sharedEnvPath(site)
	res, err := r.Run(ctx, "grep -m1 '^"+dbPasswordKey+"=' "+shQuote(env), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode == 0 {
		if pw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(res.Stdout), dbPasswordKey+"=")); pw != "" {
			if !reDBPassword.MatchString(pw) {
				return "", fmt.Errorf("reused %s from %s is outside the allowed charset; refusing to use it", dbPasswordKey, env)
			}
			return pw, nil
		}
	}
	return "", fmt.Errorf("%s for %s exists but has no %s; add one or remove the file to have berth re-seed it", env, site.Domain, dbPasswordKey)
}

// newPassword returns the locally cached password for dbUser (a re-run whose
// seed crashed before reaching the host) or generates a fresh one.
func newPassword(dbUser string, cache map[string]string) (string, error) {
	if pw := cache[dbUser]; pw != "" {
		if !reDBPassword.MatchString(pw) {
			return "", fmt.Errorf("cached password for %s is outside the allowed charset; refusing to use it", dbUser)
		}
		return pw, nil
	}
	pw, err := secret.Generate(dbPasswordLen)
	if err != nil {
		return "", fmt.Errorf("generate database password: %w", err)
	}
	return pw, nil
}
```

Also delete the now-unused `appKeyKey` grep constant usage if nothing else references it (`appKeyKey` itself stays — `seedSharedEnv` uses it as a map key).

- [ ] **Step 4: Run the full suite**

Run: `go test ./... && go vet ./... && gofmt -l .`
Expected: all PASS, vet clean, gofmt silent.

- [ ] **Step 5: Commit**

```bash
git add internal/provision/steps/database.go internal/provision/steps/database_test.go
git commit -m "fix(database): never rewrite an existing shared/.env on Apply

A heal-run triggered by one broken site used to rewrite EVERY site's .env,
clobbering operator-added keys and re-deriving the positional REDIS_DB
index. Apply now seeds only an absent .env (WriteFile is atomic, so a
present file is complete); when the file exists, the role's password must
come from it — a missing DB_PASSWORD is a pointed error instead of a
silently generated password the file does not carry.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: whole-branch verification (controller-run)

**Files:** none (verification only)

- [ ] **Step 1: Full gate**

Run: `go test -race -count=1 ./... && go vet ./...`
Expected: PASS, vet clean.

- [ ] **Step 2: Live heal validation on the test box**

```bash
make build
# baseline: box is provisioned; second run must be all-Satisfied
./berth provision --no-tty servers/ovh.yml
# snapshot the healthy .env, then break the DB state the way the bug report describes
ssh -i ~/.ssh/<key> berth@ovh.onee.pl 'sudo cat /home/deploy/*/shared/.env' > /tmp/env-before  # adjust path to the site's deploy_path
ssh -i ~/.ssh/<key> berth@ovh.onee.pl "sudo mysql --protocol=socket -e \"DROP USER '<dbuser>'@'localhost'; FLUSH PRIVILEGES;\""
# heal: the run must report database as APPLIED (not satisfied), recreate the role, and touch nothing else
./berth provision --no-tty servers/ovh.yml
ssh -i ~/.ssh/<key> berth@ovh.onee.pl 'sudo cat /home/deploy/*/shared/.env' > /tmp/env-after
diff /tmp/env-before /tmp/env-after && echo ENV-UNTOUCHED
# converged: third run all-Satisfied
./berth provision --no-tty servers/ovh.yml
```

Expected: run 2 shows `apply database` with every other step `ok ... (already)`; the diff is empty; run 3 shows `ok database (already)`. Then run the integration suite once (`BERTH_TEST_SERVER=$(pwd)/servers/ovh.yml go test -tags integration -count=1 -timeout 60m ./test/integration/...`) — its app-user DB auth assertion proves the recreated role's password still matches the untouched `.env`.

- [ ] **Step 3: Roadmap bookkeeping (local only, never commit docs/)**

In `docs/improvement-roadmap.md` § "Design-review findings — 2026-07-02", prefix the `database.Check` bullet with `[FIXED fix/database-check-probe]`; note that absent-only seeding also defuses M5's renumbering for existing sites (M5's stable-derivation fix itself stays open).

# Tuning & Defaults Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close MEDIUM findings 1, 2 and 4: a RAM-bound guard before the MariaDB tuning restart, a pre-flight `--only tuning` refusal when Valkey is enabled but unprovisioned, and fail2ban defaults moved into `*Eff()` accessors.

**Architecture:** All three fixes ride the existing idempotent Step pipeline. The RAM guard is two remote-probe helpers plus a pure size parser in `steps/tuning.go`, called at the top of Check's MariaDB block (error, not unsatisfied) and again in Apply just before write+restart. The `--only` fix threads `Server.Valkey` into the `Tuning` constructor so `Requires()` names the `valkey` step. The fail2ban fix copies the exact Tuning/Backups accessor pattern in `internal/config`.

**Tech Stack:** Go 1.25, stdlib only (`strconv`, `strings`, `math` additions). Tests use the existing `bssh.FakeRunner` (exact-command-string stubs).

**Spec:** `docs/superpowers/specs/2026-07-03-tuning-defaults-hardening-design.md` (approved; Codex-reviewed).

## Global Constraints

- Branch: `fix/tuning-defaults-hardening` (already exists, spec committed).
- Never run `go mod tidy`; no new dependencies at all here.
- Public MIT repo: code, comments, commits English-only, no personal/host data.
- FakeRunner stubs EXACT command strings — step code must emit stable, matchable commands.
- Managed-marker mechanics (`templates.Render` / `checkManagedFile`) untouched: the fail2ban template and golden files must NOT change.
- Every commit message ends with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- NEVER `git push` — the user pushes manually (repo hook blocks it anyway).
- Verification trio for every task: `go test ./<touched packages>/...`, and at the end `test -z "$(gofmt -l .)"`, `go vet ./...`, `go test -race ./...`.

---

### Task 1: fail2ban `*Eff()` accessors, defaults out of `Load()`

**Files:**
- Modify: `internal/config/config.go` (Fail2ban struct comment ~line 30; consts+accessors after the struct ~line 38; delete three `SetDefault` lines ~354-356)
- Create: `internal/config/fail2ban_test.go`
- Modify: `internal/config/config_test.go:42-49` (`TestLoadFail2banDefaults`)
- Modify: `internal/provision/steps/hardening.go:28-29` (`renderFail2banJail` data)
- Modify: `internal/provision/steps/hardening_test.go` (one added render test)
- Modify: `internal/wizard/matrix_test.go:~975-980` (comment only)

**Interfaces:**
- Consumes: existing `config.Fail2ban{Bantime, Findtime string; Maxretry int}`.
- Produces: `func (f Fail2ban) BantimeEff() string`, `func (f Fail2ban) FindtimeEff() string`, `func (f Fail2ban) MaxretryEff() int` — later tasks don't depend on these, but `renderFail2banJail` does from this task on.

- [ ] **Step 1: Write the failing tests**

Create `internal/config/fail2ban_test.go` (mirrors `internal/config/tuning_test.go`):

```go
package config

import "testing"

func TestFail2banAccessorsDefaultWhenZero(t *testing.T) {
	var f Fail2ban // all zero -> defaults
	if got := f.BantimeEff(); got != "1h" {
		t.Errorf("BantimeEff() = %q, want 1h", got)
	}
	if got := f.FindtimeEff(); got != "10m" {
		t.Errorf("FindtimeEff() = %q, want 10m", got)
	}
	if got := f.MaxretryEff(); got != 5 {
		t.Errorf("MaxretryEff() = %d, want 5", got)
	}
	// Defensive: a negative maxretry (rejected by validate() on the Load path,
	// but literal callers bypass it) also falls back to the default.
	if got := (Fail2ban{Maxretry: -1}).MaxretryEff(); got != 5 {
		t.Errorf("MaxretryEff(-1) = %d, want 5", got)
	}
}

func TestFail2banAccessorsHonorOverrides(t *testing.T) {
	f := Fail2ban{Bantime: "2h", Findtime: "5m", Maxretry: 3}
	if got := f.BantimeEff(); got != "2h" {
		t.Errorf("BantimeEff() = %q, want 2h", got)
	}
	if got := f.FindtimeEff(); got != "5m" {
		t.Errorf("FindtimeEff() = %q, want 5m", got)
	}
	if got := f.MaxretryEff(); got != 3 {
		t.Errorf("MaxretryEff() = %d, want 3", got)
	}
}
```

Replace the body of `TestLoadFail2banDefaults` in `internal/config/config_test.go` (the fixture `testdata/defaults.yml` has no `fail2ban:` block — verified):

```go
func TestLoadFail2banDefaults(t *testing.T) {
	s, err := Load("testdata/defaults.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// Defaults live in the *Eff accessors, not in Load(): omitted fields stay
	// zero in the struct, and the accessors supply 1h/10m/5 at render time.
	if s.Fail2ban.Bantime != "" || s.Fail2ban.Findtime != "" || s.Fail2ban.Maxretry != 0 {
		t.Errorf("Load must not inject fail2ban defaults: %+v", s.Fail2ban)
	}
	if s.Fail2ban.BantimeEff() != "1h" || s.Fail2ban.FindtimeEff() != "10m" || s.Fail2ban.MaxretryEff() != 5 {
		t.Errorf("accessor defaults wrong: %q/%q/%d",
			s.Fail2ban.BantimeEff(), s.Fail2ban.FindtimeEff(), s.Fail2ban.MaxretryEff())
	}
}
```

Add to `internal/provision/steps/hardening_test.go` (the exact bug scenario: a literal Server with a zero-value Fail2ban must render the defaults, not empty strings and 0; add `strings` to the imports if not present):

```go
func TestRenderFail2banJailZeroValueUsesDefaults(t *testing.T) {
	got, err := renderFail2banJail(&config.Server{SSH: config.SSH{Port: 22}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bantime = 1h", "findtime = 10m", "maxretry = 5"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("zero-value jail render missing %q:\n%s", want, got)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/config/... ./internal/provision/steps/... 2>&1 | head -30`
Expected: compile error `s.Fail2ban.BantimeEff undefined` (and the accessor test file failing to build). That IS the failing state for a compile-time TDD step.

- [ ] **Step 3: Implement**

In `internal/config/config.go`, replace the `Fail2ban` struct comment:

```go
// Fail2ban holds the tunable knobs for berth's managed jail.local. bantime and
// findtime are a number optionally suffixed s/m/h/d/w (e.g. "1h", "10m");
// compound forms like "1h30m" are not supported. Zero/empty values mean "use
// the default"; defaults live in the *Eff accessors (NOT in Load() via
// SetDefault) so wizard ToServer() and literal Server callers that bypass
// Load() still render valid, non-empty values into jail.local.
```

Directly after the `Fail2ban` struct, add (mirroring the Tuning consts/accessors):

```go
const (
	defaultFail2banBantime  = "1h"
	defaultFail2banFindtime = "10m"
	defaultFail2banMaxretry = 5
)

// BantimeEff returns the configured bantime or the default ("1h").
func (f Fail2ban) BantimeEff() string {
	if f.Bantime == "" {
		return defaultFail2banBantime
	}
	return f.Bantime
}

// FindtimeEff returns the configured findtime or the default ("10m").
func (f Fail2ban) FindtimeEff() string {
	if f.Findtime == "" {
		return defaultFail2banFindtime
	}
	return f.Findtime
}

// MaxretryEff returns the configured maxretry or the default (5).
func (f Fail2ban) MaxretryEff() int {
	if f.Maxretry <= 0 {
		return defaultFail2banMaxretry
	}
	return f.Maxretry
}
```

In `Load()` (~line 354), DELETE these three lines:

```go
	v.SetDefault("fail2ban.bantime", "1h")
	v.SetDefault("fail2ban.findtime", "10m")
	v.SetDefault("fail2ban.maxretry", 5)
```

In `internal/provision/steps/hardening.go` `renderFail2banJail`, change the data fields:

```go
		Bantime: s.Fail2ban.BantimeEff(), Findtime: s.Fail2ban.FindtimeEff(),
		Maxretry: s.Fail2ban.MaxretryEff(), SSHPort: s.SSH.Port,
```

In `internal/wizard/matrix_test.go` (~line 975), replace the stale comment sentences:

```go
		// The scenario's intent: an all-empty advanced gate round-trips and relies
		// on runtime defaults. The genuinely-empty artifact is the YAML on disk: the
		// fail2ban/tuning keys are omitted (omitempty over an all-zero block), and
		// the SSH fingerprint is omitted (TOFU). Loaded fail2ban fields stay zero —
		// the defaults (1h/10m/5) come from the *Eff accessors at render time, same
		// as tuning — so we assert the empty state on the on-disk YAML, and the
		// validity/nil-scheduler on the loaded srv.
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/config/... ./internal/provision/steps/... ./internal/wizard/...`
Expected: all PASS. (jail.local content for Load()-based configs is byte-identical — the accessors return the same `1h`/`10m`/`5` SetDefault used to inject — so no hardening test may need content changes; if any hardening test fails, STOP and investigate rather than editing expectations.)

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/fail2ban_test.go internal/config/config_test.go internal/provision/steps/hardening.go internal/provision/steps/hardening_test.go internal/wizard/matrix_test.go
git commit -m "fix(config): fail2ban defaults move to *Eff accessors

A Server built by wizard ToServer() or as a literal rendered 'bantime = ' /
'maxretry = 0' into jail.local because the defaults lived only in
config.Load()'s SetDefault calls. Defaults now live in BantimeEff/
FindtimeEff/MaxretryEff (the Tuning/Backups pattern); rendered output for
Load()-based configs is byte-identical, so provisioned hosts see no drift.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: dynamic `Requires()` — `--only tuning` refuses when Valkey is unprovisioned

**Files:**
- Modify: `internal/provision/steps/tuning.go:20-28` (struct, constructor, Requires)
- Modify: `internal/provision/steps/registry.go:23` (`Tuning(s.Valkey)`)
- Modify: `internal/provision/steps/tuning_test.go` (21 existing `Tuning()` call sites + new tests)
- Modify: `internal/provision/steps/registry_test.go` (one added test)

**Interfaces:**
- Consumes: `provision.New`, `provision.Options{Only, DryRun}`, `provision.Step` (all existing).
- Produces: `func Tuning(valkey bool) provision.Step` — Task 3 and `registry.go` use this exact signature. `Tuning(true).Requires()` returns `["database", "valkey"]`; `Tuning(false).Requires()` returns `["database"]`. Check/Apply behavior does NOT depend on the flag (they gate on `s.Valkey` / `s.Database.Engine` as today).

- [ ] **Step 1: Write the failing tests**

In `internal/provision/steps/tuning_test.go`, replace `TestTuningRequiresDatabase` with:

```go
func TestTuningRequires(t *testing.T) {
	if got := Tuning(false).Requires(); len(got) != 1 || got[0] != "database" {
		t.Fatalf("Tuning(false).Requires() = %v, want [database]", got)
	}
	if got := Tuning(true).Requires(); len(got) != 2 || got[0] != "database" || got[1] != "valkey" {
		t.Fatalf("Tuning(true).Requires() = %v, want [database valkey]", got)
	}
}
```

Add the engine-gate integration tests to `internal/provision/steps/tuning_test.go` (package `steps` — `provision` and `bssh` are already imported; `gateStub` is a minimal `provision.Step`, no such type exists in the package yet — verified):

```go
// gateStub is a minimal provision.Step for exercising the --only dependency
// gate against the REAL tuning step: only Name and a fixed Check verdict matter.
type gateStub struct {
	name      string
	satisfied bool
}

func (s gateStub) Name() string       { return s.name }
func (s gateStub) Requires() []string { return nil }
func (s gateStub) Check(context.Context, provision.RunCtx, *config.Server, bssh.Runner) (provision.CheckResult, error) {
	return provision.CheckResult{Satisfied: s.satisfied, Reason: "stub"}, nil
}
func (s gateStub) Apply(context.Context, provision.RunCtx, *config.Server, bssh.Runner) error {
	return nil
}

func TestOnlyTuningRefusesWhenValkeyUnsatisfied(t *testing.T) {
	// valkey: true in config, but the valkey step is unsatisfied (never
	// provisioned): --only tuning must refuse pre-flight, not fail mid-Apply.
	eng := provision.New(
		gateStub{name: "database", satisfied: true},
		gateStub{name: "valkey", satisfied: false},
		Tuning(true),
	)
	_, err := eng.Run(context.Background(), valkeyOnlyServer(), bssh.NewFakeRunner(), provision.Options{Only: "tuning"})
	if err == nil || !strings.Contains(err.Error(), "valkey") {
		t.Fatalf("expected pre-flight refusal naming valkey; got %v", err)
	}
}

func TestOnlyTuningPassesWhenValkeySatisfied(t *testing.T) {
	eng := provision.New(
		gateStub{name: "database", satisfied: true},
		gateStub{name: "valkey", satisfied: true},
		Tuning(true),
	)
	f := bssh.NewFakeRunner()
	// Dry-run stops at Planned, so only tuning's own Check runs: valkey block,
	// drop-in absent -> unsatisfied -> Planned.
	f.On("cat '/etc/systemd/system/valkey-server.service.d/berth.conf'", bssh.Result{ExitCode: 1})
	events, err := eng.Run(context.Background(), valkeyOnlyServer(), f, provision.Options{Only: "tuning", DryRun: true})
	if err != nil {
		t.Fatalf("gate must pass when valkey is satisfied: %v", err)
	}
	for range events {
	} // drain until the pipeline goroutine closes the channel
}
```

Add to `internal/provision/steps/registry_test.go` (package `steps_test`; `contains` helper exists there):

```go
// TestPipelineTuningRequiresValkeyWhenEnabled pins that Pipeline threads
// Server.Valkey into the tuning constructor, not just that tuning is present.
func TestPipelineTuningRequiresValkeyWhenEnabled(t *testing.T) {
	s := &config.Server{Valkey: true, Database: config.Database{Engine: "postgres"}, Sites: []config.Site{{Domain: "a.example.com"}}}
	for _, st := range steps.Pipeline(s, nil, true) {
		if st.Name() == "tuning" {
			if !contains(st.Requires(), "valkey") {
				t.Errorf("tuning built by Pipeline(valkey=true) must require valkey; got %v", st.Requires())
			}
			return
		}
	}
	t.Fatal("tuning step missing from pipeline")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/provision/steps/... 2>&1 | head -20`
Expected: compile error `too many arguments in call to Tuning` (constructor still takes none).

- [ ] **Step 3: Implement**

In `internal/provision/steps/tuning.go`, replace lines 20-28 (struct, doc comment, constructor, Name, Requires):

```go
type tuning struct{ valkey bool }

// Tuning writes managed performance-tuning drop-ins for Valkey (systemd drop-in)
// and MariaDB (mariadb.conf.d), each gated on whether that service is provisioned.
// It runs after database so both services are installed. valkey mirrors
// Server.Valkey: when set, Requires() also names the valkey step so the --only
// gate refuses to tune a host whose Valkey was never provisioned (full runs are
// ordered by registration and unaffected).
func Tuning(valkey bool) provision.Step { return tuning{valkey: valkey} }

func (tuning) Name() string { return "tuning" }

func (t tuning) Requires() []string {
	if t.valkey {
		return []string{"database", "valkey"}
	}
	return []string{"database"}
}
```

In `internal/provision/steps/registry.go:23`:

```go
		steps = append(steps, Tuning(s.Valkey))
```

Mechanically update the remaining `Tuning()` call sites in `tuning_test.go` (21 before this task; the rule: pass the same value as the test server's `Valkey` field — the flag only affects `Requires()`, so this is semantic hygiene, not behavior):
- tests using `valkeyOnlyServer()` or a combined valkey+mariadb server → `Tuning(true)`
- tests using `mariadbOnlyServer()` or postgres/no-valkey servers → `Tuning(false)`

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/provision/... `
Expected: all PASS (engine package included — nothing there changed, but `provision.New` composition is exercised by the new gate tests).

- [ ] **Step 5: Commit**

```bash
git add internal/provision/steps/tuning.go internal/provision/steps/registry.go internal/provision/steps/tuning_test.go internal/provision/steps/registry_test.go
git commit -m "fix(tuning): --only tuning pre-flight-requires the valkey step when enabled

tuning.Requires() was a static [database], so --only tuning with valkey: true
on a host whose valkey step never ran passed the dependency gate and died
mid-Apply at systemctl restart valkey-server. Pipeline now threads
Server.Valkey into the constructor and Requires() names valkey, so the gate
refuses pre-flight with 'unmet prerequisites: [valkey]'. The MariaDB block
was already covered: database.Check requires the engine server installed.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: RAM-bound guard before the MariaDB tuning write+restart

**Files:**
- Modify: `internal/provision/steps/tuning.go` (new consts + three helpers; Check MariaDB block; Apply MariaDB block; imports gain `math`, `strconv`, `strings`)
- Modify: `internal/provision/steps/tuning_test.go` (new tests + MemTotal stubs in existing MariaDB-block tests)

**Interfaces:**
- Consumes: `Tuning(valkey bool)` from Task 2; `config.Tuning.MariaDBBufferPoolEff() string` (existing); `bssh.Runner`, `bssh.Result` (existing).
- Produces (all unexported, package `steps`): `const memTotalCmd = "awk '/^MemTotal:/{print $2}' /proc/meminfo"`, `parseMariaDBSize(v string) (uint64, error)`, `hostMemTotalBytes(ctx context.Context, r bssh.Runner) (uint64, error)`, `checkMariaDBBufferPoolFits(ctx context.Context, r bssh.Runner, s *config.Server) error`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/provision/steps/tuning_test.go`:

```go
func TestParseMariaDBSize(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"268435456", 268435456, true}, // bare bytes
		{"64K", 64 << 10, true},
		{"256M", 256 << 20, true},
		{"2G", 2 << 30, true},
		// MariaDB accepts lowercase suffixes; literal-Server callers bypass the
		// uppercase-only reMariaDBSize, so the parser must not false-reject.
		{"1k", 1 << 10, true},
		{"256m", 256 << 20, true},
		{"1g", 1 << 30, true},
		{"99999999999G", 0, false}, // overflows uint64
		{"", 0, false},
		{"G", 0, false},   // suffix without digits
		{"12Q", 0, false}, // unknown suffix
		{"12.5M", 0, false},
	} {
		got, err := parseMariaDBSize(tc.in)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("parseMariaDBSize(%q) = %d, %v; want %d, nil", tc.in, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Errorf("parseMariaDBSize(%q) = %d, nil; want error", tc.in, got)
		}
	}
}

func TestTuningMariaDBBufferPoolGuardBoundaries(t *testing.T) {
	// MemTotal 1000000 kB = 1024000000 bytes; limit = 1024000000/100*80 =
	// 819200000. Exactly the limit passes; one byte over errors.
	for _, tc := range []struct {
		pool string
		ok   bool
	}{
		{"819200000", true},
		{"819200001", false},
	} {
		srv := mariadbOnlyServer()
		srv.Tuning.MariaDBBufferPool = tc.pool
		f := bssh.NewFakeRunner()
		f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1000000\n"})
		if tc.ok {
			// Fitting value: Check proceeds to the normal file probe.
			f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 1})
		}
		cr, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f)
		if tc.ok {
			if err != nil {
				t.Fatalf("pool %s: unexpected error: %v", tc.pool, err)
			}
			if cr.Satisfied {
				t.Errorf("pool %s: expected unsatisfied (file absent)", tc.pool)
			}
		} else if err == nil {
			t.Errorf("pool %s: expected guard error", tc.pool)
		}
	}
}

func TestTuningMariaDBGuardBadMemTotal(t *testing.T) {
	for _, out := range []string{"", "banana"} {
		srv := mariadbOnlyServer()
		f := bssh.NewFakeRunner()
		f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: out})
		if _, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f); err == nil {
			t.Errorf("MemTotal output %q: expected error, got nil", out)
		}
	}
}

func TestTuningCheckMariaDBOverLimitErrorsEvenWhenDeployed(t *testing.T) {
	// Accepted behavior change pinned: a host already running with an
	// over-limit drop-in fails Check on every run until the value is lowered.
	// The guard fires before the file is even consulted.
	srv := mariadbOnlyServer()
	srv.Tuning.MariaDBBufferPool = "2G"
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"}) // 1 GiB
	if _, err := Tuning(false).Check(context.Background(), provision.RunCtx{}, srv, f); err == nil {
		t.Fatal("expected guard error for 2G pool on a 1 GiB host")
	}
	if calledCmd(f, "cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'") {
		t.Error("guard must fire before the managed-file probe")
	}
}

func TestTuningApplyMariaDBOverLimitNoWriteNoRestart(t *testing.T) {
	// Config raised above the limit while an old, fitting managed drop-in is
	// on disk: Apply must error BEFORE any write or restart.
	srv := mariadbOnlyServer()
	srv.Tuning.MariaDBBufferPool = "2G"
	old, err := renderMariaDBTuning(mariadbOnlyServer()) // default 256M content
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(old)})
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"}) // 1 GiB
	if err := Tuning(false).Apply(context.Background(), provision.RunCtx{}, srv, f); err == nil {
		t.Fatal("expected guard error from Apply")
	}
	if len(f.Writes()) != 0 {
		t.Errorf("Apply must not write anything past a failing guard: %+v", f.Writes())
	}
	if calledCmd(f, "systemctl restart mariadb.service") {
		t.Error("Apply must not restart mariadb past a failing guard")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/provision/steps/... 2>&1 | head -20`
Expected: compile error `undefined: parseMariaDBSize` (and `memTotalCmd`).

- [ ] **Step 3: Implement**

In `internal/provision/steps/tuning.go`, extend the imports:

```go
import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)
```

Add below the existing consts:

```go
// mariadbBufferPoolMaxPercent caps innodb_buffer_pool_size at this share of
// the host's MemTotal. A pool that exceeds physical RAM makes mariadbd fail
// at startup (the failure is allocation, so no config parser can catch it)
// and the poison drop-in would fail every subsequent run identically. The
// threshold is a conservative sanity policy, not a startup guarantee: it
// ignores cgroup limits and co-resident workload memory.
const mariadbBufferPoolMaxPercent = 80

const memTotalCmd = `awk '/^MemTotal:/{print $2}' /proc/meminfo`

// parseMariaDBSize converts a MariaDB size value — bare bytes or a K/M/G
// suffix (1024-based, case-insensitive; MariaDB itself accepts lowercase and
// literal-Server callers bypass the uppercase-only reMariaDBSize) — to bytes.
func parseMariaDBSize(v string) (uint64, error) {
	num, mult := v, uint64(1)
	if len(v) > 0 {
		switch v[len(v)-1] {
		case 'K', 'k':
			num, mult = v[:len(v)-1], 1<<10
		case 'M', 'm':
			num, mult = v[:len(v)-1], 1<<20
		case 'G', 'g':
			num, mult = v[:len(v)-1], 1<<30
		}
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q is not a number with an optional K/M/G suffix", v)
	}
	if n > math.MaxUint64/mult {
		return 0, fmt.Errorf("size %q overflows", v)
	}
	return n * mult, nil
}

// hostMemTotalBytes reads the host's MemTotal from /proc/meminfo. An empty or
// unparsable value is an error, never zero — the guard below must fail loud
// rather than wave an oversized pool through.
func hostMemTotalBytes(ctx context.Context, r bssh.Runner) (uint64, error) {
	res, err := r.Run(ctx, memTotalCmd, nil)
	if err != nil {
		return 0, err
	}
	out := strings.TrimSpace(res.Stdout)
	if res.ExitCode != 0 || out == "" {
		return 0, fmt.Errorf("cannot determine host RAM: %s", res.Stderr)
	}
	kb, err := strconv.ParseUint(out, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot determine host RAM: MemTotal %q: %w", out, err)
	}
	if kb > math.MaxUint64/1024 {
		return 0, fmt.Errorf("cannot determine host RAM: MemTotal %q overflows", out)
	}
	return kb * 1024, nil
}

// checkMariaDBBufferPoolFits errors when the configured (or default)
// innodb_buffer_pool_size exceeds mariadbBufferPoolMaxPercent of host RAM.
// Overflow-safe: divide before multiplying; the sub-1% truncation is noise.
func checkMariaDBBufferPoolFits(ctx context.Context, r bssh.Runner, s *config.Server) error {
	val := s.Tuning.MariaDBBufferPoolEff()
	pool, err := parseMariaDBSize(val)
	if err != nil {
		return fmt.Errorf("tuning.mariadb_innodb_buffer_pool: %w", err)
	}
	total, err := hostMemTotalBytes(ctx, r)
	if err != nil {
		return err
	}
	if pool > total/100*mariadbBufferPoolMaxPercent {
		return fmt.Errorf("tuning.mariadb_innodb_buffer_pool %s exceeds %d%% of host RAM (MemTotal %d MiB); lower it",
			val, mariadbBufferPoolMaxPercent, total/(1<<20))
	}
	return nil
}
```

In `Check`, add the guard at the TOP of the MariaDB block (before rendering — it must run even when everything is satisfied, so an already-deployed over-limit drop-in fails loud every run):

```go
	if s.Database.Engine == "mariadb" {
		if err := checkMariaDBBufferPoolFits(ctx, r, s); err != nil {
			return provision.CheckResult{}, err
		}
		want, err := renderMariaDBTuning(s)
		// ... rest of the block unchanged ...
```

In `Apply`, add the guard inside the MariaDB `if !ok {` branch, immediately before the WriteFile+restart pair (repo convention: validate-before-reload lives in Apply):

```go
		if !ok {
			if err := checkMariaDBBufferPoolFits(ctx, r, s); err != nil {
				return err
			}
			if err := r.WriteFile(ctx, bssh.FileSpec{Path: mariadbTuningPath, Content: cfg, Owner: "root", Group: "root", Mode: 0o644, Sudo: true}); err != nil {
			// ... rest unchanged ...
```

- [ ] **Step 4: Run and stub the existing MariaDB-block tests**

Run: `go test ./internal/provision/steps/... 2>&1 | head -40`
Expected: the new tests PASS; existing MariaDB-block tests FAIL with `FakeRunner: unstubbed command "awk '/^MemTotal:/{print $2}' /proc/meminfo"`. Add this stub line to each (1 GiB — the default 256M pool fits):

```go
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
```

Known list (the FakeRunner error names any missed one — fix all it surfaces):
- `TestTuningCheckMariaDBSatisfiedWhenLoaded`
- `TestTuningCheckMariaDBUnsatisfiedWhenNotLoaded`
- `TestTuningCheckMariaDBUnsatisfiedWhenAbsent`
- `TestTuningCheckCombinedSatisfiedWhenBothLoaded`
- `TestTuningApplyMariaDBWritesDropInRestarts`
- `TestTuningApplyCombinedWritesBothRestartsBoth`
- `TestTuningApplyCombinedOnlyMariaDBDriftedRestartsOnlyMariaDB`

(`TestTuningApplyCombinedOnlyValkeyDriftedRestartsOnlyValkey` should NOT need it — its MariaDB block is satisfied, so Apply never reaches the guard. If it fails, the guard is in the wrong place: STOP and re-check Step 3 rather than stubbing.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/provision/... ./internal/config/...`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/provision/steps/tuning.go internal/provision/steps/tuning_test.go
git commit -m "fix(tuning): guard MariaDB buffer pool against host RAM before restart

tuning restarted mariadb with no validation; an innodb_buffer_pool_size
larger than host RAM (format-checked only, never against the host) kills
mariadbd at startup and the poison drop-in made every later run fail
identically. Check now errors (before anything reaches disk, visible in
dry-run) and Apply re-checks right before write+restart, when the pool
exceeds 80% of MemTotal. The threshold is a conservative sanity policy, not
a startup guarantee. Valkey stays unguarded on purpose: maxmemory is an
eviction limit, not an allocation.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Full verification + Codex diff review

**Files:** none new (fixes only if review/verification surfaces problems).

- [ ] **Step 1: Full local verification**

```bash
test -z "$(gofmt -l .)" && echo FMT-OK
go vet ./...
go test -race ./...
```

Expected: `FMT-OK`, vet silent, all tests pass. Golden files must show NO diff (`git status` clean apart from committed work) — no template changed in this package.

- [ ] **Step 2: Codex foreground review of the full diff**

Write a prompt file to the scratchpad asking for a correctness review of `git diff main...HEAD` against the spec `docs/superpowers/specs/2026-07-03-tuning-defaults-hardening-design.md`, then run:

```bash
codex exec --skip-git-repo-check < <scratchpad>/codex-diff-review.md
```

Verify each finding against the code before acting on it (standing project discipline). Fix confirmed problems, re-run Step 1, commit fixes.

- [ ] **Step 3 (optional, user-driven): live sanity on the disposable test box**

`berth provision --only tuning` against the current test server (MariaDB
config): expect either all-Satisfied or a clean apply; then a second run
all-Satisfied. Skip if the box is not currently provisioned.

- [ ] **Step 4: Prepare the PR (user pushes manually)**

Prepare the PR title/body (English; body ends with the standard generated-with footer). Branch: `fix/tuning-defaults-hardening` → `main`. Do NOT push — tell the user to run `! git push -u origin fix/tuning-defaults-hardening` and open the PR (or `gh pr create` after their push).

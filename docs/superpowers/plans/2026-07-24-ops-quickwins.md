# Ops Quick-Wins Iteration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Four small operational features in one iteration: declarative `system.hostname`, per-site DB client-credentials file (`~/.my.cnf` / `~/.pgpass`), MariaDB slow-query-log tuning knobs, and a `berth site key` command that prints a site's git deploy public key.

**Architecture:** All four reuse existing patterns 1:1 — hostname mirrors the `system` step's timezone knob (plus a marked `/etc/hosts` alias line mirroring the fstab swap line); the credentials file follows the `shared/.env` seed-if-absent pattern in the `database` step via a new `Engine` interface method; slow log is a conditional block in the existing `mariadb_tuning.cnf.tmpl` (byte-identical when off → no drift on existing hosts); `site key` is a read-only cobra subcommand with the SSH-independent logic factored out for FakeRunner tests.

**Tech Stack:** Go 1.25, cobra, huh v2 (`charm.land/huh/v2`), FakeRunner (`internal/ssh/fake.go`), golden templates (`go test ./internal/templates/... -update`).

## Global Constraints

- Public MIT repo: code, comments, commits **English-only**, no personal/host-identifying data.
- **Never run `go mod tidy`** (prunes Charm v2 deps); no new deps are needed anyway.
- Every config struct field needs **both** `mapstructure` and `yaml` tags.
- Defaults for wizard/literal-Server compatibility live in `*Eff` accessors, **NOT** `SetDefault`.
- Steps must emit **stable, exactly matchable command strings** (FakeRunner `On(...)` stubs exact strings).
- Secrets go via `stdin` or `WriteFile` content, never into command strings; `Check` must stay secret-free (exit-code/existence probes only).
- Managed files with drift detection use `templates.Render` (marker); **seed-if-absent secret files (like `shared/.env`) carry NO marker and are never rewritten**.
- After editing a `.tmpl`: `go test ./internal/templates/... -update`, then **diff the goldens** and commit them.
- Branch: `feat/ops-quickwins` off up-to-date `main`. Commit per task. **Never `git push`** (hook blocks it; the user pushes manually).
- Commits end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 0: Branch

- [ ] **Step 0.1:** `git checkout -b feat/ops-quickwins main` (working tree is clean, local main == origin after the v0.12.0 release).

---

### Task 1: Config — `system.hostname` + MariaDB slow-log knobs

**Files:**
- Modify: `internal/config/config.go` (System struct ~line 225, Tuning struct ~line 83, defaults const block ~line 93)
- Modify: `internal/config/validate.go` (`System.validate` ~line 353, `Tuning.validate` ~line 319)
- Test: `internal/config/validate_test.go` (or `config_test.go` — put new tests next to existing `System`/`Tuning` tests)

**Interfaces:**
- Produces: `config.System.Hostname string`, `config.Tuning.MariaDBSlowQueryLog bool`, `config.Tuning.MariaDBLongQueryTime int`, `config.Tuning.MariaDBLongQueryTimeEff() int` (default 2). Later tasks (system step, tuning step, wizard) consume exactly these names.

- [ ] **Step 1.1: Write failing tests** (same package `config`, direct method calls — no server fixture needed):

```go
func TestSystemValidateHostname(t *testing.T) {
	if err := (System{Hostname: "web-1.example.com"}).validate(); err != nil {
		t.Fatalf("valid hostname rejected: %v", err)
	}
	if err := (System{}).validate(); err != nil {
		t.Fatalf("empty hostname must pass: %v", err)
	}
	if err := (System{Hostname: strings.Repeat("a", 65)}).validate(); err == nil {
		t.Error("hostname longer than 64 chars must be rejected (kernel HOST_NAME_MAX)")
	}
	if err := (System{Hostname: "bad host"}).validate(); err == nil {
		t.Error("hostname with a space must be rejected")
	}
	if err := (System{Hostname: "-bad.example.com"}).validate(); err == nil {
		t.Error("label starting with '-' must be rejected")
	}
}

func TestTuningValidateSlowQueryLog(t *testing.T) {
	if err := (Tuning{MariaDBSlowQueryLog: true}).validate(); err != nil {
		t.Fatalf("slow log alone must pass: %v", err)
	}
	if err := (Tuning{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: 5}).validate(); err != nil {
		t.Fatalf("slow log + threshold must pass: %v", err)
	}
	if err := (Tuning{MariaDBLongQueryTime: 5}).validate(); err == nil {
		t.Error("long_query_time without slow_query_log must be rejected (silently-ignored knob = config lie)")
	}
	if err := (Tuning{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: 100000}).validate(); err == nil {
		t.Error("long_query_time above 86400 must be rejected")
	}
	if err := (Tuning{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: -1}).validate(); err == nil {
		t.Error("negative long_query_time must be rejected")
	}
}

func TestTuningMariaDBLongQueryTimeEff(t *testing.T) {
	if got := (Tuning{}).MariaDBLongQueryTimeEff(); got != 2 {
		t.Errorf("default long_query_time = %d, want 2", got)
	}
	if got := (Tuning{MariaDBLongQueryTime: 10}).MariaDBLongQueryTimeEff(); got != 10 {
		t.Errorf("explicit long_query_time = %d, want 10", got)
	}
}
```

(`strings` may need adding to the test file's imports.)

- [ ] **Step 1.2:** Run: `go test -run 'TestSystemValidateHostname|TestTuningValidateSlowQueryLog|TestTuningMariaDBLongQueryTimeEff' ./internal/config/` — expect FAIL (fields undefined).

- [ ] **Step 1.3: Implement.** In `config.go`:

System struct — add field (keep tag alignment style):

```go
	Hostname string `mapstructure:"hostname" yaml:"hostname,omitempty"` // static hostname; empty = leave untouched
```

Also extend the System doc comment sentence about Timezone to cover Hostname (same no-revert semantics: "clearing Hostname/Timezone drift-removes nothing").

Tuning struct — add after `MariaDBBufferPool`:

```go
	MariaDBSlowQueryLog  bool   `mapstructure:"mariadb_slow_query_log" yaml:"mariadb_slow_query_log,omitempty"`
	MariaDBLongQueryTime int    `mapstructure:"mariadb_long_query_time" yaml:"mariadb_long_query_time,omitempty"`
```

Const block: add `defaultMariaDBLongQueryTime = 2`.

Accessor (next to `MariaDBBufferPoolEff`):

```go
// MariaDBLongQueryTimeEff returns the slow-query threshold in seconds or the
// default (2). Non-positive means "unset" (the MaxretryEff precedent). Only
// rendered when MariaDBSlowQueryLog is true.
func (t Tuning) MariaDBLongQueryTimeEff() int {
	if t.MariaDBLongQueryTime <= 0 {
		return defaultMariaDBLongQueryTime
	}
	return t.MariaDBLongQueryTime
}
```

In `validate.go`, `System.validate` — add before the final `return nil`:

```go
	if sy.Hostname != "" {
		if len(sy.Hostname) > 64 {
			return fmt.Errorf("system.hostname %q exceeds 64 characters (the kernel HOST_NAME_MAX)", sy.Hostname)
		}
		if !reHostname.MatchString(sy.Hostname) {
			return fmt.Errorf("system.hostname %q is not a valid hostname", sy.Hostname)
		}
	}
```

`Tuning.validate` — add before the final `return nil`:

```go
	if t.MariaDBLongQueryTime != 0 && (t.MariaDBLongQueryTime < 1 || t.MariaDBLongQueryTime > 86400) {
		return fmt.Errorf("tuning.mariadb_long_query_time %d out of range (1-86400 s)", t.MariaDBLongQueryTime)
	}
	if t.MariaDBLongQueryTime != 0 && !t.MariaDBSlowQueryLog {
		return fmt.Errorf("tuning.mariadb_long_query_time is set but tuning.mariadb_slow_query_log is false; enable the slow log or remove the threshold")
	}
```

- [ ] **Step 1.4:** Run: `go test ./internal/config/` — expect PASS.

- [ ] **Step 1.5: Commit** `feat(config): system.hostname + mariadb slow-query-log tuning knobs`.

---

### Task 2: `system` step — managed static hostname

**Files:**
- Modify: `internal/provision/steps/system.go`
- Test: `internal/provision/steps/system_test.go`

**Interfaces:**
- Consumes: `s.System.Hostname` (Task 1), existing helpers `catTrim`, `runOK`, `shQuote`, `managedMarker`.
- Produces: hostname handling inside the existing `system` step (no new step, no pipeline change).

**Design (locked):**
- Check probe: `hostnamectl --static`; set: `hostnamectl set-hostname '<name>'`.
- `/etc/hosts`: berth owns the `127.0.1.1` alias line (Debian convention so sudo/name lookups resolve the hostname without DNS). Exactly one marked line `127.0.1.1 <fqdn> <short> # managed by berth` (`<short>` = first dot-label, omitted when the name has no dot). Unlike the fstab swap line, a foreign `127.0.1.1` line is **replaced without --force**: that address exists solely to alias the local hostname, and once the operator declares `system.hostname` the old alias is stale by definition.
- No removal branch (timezone precedent): clearing the knob stops managing; the marked line stays (it still names the host).

- [ ] **Step 2.1: Write failing tests** (append to `system_test.go`; the baseline stubs mirror the timezone tests exactly):

```go
func TestSystemCheckHostnameMismatchUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "debian\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.0.1 localhost\n127.0.1.1 debian\n"})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the static hostname differs from system.hostname")
	}
}

func TestSystemCheckHostnameSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "web-1.example.com\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.0.1 localhost\n127.0.1.1 web-1.example.com web-1 # managed by berth\n"})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when hostname and hosts alias match; got %+v", cr)
	}
}

func TestSystemCheckHostnameHostsLineMissingUnsatisfied(t *testing.T) {
	// Hostname already set but berth's marked alias line absent -> still work to do.
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "web-1.example.com\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.0.1 localhost\n127.0.1.1 debian\n"})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while the marked 127.0.1.1 alias line is missing")
	}
}

func TestSystemHostnameUnsetNeverProbed(t *testing.T) {
	// Empty knob = berth never reads or writes the hostname on either path.
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	if _, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatal(err)
	}
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "hostnamectl") {
			t.Errorf("unset hostname must not run hostnamectl; ran %q", c.Cmd)
		}
	}
}

func TestSystemApplyHostnameSetsAndRewritesHosts(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "debian\n"})
	f.On("hostnamectl set-hostname 'web-1.example.com'", bssh.Result{})
	// A foreign 127.0.1.1 line (the image's default alias) is replaced WITHOUT --force.
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.0.1 localhost\n127.0.1.1 debian\n"})
	f.On(`sed -i '\|^[[:space:]]*127\.0\.1\.1[[:space:]]|d' /etc/hosts`, bssh.Result{})
	f.On("printf '\\n%s\\n' '127.0.1.1 web-1.example.com web-1 # managed by berth' >> /etc/hosts", bssh.Result{})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, "hostnamectl set-hostname 'web-1.example.com'") {
		t.Error("expected hostnamectl set-hostname")
	}
	if !calledCmd(f, "printf '\\n%s\\n' '127.0.1.1 web-1.example.com web-1 # managed by berth' >> /etc/hosts") {
		t.Error("expected the marked 127.0.1.1 alias appended")
	}
}

func TestSystemApplyHostnameNoopWhenSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "web-1.example.com\n"})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.1.1 web-1.example.com web-1 # managed by berth\n"})
	s := &config.Server{System: config.System{Hostname: "web-1.example.com"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "set-hostname") || strings.Contains(c.Cmd, "sed -i '\\|^[[:space:]]*127\\.") {
			t.Errorf("satisfied hostname must not mutate; ran %q", c.Cmd)
		}
	}
}

func TestSystemApplyHostnameShortNameNoDot(t *testing.T) {
	// A single-label hostname gets no short alias (no duplicate token).
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("hostnamectl --static", bssh.Result{ExitCode: 0, Stdout: "debian\n"})
	f.On("hostnamectl set-hostname 'web1'", bssh.Result{})
	f.On("cat '/etc/hosts'", bssh.Result{ExitCode: 0, Stdout: "127.0.0.1 localhost\n"})
	f.On(`sed -i '\|^[[:space:]]*127\.0\.1\.1[[:space:]]|d' /etc/hosts`, bssh.Result{})
	f.On("printf '\\n%s\\n' '127.0.1.1 web1 # managed by berth' >> /etc/hosts", bssh.Result{})
	s := &config.Server{System: config.System{Hostname: "web1"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, "printf '\\n%s\\n' '127.0.1.1 web1 # managed by berth' >> /etc/hosts") {
		t.Error("expected the single-label alias line appended without a short duplicate")
	}
}
```

- [ ] **Step 2.2:** Run: `go test -run 'TestSystem.*Hostname' ./internal/provision/steps/` — expect FAIL.

- [ ] **Step 2.3: Implement** in `system.go`.

Constants (next to `fstabPath`):

```go
	hostsPath = "/etc/hosts"
```

Next to `fstabSedAny`:

```go
// hostsSedLocalAlias deletes ANY 127.0.1.1 alias line; used before appending
// berth's marked line. Unlike fstab's swap line this takeover needs no --force:
// 127.0.1.1 exists solely to alias the local hostname (Debian convention), so
// once system.hostname is declared any previous alias is stale by definition.
const hostsSedLocalAlias = `\|^[[:space:]]*127\.0\.1\.1[[:space:]]|d`
```

Helpers (place after `checkTimezone`/`applyTimezone`):

```go
// hostsHostnameLine is the exact /etc/hosts alias line berth manages for the
// configured static hostname: FQDN plus its short (first-label) alias, ending
// with the managed marker as the ownership signal (the fstabSwapLine pattern).
func hostsHostnameLine(hostname string) string {
	names := hostname
	if short, _, ok := strings.Cut(hostname, "."); ok && short != "" {
		names = hostname + " " + short
	}
	return "127.0.1.1 " + names + " " + managedMarker
}

// hostsAliasPresent reports whether berth's exact marked alias line for
// hostname is present (whitespace-trimmed match, like fstabSwapState).
func hostsAliasPresent(content, hostname string) bool {
	want := hostsHostnameLine(hostname)
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// checkHostname is the read-only predicate for a managed static hostname:
// satisfied iff `hostnamectl --static` equals the configured name AND berth's
// marked 127.0.1.1 alias line is present in /etc/hosts (so sudo and other
// local lookups resolve the name without DNS). Like timezone there is no
// removal counterpart — clearing the knob stops managing the hostname; the
// marked alias line stays (it still names the host).
func checkHostname(ctx context.Context, r bssh.Runner, hostname string) (bool, []string, error) {
	res, err := r.Run(ctx, "hostnamectl --static", nil)
	if err != nil {
		return false, nil, err
	}
	if res.ExitCode != 0 {
		return false, nil, fmt.Errorf("hostnamectl --static: %s", res.Stderr)
	}
	var changes []string
	if strings.TrimSpace(res.Stdout) != hostname {
		changes = append(changes, "hostnamectl set-hostname "+hostname)
	}
	hosts, _, err := catTrim(ctx, r, hostsPath)
	if err != nil {
		return false, nil, err
	}
	if !hostsAliasPresent(hosts, hostname) {
		changes = append(changes, "update the 127.0.1.1 alias in "+hostsPath)
	}
	if len(changes) == 0 {
		return true, nil, nil
	}
	return false, changes, nil
}

// applyHostname sets the static hostname and normalizes /etc/hosts to exactly
// one marked 127.0.1.1 alias line naming it (delete-any + newline-safe append,
// the applySwap fstab pattern). Re-entrant: each piece is skipped when already
// converged, so a satisfied hostname is a full no-op.
func applyHostname(ctx context.Context, r bssh.Runner, hostname string) error {
	res, err := r.Run(ctx, "hostnamectl --static", nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("hostnamectl --static: %s", res.Stderr)
	}
	if strings.TrimSpace(res.Stdout) != hostname {
		if err := runOK(ctx, r, "hostnamectl set-hostname "+shQuote(hostname)); err != nil {
			return err
		}
	}
	hosts, _, err := catTrim(ctx, r, hostsPath)
	if err != nil {
		return err
	}
	if hostsAliasPresent(hosts, hostname) {
		return nil
	}
	if err := runOK(ctx, r, "sed -i "+shQuote(hostsSedLocalAlias)+" "+hostsPath); err != nil {
		return err
	}
	return runOK(ctx, r, "printf '\\n%s\\n' "+shQuote(hostsHostnameLine(hostname))+" >> "+hostsPath)
}
```

Wire into `Check` after the timezone block:

```go
	if s.System.Hostname != "" {
		ok, ch, err := checkHostname(ctx, r, s.System.Hostname)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	}
```

Update the two Reason strings: `"swap, sysctl, timezone & hostname in desired state"` and `"system (swap/sysctl/timezone/hostname) not in desired state"`.

Wire into `Apply` after the timezone block:

```go
	if s.System.Hostname != "" {
		if err := applyHostname(ctx, r, s.System.Hostname); err != nil {
			return err
		}
	}
```

Update the `System()` doc comment: mention the hostname knob and that (like timezone) it has no removal branch.

- [ ] **Step 2.4:** Run: `go test ./internal/provision/steps/` — expect PASS (existing swap/sysctl/timezone tests must stay green: hostname is only probed when set).

- [ ] **Step 2.5: Commit** `feat(system): declarative static hostname with managed /etc/hosts alias`.

---

### Task 3: MariaDB slow query log in the `tuning` step

**Files:**
- Modify: `internal/templates/mariadb_tuning.cnf.tmpl`
- Modify: `internal/provision/steps/tuning.go` (`renderMariaDBTuning` ~line 129)
- Modify: `internal/templates/templates_test.go` (`TestRenderMariaDBTuningGolden` ~line 198)
- Create (via `-update`): `internal/templates/testdata/mariadb_tuning_slowlog.golden`
- Test: `internal/provision/steps/tuning_test.go`

**Interfaces:**
- Consumes: `s.Tuning.MariaDBSlowQueryLog`, `s.Tuning.MariaDBLongQueryTimeEff()` (Task 1).
- Produces: the render data struct `struct{ BufferPool string; SlowQueryLog bool; LongQueryTime int }` — the templates_test call sites must use the same shape.

**Design (locked):** slow-log lines are a conditional block, so the default (off) render stays **byte-identical** to today's output — existing hosts see zero drift and no MariaDB restart. Log path `/var/log/mysql/mariadb-slow.log` deliberately sits in the directory Debian's mariadb packaging already logrotates. `slow_query_log`/`long_query_time` load on the restart `tuning`'s Apply already performs (checkTuned's liveness gate covers it).

- [ ] **Step 3.1: Write failing tests.**

In `internal/provision/steps/tuning_test.go` append:

```go
func TestRenderMariaDBTuningSlowLog(t *testing.T) {
	s := &config.Server{Tuning: config.Tuning{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: 5}}
	b, err := renderMariaDBTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"slow_query_log = 1",
		"slow_query_log_file = /var/log/mysql/mariadb-slow.log",
		"long_query_time = 5",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("enabled slow log render missing %q:\n%s", want, b)
		}
	}
	off, err := renderMariaDBTuning(&config.Server{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(off), "slow_query_log") {
		t.Errorf("disabled slow log must render nothing slow-log related:\n%s", off)
	}
}

func TestRenderMariaDBTuningSlowLogDefaultThreshold(t *testing.T) {
	s := &config.Server{Tuning: config.Tuning{MariaDBSlowQueryLog: true}}
	b, err := renderMariaDBTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "long_query_time = 2") {
		t.Errorf("default threshold must render as 2 s:\n%s", b)
	}
}
```

(Add `strings` to that file's imports if missing.)

In `internal/templates/templates_test.go` replace `TestRenderMariaDBTuningGolden` with:

```go
func TestRenderMariaDBTuningGolden(t *testing.T) {
	checkGolden(t, "mariadb_tuning.cnf.tmpl", "mariadb_tuning.golden", struct {
		BufferPool    string
		SlowQueryLog  bool
		LongQueryTime int
	}{BufferPool: "256M"})
}

func TestRenderMariaDBTuningSlowLogGolden(t *testing.T) {
	checkGolden(t, "mariadb_tuning.cnf.tmpl", "mariadb_tuning_slowlog.golden", struct {
		BufferPool    string
		SlowQueryLog  bool
		LongQueryTime int
	}{BufferPool: "256M", SlowQueryLog: true, LongQueryTime: 2})
}
```

- [ ] **Step 3.2:** Run: `go test -run 'TestRenderMariaDBTuning' ./internal/provision/steps/ ./internal/templates/` — expect FAIL (template lacks fields / golden missing).

- [ ] **Step 3.3: Implement.**

`internal/templates/mariadb_tuning.cnf.tmpl` becomes:

```
[mysqld]
innodb_buffer_pool_size = {{ .BufferPool }}
{{- if .SlowQueryLog }}
slow_query_log = 1
slow_query_log_file = /var/log/mysql/mariadb-slow.log
long_query_time = {{ .LongQueryTime }}
{{- end }}
```

`tuning.go` `renderMariaDBTuning` becomes:

```go
// renderMariaDBTuning renders the managed mariadb.conf.d drop-in. The slow-log
// block is conditional so the default render stays byte-identical to the
// pre-slow-log output (no drift/restart on existing hosts). The log file sits
// in /var/log/mysql, the directory Debian's mariadb packaging already
// logrotates, so no berth logrotate entry is needed.
func renderMariaDBTuning(s *config.Server) ([]byte, error) {
	return templates.Render("mariadb_tuning.cnf.tmpl", struct {
		BufferPool    string
		SlowQueryLog  bool
		LongQueryTime int
	}{
		BufferPool:    s.Tuning.MariaDBBufferPoolEff(),
		SlowQueryLog:  s.Tuning.MariaDBSlowQueryLog,
		LongQueryTime: s.Tuning.MariaDBLongQueryTimeEff(),
	})
}
```

- [ ] **Step 3.4:** Run: `go test ./internal/templates/... -update`, then `git diff internal/templates/testdata/` — `mariadb_tuning.golden` must be **unchanged**; `mariadb_tuning_slowlog.golden` is new and must read exactly:

```
# managed by berth
[mysqld]
innodb_buffer_pool_size = 256M
slow_query_log = 1
slow_query_log_file = /var/log/mysql/mariadb-slow.log
long_query_time = 2
```

- [ ] **Step 3.5:** Run: `go test ./internal/templates/... ./internal/provision/steps/` — expect PASS.

- [ ] **Step 3.6: Commit** `feat(tuning): opt-in MariaDB slow query log knobs` (include the new golden).

---

### Task 4: `Engine.ClientAuthFileName/ClientAuthFile` (mariadb + postgres)

**Files:**
- Modify: `internal/database/engine.go` (Engine interface)
- Modify: `internal/database/mariadb.go`, `internal/database/postgres.go`
- Test: `internal/database/mariadb_test.go`, `internal/database/postgres_test.go`

**Interfaces:**
- Produces (Task 5 consumes exactly these):

```go
ClientAuthFileName() string                                  // ".my.cnf" / ".pgpass"
ClientAuthFile(database, user, password string) []byte       // file content
```

(No fake Engine implementations exist in tests — only the two real engines implement the interface, so adding methods breaks nothing else.)

- [ ] **Step 4.1: Write failing tests.**

`mariadb_test.go`:

```go
func TestMariaDBClientAuthFile(t *testing.T) {
	if got := (MariaDB{}).ClientAuthFileName(); got != ".my.cnf" {
		t.Errorf("ClientAuthFileName = %q, want .my.cnf", got)
	}
	got := string(MariaDB{}.ClientAuthFile("app_db", "app_user", "s3cretPW"))
	want := "[client]\nuser = app_user\npassword = s3cretPW\n\n[mysql]\ndatabase = app_db\n"
	if got != want {
		t.Errorf("ClientAuthFile:\n%q\nwant:\n%q", got, want)
	}
}
```

`postgres_test.go`:

```go
func TestPostgresClientAuthFile(t *testing.T) {
	if got := (Postgres{}).ClientAuthFileName(); got != ".pgpass" {
		t.Errorf("ClientAuthFileName = %q, want .pgpass", got)
	}
	got := string(Postgres{}.ClientAuthFile("app_db", "app_user", "s3cretPW"))
	if got != "*:*:app_db:app_user:s3cretPW\n" {
		t.Errorf("ClientAuthFile = %q", got)
	}
}
```

- [ ] **Step 4.2:** Run: `go test -run 'ClientAuthFile' ./internal/database/` — expect FAIL.

- [ ] **Step 4.3: Implement.**

`engine.go` — append to the Engine interface after `DumpCommand`:

```go
	// ClientAuthFileName is the name, relative to the site user's home, of this
	// engine's client-credentials file (MariaDB ~/.my.cnf, Postgres ~/.pgpass).
	ClientAuthFileName() string
	// ClientAuthFile renders that file's content for one site's credentials,
	// letting the site user run the engine's CLI tools (mariadb/mariadb-dump,
	// psql/pg_dump) without pasting the password. Inputs are pre-validated
	// (reSQLIdent identifiers, alphanumeric password), so no escaping is
	// needed. Like DumpCommand it renders only — it never executes anything.
	ClientAuthFile(database, user, password string) []byte
```

`mariadb.go`:

```go
// ClientAuthFileName is the MariaDB per-user option file.
func (MariaDB) ClientAuthFileName() string { return ".my.cnf" }

// ClientAuthFile puts the credential under [client] (read by mariadb,
// mariadb-dump and the mysql compatibility names) and pre-selects the site
// database under [mysql] only — the interactive-client group — because
// mariadb-dump takes its database as an argument and would reject an unknown
// 'database' option in [client].
func (MariaDB) ClientAuthFile(database, user, password string) []byte {
	return []byte("[client]\nuser = " + user + "\npassword = " + password + "\n\n[mysql]\ndatabase = " + database + "\n")
}
```

`postgres.go`:

```go
// ClientAuthFileName is libpq's per-user password file.
func (Postgres) ClientAuthFileName() string { return ".pgpass" }

// ClientAuthFile emits one full-wildcard match line: the site role exists only
// for its own database, so scoping host/port adds nothing, and the wildcard
// keeps psql/pg_dump working over TCP 127.0.0.1 (the .env transport) and any
// local alias alike. libpq ignores the file unless it is 0600 — the database
// step writes it with exactly that mode.
func (Postgres) ClientAuthFile(database, user, password string) []byte {
	return []byte("*:*:" + database + ":" + user + ":" + password + "\n")
}
```

- [ ] **Step 4.4:** Run: `go test ./internal/database/` — expect PASS.

- [ ] **Step 4.5: Commit** `feat(database): engine client-credentials file rendering (.my.cnf/.pgpass)`.

---

### Task 5: `database` step — seed the client-credentials file per site

**Files:**
- Modify: `internal/provision/steps/database.go`
- Test: `internal/provision/steps/database_test.go`

**Interfaces:**
- Consumes: `eng.ClientAuthFileName()`, `eng.ClientAuthFile(db, user, pw)` (Task 4); existing `fileExists`, `s.SiteUser`.

**Design (locked):** seed-if-absent, exactly like `shared/.env` (never rewritten — the password is reused-not-rotated and the operator may customize the file; no managed marker on a secret-bearing file). Written **after** `EnsureUser`, so the credential it holds is live; a crash in between heals on the next run because Check probes the file's existence. Check stays secret-free (a `test -e` probe only).

- [ ] **Step 5.1: Write failing tests** (append to `database_test.go`; copy the Check/Apply stub baselines from the neighboring tests — e.g. `TestDatabaseApply*` for the install/SQL stubs — and add the new `test -e`/WriteFile expectations):

```go
func TestDatabaseApplySeedsClientAuthFile(t *testing.T) {
	// Fresh box (no .env): after EnsureUser the site user's ~/.my.cnf is seeded
	// 0600. Base the stubs on the existing fresh-box Apply test for mariadb and
	// add: f.On("test -e '/home/deploy/.my.cnf'", bssh.Result{ExitCode: 1}).
	// Assert via f.Writes(): a write to /home/deploy/.my.cnf, Owner deploy,
	// Group deploy, Mode 0600, content containing "[client]", "user = ", and
	// the same password seeded into shared/.env.
}

func TestDatabaseApplyClientAuthFileNeverRewritten(t *testing.T) {
	// Same as above but f.On("test -e '/home/deploy/.my.cnf'", bssh.Result{ExitCode: 0}).
	// Assert NO write to /home/deploy/.my.cnf occurred.
}

func TestDatabaseCheckUnsatisfiedWhenClientAuthMissing(t *testing.T) {
	// Base on the existing "fully satisfied" Check test (server installed,
	// credential present, database exists, user granted) and stub
	// f.On("test -e '/home/deploy/.my.cnf'", bssh.Result{ExitCode: 1}).
	// Expect Satisfied == false with Reason containing "client DB credentials".
}

func TestDatabaseCheckSatisfiedIncludesClientAuth(t *testing.T) {
	// The satisfied path now requires the probe to pass: extend the existing
	// satisfied Check test with f.On("test -e '/home/deploy/.my.cnf'",
	// bssh.Result{ExitCode: 0}) and assert Satisfied == true.
}

func TestDatabaseApplyPostgresSeedsPgpass(t *testing.T) {
	// Engine postgres: same seed flow, path /home/deploy/.pgpass, content
	// "*:*:<db>:<user>:<pw>\n". Base stubs on the existing postgres Apply test;
	// add f.On("test -e '/home/deploy/.pgpass'", bssh.Result{ExitCode: 1}).
}
```

These five test bodies are written concretely at implementation time by copying the exact stub sets from the neighboring tests they name (the stub sets are long and engine-specific; duplicating them here would drift). The assertions above are the contract. **Additionally: every existing database test that drives Check to the satisfied end or Apply through a site loop now needs the matching `test -e '/home/<user>/.my.cnf'` (or `.pgpass`) stub — add `ExitCode: 0` for "already seeded" unless the test asserts seeding.**

- [ ] **Step 5.2:** Run: `go test -run 'TestDatabase' ./internal/provision/steps/` — expect FAIL (new tests + existing tests missing stubs).

- [ ] **Step 5.3: Implement** in `database.go`.

Helper (next to `sharedEnvPath`):

```go
// clientAuthPath is the server-side path of a site user's engine
// client-credentials file (~/.my.cnf or ~/.pgpass). The /home/<user> layout is
// the same assumption ensureUser enforces for every managed account.
func clientAuthPath(s *config.Server, site config.Site, name string) string {
	return "/home/" + s.SiteUser(site) + "/" + name
}
```

`Check` — extend the per-site loop after the `granted` probe:

```go
		authOK, err := fileExists(ctx, r, clientAuthPath(s, site, eng.ClientAuthFileName()))
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !authOK {
			return d.unsatisfied(eng, "client DB credentials for "+site.Domain+" not yet seeded"), nil
		}
```

`changes()` — update the second line to:

```go
		"per site: persist DB credential to shared/.env and ~/" + eng.ClientAuthFileName() + " (when absent), ensure database + user",
```

`Apply` — in the site loop, after `eng.EnsureUser(...)` succeeds and before `cache[dbUser] = pw`:

```go
		authPath := clientAuthPath(s, site, eng.ClientAuthFileName())
		authExists, err := fileExists(ctx, r, authPath)
		if err != nil {
			return err
		}
		if !authExists {
			// Seed-if-absent, like shared/.env: the password is reused (never
			// rotated) and the operator may customize the file, so a present
			// file is never rewritten. Written AFTER EnsureUser so the
			// credential it holds is live; a crash in between heals on the
			// next run via Check's existence probe.
			user := s.SiteUser(site)
			if err := r.WriteFile(ctx, bssh.FileSpec{
				Path: authPath, Content: eng.ClientAuthFile(dbName, dbUser, pw),
				Owner: user, Group: user, Mode: 0o600, Sudo: true,
			}); err != nil {
				return fmt.Errorf("write %s: %w", authPath, err)
			}
		}
```

Also update the `Database`/step doc comment ("persists the credential to that site's shared/.env **and client-credentials file**").

- [ ] **Step 5.4:** Run: `go test ./internal/provision/steps/` — expect PASS.

- [ ] **Step 5.5: Commit** `feat(database): seed per-site ~/.my.cnf / ~/.pgpass client credentials`.

---

### Task 6: `berth site key <server> [domain]` — print deploy public keys

**Files:**
- Modify: `cmd/site.go`
- Test: Create `cmd/site_test.go`

**Interfaces:**
- Consumes: `config.Load`, `srv.SiteUser(site)`, `bssh.Connect`/`bssh.Runner`/`bssh.NewFakeRunner`, `defaultKnownHosts()`/`confirmFingerprint()` (both already in `cmd/provision.go`), `ui.IsTTY`.
- Produces: `printDeployKeys(ctx, out, srv, r, domain)` — the SSH-independent core, unit-tested with FakeRunner.

**Design (locked):** read-only — it never generates anything. The accounts step already generates `/home/<user>/.ssh/id_ed25519` for every site with `repository:`; this command surfaces the `.pub`. Site user names are validated (`reLinuxUser`, no shell metachars), so the `cat` command needs no quoting — keep it unquoted for a stable, matchable string. Non-root connections are fine: `Run` sudo-wraps, and berth's account has full sudo, so root reads the 0700 `.ssh` dir.

- [ ] **Step 6.1: Write failing tests** (`cmd/site_test.go`):

```go
package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func siteKeyServer() *config.Server {
	return &config.Server{
		Host: "203.0.113.10",
		Sites: []config.Site{
			{Domain: "a.example.com", DeployPath: "/srv/a", User: "alpha", Repository: "git@github.com:acme/a.git"},
			{Domain: "b.example.com", DeployPath: "/srv/b", User: "beta"},
		},
	}
}

func TestPrintDeployKeysAllSites(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat /home/alpha/.ssh/id_ed25519.pub", bssh.Result{ExitCode: 0, Stdout: "ssh-ed25519 AAAAC3Nz alpha@github.com\n"})
	var out bytes.Buffer
	if err := printDeployKeys(context.Background(), &out, siteKeyServer(), f, ""); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "ssh-ed25519 AAAAC3Nz alpha@github.com") {
		t.Errorf("missing the deploy key for a.example.com:\n%s", got)
	}
	if !strings.Contains(got, "b.example.com") || !strings.Contains(got, "no deploy key is managed") {
		t.Errorf("the repository-less site must be reported, not skipped silently:\n%s", got)
	}
}

func TestPrintDeployKeysDomainFilter(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat /home/alpha/.ssh/id_ed25519.pub", bssh.Result{ExitCode: 0, Stdout: "ssh-ed25519 AAAAC3Nz alpha@github.com\n"})
	var out bytes.Buffer
	if err := printDeployKeys(context.Background(), &out, siteKeyServer(), f, "a.example.com"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "b.example.com") {
		t.Errorf("domain filter must exclude other sites:\n%s", out.String())
	}
}

func TestPrintDeployKeysUnknownDomain(t *testing.T) {
	var out bytes.Buffer
	err := printDeployKeys(context.Background(), &out, siteKeyServer(), bssh.NewFakeRunner(), "nope.example.com")
	if err == nil || !strings.Contains(err.Error(), "no site with domain") {
		t.Errorf("unknown domain must error; got %v", err)
	}
}

func TestPrintDeployKeysNotProvisioned(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat /home/alpha/.ssh/id_ed25519.pub", bssh.Result{ExitCode: 1, Stderr: "No such file"})
	var out bytes.Buffer
	if err := printDeployKeys(context.Background(), &out, siteKeyServer(), f, "a.example.com"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "not generated yet") {
		t.Errorf("missing key must be reported as not provisioned:\n%s", out.String())
	}
}

func TestSiteKeySubcommandRegistered(t *testing.T) {
	root := newRootCmd()
	for _, c := range root.Commands() {
		if c.Name() == "site" {
			for _, sub := range c.Commands() {
				if sub.Name() == "key" {
					return
				}
			}
		}
	}
	t.Error("site key subcommand not registered")
}
```

- [ ] **Step 6.2:** Run: `go test ./cmd/` — expect FAIL (`printDeployKeys` undefined).

- [ ] **Step 6.3: Implement** — `cmd/site.go` becomes:

```go
package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/ui"
)

func newSiteCmd() *cobra.Command {
	c := &cobra.Command{Use: "site", Short: "Manage sites on a server"}
	c.AddCommand(&cobra.Command{
		Use:   "add <server>",
		Short: "Add another site to an existing server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errNotImplemented("site:add") // post-v1
		},
	})
	c.AddCommand(newSiteKeyCmd())
	return c
}

func newSiteKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "key <server> [domain]",
		Short: "Print a site's git deploy public key (paste it into the repo host)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			srv, err := config.Load(args[0])
			if err != nil {
				return err
			}
			domain := ""
			if len(args) == 2 {
				domain = args[1]
			}
			client, err := bssh.Connect(cmd.Context(), srv, bssh.HostKeyPolicy{
				Pinned: srv.SSH.Fingerprint, KnownHosts: defaultKnownHosts(),
				AllowTOFU: ui.IsTTY(os.Stdin), ConfirmTOFU: confirmFingerprint(cmd),
			})
			if err != nil {
				return err
			}
			defer client.Close()
			return printDeployKeys(cmd.Context(), cmd.OutOrStdout(), srv, client, domain)
		},
	}
}

// printDeployKeys writes each selected site's deploy public key — generated by
// the accounts step for sites with a repository — to out. Read-only: it never
// generates or mutates anything. A site without a repository has no managed
// key by design; a missing key file means the host was not provisioned yet.
// The site user is validated (reLinuxUser, no shell metacharacters), so the
// cat command is stable and unquoted.
func printDeployKeys(ctx context.Context, out io.Writer, srv *config.Server, r bssh.Runner, domain string) error {
	sites := srv.Sites
	if domain != "" {
		sites = nil
		for _, site := range srv.Sites {
			if site.Domain == domain {
				sites = []config.Site{site}
				break
			}
		}
		if sites == nil {
			return fmt.Errorf("no site with domain %q in this config", domain)
		}
	}
	for _, site := range sites {
		user := srv.SiteUser(site)
		fmt.Fprintf(out, "# %s (user %s)\n", site.Domain, user)
		if site.Repository == "" {
			fmt.Fprintln(out, "no deploy key is managed for this site (set sites[].repository to have berth generate one)")
			continue
		}
		res, err := r.Run(ctx, "cat /home/"+user+"/.ssh/id_ed25519.pub", nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			fmt.Fprintln(out, "deploy key not generated yet — run `berth provision` first")
			continue
		}
		fmt.Fprintln(out, strings.TrimSpace(res.Stdout))
	}
	return nil
}
```

- [ ] **Step 6.4:** Run: `go test ./cmd/` — expect PASS.

- [ ] **Step 6.5: Commit** `feat(cmd): berth site key — print per-site deploy public keys`.

---

### Task 7: Wizard coverage for the three new config fields

**Files:**
- Modify: `internal/wizard/wizard.go` (SystemAnswers ~line 70, TuningAnswers ~line 60)
- Modify: `internal/wizard/prompter.go` (`ServerAdvanced` ~line 91 group 2, `ServerOps` ~line 118 group 1)
- Modify: `internal/wizard/toserver.go` (~lines 17–27)
- Modify: `internal/wizard/validate.go` (new `optionalSystemHostname`)
- Test: `internal/wizard/toserver_test.go`, `internal/wizard/validate_test.go`

**Interfaces:**
- Consumes: `config.System.Hostname`, `config.Tuning.MariaDBSlowQueryLog/MariaDBLongQueryTime` (Task 1).

- [ ] **Step 7.1: Write failing tests.**

`validate_test.go`:

```go
func TestOptionalSystemHostname(t *testing.T) {
	for _, ok := range []string{"", "web-1.example.com", "web1"} {
		if err := optionalSystemHostname(ok); err != nil {
			t.Errorf("optionalSystemHostname(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"bad host", strings.Repeat("a", 65), "-x.example.com"} {
		if err := optionalSystemHostname(bad); err == nil {
			t.Errorf("optionalSystemHostname(%q) = nil, want error", bad)
		}
	}
}
```

`toserver_test.go` — locate the existing test that asserts the `System`/`Tuning` mapping (it builds a full `Answers` and compares `ToServer()` output) and extend its fixture + expectations with:

```go
// in the Answers fixture:
System: SystemAnswers{Swap: "1G", Sysctl: true, Timezone: "Europe/Warsaw", Hostname: "web-1.example.com"},
// Tuning fixture additions:
MariaDBSlowQueryLog: true, MariaDBLongQueryTime: 5,
// and the matching expectations on the produced config.Server:
// srv.System.Hostname == "web-1.example.com"
// srv.Tuning.MariaDBSlowQueryLog == true, srv.Tuning.MariaDBLongQueryTime == 5
```

- [ ] **Step 7.2:** Run: `go test ./internal/wizard/` — expect FAIL.

- [ ] **Step 7.3: Implement.**

`wizard.go`:

```go
type SystemAnswers struct {
	Swap     string // e.g. "2G"; blank = no swap
	Sysctl   bool
	Timezone string // IANA zone; blank = leave untouched
	Hostname string // static hostname; blank = leave untouched
}
```

`TuningAnswers` — add:

```go
	MariaDBSlowQueryLog  bool
	MariaDBLongQueryTime int
```

`validate.go` — next to `optionalTimezone`:

```go
// optionalSystemHostname allows blank (leave untouched) or a valid hostname of
// at most 64 chars (kernel HOST_NAME_MAX); config.Server.Validate stays
// authoritative.
func optionalSystemHostname(s string) error {
	if s == "" || (len(s) <= 64 && reHostname.MatchString(s)) {
		return nil
	}
	return fmt.Errorf("hostname %q must be a valid hostname of at most 64 characters", s)
}
```

`prompter.go` `ServerAdvanced` — in the second group (after the MariaDB buffer-pool input) add, with `longQuery := strconv.Itoa(a.Tuning.MariaDBLongQueryTime)` declared next to `execTime`:

```go
	huh.NewConfirm().Title("MariaDB slow query log?").Value(&a.Tuning.MariaDBSlowQueryLog),
	huh.NewInput().Title("MariaDB long_query_time (1-86400 s, blank/0=default 2; needs slow log on)").Value(&longQuery).Validate(optionalInt("tuning.mariadb_long_query_time", 1, 86400)),
```

and after `form.Run()`:

```go
	a.Tuning.MariaDBLongQueryTime, _ = parseIntInRange("tuning.mariadb_long_query_time", longQuery, 1, 86400)
```

(The slow-log/threshold pairing rule stays enforced by `config.Server.Validate` at Write — the existing whole-form re-prompt path — matching the documented queue/daemon precedent.)

`ServerOps` — after the timezone input:

```go
	huh.NewInput().Title("System hostname (blank=leave untouched)").Value(&a.System.Hostname).Validate(optionalSystemHostname),
```

`toserver.go`:

```go
		System: config.System{Swap: a.System.Swap, Sysctl: a.System.Sysctl, Timezone: a.System.Timezone, Hostname: a.System.Hostname},
```

and in the Tuning literal:

```go
			MariaDBSlowQueryLog:  a.Tuning.MariaDBSlowQueryLog,
			MariaDBLongQueryTime: a.Tuning.MariaDBLongQueryTime,
```

- [ ] **Step 7.4:** Run: `go test ./internal/wizard/` — expect PASS (the matrix round-trip tests will exercise the new fields through Write → config.Load).

- [ ] **Step 7.5: Commit** `feat(wizard): collect system.hostname and MariaDB slow-log knobs`.

---

### Task 8: Docs — README, CHANGELOG, CLAUDE.md

**Files:**
- Modify: `README.md` (config reference near the `timezone:` sample ~line 122; tuning knobs section; a short `site key` usage mention next to the provision usage; the database/.env description gains the client-credentials file)
- Modify: `CHANGELOG.md` (new `## [Unreleased]` section on top)
- Modify: `CLAUDE.md` (three one-line touches)

- [ ] **Step 8.1: README.** Locate via `grep -n "timezone:" README.md` and add below the timezone lines:

```yaml
  hostname: web-1.example.com  # default off when absent; sets the static hostname
                               # (hostnamectl) and keeps a 127.0.1.1 alias in
                               # /etc/hosts so sudo resolves it without DNS
```

In the tuning reference add:

```yaml
  mariadb_slow_query_log: true # default off; logs queries slower than
  mariadb_long_query_time: 2   # long_query_time seconds (default 2) to
                               # /var/log/mysql/mariadb-slow.log
```

In the database/provisioning description add one sentence: berth also seeds a per-site `~/.my.cnf` (MariaDB) / `~/.pgpass` (PostgreSQL) for the site user — seed-once like `shared/.env`, never rewritten — so `mariadb`/`mariadb-dump`/`psql`/`pg_dump` work for that user without pasting the password.

In the usage/commands section add:

```
berth site key servers/prod.yml [domain]   # print each site's git deploy public key
```

- [ ] **Step 8.2: CHANGELOG.** Insert above `## [0.12.0]`:

```markdown
## [Unreleased]

### Added

- **Declarative static hostname** — opt-in `system.hostname`: sets the
  hostname via `hostnamectl` and maintains a berth-marked `127.0.1.1` alias
  line in `/etc/hosts` (Debian convention, so sudo resolves the name without
  DNS). Empty = berth never touches the hostname. Available in `berth init`.
- **Per-site DB client credentials** — the database step now seeds the site
  user's `~/.my.cnf` (MariaDB) / `~/.pgpass` (PostgreSQL) alongside
  `shared/.env` — seed-once, never rewritten — so `mariadb`, `mariadb-dump`,
  `psql` and `pg_dump` run as the site user without pasting the password.
- **MariaDB slow query log** — opt-in `tuning.mariadb_slow_query_log` with
  `tuning.mariadb_long_query_time` (default 2 s), rendered into the managed
  tuning drop-in; logs to `/var/log/mysql/mariadb-slow.log` (already covered
  by the distro logrotate). Off by default with a byte-identical render, so
  existing hosts see no drift. Available in `berth init`.
- **`berth site key <server> [domain]`** — prints each site's git deploy
  public key (generated at provision time for sites with `repository:`),
  ready to paste into the repo host's deploy-key settings.
```

- [ ] **Step 8.3: CLAUDE.md.** Three surgical edits:
  1. In the Tier-1/system-step-adjacent description of `system.go` (the DAG note mentions steps; find the sentence describing the system step in "Tier 1"/architecture context — if none exists, extend the step DAG comment): note the step now manages swap/sysctl/timezone/**hostname** (hostname adds a marked `127.0.1.1` `/etc/hosts` alias; foreign alias replaced without `--force` by design).
  2. In the `internal/apt` + `internal/database` bullet: add "engines also render a per-site client-credentials file (`ClientAuthFileName`/`ClientAuthFile`: `~/.my.cnf` / `~/.pgpass`), seeded once by the database step like `shared/.env`".
  3. In "Repo-specific conventions", update the sentence "Post-v1 features (`site add`) return `errNotImplemented`" to also mention `site key` is implemented and read-only.

- [ ] **Step 8.4: Commit** `docs: README/CHANGELOG/CLAUDE.md for the ops quick-wins iteration`.

---

### Task 9: Verification, Codex review, PR prep

- [ ] **Step 9.1:** `gofmt -l .` (expect empty), `go vet ./...`, `go test -race ./...` — all green.
- [ ] **Step 9.2:** Codex foreground review (standing goal): write a review prompt to `$CLAUDE_JOB_DIR/tmp/codex-review.md` (diff scope `git diff main...feat/ops-quickwins`), run `codex exec --skip-git-repo-check < $CLAUDE_JOB_DIR/tmp/codex-review.md` in the foreground, **verify each finding against the code before fixing** (prior iterations: Codex finds real issues but also misfires).
- [ ] **Step 9.3:** Apply verified fixes (each as a focused commit), re-run Step 9.1.
- [ ] **Step 9.4:** Write the PR body to `docs/pr-body-ops-quickwins.md` (feature summary, design decisions incl. the no-force `/etc/hosts` takeover rationale and the seed-if-absent secret-file rule, test coverage, drift-neutrality of the default tuning render). Commit it.
- [ ] **Step 9.5:** Report to the user: branch ready, ask them to run `! git push -u origin feat/ops-quickwins` and open the PR (berth hook blocks Claude's pushes).

---

## Self-Review Notes

- **Spec coverage:** feature 3 (hostname) → Tasks 1, 2, 7, 8; feature 4 (client creds) → Tasks 4, 5, 8; feature 5 (slow log) → Tasks 1, 3, 7, 8; closing feature 6 (deploy key surfacing) → Tasks 6, 8. Wizard "all fields settable" property preserved by Task 7.
- **Type consistency:** `ClientAuthFileName() string` + `ClientAuthFile(database, user, password string) []byte` used identically in Tasks 4 and 5; render struct `{BufferPool string; SlowQueryLog bool; LongQueryTime int}` identical in Task 3's two call sites; `MariaDBLongQueryTimeEff` named identically in Tasks 1 and 3.
- **Known deviation from "No Placeholders":** Task 5's test bodies reference neighboring stub sets instead of duplicating ~30 lines of engine SQL stubs each — the stub sets are load-bearing exact strings that must be copied from the current file, not from a plan that would drift. The assertions (the actual contract) are fully specified.
- **Deliberate scope cuts (YAGNI):** no `deploy_key: true` knob (repository-gated generation already covers the real flow); no hostname removal branch (timezone precedent); no Postgres slow-query counterpart (knob named `mariadb_*` to leave room); no cross-check engine↔tuning knobs (buffer-pool precedent).



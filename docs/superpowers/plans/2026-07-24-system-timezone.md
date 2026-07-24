# Declarative System Timezone Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `system.timezone` knob (empty = berth never touches the zone) applied idempotently by the existing `system` step, with wizard coverage, per spec `docs/superpowers/specs/2026-07-24-system-timezone-design.md`.

**Architecture:** A third gated block in the `system` step next to swap and sysctl, following its `checkX`/`applyX` re-entrant pattern: Check compares `timedatectl show -p Timezone --value` to the configured zone; Apply runs `timedatectl set-timezone` then `systemctl try-restart cron` (cron reads local time at startup and berth's backup cron is wall-clock-sensitive). No default, no `*Eff` accessor, no removal branch (a timezone is system state, not a berth artifact — documented asymmetry vs swap).

**Tech Stack:** Go 1.25, FakeRunner exact-string test doubles.

## Global Constraints

- Public MIT repo: all code, comments, and commit messages **English-only**, no personal/host-identifying data.
- Never run `go mod tidy`. Never `git push` — the user pushes; prepare the branch and PR body.
- Every config struct field needs BOTH `mapstructure` and `yaml` tags.
- Validation is **lenient**: empty string = "don't manage" and passes. The regex, both in config and its wizard mirror, is EXACTLY `^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$` — identical domains on both public config paths (the fingerprint-era lesson: a narrower inline validator traps the operator in the site retry loop; a wider one lets bad values reach validation the loop cannot fix).
- FakeRunner stubs are **exact command strings**; an unstubbed command returns an error. Baseline stubs for a `System{}` with swap/sysctl off (both Check paths hit them): `cat '/etc/fstab'`, `cat '/etc/sysctl.d/99-berth-swap.conf'` (exit 1), `cat '/etc/sysctl.d/99-berth.conf'` (exit 1).
- Exact remote commands this feature runs: `timedatectl show -p Timezone --value` (Check, read-only), `timedatectl set-timezone 'Europe/Warsaw'` (shQuote'd value) and `systemctl try-restart cron` (Apply).
- CI runs `go test -race ./...` and `go vet ./...`; format with `gofmt`. The integration package compiles only under `-tags integration`.

---

### Task 1: Config field + validation

**Files:**
- Modify: `internal/config/config.go` (`System` struct ~line 118)
- Modify: `internal/config/validate.go` (regex var block ~line 28, `System.validate()` ~line 345)
- Test: create `internal/config/system_test.go`

**Interfaces:**
- Produces (used by Tasks 2, 3): `System.Timezone string` (empty = don't manage), `reTimezone` regexp.

- [ ] **Step 1: Create the feature branch**

```bash
cd /Users/robson/AI/berth
git checkout main && git checkout -b feat/system-timezone
```

- [ ] **Step 2: Write the failing tests**

Create `internal/config/system_test.go`:

```go
package config

import "testing"

func TestSystemTimezoneValidate(t *testing.T) {
	for _, ok := range []string{
		"", // empty = don't manage, lenient
		"UTC",
		"Europe/Warsaw",
		"Etc/GMT+8",
		"America/Argentina/Buenos_Aires", // three segments (IANA max)
		"America/Port-au-Prince",         // hyphens
	} {
		if err := (System{Timezone: ok}).validate(); err != nil {
			t.Errorf("validate(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"Europe/Warsaw; rm -rf /", // the value reaches a command line
		"../etc/passwd",
		"Europe Warsaw",
		"/Europe",
		"Europe/",
		"A/B/C/D", // four segments
	} {
		if err := (System{Timezone: bad}).validate(); err == nil {
			t.Errorf("validate(%q) expected error, got nil", bad)
		}
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/config/ -run TestSystemTimezoneValidate 2>&1 | head -5`
Expected: compile FAIL — unknown field `Timezone` in `System`.

- [ ] **Step 4: Implement**

(a) `internal/config/config.go` — extend `System` and its doc comment. Replace the struct (keep the existing comment's first sentences, adjust "Both default off" and append the timezone sentence):

```go
// System holds optional, opt-in host-level OS provisioning knobs. All default
// off: an empty Swap, a false Sysctl and an empty Timezone mean berth never
// touches swap, kernel sysctl or the system timezone. Values are constants in
// the step (no SetDefault), so wizard ToServer() and literal-Server callers
// that bypass Load() need nothing seeded. Unlike Swap, clearing Timezone
// drift-removes nothing — a timezone is plain system state with no berth
// artifact, so empty means "stop managing", never "revert".
type System struct {
	Swap     string `mapstructure:"swap"     yaml:"swap,omitempty"`     // e.g. "2G"; empty = no swap
	Sysctl   bool   `mapstructure:"sysctl"   yaml:"sysctl,omitempty"`   // default false = no sysctl drop-in
	Timezone string `mapstructure:"timezone" yaml:"timezone,omitempty"` // IANA zone (e.g. Europe/Warsaw); empty = leave untouched
}
```

(b) `internal/config/validate.go` — add to the regex var block:

```go
	// reTimezone guards IANA zone names (UTC, Europe/Warsaw, Etc/GMT+8,
	// America/Argentina/Buenos_Aires — at most three segments). The value
	// reaches `timedatectl set-timezone` verbatim (config-injection defence);
	// existence is deliberately NOT validated locally — Windows berth binaries
	// ship no tzdb, and timedatectl rejects unknown zones loudly on the host.
	reTimezone = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
```

(c) In `func (sy System) validate() error`, before the final `return nil`:

```go
	if sy.Timezone != "" && !reTimezone.MatchString(sy.Timezone) {
		return fmt.Errorf("system.timezone %q must be an IANA zone name like Europe/Warsaw (letters, digits, _ + -, at most two /)", sy.Timezone)
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/validate.go internal/config/system_test.go
git commit -m "feat(config): opt-in system.timezone knob (empty = leave untouched)"
```

---

### Task 2: system step — timezone block

**Files:**
- Modify: `internal/provision/steps/system.go` (doc comment line 87-90, `Check` lines 96-136, new helpers after `checkSysctlRemoval` ~line 321, `Apply` lines 323-343)
- Test: `internal/provision/steps/system_test.go`

**Interfaces:**
- Consumes: `System.Timezone` from Task 1; existing `runOK`, `shQuote`.
- Produces: `checkTimezone(ctx, r, tz) (bool, []string, error)`, `applyTimezone(ctx, r, tz) error` (package-private).

- [ ] **Step 1: Write the failing tests**

Add to `internal/provision/steps/system_test.go` (the three baseline stubs are the swap-off/sysctl-off Check path — copied from `TestSystemCheckSwapDisabledNoArtifactsSatisfied`):

```go
func TestSystemCheckTimezoneMismatchUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Etc/UTC\n"})
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the host zone differs from system.timezone")
	}
}

func TestSystemCheckTimezoneMatchSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Europe/Warsaw\n"}) // trailing \n trimmed
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when the host zone matches; got %+v", cr)
	}
}

func TestSystemCheckTimezoneUnsetNeverProbed(t *testing.T) {
	// Empty knob = berth never touches (or even reads) the zone: an unstubbed
	// timedatectl would error the FakeRunner, so this passing proves no call.
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied no-op; got %+v", cr)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "timedatectl") {
			t.Errorf("unset timezone must not run timedatectl; ran %q", c.Cmd)
		}
	}
}

func TestSystemApplyTimezoneSetsAndRestartsCron(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Etc/UTC\n"})
	f.On("timedatectl set-timezone 'Europe/Warsaw'", bssh.Result{})
	f.On("systemctl try-restart cron", bssh.Result{})
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var set, cron bool
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "timedatectl set-timezone 'Europe/Warsaw'":
			set = true
		case "systemctl try-restart cron":
			if !set {
				t.Error("cron restart must come AFTER set-timezone")
			}
			cron = true
		}
	}
	if !set || !cron {
		t.Errorf("want set-timezone + try-restart cron; got set=%v cron=%v", set, cron)
	}
}

func TestSystemApplyTimezoneNoopWhenSatisfied(t *testing.T) {
	// Re-entrant like applySwap/applySysctl: a matching zone must neither
	// set-timezone nor restart cron (unstubbed commands would error).
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Europe/Warsaw\n"})
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl try-restart cron" || strings.Contains(c.Cmd, "set-timezone") {
			t.Errorf("satisfied timezone must be a no-op; ran %q", c.Cmd)
		}
	}
}

func TestSystemApplyTimezoneCronRestartFailureAborts(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	f.On("timedatectl show -p Timezone --value", bssh.Result{ExitCode: 0, Stdout: "Etc/UTC\n"})
	f.On("timedatectl set-timezone 'Europe/Warsaw'", bssh.Result{})
	f.On("systemctl try-restart cron", bssh.Result{ExitCode: 1, Stderr: "boom"})
	s := &config.Server{System: config.System{Timezone: "Europe/Warsaw"}}
	if err := System().Apply(context.Background(), provision.RunCtx{}, s, f); err == nil {
		t.Fatal("expected the cron restart failure to surface as the step error")
	}
}
```

If `strings` is not already imported in `system_test.go`, add it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/provision/steps/ -run TestSystemCheckTimezone 2>&1 | head -5`
Expected: FAIL — `TestSystemCheckTimezoneMismatchUnsatisfied` reports satisfied (the timezone block does not exist yet, so Check ignores the field). (The Apply tests fail similarly.)

- [ ] **Step 3: Implement**

(a) `internal/provision/steps/system.go` — update the constructor doc comment (line 87):

```go
// System provisions optional host-level OS settings: a swap file (+ vm.swappiness),
// an opt-in web/DB kernel sysctl drop-in, and an opt-in system timezone. It is
// ALWAYS in the pipeline (ungated) so disabling a knob can drift-remove berth's
// artifacts, and runs right after base (before php/composer/database) so the swap
// margin protects provisioning itself. The timezone knob has NO removal branch:
// a zone is plain system state with no berth artifact — clearing the field stops
// managing it, never reverts it.
```

(b) In `Check`, insert after the sysctl if/else (line ~131), before the `len(changes)` check:

```go
	if s.System.Timezone != "" {
		ok, ch, err := checkTimezone(ctx, r, s.System.Timezone)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	}
```

and update the two Reason strings:

```go
		return provision.CheckResult{Satisfied: true, Reason: "swap, sysctl & timezone in desired state"}, nil
	}
	return provision.CheckResult{Satisfied: false, Reason: "system (swap/sysctl/timezone) not in desired state", Changes: changes}, nil
```

(c) New helpers after `checkSysctlRemoval` (~line 321):

```go
// checkTimezone is the read-only predicate for a managed timezone: satisfied
// iff the host's current zone equals the configured one. There is no removal
// counterpart — see the System() doc comment.
func checkTimezone(ctx context.Context, r bssh.Runner, tz string) (bool, []string, error) {
	res, err := r.Run(ctx, "timedatectl show -p Timezone --value", nil)
	if err != nil {
		return false, nil, err
	}
	if res.ExitCode != 0 {
		return false, nil, fmt.Errorf("timedatectl show: %s", res.Stderr)
	}
	if strings.TrimSpace(res.Stdout) == tz {
		return true, nil, nil
	}
	return false, []string{"timedatectl set-timezone " + tz + " + restart cron"}, nil
}

// applyTimezone sets the zone, then restarts cron: cron reads the local time
// at startup and berth's own backup cron (30 3 * * *) is wall-clock-sensitive,
// so without the restart the OLD zone's schedule would persist indefinitely.
// try-restart (not restart) is a no-op when cron isn't running — the step never
// starts a service it doesn't own. Re-entrant: re-runs checkTimezone first.
func applyTimezone(ctx context.Context, r bssh.Runner, tz string) error {
	ok, _, err := checkTimezone(ctx, r, tz)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	if err := runOK(ctx, r, "timedatectl set-timezone "+shQuote(tz)); err != nil {
		return err
	}
	return runOK(ctx, r, "systemctl try-restart cron")
}
```

(d) In `Apply`, append after the sysctl if/else (line ~341), before `return nil`:

```go
	if s.System.Timezone != "" {
		if err := applyTimezone(ctx, r, s.System.Timezone); err != nil {
			return err
		}
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/provision/steps/`
Expected: PASS (all step tests — the existing system tests carry an empty Timezone, so the new block is skipped and their stub sets stay complete).

- [ ] **Step 5: Commit**

```bash
git add internal/provision/steps/system.go internal/provision/steps/system_test.go
git commit -m "feat(system): apply system.timezone via timedatectl + cron restart"
```

---

### Task 3: Wizard coverage

**Files:**
- Modify: `internal/wizard/wizard.go` (`SystemAnswers` ~line 66)
- Modify: `internal/wizard/validate.go` (mirror-regex var block ~line 120, new `optionalTimezone`)
- Modify: `internal/wizard/prompter.go` (`ServerOps` system group ~line 108)
- Modify: `internal/wizard/toserver.go` (`System` literal ~line 22)
- Test: `internal/wizard/validate_test.go`, `internal/wizard/toserver_test.go`, `internal/wizard/matrix_test.go`

**Interfaces:**
- Consumes: `config.System.Timezone` from Task 1.
- Produces: `SystemAnswers.Timezone string`, `optionalTimezone` validator.

- [ ] **Step 1: Write the failing tests**

(a) `internal/wizard/validate_test.go`:

```go
func TestOptionalTimezone(t *testing.T) {
	for _, ok := range []string{"", "UTC", "Europe/Warsaw", "Etc/GMT+8", "America/Argentina/Buenos_Aires"} {
		if err := optionalTimezone(ok); err != nil {
			t.Errorf("optionalTimezone(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"Europe/Warsaw; rm -rf /", "../etc/passwd", "Europe Warsaw", "/Europe", "A/B/C/D"} {
		if err := optionalTimezone(bad); err == nil {
			t.Errorf("optionalTimezone(%q) expected error, got nil", bad)
		}
	}
}
```

(b) `internal/wizard/toserver_test.go`:

```go
func TestToServerCarriesSystemTimezone(t *testing.T) {
	a := Answers{System: SystemAnswers{Timezone: "Europe/Warsaw"}}
	if s := a.ToServer(); s.System.Timezone != "Europe/Warsaw" {
		t.Errorf("ToServer() dropped system.timezone: %+v", s.System)
	}
}
```

(c) `internal/wizard/matrix_test.go` — two subtests next to the existing system-block cases (mirror their `base(...)`/site shape; place them adjacent to the swap/sysctl subtests):

```go
	t.Run("system-timezone-valid", func(t *testing.T) {
		a := base("sys-tz", "vps.example.com")
		a.System = SystemAnswers{Timezone: "Europe/Warsaw"}
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		srv, raw := writeValid(t, a)
		if srv.System.Timezone != "Europe/Warsaw" {
			t.Fatalf("timezone = %q", srv.System.Timezone)
		}
		if !strings.Contains(raw, "timezone: Europe/Warsaw") {
			t.Fatalf("yaml missing timezone:\n%s", raw)
		}
	})

	t.Run("system-timezone-injection-invalid", func(t *testing.T) {
		a := base("sys-tz-bad", "vps.example.com")
		a.System = SystemAnswers{Timezone: "Europe/Warsaw; rm -rf /"}
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "system.timezone")
	})
```

(Verify the exact `writeValid` return shape against neighbouring subtests — it returns `(*config.Server, string raw)`; adjust the raw-yaml assertion only if the actual serialization quotes the value.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/wizard/ 2>&1 | head -5`
Expected: compile FAIL — `undefined: optionalTimezone`, unknown field `Timezone` in `SystemAnswers`.

- [ ] **Step 3: Implement**

(a) `internal/wizard/wizard.go`:

```go
type SystemAnswers struct {
	Swap     string // e.g. "2G"; blank = no swap
	Sysctl   bool
	Timezone string // IANA zone; blank = leave untouched
}
```

(b) `internal/wizard/validate.go` — add to the mirror-regex var block (the one holding `reSwapSize`; same "mirrors config's unexported ..." rationale applies):

```go
	reTimezone = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
```

and after `optionalSwapSize`:

```go
func optionalTimezone(s string) error {
	if s == "" || reTimezone.MatchString(s) {
		return nil
	}
	return fmt.Errorf("timezone %q must be an IANA zone name like Europe/Warsaw", s)
}
```

(c) `internal/wizard/prompter.go` — in `ServerOps`, add one input to the system group, directly after the swap input:

```go
			huh.NewInput().Title("System timezone (e.g. Europe/Warsaw, blank=leave untouched)").Value(&a.System.Timezone).Validate(optionalTimezone),
```

(d) `internal/wizard/toserver.go` — extend the literal:

```go
		System: config.System{Swap: a.System.Swap, Sysctl: a.System.Sysctl, Timezone: a.System.Timezone},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/wizard/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wizard/wizard.go internal/wizard/validate.go internal/wizard/prompter.go \
  internal/wizard/toserver.go internal/wizard/validate_test.go internal/wizard/toserver_test.go \
  internal/wizard/matrix_test.go
git commit -m "feat(wizard): collect system.timezone in the ops group"
```

---

### Task 4: README + integration assert + verification + PR prep

**Files:**
- Modify: `README.md` (`system:` block in the config reference ~line 113, and the system-step thematic section if present — locate with `grep -n "swap" README.md`)
- Modify: `test/integration/assert_system.go`
- Create: `docs/pr-body-system-timezone.md` (local-only; `docs/` is gitignored — do NOT force-add)

- [ ] **Step 1: README — config reference**

Extend the `system:` block (~line 113):

```yaml
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
```

If the thematic "system" section elsewhere in the README enumerates swap+sysctl, add one matching sentence for timezone there; keep the wording consistent with the block above.

- [ ] **Step 2: Integration assert**

In `test/integration/assert_system.go`, append inside `assertSwapSysctl` (end of the function), and update its doc comment's last sentence to `A no-op when all three are off.`:

```go
	if srv.System.Timezone != "" {
		tz, err := c.Run(ctx, "timedatectl show -p Timezone --value", nil)
		if err != nil {
			t.Fatalf("timedatectl show: %v", err)
		}
		if got := strings.TrimSpace(tz.Stdout); got != srv.System.Timezone {
			t.Errorf("system timezone = %q, want %q", got, srv.System.Timezone)
		}
	}
```

Compile check: `go vet -tags integration ./test/integration/`
Expected: clean.

- [ ] **Step 3: Full verification**

```bash
gofmt -l .          # expected: no output
go vet ./...        # expected: no output
go test -race ./... # expected: all ok
```

- [ ] **Step 4: Commit**

```bash
git add README.md test/integration/assert_system.go
git commit -m "docs+test: document system.timezone; assert it in the live harness"
```

- [ ] **Step 5: Write the PR body and hand off**

Create `docs/pr-body-system-timezone.md` summarizing: the opt-in semantics (empty = never touched; no revert on clear — asymmetry vs swap documented), the cron-restart rationale, the injection-guard regex with the deliberately-skipped tzdb existence check (Windows binaries ship no tzdb; `timedatectl` fails loud on the host), wizard coverage, and the integration assert. Reference the spec path.

Do NOT push. Tell the user the branch `feat/system-timezone` is ready:

```
! git push -u origin feat/system-timezone
```

---

## Self-review notes (already applied)

- Spec coverage: §2 → Task 1; §3 → Task 2; §4 → Task 3; §5 + §6-integration → Task 4. No default/Eff anywhere (spec §2). The no-removal asymmetry is stated in the config doc comment, the step doc comment, and the README block.
- The unset-path test (`TestSystemCheckTimezoneUnsetNeverProbed`) doubles as the guard that existing system tests (all with empty Timezone) keep passing without new stubs.
- Names consistent across tasks: `Timezone`, `reTimezone` (same literal in config and wizard mirror), `optionalTimezone`, `checkTimezone`, `applyTimezone`.
- Exact command strings appear identically in implementation and stubs: `timedatectl show -p Timezone --value`, `timedatectl set-timezone 'Europe/Warsaw'`, `systemctl try-restart cron`.

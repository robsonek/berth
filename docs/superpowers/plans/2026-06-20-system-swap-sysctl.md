# System (swap + sysctl) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in, idempotent, drift-managed `system` provisioning step that creates a swap file (with `vm.swappiness`) and, optionally, a small web+DB kernel sysctl drop-in.

**Architecture:** A new `system` step (always in the pipeline, placed right after `base`) reconciles four artifacts gated by a new `system:` config block: `/swapfile`, a marked `/etc/fstab` line, `/etc/sysctl.d/99-berth-swap.conf` (swappiness, with swap), and `/etc/sysctl.d/99-berth.conf` (general set, with `sysctl: true`). All file drift uses the existing managed-marker mechanism; swap-file ownership is tracked via the fstab marker so berth never clobbers a foreign swap. Turning a knob off removes berth's artifacts.

**Tech Stack:** Go 1.25, `internal/provision` Step pipeline, `internal/ssh` Runner/FakeRunner, `internal/templates` (embed + golden tests), `internal/config` (Viper + Validate).

## Global Constraints

- Go version floor: **1.25** (`go.mod` declares `go 1.25.8`).
- **Public MIT repo:** code, comments, commits English-only; no personal/host-identifying data.
- **No `go mod tidy`** — no new deps are added by this plan.
- Managed config files MUST be written via `templates.Render` (prepends `# managed by berth`). The marker constant is `managedMarker = "# managed by berth"` (`internal/provision/steps/common.go`).
- A non-zero `ssh.Result.ExitCode` is data, not a Go error — every `r.Run` call checks BOTH the returned error and `ExitCode`.
- `FakeRunner.Run` returns an error for any unstubbed command — tests MUST stub every exact command string a code path reaches.
- Every struct field needs BOTH `mapstructure` and `yaml` tags.
- Pipeline order is by hand in `steps.Pipeline()`; `Requires()` only feeds the `--only` gate.
- After editing a `.tmpl`, run `go test -update ./internal/templates/...`, diff, commit the goldens.
- Branch off up-to-date `main`: `git checkout main && git pull` then `git checkout -b feat/system-swap-sysctl` (the user pushes; `git push` is hook-blocked for the assistant).

---

### Task 1: Config — `System` struct, field, and validation

**Files:**
- Modify: `internal/config/config.go` (add `System` struct near `Tuning`; add `System` field to `Server`)
- Modify: `internal/config/validate.go` (add `reSwapSize`, `System.validate()`, call it from `Server.Validate()`)
- Test: `internal/config/validate_test.go`

**Interfaces:**
- Produces: `config.System{ Swap string; Sysctl bool }`; `Server.System System`; method `func (System) validate() error`.

- [ ] **Step 1: Write the failing test**

Append to `internal/config/validate_test.go`:

```go
func TestSystemValidate(t *testing.T) {
	cases := []struct {
		name    string
		sys     System
		wantErr bool
	}{
		{"empty is off", System{}, false},
		{"sysctl only", System{Sysctl: true}, false},
		{"swap 2G", System{Swap: "2G"}, false},
		{"swap 512M", System{Swap: "512M"}, false},
		{"swap lowercase g", System{Swap: "2g"}, false},
		{"swap lowercase m", System{Swap: "512m"}, false},
		{"swap zero", System{Swap: "0G"}, true},
		{"swap no unit", System{Swap: "2"}, true},
		{"swap GB two letters", System{Swap: "2GB"}, true},
		{"swap trailing space", System{Swap: "2G "}, true},
		{"swap negative", System{Swap: "-1G"}, true},
		{"swap kilobytes unit", System{Swap: "1024K"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sys.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestSystemValidate`
Expected: FAIL — `System` / `validate` undefined (does not compile).

- [ ] **Step 3: Write minimal implementation**

In `internal/config/config.go`, add this struct immediately after the `Tuning` accessor methods (after `MariaDBBufferPoolEff`, before `type Server struct`):

```go
// System holds optional, opt-in host-level OS provisioning knobs. Both default
// off: an empty Swap and a false Sysctl mean berth never touches swap or kernel
// sysctl. Values are constants in the step (no SetDefault), so wizard ToServer()
// and literal-Server callers that bypass Load() need nothing seeded.
type System struct {
	Swap   string `mapstructure:"swap"   yaml:"swap,omitempty"`   // e.g. "2G"; empty = no swap
	Sysctl bool   `mapstructure:"sysctl" yaml:"sysctl,omitempty"` // default false = no sysctl drop-in
}
```

In `internal/config/config.go`, add the field to `Server` (after the `Tuning` field):

```go
	System         System   `mapstructure:"system" yaml:"system,omitempty"`
```

In `internal/config/validate.go`, add to the `var ( … )` regexp block:

```go
	reSwapSize     = regexp.MustCompile(`^[1-9][0-9]*[MmGg]$`)
```

In `internal/config/validate.go`, add the method (next to `Tuning.validate`):

```go
// validate guards the system knobs. Empty Swap / false Sysctl mean "off" and pass.
// A non-empty Swap must be a positive integer suffixed M (MiB) or G (GiB); the value
// reaches `fallocate -l` verbatim, so reject anything else (config-injection defence).
func (sy System) validate() error {
	if sy.Swap != "" && !reSwapSize.MatchString(sy.Swap) {
		return fmt.Errorf("system.swap %q must be a positive size suffixed M or G (e.g. 512M, 2G)", sy.Swap)
	}
	return nil
}
```

In `internal/config/validate.go`, call it inside `Server.Validate()` right after the `s.Tuning.validate()` block:

```go
	if err := s.System.validate(); err != nil {
		return err
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/ -run TestSystemValidate`
Expected: PASS.

- [ ] **Step 5: Run the package's full tests + vet, then commit**

Run: `go test ./internal/config/... && go vet ./internal/config/...`
Expected: PASS, no vet output.

```bash
git add internal/config/config.go internal/config/validate.go internal/config/validate_test.go
git commit -m "feat(config): add system.swap/system.sysctl knobs + validation"
```

---

### Task 2: Templates — two sysctl drop-ins + goldens

**Files:**
- Create: `internal/templates/sysctl_swap.conf.tmpl`
- Create: `internal/templates/sysctl_berth.conf.tmpl`
- Create: `internal/templates/testdata/sysctl_swap.golden`
- Create: `internal/templates/testdata/sysctl_berth.golden`
- Test: `internal/templates/templates_test.go`

**Interfaces:**
- Produces: templates renderable as `templates.Render("sysctl_swap.conf.tmpl", nil)` and `templates.Render("sysctl_berth.conf.tmpl", nil)`. Both static (nil data), `#` marker prepended by `Render`.

- [ ] **Step 1: Write the failing test**

Append to `internal/templates/templates_test.go`:

```go
func TestRenderSysctlSwapGolden(t *testing.T) {
	checkGolden(t, "sysctl_swap.conf.tmpl", "sysctl_swap.golden", nil)
}

func TestRenderSysctlBerthGolden(t *testing.T) {
	checkGolden(t, "sysctl_berth.conf.tmpl", "sysctl_berth.golden", nil)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/templates/ -run 'TestRenderSysctl'`
Expected: FAIL — template not found / golden missing.

- [ ] **Step 3: Create the templates**

Create `internal/templates/sysctl_swap.conf.tmpl` (exact content, with a trailing newline):

```
vm.swappiness = 10
```

Create `internal/templates/sysctl_berth.conf.tmpl` (exact content, with a trailing newline):

```
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
fs.file-max = 1048576
fs.inotify.max_user_watches = 524288
```

- [ ] **Step 4: Generate the goldens and verify they pass**

Run: `go test ./internal/templates/ -run 'TestRenderSysctl' -update`
Then: `go test ./internal/templates/ -run 'TestRenderSysctl'`
Expected: PASS. Confirm `internal/templates/testdata/sysctl_swap.golden` begins with `# managed by berth` then `vm.swappiness = 10`, and `sysctl_berth.golden` begins with `# managed by berth` then the four keys.

- [ ] **Step 5: Commit**

```bash
git add internal/templates/sysctl_swap.conf.tmpl internal/templates/sysctl_berth.conf.tmpl \
        internal/templates/testdata/sysctl_swap.golden internal/templates/testdata/sysctl_berth.golden \
        internal/templates/templates_test.go
git commit -m "feat(templates): managed sysctl drop-ins for swap + web/DB tuning"
```

---

### Task 3: Pure helpers — `parseSwapBytes` and `fstabSwapState`

**Files:**
- Create: `internal/provision/steps/system.go` (constants + the two pure helpers only, for now)
- Test: `internal/provision/steps/system_test.go`

**Interfaces:**
- Produces:
  - `func parseSwapBytes(size string) (int64, error)` — `"2G"`→`2*1024³`, `"512M"`→`512*1024²`, case-insensitive; error on bad input.
  - `func fstabSwapState(content string) (marked, foreign bool)` — scans `/etc/fstab` content for `/swapfile` lines; `marked` = a `/swapfile` line carrying the berth marker, `foreign` = a `/swapfile` line without it.
  - Path constants: `swapfilePath`, `fstabPath`, `swapSysctlPath`, `sysctlPath`, `swappinessProcPath`, `swappinessValue`, `fstabSwapLine`.

- [ ] **Step 1: Write the failing test**

Create `internal/provision/steps/system_test.go`:

```go
package steps

import "testing"

func TestParseSwapBytes(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"2G", 2 * 1024 * 1024 * 1024, false},
		{"512M", 512 * 1024 * 1024, false},
		{"1G", 1024 * 1024 * 1024, false},
		{"2g", 2 * 1024 * 1024 * 1024, false},
		{"512m", 512 * 1024 * 1024, false},
		{"0G", 0, true},
		{"2", 0, true},
		{"2GB", 0, true},
		{"", 0, true},
		{"G", 0, true},
	}
	for _, tc := range cases {
		got, err := parseSwapBytes(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseSwapBytes(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("parseSwapBytes(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestFstabSwapState(t *testing.T) {
	const fstab = "UUID=abc / ext4 defaults 0 1\n" +
		"/swapfile none swap sw 0 0 # managed by berth\n"
	marked, foreign := fstabSwapState(fstab)
	if !marked || foreign {
		t.Errorf("marked line: marked=%v foreign=%v, want true,false", marked, foreign)
	}

	const foreignFstab = "UUID=abc / ext4 defaults 0 1\n" +
		"/swapfile none swap sw 0 0\n"
	marked, foreign = fstabSwapState(foreignFstab)
	if marked || !foreign {
		t.Errorf("foreign line: marked=%v foreign=%v, want false,true", marked, foreign)
	}

	const none = "UUID=abc / ext4 defaults 0 1\n# /swapfile none swap sw 0 0\n"
	marked, foreign = fstabSwapState(none)
	if marked || foreign {
		t.Errorf("no/commented line: marked=%v foreign=%v, want false,false", marked, foreign)
	}

	// Marker present but NOT at end-of-line -> foreign (the removal sed anchors at $,
	// so ownership must require the marker at EOL, not merely contained).
	const markerMidLine = "/swapfile none swap sw 0 0 # managed by berth tail\n"
	marked, foreign = fstabSwapState(markerMidLine)
	if marked || !foreign {
		t.Errorf("marker mid-line: marked=%v foreign=%v, want false,true", marked, foreign)
	}

	// Leading whitespace before a properly-marked line -> still owned (trimmed).
	const indented = "  /swapfile none swap sw 0 0 # managed by berth\n"
	marked, foreign = fstabSwapState(indented)
	if !marked || foreign {
		t.Errorf("indented marked line: marked=%v foreign=%v, want true,false", marked, foreign)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/provision/steps/ -run 'TestParseSwapBytes|TestFstabSwapState'`
Expected: FAIL — undefined `parseSwapBytes` / `fstabSwapState`.

- [ ] **Step 3: Write minimal implementation**

Create `internal/provision/steps/system.go`:

```go
package steps

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

const (
	swapfilePath       = "/swapfile"
	fstabPath          = "/etc/fstab"
	swapSysctlPath     = "/etc/sysctl.d/99-berth-swap.conf"
	sysctlPath         = "/etc/sysctl.d/99-berth.conf"
	swappinessProcPath = "/proc/sys/vm/swappiness"
	swappinessValue    = "10"
)

// fstabSwapLine is the exact /etc/fstab entry berth appends for its swap file. The
// trailing managed marker is the ownership signal: removal targets only this line,
// and a /swapfile line WITHOUT it is treated as a foreign (operator-managed) swap.
const fstabSwapLine = swapfilePath + " none swap sw 0 0 " + managedMarker

// parseSwapBytes converts a validated swap size ("2G", "512M", case-insensitive)
// to bytes. Units are binary (M = MiB, G = GiB) to match `fallocate -l` and
// `stat -c %s`. It re-rejects bad input defensively (config.Validate already guards).
func parseSwapBytes(size string) (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(size))
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid swap size %q", size)
	}
	num, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
	if err != nil || num <= 0 {
		return 0, fmt.Errorf("invalid swap size %q", size)
	}
	switch s[len(s)-1] {
	case 'M':
		return num * 1024 * 1024, nil
	case 'G':
		return num * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("invalid swap size unit in %q (use M or G)", size)
	}
}

// fstabSwapState scans /etc/fstab content for /swapfile entries. marked is true if a
// /swapfile mount line ENDS WITH the berth marker (berth owns it); foreign is true if a
// /swapfile mount line lacks the marker at end-of-line (operator-managed). Comment lines
// are ignored. Ownership is HasSuffix(trimmed, marker) — NOT Contains — so this matches
// the removal sed (which anchors the marker at `$`); using Contains would classify a
// line with the marker mid-text as owned while the sed left it in place.
func fstabSwapState(content string) (marked, foreign bool) {
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) == 0 || fields[0] != swapfilePath {
			continue
		}
		if strings.HasSuffix(t, managedMarker) {
			marked = true
		} else {
			foreign = true
		}
	}
	return marked, foreign
}
```

Note: the imports `context`, `config`, `provision`, `bssh`, `templates` are used by Tasks 4–5; Go will complain they are unused until then. To keep this task compiling and committable on its own, add the step boilerplate now (its Check/Apply are filled in Tasks 4–5):

```go
type system struct{}

// System provisions optional host-level OS settings: a swap file (+ vm.swappiness)
// and an opt-in web/DB kernel sysctl drop-in. It is ALWAYS in the pipeline (ungated)
// so disabling a knob can drift-remove berth's artifacts, and runs right after base
// (before php/composer/database) so the swap margin protects provisioning itself.
func System() provision.Step { return system{} }

func (system) Name() string       { return "system" }
func (system) Requires() []string { return []string{"preflight"} }

func (system) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	return provision.CheckResult{Satisfied: true}, nil // Tasks 4 fills this in
}

func (system) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	return nil // Task 5 fills this in
}

// renderSwapSysctl renders the vm.swappiness drop-in (static; '#' marker).
func renderSwapSysctl() ([]byte, error) { return templates.Render("sysctl_swap.conf.tmpl", nil) }

// renderSysctl renders the general web/DB sysctl drop-in (static; '#' marker).
func renderSysctl() ([]byte, error) { return templates.Render("sysctl_berth.conf.tmpl", nil) }

// sysctlKeys mirrors sysctl_berth.conf.tmpl: the (key, value) pairs Check reads back
// via `sysctl -n` to confirm the drop-in is live. Kept in sync with the template by
// TestSysctlKeysMatchTemplate.
var sysctlKeys = []struct{ Key, Value string }{
	{"net.core.somaxconn", "4096"},
	{"net.ipv4.tcp_tw_reuse", "1"},
	{"fs.file-max", "1048576"},
	{"fs.inotify.max_user_watches", "524288"},
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/provision/steps/ -run 'TestParseSwapBytes|TestFstabSwapState' && go vet ./internal/provision/steps/`
Expected: PASS, no vet output (all imports now used).

- [ ] **Step 5: Add the template/keys sync guard and commit**

Append to `internal/provision/steps/system_test.go`:

```go
func TestSysctlKeysMatchTemplate(t *testing.T) {
	out, err := renderSysctl()
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range sysctlKeys {
		want := kv.Key + " = " + kv.Value
		if !strings.Contains(string(out), want) {
			t.Errorf("sysctl_berth.conf.tmpl missing %q (keep sysctlKeys in sync with the template)", want)
		}
	}
}
```

Add `"strings"` to the test file's imports. Run: `go test ./internal/provision/steps/ -run 'TestParseSwapBytes|TestFstabSwapState|TestSysctlKeysMatchTemplate'` → PASS.

```bash
git add internal/provision/steps/system.go internal/provision/steps/system_test.go
git commit -m "feat(system): swap-size + fstab parsing helpers, step skeleton"
```

---

### Task 4: `system` step — `Check`

**Files:**
- Modify: `internal/provision/steps/system.go` (replace the stub `Check`; add the predicate helpers + small runners)
- Test: `internal/provision/steps/system_test.go`

**Interfaces:**
- Consumes: `parseSwapBytes`, `fstabSwapState`, `renderSwapSysctl`, `renderSysctl`, `sysctlKeys`, the path constants (Task 3); `checkManagedFile`, `managedFileSatisfied`, `managedFilePresent`, `shQuote`, `managedMarker` (common.go).
- Produces:
  - `func checkSwap(ctx, rc, r, size) (satisfied bool, changes []string, err error)`
  - `func checkSwapRemoval(ctx, r) (satisfied bool, changes []string, err error)`
  - `func checkSysctl(ctx, rc, r) (satisfied bool, changes []string, err error)`
  - `func checkSysctlRemoval(ctx, r) (satisfied bool, changes []string, err error)`
  - helpers `catTrim`, `swapfileSize`, `swapActive`
  - a real `system.Check` aggregating them.

- [ ] **Step 1: Write the failing tests**

Append to `internal/provision/steps/system_test.go` (add imports `context`, `github.com/robsonek/berth/internal/config`, `github.com/robsonek/berth/internal/provision`, `bssh "github.com/robsonek/berth/internal/ssh"`):

```go
// swapServer builds a Server with swap enabled at the given size and sysctl off.
func swapServer(size string) *config.Server {
	return &config.Server{System: config.System{Swap: size}}
}

// stubSwapSatisfied stubs every command checkSwap issues for a converged 2G swap.
func stubSwapSatisfied(t *testing.T, f *bssh.FakeRunner, size string) {
	t.Helper()
	want, err := renderSwapSysctl()
	if err != nil {
		t.Fatal(err)
	}
	bytes := func() int64 { b, _ := parseSwapBytes(size); return b }()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(bytes, 10) + "\n"})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "10\n"})
	// sysctl is off in these swap-only tests, so the step's Check/Apply also reach the
	// sysctl-removal predicate, which reads the general drop-in. Stub it absent.
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
}

func TestSystemCheckSwapSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubSwapSatisfied(t, f, "2G")
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer("2G"), f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestSystemCheckSwapAbsentUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 1})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "60\n"})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer("2G"), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when swap absent")
	}
}

func TestSystemCheckSwapSizeMismatchUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubSwapSatisfied(t, f, "2G")
	// Re-stub stat to report a 1G file while config wants 2G.
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(1024*1024*1024, 10) + "\n"})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer("2G"), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when swap file size differs from config")
	}
}

func TestSystemCheckForeignSwapAbortsWithoutForce(t *testing.T) {
	f := bssh.NewFakeRunner()
	// A foreign /swapfile: fstab line without the berth marker, file present.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(1024*1024*1024, 10) + "\n"})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // reached only on the --force pass (sysctl off)
	cr, err := System().Check(context.Background(), provision.RunCtx{}, swapServer("2G"), f)
	if err == nil {
		t.Error("expected abort error on foreign /swapfile without --force")
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied on foreign /swapfile")
	}
	// With --force: unsatisfied (overwrite pending) but no error.
	cr, err = System().Check(context.Background(), provision.RunCtx{Force: true}, swapServer("2G"), f)
	if err != nil {
		t.Errorf("unexpected error with --force: %v", err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied (overwrite pending) with --force")
	}
}

func TestSystemCheckSwapDisabledNoArtifactsSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied no-op when nothing enabled and no artifacts; got %+v", cr)
	}
}

func TestSystemCheckSwapDisabledButPresentUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied: a berth-marked swap lingers while swap is off")
	}
}

func TestSystemCheckSysctlSatisfied(t *testing.T) {
	want, _ := renderSysctl()
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	for _, kv := range sysctlKeys {
		f.On("sysctl -n "+kv.Key, bssh.Result{ExitCode: 0, Stdout: kv.Value + "\n"})
	}
	cr, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{System: config.System{Sysctl: true}}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestSystemCheckSysctlStaleValueUnsatisfied(t *testing.T) {
	want, _ := renderSysctl()
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	// File up-to-date but the first key's running value is stale.
	f.On("sysctl -n net.core.somaxconn", bssh.Result{ExitCode: 0, Stdout: "128\n"})
	cr, err := System().Check(context.Background(), provision.RunCtx{}, &config.Server{System: config.System{Sysctl: true}}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when running sysctl value is stale")
	}
}
```

(Add `"strconv"` to the test imports.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/provision/steps/ -run 'TestSystemCheck'`
Expected: FAIL — the stub `Check` returns `Satisfied:true` (most assertions fail) and predicate helpers are undefined once referenced.

- [ ] **Step 3: Implement `Check` and its predicates**

In `internal/provision/steps/system.go`, replace the stub `Check` with the real one and add the helpers below it:

```go
func (system) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	var changes []string
	if s.System.Swap != "" {
		ok, ch, err := checkSwap(ctx, rc, r, s.System.Swap)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	} else {
		ok, ch, err := checkSwapRemoval(ctx, r)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	}
	if s.System.Sysctl {
		ok, ch, err := checkSysctl(ctx, rc, r)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	} else {
		ok, ch, err := checkSysctlRemoval(ctx, r)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	}
	if len(changes) == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "swap & sysctl in desired state"}, nil
	}
	return provision.CheckResult{Satisfied: false, Reason: "system (swap/sysctl) not in desired state", Changes: changes}, nil
}

// catTrim returns the trimmed stdout of `cat <path>` and whether the file was
// readable (exit 0). Read-only; mirrors checkManagedFile's read style.
func catTrim(ctx context.Context, r bssh.Runner, path string) (string, bool, error) {
	res, err := r.Run(ctx, "cat "+shQuote(path), nil)
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(res.Stdout), res.ExitCode == 0, nil
}

// swapfileSize reports whether /swapfile exists and its size in bytes (stat -c %s).
func swapfileSize(ctx context.Context, r bssh.Runner) (exists bool, size int64, err error) {
	res, err := r.Run(ctx, "stat -c %s "+shQuote(swapfilePath)+" 2>/dev/null", nil)
	if err != nil {
		return false, 0, err
	}
	if res.ExitCode != 0 {
		return false, 0, nil
	}
	n, perr := strconv.ParseInt(strings.TrimSpace(res.Stdout), 10, 64)
	if perr != nil {
		return false, 0, nil
	}
	return true, n, nil
}

// swapActive reports whether /swapfile is an active swap area (swapon --show).
func swapActive(ctx context.Context, r bssh.Runner) (bool, error) {
	res, err := r.Run(ctx, "swapon --show=NAME --noheadings", nil)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if strings.TrimSpace(line) == swapfilePath {
			return true, nil
		}
	}
	return false, nil
}

// checkSwap is the read-only predicate for an enabled swap. It enforces the conflict
// guard (a foreign /swapfile fstab line — even alongside a berth-marked one — or a
// /swapfile file with no berth-marked line aborts unless --force), then reports
// satisfied iff the file exists at the configured size, is an active swap area, the
// marked fstab line is present, and the swappiness drop-in is up-to-date AND live
// (running vm.swappiness == 10).
func checkSwap(ctx context.Context, rc provision.RunCtx, r bssh.Runner, size string) (bool, []string, error) {
	wantBytes, err := parseSwapBytes(size)
	if err != nil {
		return false, nil, err
	}
	fstab, _, err := catTrim(ctx, r, fstabPath)
	if err != nil {
		return false, nil, err
	}
	marked, foreign := fstabSwapState(fstab)
	exists, gotBytes, err := swapfileSize(ctx, r)
	if err != nil {
		return false, nil, err
	}
	// Conflict: a foreign fstab line (even if a marked one also exists — a duplicate
	// state berth must not silently bless), or a /swapfile present with no marked line.
	if foreign || (exists && !marked) {
		if !rc.Force {
			return false, nil, fmt.Errorf("%s present but not managed by berth (need %q at the end of its /etc/fstab line); re-run with --force to take it over", swapfilePath, managedMarker)
		}
		return false, []string{"take over and rewrite " + swapfilePath + " (--force)"}, nil
	}
	var changes []string
	if !exists || gotBytes != wantBytes {
		changes = append(changes, fmt.Sprintf("create %s (%s) + mkswap + swapon", swapfilePath, size))
	}
	active, err := swapActive(ctx, r)
	if err != nil {
		return false, nil, err
	}
	if !active {
		changes = append(changes, "swapon "+swapfilePath)
	}
	if !marked {
		changes = append(changes, "add "+swapfilePath+" entry to "+fstabPath)
	}
	swapDropOK, err := swappinessLive(ctx, rc, r)
	if err != nil {
		return false, nil, err
	}
	if !swapDropOK {
		changes = append(changes, "write "+swapSysctlPath+" (vm.swappiness="+swappinessValue+") + sysctl -p")
	}
	if len(changes) == 0 {
		return true, nil, nil
	}
	return false, changes, nil
}

// swappinessLive reports whether the swappiness drop-in is up-to-date (managed-file
// drift; an unmanaged file aborts unless --force) AND the running value is loaded.
func swappinessLive(ctx context.Context, rc provision.RunCtx, r bssh.Runner) (bool, error) {
	want, err := renderSwapSysctl()
	if err != nil {
		return false, err
	}
	state, err := checkManagedFile(ctx, r, swapSysctlPath, want)
	if err != nil {
		return false, err
	}
	fileOK, err := managedFileSatisfied(state, swapSysctlPath, rc.Force)
	if err != nil {
		return false, err
	}
	val, _, err := catTrim(ctx, r, swappinessProcPath)
	if err != nil {
		return false, err
	}
	return fileOK && val == swappinessValue, nil
}

// checkSwapRemoval reports satisfied unless a berth-owned swap lingers while swap is
// off: a marked fstab line or a berth-managed swappiness drop-in. A foreign swap is
// never flagged (berth removes only what it created).
func checkSwapRemoval(ctx context.Context, r bssh.Runner) (bool, []string, error) {
	fstab, _, err := catTrim(ctx, r, fstabPath)
	if err != nil {
		return false, nil, err
	}
	marked, _ := fstabSwapState(fstab)
	dropPresent, err := managedFilePresent(ctx, r, swapSysctlPath)
	if err != nil {
		return false, nil, err
	}
	if marked || dropPresent {
		return false, []string{"remove berth swap (" + swapfilePath + " + fstab entry + " + swapSysctlPath + ")"}, nil
	}
	return true, nil, nil
}

// checkSysctl reports satisfied iff the general drop-in is up-to-date (unmanaged
// aborts unless --force) AND every key's running value matches.
func checkSysctl(ctx context.Context, rc provision.RunCtx, r bssh.Runner) (bool, []string, error) {
	want, err := renderSysctl()
	if err != nil {
		return false, nil, err
	}
	state, err := checkManagedFile(ctx, r, sysctlPath, want)
	if err != nil {
		return false, nil, err
	}
	fileOK, err := managedFileSatisfied(state, sysctlPath, rc.Force)
	if err != nil {
		return false, nil, err
	}
	if !fileOK {
		return false, []string{"write " + sysctlPath + " + sysctl --system"}, nil
	}
	for _, kv := range sysctlKeys {
		res, err := r.Run(ctx, "sysctl -n "+kv.Key, nil)
		if err != nil {
			return false, nil, err
		}
		if strings.TrimSpace(res.Stdout) != kv.Value {
			return false, []string{"reload " + sysctlPath + " (running values stale)"}, nil
		}
	}
	return true, nil, nil
}

// checkSysctlRemoval reports satisfied unless the general drop-in is berth-managed
// while sysctl is off.
func checkSysctlRemoval(ctx context.Context, r bssh.Runner) (bool, []string, error) {
	present, err := managedFilePresent(ctx, r, sysctlPath)
	if err != nil {
		return false, nil, err
	}
	if present {
		return false, []string{"remove " + sysctlPath + " + sysctl --system"}, nil
	}
	return true, nil, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/provision/steps/ -run 'TestSystemCheck'`
Expected: PASS (all `TestSystemCheck*`).

- [ ] **Step 5: Run the package suite + vet, then commit**

Run: `go test ./internal/provision/steps/ && go vet ./internal/provision/steps/`
Expected: PASS, no vet output.

```bash
git add internal/provision/steps/system.go internal/provision/steps/system_test.go
git commit -m "feat(system): Check predicate for swap + sysctl (drift + foreign guard)"
```

---

### Task 5: `system` step — `Apply`

**Files:**
- Modify: `internal/provision/steps/system.go` (replace the stub `Apply`; add apply helpers + `runOK`/`swapoffIfActive`)
- Test: `internal/provision/steps/system_test.go`

**Interfaces:**
- Consumes: all predicates + helpers from Task 4; `bssh.FileSpec` for writes.
- Produces: real `system.Apply`, plus `applySwap`, `applySwapRemoval`, `applySysctl`, `applySysctlRemoval`, `runOK`, `swapoffIfActive`, and the two fstab sed constants `fstabSedAny`, `fstabSedMarked`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/provision/steps/system_test.go`:

```go
func TestSystemApplySwapCreates(t *testing.T) {
	f := bssh.NewFakeRunner()
	// checkSwap pre-check sees nothing present (fresh box).
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 1})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "60\n"})
	// create path commands.
	f.On("fallocate -l 2G /swapfile", bssh.Result{})
	f.On("chmod 600 /swapfile", bssh.Result{})
	f.On("mkswap /swapfile", bssh.Result{})
	f.On("swapon /swapfile", bssh.Result{})
	f.On("printf '\\n%s\\n' '/swapfile none swap sw 0 0 # managed by berth' >> /etc/fstab", bssh.Result{})
	f.On("sed -i '\\|^[[:space:]]*/swapfile[[:space:]]|d' /etc/fstab", bssh.Result{})
	f.On("sysctl -p /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)

	if err := System().Apply(context.Background(), provision.RunCtx{}, swapServer("2G"), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, want := range []string{"fallocate -l 2G /swapfile", "mkswap /swapfile", "swapon /swapfile",
		"printf '\\n%s\\n' '/swapfile none swap sw 0 0 # managed by berth' >> /etc/fstab",
		"sysctl -p /etc/sysctl.d/99-berth-swap.conf"} {
		if !calledCmd(f, want) {
			t.Errorf("Apply did not run %q", want)
		}
	}
	if !wrotePath(f, swapSysctlPath) {
		t.Error("swappiness drop-in not written")
	}
	// Order: fallocate < mkswap < swapon.
	if !(cmdIndex(f, "fallocate -l 2G /swapfile") < cmdIndex(f, "mkswap /swapfile") &&
		cmdIndex(f, "mkswap /swapfile") < cmdIndex(f, "swapon /swapfile")) {
		t.Error("wrong create order; want fallocate < mkswap < swapon")
	}
}

func TestSystemApplySwapNoopWhenSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubSwapSatisfied(t, f, "2G")
	if err := System().Apply(context.Background(), provision.RunCtx{}, swapServer("2G"), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if calledCmd(f, "fallocate -l 2G /swapfile") || len(f.Writes()) != 0 {
		t.Errorf("expected no mutation when already satisfied; calls=%v writes=%v", f.Calls(), f.Writes())
	}
}

func TestSystemApplySwapResizeRecreates(t *testing.T) {
	f := bssh.NewFakeRunner()
	// Marked + active + correct fstab + swappiness loaded, but the file is 1G vs 2G.
	want, _ := renderSwapSysctl()
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(1024*1024*1024, 10) + "\n"})
	// Active in checkSwap and again in swapoffIfActive, then empty after the rebuild so
	// swapon re-enables — proves the resized swap is actually turned back on.
	f.OnSeq("swapon --show=NAME --noheadings",
		bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"},
		bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"},
		bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On("cat '/proc/sys/vm/swappiness'", bssh.Result{ExitCode: 0, Stdout: "10\n"})
	// resize path.
	f.On("swapoff /swapfile", bssh.Result{})
	f.On("rm -f /swapfile", bssh.Result{})
	f.On("fallocate -l 2G /swapfile", bssh.Result{})
	f.On("chmod 600 /swapfile", bssh.Result{})
	f.On("mkswap /swapfile", bssh.Result{})
	f.On("swapon /swapfile", bssh.Result{})
	f.On("sysctl -p /etc/sysctl.d/99-berth-swap.conf", bssh.Result{}) // applySwap always rewrites the swappiness drop-in
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)

	if err := System().Apply(context.Background(), provision.RunCtx{}, swapServer("2G"), f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !(cmdIndex(f, "swapoff /swapfile") < cmdIndex(f, "rm -f /swapfile") &&
		cmdIndex(f, "rm -f /swapfile") < cmdIndex(f, "fallocate -l 2G /swapfile")) {
		t.Error("resize must swapoff + rm before recreating at the new size")
	}
	if !calledCmd(f, "swapon /swapfile") {
		t.Error("resize must re-enable the swap (swapon) after rebuilding")
	}
}

func TestSystemApplySwapRemovalTargetsMarkedLineOnly(t *testing.T) {
	f := bssh.NewFakeRunner()
	// Swap off, but a berth-marked swap lingers.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 0, Stdout: "# managed by berth\nvm.swappiness = 10\n"})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"}) // swapoffIfActive sees it active
	f.On("swapoff /swapfile", bssh.Result{})
	f.On("sed -i '\\|^[[:space:]]*/swapfile[[:space:]].*# managed by berth$|d' /etc/fstab", bssh.Result{})
	f.On("rm -f /swapfile", bssh.Result{})
	f.On("rm -f /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)

	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, want := range []string{"swapoff /swapfile",
		"sed -i '\\|^[[:space:]]*/swapfile[[:space:]].*# managed by berth$|d' /etc/fstab",
		"rm -f /swapfile", "rm -f /etc/sysctl.d/99-berth-swap.conf"} {
		if !calledCmd(f, want) {
			t.Errorf("removal did not run %q", want)
		}
	}
}

func TestSystemApplySwapRemovalSkipsForeign(t *testing.T) {
	f := bssh.NewFakeRunner()
	// Swap off; a FOREIGN /swapfile line (no marker) and no berth drop-in: leave it.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if calledCmd(f, "rm -f /swapfile") || calledCmd(f, "swapoff /swapfile") {
		t.Error("must not touch a foreign /swapfile on removal")
	}
}

func TestSystemApplySwapoffFailureAborts(t *testing.T) {
	f := bssh.NewFakeRunner()
	// swap off; a berth-marked ACTIVE swap, but swapoff fails (e.g. ENOMEM). Apply must
	// abort BEFORE rm -f, never removing a file backing a still-active swap.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "/swapfile none swap sw 0 0 # managed by berth\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("swapon --show=NAME --noheadings", bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"})
	f.On("swapoff /swapfile", bssh.Result{ExitCode: 1, Stderr: "swapoff: Cannot allocate memory"})
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err == nil {
		t.Fatal("expected Apply to abort when an active swapoff fails")
	}
	if calledCmd(f, "rm -f /swapfile") {
		t.Error("must NOT rm /swapfile after a failed active swapoff")
	}
}

func TestSystemApplySwapForceTakeoverSameSize(t *testing.T) {
	f := bssh.NewFakeRunner()
	// A foreign 2G /swapfile (no marker). --force must REBUILD it (mkswap) and normalize
	// fstab, not merely swapon a possibly-non-swap file.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n"})
	f.On("stat -c %s '/swapfile' 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: strconv.FormatInt(2*1024*1024*1024, 10) + "\n"})
	// checkSwap returns at the conflict guard (no swapActive there), so only 2 reads:
	// swapoffIfActive (active) then post-rebuild (empty).
	f.OnSeq("swapon --show=NAME --noheadings",
		bssh.Result{ExitCode: 0, Stdout: "/swapfile\n"},
		bssh.Result{ExitCode: 0, Stdout: ""})
	f.On("swapoff /swapfile", bssh.Result{})
	f.On("rm -f /swapfile", bssh.Result{})
	f.On("fallocate -l 2G /swapfile", bssh.Result{})
	f.On("chmod 600 /swapfile", bssh.Result{})
	f.On("mkswap /swapfile", bssh.Result{})
	f.On("swapon /swapfile", bssh.Result{})
	f.On("sed -i '\\|^[[:space:]]*/swapfile[[:space:]]|d' /etc/fstab", bssh.Result{})
	f.On("printf '\\n%s\\n' '/swapfile none swap sw 0 0 # managed by berth' >> /etc/fstab", bssh.Result{})
	f.On("sysctl -p /etc/sysctl.d/99-berth-swap.conf", bssh.Result{})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // sysctl-removal read (sysctl off)
	srv := &config.Server{System: config.System{Swap: "2G"}}
	if err := System().Apply(context.Background(), provision.RunCtx{Force: true}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, "mkswap /swapfile") {
		t.Error("--force takeover must rebuild the swap (mkswap), not trust the existing file")
	}
	if !calledCmd(f, "sed -i '\\|^[[:space:]]*/swapfile[[:space:]]|d' /etc/fstab") {
		t.Error("--force takeover must normalize fstab (delete the foreign line)")
	}
}

func TestSystemApplySysctlEnables(t *testing.T) {
	f := bssh.NewFakeRunner()
	// swap is off, so Apply first runs the swap-removal predicate (a no-op here).
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 1}) // absent
	f.On("sysctl --system", bssh.Result{})
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{System: config.System{Sysctl: true}}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !wrotePath(f, sysctlPath) {
		t.Error("general sysctl drop-in not written")
	}
	if !calledCmd(f, "sysctl --system") {
		t.Error("sysctl --system not run")
	}
}

func TestSystemApplySysctlRemoval(t *testing.T) {
	f := bssh.NewFakeRunner()
	// sysctl off; the general drop-in is berth-managed -> remove.
	f.On("cat '/etc/fstab'", bssh.Result{ExitCode: 0, Stdout: "UUID=x / ext4 defaults 0 1\n"})
	f.On("cat '/etc/sysctl.d/99-berth-swap.conf'", bssh.Result{ExitCode: 1})
	f.On("cat '/etc/sysctl.d/99-berth.conf'", bssh.Result{ExitCode: 0, Stdout: "# managed by berth\nnet.core.somaxconn = 4096\n"})
	f.On("rm -f /etc/sysctl.d/99-berth.conf", bssh.Result{})
	f.On("sysctl --system", bssh.Result{})
	if err := System().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, "rm -f /etc/sysctl.d/99-berth.conf") {
		t.Error("expected the general drop-in removed")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/provision/steps/ -run 'TestSystemApply'`
Expected: FAIL — the stub `Apply` does nothing.

- [ ] **Step 3: Implement `Apply` and helpers**

In `internal/provision/steps/system.go`, add the two sed constants next to `fstabSwapLine`:

```go
// fstabSedAny deletes ANY /swapfile mount line; used before appending berth's line
// (a no-op on a clean box, a clean takeover under --force). fstabSedMarked deletes
// ONLY berth's marked line; used on removal so a foreign swap is never touched.
const (
	fstabSedAny    = `\|^[[:space:]]*` + swapfilePath + `[[:space:]]|d`
	fstabSedMarked = `\|^[[:space:]]*` + swapfilePath + `[[:space:]].*` + managedMarker + `$|d`
)
```

Replace the stub `Apply` and add the helpers:

```go
func (system) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if s.System.Swap != "" {
		if err := applySwap(ctx, rc, r, s.System.Swap); err != nil {
			return err
		}
	} else {
		if err := applySwapRemoval(ctx, r); err != nil {
			return err
		}
	}
	if s.System.Sysctl {
		if err := applySysctl(ctx, rc, r); err != nil {
			return err
		}
	} else {
		if err := applySysctlRemoval(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// runOK runs cmd and fails on a transport error OR a non-zero exit.
func runOK(ctx context.Context, r bssh.Runner, cmd string) error {
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%q: %s", cmd, res.Stderr)
	}
	return nil
}

// swapoffIfActive runs `swapoff /swapfile` only when it is an active swap area, failing
// loud (runOK) if that swapoff fails — e.g. ENOMEM on a memory-pressured small box — so
// a caller never rm's/recreates over a still-active swap. A no-op when inactive (a "not
// active" state is never treated as an error).
func swapoffIfActive(ctx context.Context, r bssh.Runner) error {
	active, err := swapActive(ctx, r)
	if err != nil {
		return err
	}
	if !active {
		return nil
	}
	return runOK(ctx, r, "swapoff "+swapfilePath)
}

// applySwap creates/converges the swap file, fstab entry and swappiness drop-in. It
// re-runs checkSwap first (so a satisfied swap is a no-op, and the conflict guard aborts
// as in Check). `recreate` also fires when the existing /swapfile is unmarked (a --force
// takeover): a crash between fallocate and mkswap could have left a non-swap file, so we
// never trust an unmarked file — we rebuild it.
func applySwap(ctx context.Context, rc provision.RunCtx, r bssh.Runner, size string) error {
	ok, _, err := checkSwap(ctx, rc, r, size)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	norm := strings.ToUpper(strings.TrimSpace(size))
	wantBytes, err := parseSwapBytes(norm)
	if err != nil {
		return err
	}
	fstab, _, err := catTrim(ctx, r, fstabPath)
	if err != nil {
		return err
	}
	marked, foreign := fstabSwapState(fstab)
	exists, gotBytes, err := swapfileSize(ctx, r)
	if err != nil {
		return err
	}
	recreate := !exists || gotBytes != wantBytes || !marked
	if exists && recreate {
		if err := swapoffIfActive(ctx, r); err != nil {
			return err
		}
		if err := runOK(ctx, r, "rm -f "+swapfilePath); err != nil {
			return err
		}
	}
	if recreate {
		for _, cmd := range []string{
			"fallocate -l " + norm + " " + swapfilePath,
			"chmod 600 " + swapfilePath,
			"mkswap " + swapfilePath,
		} {
			if err := runOK(ctx, r, cmd); err != nil {
				return err
			}
		}
	}
	active, err := swapActive(ctx, r)
	if err != nil {
		return err
	}
	if !active {
		if err := runOK(ctx, r, "swapon "+swapfilePath); err != nil {
			return err
		}
	}
	// Normalize fstab to exactly one marked line when ours is missing OR a foreign line
	// exists: delete any /swapfile line (no-op when clean), then newline-safe append so a
	// missing trailing newline in /etc/fstab cannot merge our entry onto the prior line.
	if !marked || foreign {
		if err := runOK(ctx, r, "sed -i "+shQuote(fstabSedAny)+" "+fstabPath); err != nil {
			return err
		}
		if err := runOK(ctx, r, "printf '\\n%s\\n' "+shQuote(fstabSwapLine)+" >> "+fstabPath); err != nil {
			return err
		}
	}
	want, err := renderSwapSysctl()
	if err != nil {
		return err
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{Path: swapSysctlPath, Content: want, Owner: "root", Group: "root", Mode: 0o644, Sudo: true}); err != nil {
		return fmt.Errorf("write %s: %w", swapSysctlPath, err)
	}
	return runOK(ctx, r, "sysctl -p "+swapSysctlPath)
}

// applySwapRemoval removes berth's swap artifacts when swap is off. It removes the
// swap file + fstab line only if berth marked it (never a foreign swap), and the
// swappiness drop-in if berth-managed.
func applySwapRemoval(ctx context.Context, r bssh.Runner) error {
	fstab, _, err := catTrim(ctx, r, fstabPath)
	if err != nil {
		return err
	}
	marked, _ := fstabSwapState(fstab)
	dropPresent, err := managedFilePresent(ctx, r, swapSysctlPath)
	if err != nil {
		return err
	}
	if !marked && !dropPresent {
		return nil
	}
	if marked {
		if err := swapoffIfActive(ctx, r); err != nil {
			return err
		}
		if err := runOK(ctx, r, "sed -i "+shQuote(fstabSedMarked)+" "+fstabPath); err != nil {
			return err
		}
		if err := runOK(ctx, r, "rm -f "+swapfilePath); err != nil {
			return err
		}
	}
	if dropPresent {
		if err := runOK(ctx, r, "rm -f "+swapSysctlPath); err != nil {
			return err
		}
	}
	return nil
}

// applySysctl writes the general drop-in and reloads, unless already satisfied.
func applySysctl(ctx context.Context, rc provision.RunCtx, r bssh.Runner) error {
	ok, _, err := checkSysctl(ctx, rc, r)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	want, err := renderSysctl()
	if err != nil {
		return err
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{Path: sysctlPath, Content: want, Owner: "root", Group: "root", Mode: 0o644, Sudo: true}); err != nil {
		return fmt.Errorf("write %s: %w", sysctlPath, err)
	}
	return runOK(ctx, r, "sysctl --system")
}

// applySysctlRemoval removes the general drop-in when sysctl is off and it is
// berth-managed, then reloads.
func applySysctlRemoval(ctx context.Context, r bssh.Runner) error {
	present, err := managedFilePresent(ctx, r, sysctlPath)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if err := runOK(ctx, r, "rm -f "+sysctlPath); err != nil {
		return err
	}
	return runOK(ctx, r, "sysctl --system")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/provision/steps/ -run 'TestSystemApply'`
Expected: PASS (all `TestSystemApply*`).

- [ ] **Step 5: Run the full package + race + vet, then commit**

Run: `go test -race ./internal/provision/steps/ && go vet ./internal/provision/steps/`
Expected: PASS, no vet output.

```bash
git add internal/provision/steps/system.go internal/provision/steps/system_test.go
git commit -m "feat(system): Apply for swap create/resize/remove + sysctl enable/remove"
```

---

### Task 6: Pipeline wiring

**Files:**
- Modify: `internal/provision/steps/registry.go` (insert `System()` after `SystemBase()`)
- Test: `internal/provision/steps/registry_test.go`

**Interfaces:**
- Consumes: `System()` (Task 3).

- [ ] **Step 1: Write the failing test**

Append to `internal/provision/steps/registry_test.go`:

```go
func TestPipelineIncludesSystemAfterBase(t *testing.T) {
	s := &config.Server{Database: config.Database{Engine: "postgres"}, Sites: []config.Site{{Domain: "a.example.com"}}}
	names := stepNames(steps.Pipeline(s, secret.NewRedactor(), true))
	idx := func(want string) int {
		for i, n := range names {
			if n == want {
				return i
			}
		}
		return -1
	}
	if idx("system") < 0 {
		t.Fatalf("system step missing from pipeline: %v", names)
	}
	if !(idx("base") < idx("system") && idx("system") < idx("php")) {
		t.Errorf("system must sit between base and php; got base=%d system=%d php=%d",
			idx("base"), idx("system"), idx("php"))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/provision/steps/ -run TestPipelineIncludesSystemAfterBase`
Expected: FAIL — `system` not in the pipeline.

- [ ] **Step 3: Wire it in**

In `internal/provision/steps/registry.go`, change the initial slice from:

```go
	steps := []provision.Step{
		Preflight(), SystemBase(), Accounts(), Hardening(),
		PHP(), Nginx(), Composer(),
	}
```

to:

```go
	steps := []provision.Step{
		Preflight(), SystemBase(), System(), Accounts(), Hardening(),
		PHP(), Nginx(), Composer(),
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/provision/steps/ -run TestPipeline`
Expected: PASS (the new test and the existing pipeline tests).

- [ ] **Step 5: Commit**

```bash
git add internal/provision/steps/registry.go internal/provision/steps/registry_test.go
git commit -m "feat(system): place the system step after base in the pipeline"
```

---

### Task 7: Docs — README reference + example config

**Files:**
- Modify: `README.md` (Configuration reference: add the `system:` block)
- Modify: `examples/production-single.yml` (demonstrate `system:`)
- Test: `main_test.go` (`TestExampleConfigsAreValid` already loads every `examples/*.yml`)

**Interfaces:** none (docs only).

- [ ] **Step 1: Add the example block**

In `examples/production-single.yml`, add a top-level `system:` block (match the file's existing indentation/comment style). Use only public placeholder data:

```yaml
# Optional host-level OS provisioning (both default off).
system:
  swap: 2G        # create /swapfile (2 GiB) + vm.swappiness=10; omit to leave swap untouched
  sysctl: true    # write a conservative web/DB kernel sysctl drop-in
```

- [ ] **Step 2: Add the README reference**

In `README.md`, locate the annotated Configuration reference YAML and add the same `system:` block with inline documentation of each field, its default (`swap` empty = off, `sysctl` false), and accepted values (`swap`: positive integer + `M`/`G`; `sysctl`: bool). Place it consistently with the neighbouring `tuning:`/`fail2ban:` documentation.

- [ ] **Step 3: Verify the examples still load**

Run: `go test . -run TestExampleConfigsAreValid`
Expected: PASS (the new `system:` block parses and validates).

- [ ] **Step 4: Commit**

```bash
git add README.md examples/production-single.yml
git commit -m "docs: document and demonstrate the system swap/sysctl block"
```

---

### Task 8: Live integration asserts

**Files:**
- Create: `test/integration/assert_system.go`
- Modify: `test/integration/provision_test.go` (call the new assert in the `invCtx` block)

**Interfaces:**
- Consumes: `*bssh.Client`, `*config.Server` (the live test harness), `srv.System`.
- Produces: `func assertSwapSysctl(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server)`.

- [ ] **Step 1: Write the assert helper**

Create `test/integration/assert_system.go`:

```go
//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertSwapSysctl verifies the live end state of the system step: when swap is
// configured, /swapfile is an active swap area and vm.swappiness is 10; when sysctl
// is enabled, each managed key's running value matches. A no-op when both are off.
func assertSwapSysctl(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()

	if srv.System.Swap != "" {
		on, err := c.Run(ctx, "swapon --show=NAME --noheadings", nil)
		if err != nil {
			t.Fatalf("swapon --show: %v", err)
		}
		if !strings.Contains(on.Stdout, "/swapfile") {
			t.Errorf("/swapfile not an active swap area:\n%s", on.Stdout)
		}
		fstab, err := c.Run(ctx, "grep -F '/swapfile none swap sw 0 0 # managed by berth' /etc/fstab", nil)
		if err != nil {
			t.Fatalf("grep fstab: %v", err)
		}
		if fstab.ExitCode != 0 {
			t.Error("berth swap line missing from /etc/fstab")
		}
		sw, err := c.Run(ctx, "cat /proc/sys/vm/swappiness", nil)
		if err != nil {
			t.Fatalf("read swappiness: %v", err)
		}
		if strings.TrimSpace(sw.Stdout) != "10" {
			t.Errorf("vm.swappiness = %q, want 10", strings.TrimSpace(sw.Stdout))
		}
	}

	if srv.System.Sysctl {
		for _, kv := range []struct{ key, val string }{
			{"net.core.somaxconn", "4096"},
			{"net.ipv4.tcp_tw_reuse", "1"},
			{"fs.file-max", "1048576"},
			{"fs.inotify.max_user_watches", "524288"},
		} {
			res, err := c.Run(ctx, "sysctl -n "+kv.key, nil)
			if err != nil {
				t.Fatalf("sysctl -n %s: %v", kv.key, err)
			}
			if strings.TrimSpace(res.Stdout) != kv.val {
				t.Errorf("sysctl %s = %q, want %q", kv.key, strings.TrimSpace(res.Stdout), kv.val)
			}
		}
	}
}
```

- [ ] **Step 2: Wire it into the live test**

In `test/integration/provision_test.go`, add a call inside the `invCtx` assertion block (next to `assertHardeningEndState(invCtx, t, client, srv)`):

```go
	assertSwapSysctl(invCtx, t, client, srv)
```

- [ ] **Step 3: Verify it compiles under the integration tag**

Run: `go build -tags integration ./test/integration/...`
Expected: builds clean (no host needed for compilation).

- [ ] **Step 4: Commit**

```bash
git add test/integration/assert_system.go test/integration/provision_test.go
git commit -m "test(integration): assert live swap + sysctl end state"
```

- [ ] **Step 5: Live validation (operator-run, on a fresh Debian 13 ext4 host)**

Add `system: { swap: 2G, sysctl: true }` to the smoke config, then run a real provision (NOT cached — pass `-count=1`):

```bash
BERTH_TEST_FORCE=true BERTH_TEST_SERVER=$(pwd)/servers/smoke.yml \
  go test -tags integration -count=1 -v -timeout 60m ./test/integration/...
```

Expected: every step `applied` (incl. `system`), `assertSwapSysctl` green, and the second-run idempotency assert reports all steps `Satisfied`. Then exercise the disable round-trip: remove the `system:` block and re-provision; confirm on the box `swapon --show` is empty, no berth `/etc/fstab` line, and `/etc/sysctl.d/99-berth*.conf` are gone.

---

## Notes for the implementer

- The whole `system` step is exercised through `bssh.Runner`; never shell out directly. Build stable, exact command strings — tests stub them verbatim.
- `Check` must stay side-effect-free (only `cat`/`stat`/`swapon --show`/`sysctl -n` — all read-only).
- Do not reorder `Apply`'s swap sub-steps: a resize must `swapoff` + `rm` before recreating; the fstab line append must follow the `sed` normalize.
- Keep `sysctlKeys` in sync with `sysctl_berth.conf.tmpl` (guarded by `TestSysctlKeysMatchTemplate`).
- **Both-branches stubbing rule (tests):** `Check` and `Apply` ALWAYS traverse the swap branch AND the sysctl branch (each routes to its enable or removal predicate). So a `FakeRunner` test for the *whole step* (`System().Check`/`Apply`) must also stub the disabled branch's read: with `Sysctl` off, stub `cat '/etc/sysctl.d/99-berth.conf'` (ExitCode 1 = absent); with `Swap` empty, stub `cat '/etc/fstab'` and `cat '/etc/sysctl.d/99-berth-swap.conf'`. The plan's tests already do this; if you add a test and see `FakeRunner: unstubbed command`, this is why.
- After Task 6, run the whole `internal/provision/steps` suite — the existing `registry_test.go` checks are subset/ordering based (`contains`/`indexOf`), so adding `system` does not break them; if any other test asserts an exact full pipeline slice, update it to include `system` after `base`.
- The step is a cheap read-only no-op when `system:` is unset (both predicates report satisfied), so it is safe in every existing config and in the live smoke run even before Task 8 Step 5 enables it.
- After all tasks: `gofmt -l .` (empty), `go vet ./...` (clean), `go test -race ./...` (green).

# Managed PHP-FPM Tuning Drop-in Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> Revision 2 — incorporates the Codex (gpt-5.6-sol) FIX-FIRST review recorded in
> spec §11: tightened size grammar + 64 GiB bound, derived `post_max_size`/nginx
> body cap with multipart headroom, `-t`/reload failure compensation, call-count
> asserts, wizard matrix coverage, honest 300 s cap rationale, input-vars ceiling.

**Goal:** Add four `tuning.php_*` config knobs rendered into one managed FPM drop-in (`/etc/php/<ver>/fpm/conf.d/99-berth-tuning.ini`) plus a derived nginx `client_max_body_size`, per spec `docs/superpowers/specs/2026-07-24-php-memory-limit-design.md`.

**Architecture:** The `php` step gains a second managed drop-in next to the existing OPcache one (same `checkManagedFile` → `writeManagedFile` → `php-fpm -t` → `systemctl reload` flow, now with rm-both-drop-ins compensation when `-t`/reload fails). `tuning.php_upload_max` is the max single-file size; `post_max_size` and nginx `client_max_body_size` derive from it (`PHPPostBodyMaxEff` = bytes + max(2 MiB, 5%), rendered as an exact byte count) via a new `nginxData.BodyMax` field that keeps the site↔tls byte-identical invariant (static config only, HSTS precedent). Defaults live in `*Eff()` accessors, never `SetDefault`.

**Tech Stack:** Go 1.25, text/template (`//go:embed`), FakeRunner exact-string test doubles, golden files.

## Global Constraints

- Public MIT repo: all code, comments, and commit messages **English-only**, no personal/host-identifying data.
- Never run `go mod tidy`; no new dependencies are needed here anyway.
- Never `git push` — prepare the branch and PR body; the user pushes manually.
- Managed files are written **only** via `templates.Render`/`RenderINI` (the marker is prepended by the renderer; `.tmpl` files must NOT contain the marker line).
- `RenderINI` (`;` marker) for anything PHP-FPM parses; `Render` (`#`) elsewhere.
- FakeRunner stubs are **exact command strings**; an unstubbed command returns an error — every remote call a code path makes must be stubbed.
- After editing any `.tmpl`: `go test ./internal/templates/... -update`, then **diff the goldens and commit them**.
- Defaults for `Tuning` fields live in `*Eff()` accessor methods (consts), **not** in `Load()` via `SetDefault` (wizard `ToServer()` and literal-`Server` callers bypass `Load()`).
- Validation is **lenient**: empty string / non-positive int = "use default" and passes.
- `nginxData` has a **test-local copy** in `internal/templates/templates_test.go` — any field added to the real struct must be mirrored there.
- CI runs `go test -race ./...` and `go vet ./...`; format with `gofmt`.

**Derived-value arithmetic used throughout (verify any new expected constant against it):**
`PHPPostBodyMaxEff = bytes(upload) + max(2097152, bytes(upload)/20)` with integer division.
`32M` → 33554432 + 2097152 = **35651584**. `64M` → 67108864 + 3355443 = **70464307**. `1G` → 1073741824 + 53687091 = **1127428915**.

---

### Task 1: Config fields, defaults, accessors, size parser

**Files:**
- Modify: `internal/config/config.go` (Tuning struct ~line 78, consts ~line 84, accessors + parser after line 112; add `math`/`strconv` imports if absent)
- Test: `internal/config/tuning_test.go`

**Interfaces:**
- Produces (used by Tasks 2, 4, 5, 6):
  - `Tuning.PHPMemoryLimit string`, `Tuning.PHPUploadMax string`, `Tuning.PHPMaxExecutionTime int`, `Tuning.PHPMaxInputVars int`
  - `func (t Tuning) PHPMemoryLimitEff() string` (default `"256M"`)
  - `func (t Tuning) PHPUploadMaxEff() string` (default `"32M"`)
  - `func (t Tuning) PHPMaxExecutionTimeEff() int` (default `30`)
  - `func (t Tuning) PHPMaxInputVarsEff() int` (default `1000`)
  - `func (t Tuning) PHPPostBodyMaxEff() string` (derived byte count, e.g. `"35651584"`)
  - `func phpSizeBytes(v string) (uint64, error)` (package-private)
  - `const phpSizeMaxBytes = 64 << 30`

- [ ] **Step 1: Create the feature branch**

```bash
cd /Users/robson/AI/berth
git checkout main && git checkout -b feat/php-tuning
```

- [ ] **Step 2: Write the failing tests**

In `internal/config/tuning_test.go`, replace `TestTuningAccessorsDefaultWhenEmpty` and `TestTuningAccessorsHonorOverrides`, and add three new tests:

```go
func TestTuningAccessorsDefaultWhenEmpty(t *testing.T) {
	var tn Tuning // all empty -> conservative defaults
	if got := tn.ValkeyMaxmemoryEff(); got != "256mb" {
		t.Errorf("ValkeyMaxmemoryEff() = %q, want 256mb", got)
	}
	if got := tn.ValkeyMaxmemoryPolicyEff(); got != "allkeys-lru" {
		t.Errorf("ValkeyMaxmemoryPolicyEff() = %q, want allkeys-lru", got)
	}
	if got := tn.MariaDBBufferPoolEff(); got != "256M" {
		t.Errorf("MariaDBBufferPoolEff() = %q, want 256M", got)
	}
	if got := tn.PHPMemoryLimitEff(); got != "256M" {
		t.Errorf("PHPMemoryLimitEff() = %q, want 256M", got)
	}
	if got := tn.PHPUploadMaxEff(); got != "32M" {
		t.Errorf("PHPUploadMaxEff() = %q, want 32M", got)
	}
	if got := tn.PHPMaxExecutionTimeEff(); got != 30 {
		t.Errorf("PHPMaxExecutionTimeEff() = %d, want 30", got)
	}
	if got := tn.PHPMaxInputVarsEff(); got != 1000 {
		t.Errorf("PHPMaxInputVarsEff() = %d, want 1000", got)
	}
}

func TestTuningAccessorsHonorOverrides(t *testing.T) {
	tn := Tuning{
		ValkeyMaxmemory: "512mb", ValkeyMaxmemoryPolicy: "volatile-lru", MariaDBBufferPool: "1G",
		PHPMemoryLimit: "768M", PHPUploadMax: "64M", PHPMaxExecutionTime: 120, PHPMaxInputVars: 5000,
	}
	if got := tn.ValkeyMaxmemoryEff(); got != "512mb" {
		t.Errorf("ValkeyMaxmemoryEff() = %q, want 512mb", got)
	}
	if got := tn.ValkeyMaxmemoryPolicyEff(); got != "volatile-lru" {
		t.Errorf("ValkeyMaxmemoryPolicyEff() = %q, want volatile-lru", got)
	}
	if got := tn.MariaDBBufferPoolEff(); got != "1G" {
		t.Errorf("MariaDBBufferPoolEff() = %q, want 1G", got)
	}
	if got := tn.PHPMemoryLimitEff(); got != "768M" {
		t.Errorf("PHPMemoryLimitEff() = %q, want 768M", got)
	}
	if got := tn.PHPUploadMaxEff(); got != "64M" {
		t.Errorf("PHPUploadMaxEff() = %q, want 64M", got)
	}
	if got := tn.PHPMaxExecutionTimeEff(); got != 120 {
		t.Errorf("PHPMaxExecutionTimeEff() = %d, want 120", got)
	}
	if got := tn.PHPMaxInputVarsEff(); got != 5000 {
		t.Errorf("PHPMaxInputVarsEff() = %d, want 5000", got)
	}
}

func TestTuningPHPIntAccessorsTreatNonPositiveAsDefault(t *testing.T) {
	// The Fail2ban.MaxretryEff precedent: <= 0 means "unset", never a literal 0.
	tn := Tuning{PHPMaxExecutionTime: -5, PHPMaxInputVars: -1}
	if got := tn.PHPMaxExecutionTimeEff(); got != 30 {
		t.Errorf("PHPMaxExecutionTimeEff() = %d, want 30", got)
	}
	if got := tn.PHPMaxInputVarsEff(); got != 1000 {
		t.Errorf("PHPMaxInputVarsEff() = %d, want 1000", got)
	}
}

func TestPHPSizeBytes(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint64
	}{{"1", 1}, {"512k", 524288}, {"32M", 33554432}, {"1G", 1073741824}, {"134217728", 134217728}} {
		got, err := phpSizeBytes(c.in)
		if err != nil || got != c.want {
			t.Errorf("phpSizeBytes(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "abc", "1.5G", "99999999999999999999G"} {
		if _, err := phpSizeBytes(bad); err == nil {
			t.Errorf("phpSizeBytes(%q) expected error, got nil", bad)
		}
	}
}

func TestTuningPHPPostBodyMaxDerivation(t *testing.T) {
	// bytes(upload) + max(2 MiB, 5%) rendered as an exact byte count — valid
	// size syntax for both PHP ini shorthand and nginx client_max_body_size.
	cases := []struct{ upload, want string }{
		{"", "35651584"},        // default 32M; 5% (1677721) is below the 2 MiB floor
		{"32M", "35651584"},     // explicit default
		{"64M", "70464307"},     // 5% headroom (3355443) above the floor
		{"1G", "1127428915"},    // 1073741824 + 53687091
		{"garbage", "35651584"}, // literal-Server fallback to the default derivation
	}
	for _, c := range cases {
		if got := (Tuning{PHPUploadMax: c.upload}).PHPPostBodyMaxEff(); got != c.want {
			t.Errorf("PHPPostBodyMaxEff(upload=%q) = %s, want %s", c.upload, got, c.want)
		}
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestTuning|TestPHPSizeBytes' 2>&1 | head -20`
Expected: compile FAIL — `tn.PHPMemoryLimitEff undefined`, `undefined: phpSizeBytes` (and the struct fields undefined).

- [ ] **Step 4: Implement the config surface**

In `internal/config/config.go`:

(a) Extend the `Tuning` struct (keep the existing doc comment, append: `PHP fields render into the php step's FPM-only conf.d drop-in; PHPUploadMax is the max single-file size, from which post_max_size and nginx client_max_body_size are derived (PHPPostBodyMaxEff).`):

```go
type Tuning struct {
	ValkeyMaxmemory       string `mapstructure:"valkey_maxmemory" yaml:"valkey_maxmemory,omitempty"`
	ValkeyMaxmemoryPolicy string `mapstructure:"valkey_maxmemory_policy" yaml:"valkey_maxmemory_policy,omitempty"`
	MariaDBBufferPool     string `mapstructure:"mariadb_innodb_buffer_pool" yaml:"mariadb_innodb_buffer_pool,omitempty"`
	PHPMemoryLimit        string `mapstructure:"php_memory_limit" yaml:"php_memory_limit,omitempty"`
	PHPUploadMax          string `mapstructure:"php_upload_max" yaml:"php_upload_max,omitempty"`
	PHPMaxExecutionTime   int    `mapstructure:"php_max_execution_time" yaml:"php_max_execution_time,omitempty"`
	PHPMaxInputVars       int    `mapstructure:"php_max_input_vars" yaml:"php_max_input_vars,omitempty"`
}
```

(b) Extend the defaults const block:

```go
const (
	defaultValkeyMaxmemory       = "256mb"
	defaultValkeyMaxmemoryPolicy = "allkeys-lru"
	defaultMariaDBBufferPool     = "256M"
	defaultPHPMemoryLimit        = "256M"
	defaultPHPUploadMax          = "32M"
	defaultPHPMaxExecutionTime   = 30
	defaultPHPMaxInputVars       = 1000
)

// phpSizeMaxBytes bounds the PHP size knobs (64 GiB — far above any sane VPS
// value). It keeps every accepted value representable in PHP's signed 64-bit
// ini parser: past that, PHP's shorthand parse wraps to the -1 "unlimited"
// sentinel, silently removing the limit.
const phpSizeMaxBytes = 64 << 30

// phpPostHeadroomMinBytes is the minimum multipart-envelope allowance added
// to php_upload_max when deriving post_max_size / client_max_body_size
// (boundaries, form fields and metadata all count toward the request body).
const phpPostHeadroomMinBytes = 2 << 20
```

(c) Add the parser and accessors after `MariaDBBufferPoolEff` (line ~112). `phpSizeBytes` deliberately mirrors `steps.parseMariaDBSize` (the packages cannot share it without an import cycle-ish dependency inversion; the duplication is two small functions with different suffix sets):

```go
// phpSizeBytes converts a PHP ini shorthand size — digits with an optional
// K/M/G suffix (1024-based, case-insensitive) — to bytes. Inputs are normally
// pre-guarded by rePHPSize; the error path covers literal-Server callers
// that bypass validation.
func phpSizeBytes(v string) (uint64, error) {
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

// PHPMemoryLimitEff returns the configured FPM memory_limit or the default.
func (t Tuning) PHPMemoryLimitEff() string {
	if t.PHPMemoryLimit == "" {
		return defaultPHPMemoryLimit
	}
	return t.PHPMemoryLimit
}

// PHPUploadMaxEff returns the configured max single-file upload size or the
// default. It renders verbatim as upload_max_filesize; the request-body caps
// (post_max_size, nginx client_max_body_size) derive from it via
// PHPPostBodyMaxEff so a file of exactly this size fits its multipart envelope.
func (t Tuning) PHPUploadMaxEff() string {
	if t.PHPUploadMax == "" {
		return defaultPHPUploadMax
	}
	return t.PHPUploadMax
}

// PHPPostBodyMaxEff returns the derived request-body cap (post_max_size and
// nginx client_max_body_size) as an exact byte count — valid size syntax for
// both PHP ini shorthand and nginx: bytes(upload) + max(2 MiB, 5%).
// Unparsable or out-of-bound values (possible only for literal-Server callers
// that bypass validation) fall back to the default derivation, keeping the
// accessor total and deterministic.
func (t Tuning) PHPPostBodyMaxEff() string {
	b, err := phpSizeBytes(t.PHPUploadMaxEff())
	if err != nil || b == 0 || b > phpSizeMaxBytes {
		b, _ = phpSizeBytes(defaultPHPUploadMax)
	}
	head := b / 20
	if head < phpPostHeadroomMinBytes {
		head = phpPostHeadroomMinBytes
	}
	return strconv.FormatUint(b+head, 10)
}

// PHPMaxExecutionTimeEff returns the configured max_execution_time (seconds)
// or the default. Non-positive means "unset" (the Fail2ban.MaxretryEff precedent).
func (t Tuning) PHPMaxExecutionTimeEff() int {
	if t.PHPMaxExecutionTime <= 0 {
		return defaultPHPMaxExecutionTime
	}
	return t.PHPMaxExecutionTime
}

// PHPMaxInputVarsEff returns the configured max_input_vars or the default.
func (t Tuning) PHPMaxInputVarsEff() int {
	if t.PHPMaxInputVars <= 0 {
		return defaultPHPMaxInputVars
	}
	return t.PHPMaxInputVars
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/ -run 'TestTuning|TestPHPSizeBytes'`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/tuning_test.go
git commit -m "feat(config): add tuning.php_* knobs with derived request-body cap"
```

---

### Task 2: Config validation

**Files:**
- Modify: `internal/config/validate.go` (regex var block ~line 28, `Tuning.validate()` ~line 279)
- Test: `internal/config/tuning_test.go`

**Interfaces:**
- Consumes: `Tuning` fields, `phpSizeBytes`, `phpSizeMaxBytes` from Task 1.
- Produces: `rePHPSize` regexp; `validatePHPSize(field, v string) error`; consts `phpMaxExecutionCeiling = 300`, `phpMaxInputVarsCeiling = 1000000`; extended `func (t Tuning) validate() error` (already called from `Server.Validate`, no wiring needed).

- [ ] **Step 1: Write the failing tests**

In `internal/config/tuning_test.go`, replace `TestTuningValidateAcceptsEmptyAndValid` and `TestTuningValidateRejectsBad`:

```go
func TestTuningValidateAcceptsEmptyAndValid(t *testing.T) {
	for _, tn := range []Tuning{
		{}, // empty = use defaults
		{ValkeyMaxmemory: "256mb", ValkeyMaxmemoryPolicy: "allkeys-lru", MariaDBBufferPool: "256M"},
		{ValkeyMaxmemory: "1gb", ValkeyMaxmemoryPolicy: "volatile-ttl", MariaDBBufferPool: "2G"},
		{ValkeyMaxmemory: "104857600"}, // bare bytes
		{PHPMemoryLimit: "768M", PHPUploadMax: "1G", PHPMaxExecutionTime: 300, PHPMaxInputVars: 1000000},
		{PHPMemoryLimit: "134217728"}, // bare bytes
		{PHPUploadMax: "512k"},        // suffixes are case-insensitive
		{PHPMaxExecutionTime: -1},     // non-positive = unset, lenient
	} {
		if err := tn.validate(); err != nil {
			t.Errorf("validate(%+v) unexpected error: %v", tn, err)
		}
	}
}

func TestTuningValidateRejectsBad(t *testing.T) {
	for _, tn := range []Tuning{
		{ValkeyMaxmemory: "256 mb; rm -rf /"},
		{ValkeyMaxmemory: "lots"},
		{ValkeyMaxmemoryPolicy: "allkeys-bogus"},
		{MariaDBBufferPool: "256MB"}, // MariaDB uses K/M/G, not MB
		{MariaDBBufferPool: "big"},
		{PHPMemoryLimit: "-1"},  // no sign in the grammar: berth never ships unlimited
		{PHPMemoryLimit: "0"},   // 0 = unlimited in PHP post/upload and nginx body checks
		{PHPMemoryLimit: "08M"}, // leading zeros: PHP shorthand parses octal, nginx decimal
		{PHPUploadMax: "010M"},
		{PHPMemoryLimit: "256MB"},
		{PHPUploadMax: "1.5G"},
		{PHPUploadMax: "64M; rm -rf /"},
		{PHPUploadMax: "65G"},                       // > 64 GiB bound
		{PHPMemoryLimit: "18446744073709551615"},    // would wrap PHP's int64 parse to -1
		{PHPMaxExecutionTime: 301},                  // opinionated 300 s cap
		{PHPMaxInputVars: 1000001},                  // matches the wizard's domain
	} {
		if err := tn.validate(); err == nil {
			t.Errorf("validate(%+v) expected error, got nil", tn)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestTuningValidate'`
Expected: FAIL — every new `PHP*` reject case reports "expected error, got nil".

- [ ] **Step 3: Implement validation**

In `internal/config/validate.go`:

(a) Add to the regex var block that holds `reValkeyMem`/`reMariaDBSize` (~line 28):

```go
	// rePHPSize guards PHP ini shorthand sizes: positive digits + optional
	// K/M/G, NO leading zeros (PHP's shorthand parser reads 010M as octal
	// while nginx reads decimal — the two sides would diverge) and no sign
	// (so -1/unlimited is unrepresentable). "0" is likewise rejected: PHP
	// treats post_max_size=0 and nginx client_max_body_size 0 as unlimited.
	rePHPSize = regexp.MustCompile(`^[1-9][0-9]*[KMGkmg]?$`)
```

(b) Add consts and the helper near `Tuning.validate`:

```go
// phpMaxExecutionCeiling caps tuning.php_max_execution_time at 300 s — an
// opinionated sanity bound (long-running work belongs in queue workers), the
// same domain the wizard input enforces. Note it is NOT a wall-clock pact
// with nginx: fastcgi_read_timeout 300 is a between-reads timeout and PHP's
// limit excludes I/O wait.
const phpMaxExecutionCeiling = 300

// phpMaxInputVarsCeiling caps tuning.php_max_input_vars, matching the wizard
// input's domain so both public config paths accept the same values.
const phpMaxInputVarsCeiling = 1000000

// validatePHPSize guards a PHP ini shorthand size knob: grammar first, then a
// parse-and-bound check so accepted values can never overflow PHP's signed
// 64-bit ini parser into the -1 "unlimited" sentinel.
func validatePHPSize(field, v string) error {
	if !rePHPSize.MatchString(v) {
		return fmt.Errorf("%s %q must be a positive number optionally suffixed K/M/G, no leading zeros (e.g. 256M)", field, v)
	}
	b, err := phpSizeBytes(v)
	if err != nil {
		return fmt.Errorf("%s %q: %v", field, v, err)
	}
	if b > phpSizeMaxBytes {
		return fmt.Errorf("%s %q exceeds the 64G bound", field, v)
	}
	return nil
}
```

(c) Append to the body of `func (t Tuning) validate() error`, before the final `return nil`:

```go
	if t.PHPMemoryLimit != "" {
		if err := validatePHPSize("tuning.php_memory_limit", t.PHPMemoryLimit); err != nil {
			return err
		}
	}
	if t.PHPUploadMax != "" {
		if err := validatePHPSize("tuning.php_upload_max", t.PHPUploadMax); err != nil {
			return err
		}
	}
	if t.PHPMaxExecutionTime > phpMaxExecutionCeiling {
		return fmt.Errorf("tuning.php_max_execution_time %d exceeds the %d s cap (long-running work belongs in queue workers)", t.PHPMaxExecutionTime, phpMaxExecutionCeiling)
	}
	if t.PHPMaxInputVars > phpMaxInputVarsCeiling {
		return fmt.Errorf("tuning.php_max_input_vars %d exceeds %d", t.PHPMaxInputVars, phpMaxInputVarsCeiling)
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/validate.go internal/config/tuning_test.go
git commit -m "feat(config): validate tuning.php_* (strict size grammar, 64G/300s/1M caps)"
```

---

### Task 3: php_tuning.ini.tmpl template + golden

**Files:**
- Create: `internal/templates/php_tuning.ini.tmpl`
- Create (generated): `internal/templates/testdata/php_tuning.golden`
- Test: `internal/templates/templates_test.go`

**Interfaces:**
- Produces: template render name `"php_tuning.ini.tmpl"` taking `struct { MemoryLimit, UploadMax, PostMax string; MaxExecutionTime, MaxInputVars int }` (consumed by Task 4's `renderPHPTuning`).

- [ ] **Step 1: Create the template**

Create `internal/templates/php_tuning.ini.tmpl` (NO marker line — `RenderINI` prepends `; managed by berth`):

```
memory_limit = {{ .MemoryLimit }}
upload_max_filesize = {{ .UploadMax }}
post_max_size = {{ .PostMax }}
max_execution_time = {{ .MaxExecutionTime }}
max_input_vars = {{ .MaxInputVars }}
expose_php = Off
```

- [ ] **Step 2: Add the golden test**

In `internal/templates/templates_test.go`, after `TestRenderPHPOpcacheGolden` (~line 101):

```go
func TestRenderPHPTuningGolden(t *testing.T) {
	checkGoldenINI(t, "php_tuning.ini.tmpl", "php_tuning.golden", struct {
		MemoryLimit, UploadMax, PostMax string
		MaxExecutionTime, MaxInputVars  int
	}{MemoryLimit: "256M", UploadMax: "32M", PostMax: "35651584", MaxExecutionTime: 30, MaxInputVars: 1000})
}
```

- [ ] **Step 3: Generate and verify the golden**

```bash
go test ./internal/templates/ -run TestRenderPHPTuningGolden -update
cat internal/templates/testdata/php_tuning.golden
```

Expected golden content, exactly:

```
; managed by berth
memory_limit = 256M
upload_max_filesize = 32M
post_max_size = 35651584
max_execution_time = 30
max_input_vars = 1000
expose_php = Off
```

Then run without `-update`: `go test ./internal/templates/`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/templates/php_tuning.ini.tmpl internal/templates/testdata/php_tuning.golden internal/templates/templates_test.go
git commit -m "feat(templates): FPM tuning drop-in template (memory, upload, limits, expose_php)"
```

---

### Task 4: php step — tuning drop-in in Check/Apply + failure compensation

**Files:**
- Modify: `internal/provision/steps/php.go` (helpers after line 29, `Check` lines 76-121, `Apply` lines 123-168)
- Test: `internal/provision/steps/php_test.go`

**Interfaces:**
- Consumes: Task 1 accessors; Task 3 template name.
- Produces: `func phpTuningDropInPath(ver string) string`, `func renderPHPTuning(s *config.Server) ([]byte, error)`, `func removePHPDropIns(ctx context.Context, r bssh.Runner, ver string)` (package-private to `steps`).

- [ ] **Step 1: Write the failing tests**

In `internal/provision/steps/php_test.go`, add six new tests:

```go
func TestPHPTuningRenderDefaultsFromLiteralServer(t *testing.T) {
	// A literal Server (bypassing config.Load) must still render every directive
	// with a valid value — guards against an accidental raw-field read.
	b, err := renderPHPTuning(&config.Server{})
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{
		"; managed by berth",
		"memory_limit = 256M",
		"upload_max_filesize = 32M",
		"post_max_size = 35651584", // 32M + 2 MiB multipart headroom, exact bytes
		"max_execution_time = 30",
		"max_input_vars = 1000",
		"expose_php = Off",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("tuning drop-in missing %q; got:\n%s", want, body)
		}
	}
}

func TestPHPTuningRenderHonorsOverrides(t *testing.T) {
	s := &config.Server{Tuning: config.Tuning{
		PHPMemoryLimit: "768M", PHPUploadMax: "64M", PHPMaxExecutionTime: 120, PHPMaxInputVars: 5000,
	}}
	b, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{
		"memory_limit = 768M",
		"upload_max_filesize = 64M",
		"post_max_size = 70464307", // 64M + 5% headroom
		"max_execution_time = 120",
		"max_input_vars = 5000",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("tuning drop-in missing %q; got:\n%s", want, body)
		}
	}
}

func TestPHPCheckUnsatisfiedWhenTuningDropInMissing(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}}
	wantOp, err := renderOpcache()
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(wantOp), ExitCode: 0})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1}) // absent
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the tuning drop-in is missing")
	}
}

func TestPHPApplyRefusesForeignTuningDropIn(t *testing.T) {
	// An operator's own file at the tuning drop-in path (no berth marker) must
	// not be clobbered by Apply without --force.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs("8.4"), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})                                    // absent -> written
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 0, Stdout: "memory_limit = 512M\n"}) // foreign

	err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	for _, w := range f.Writes() {
		if w.Path == phpTuningDropInPath("8.4") {
			t.Error("a foreign tuning drop-in must not be overwritten without --force")
		}
	}
}

func TestPHPApplyRemovesDropInsOnTestFailure(t *testing.T) {
	// A failed php-fpm -t after the writes must remove BOTH drop-ins: leaving
	// them would make the next run's Check falsely Satisfied (bytes match)
	// while the running master never loaded the new content.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	rm := "rm -f " + shQuote(opcacheDropInPath("8.4")) + " " + shQuote(phpTuningDropInPath("8.4"))
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs("8.4"), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("php-fpm8.4 -t", bssh.Result{ExitCode: 1, Stderr: "syntax error"})
	f.On(rm, bssh.Result{})

	err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "-t failed") {
		t.Fatalf("err = %v, want the -t failure", err)
	}
	var removed bool
	for _, c := range f.Calls() {
		if c.Cmd == rm {
			removed = true
		}
	}
	if !removed {
		t.Error("Apply must remove both drop-ins after a failed php-fpm -t")
	}
}

func TestPHPApplyRemovesDropInsOnReloadFailure(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	rm := "rm -f " + shQuote(opcacheDropInPath("8.4")) + " " + shQuote(phpTuningDropInPath("8.4"))
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs("8.4"), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("php-fpm8.4 -t", bssh.Result{})
	f.On("systemctl reload php8.4-fpm", bssh.Result{ExitCode: 1, Stderr: "job failed"})
	f.On(rm, bssh.Result{})

	err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "reload php8.4-fpm failed") {
		t.Fatalf("err = %v, want the reload failure", err)
	}
	var removed bool
	for _, c := range f.Calls() {
		if c.Cmd == rm {
			removed = true
		}
	}
	if !removed {
		t.Error("Apply must remove both drop-ins after a failed reload")
	}
}
```

- [ ] **Step 2: Update the four existing tests that now hit the extra remote call**

`Check` gains a `cat <tuning drop-in>` between the OPcache check and the log-dir check, and `Apply` gains a write-guard `cat` — FakeRunner errors on unstubbed commands, so these tests break without new stubs. (`TestPHPCheckUnsatisfiedWhenOpcacheDropInMissing` and `TestPHPApplyRefusesForeignOpcacheDropIn` return before the new call — leave them untouched.)

(a) `TestPHPApplyWritesOpcacheDropIn` — full updated body (adds the tuning write-guard stub, the tuning-write assertions, and the exactly-one `-t`/reload count — an upload change must not double-reload *within this step*):

```go
func TestPHPApplyWritesOpcacheDropIn(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}} // stock -> no Surý repo
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs("8.4"), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})   // write-guard: absent
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("php-fpm8.4 -t", bssh.Result{})
	f.On("systemctl reload php8.4-fpm", bssh.Result{})

	if err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var drop, tun *bssh.FileSpec
	for i := range f.Writes() {
		switch f.Writes()[i].Path {
		case opcacheDropInPath("8.4"):
			drop = &f.Writes()[i]
		case phpTuningDropInPath("8.4"):
			tun = &f.Writes()[i]
		}
	}
	if drop == nil {
		t.Fatal("OPcache drop-in was not written")
	}
	if tun == nil {
		t.Fatal("tuning drop-in was not written")
	}
	body := string(drop.Content)
	if !strings.Contains(body, "managed by berth") {
		t.Error("OPcache drop-in must carry the managed marker")
	}
	for _, want := range []string{"opcache.validate_timestamps = 0", "opcache.memory_consumption = 256", "opcache.max_accelerated_files = 20000"} {
		if !strings.Contains(body, want) {
			t.Errorf("OPcache drop-in missing %q; got:\n%s", want, body)
		}
	}
	tbody := string(tun.Content)
	if !strings.Contains(tbody, "managed by berth") {
		t.Error("tuning drop-in must carry the managed marker")
	}
	if !strings.Contains(tbody, "memory_limit = 256M") {
		t.Errorf("tuning drop-in missing default memory_limit; got:\n%s", tbody)
	}
	// FPM-only: never write a CLI drop-in (workers keep stock CLI limits).
	for _, w := range f.Writes() {
		if strings.Contains(w.Path, "/cli/conf.d/") {
			t.Errorf("must not write a CLI drop-in: %s", w.Path)
		}
	}
	// Both drop-ins share ONE validate + ONE graceful reload.
	var tests, reloads, createdLogDir int
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "php-fpm8.4 -t":
			tests++
		case "systemctl reload php8.4-fpm":
			reloads++
		case "install -d -o root -g root -m 0755 " + shQuote(phpLogDir):
			createdLogDir++
		}
	}
	if tests != 1 || reloads != 1 {
		t.Errorf("want exactly one -t and one reload; got %d and %d", tests, reloads)
	}
	if createdLogDir == 0 {
		t.Error("Apply must create " + phpLogDir)
	}
}
```

(b) `TestPHPCheckSatisfiedWhenInstalledAndOpcacheManaged` — full updated body:

```go
func TestPHPCheckSatisfiedWhenInstalledAndOpcacheManaged(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}}
	want, err := renderOpcache()
	if err != nil {
		t.Fatal(err)
	}
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})
	f.On("test -d "+shQuote(phpLogDir), bssh.Result{ExitCode: 0})
	f.On("dpkg -s php8.4-mysql", bssh.Result{ExitCode: 0}) // engine "" -> pdo_mysql, installed
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when installed and both drop-ins up to date; got %+v", cr)
	}
}
```

(c) `TestPHPCheckUnsatisfiedWhenPDODriverMissing` — insert after the opcache stub setup: `wantTuning, err := renderPHPTuning(s)` with the usual `if err != nil { t.Fatal(err) }`, plus the stub `f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})`.

(d) `TestPHPCheckUnsatisfiedWhenLogDirMissing` — same addition as (c).

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/provision/steps/ -run 'TestPHP' 2>&1 | head -20`
Expected: compile FAIL — `undefined: phpTuningDropInPath`, `undefined: renderPHPTuning`.

- [ ] **Step 4: Implement the step changes**

In `internal/provision/steps/php.go`:

(a) After `renderOpcache` (line 29):

```go
// phpTuningDropInPath is the FPM-only berth tuning drop-in (memory_limit,
// upload sizing, execution limits). FPM-only on purpose: the CLI SAPI keeps
// Debian's stock php.ini (memory_limit=-1, max_execution_time=0), so
// long-lived queue workers and artisan runs are never capped.
func phpTuningDropInPath(ver string) string {
	return "/etc/php/" + ver + "/fpm/conf.d/99-berth-tuning.ini"
}

// renderPHPTuning renders the FPM tuning drop-in (INI, ';' marker). Values are
// read only through the Tuning *Eff accessors so literal-Server callers that
// bypass config.Load still render valid directives. PostMax is the derived
// request-body cap (upload + multipart headroom, exact bytes) that the site
// step also renders as nginx client_max_body_size.
func renderPHPTuning(s *config.Server) ([]byte, error) {
	return templates.RenderINI("php_tuning.ini.tmpl", struct {
		MemoryLimit, UploadMax, PostMax string
		MaxExecutionTime, MaxInputVars  int
	}{
		MemoryLimit:      s.Tuning.PHPMemoryLimitEff(),
		UploadMax:        s.Tuning.PHPUploadMaxEff(),
		PostMax:          s.Tuning.PHPPostBodyMaxEff(),
		MaxExecutionTime: s.Tuning.PHPMaxExecutionTimeEff(),
		MaxInputVars:     s.Tuning.PHPMaxInputVarsEff(),
	})
}

// removePHPDropIns best-effort removes both managed FPM drop-ins after a
// failed validate/reload. The files were written but never loaded; leaving
// them would make the next run's Check falsely Satisfied (bytes match) while
// the running master still serves the old config. Removing them keeps disk
// state honest so the next run re-applies write -> -t -> reload. The result
// is deliberately ignored: the original failure is what the operator must
// see, and a box where even rm fails needs attention anyway.
func removePHPDropIns(ctx context.Context, r bssh.Runner, ver string) {
	_, _ = r.Run(ctx, "rm -f "+shQuote(opcacheDropInPath(ver))+" "+shQuote(phpTuningDropInPath(ver)), nil)
}
```

(b) In `Check` (line 77), extend the `changes` slice:

```go
	changes := []string{
		"install php" + s.PHP.Version + " + extensions",
		"write production OPcache drop-in",
		"write PHP tuning drop-in (memory_limit, upload, limits)",
		"ensure " + phpLogDir,
	}
```

(c) In `Check`, insert after the OPcache `if !ok { ... }` block (line 100), before the log-dir comment:

```go
	// The FPM tuning drop-in (memory_limit, upload sizing, execution limits)
	// must be the berth-managed one and up to date.
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		return provision.CheckResult{}, err
	}
	tstate, err := checkManagedFile(ctx, r, phpTuningDropInPath(s.PHP.Version), wantTuning)
	if err != nil {
		return provision.CheckResult{}, err
	}
	tok, err := managedFileSatisfied(tstate, phpTuningDropInPath(s.PHP.Version), rc.Force)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if !tok {
		return provision.CheckResult{Satisfied: false, Reason: "PHP tuning drop-in not up to date", Changes: changes}, nil
	}
```

(d) In `Check`, update the final Satisfied reason (line 120):

```go
	return provision.CheckResult{Satisfied: true, Reason: "php" + s.PHP.Version + "-fpm installed; OPcache and FPM tuning in place"}, nil
```

(e) In `Apply`, insert after the OPcache `writeManagedFile` block (line 156), before the `php-fpm -t` call:

```go
	// FPM tuning (memory_limit, upload sizing, execution limits; FPM SAPI only —
	// CLI keeps stock unlimited values for workers and artisan).
	tini, err := renderPHPTuning(s)
	if err != nil {
		return err
	}
	if err := writeManagedFile(ctx, r, rc.Force, bssh.FileSpec{
		Path: phpTuningDropInPath(v), Content: tini, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write PHP tuning drop-in: %w", err)
	}
```

(f) In `Apply`, replace the existing `-t` + reload tail (lines 157-167) with the compensating version — a non-zero exit removes both drop-ins so a re-run re-applies instead of reporting falsely Satisfied; a transport error (`err != nil`) skips cleanup (nothing can be run on a dead connection):

```go
	if res, err := r.Run(ctx, "php-fpm"+v+" -t", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		removePHPDropIns(ctx, r, v)
		return fmt.Errorf("php-fpm%s -t failed after writing drop-ins (removed them so the next run re-applies): %s", v, res.Stderr)
	}
	if res, err := r.Run(ctx, "systemctl reload php"+v+"-fpm", nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		removePHPDropIns(ctx, r, v)
		return fmt.Errorf("reload php%s-fpm failed (removed the drop-ins so the next run re-applies): %s", v, res.Stderr)
	}
	return nil
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/provision/steps/`
Expected: PASS (all step tests, not just TestPHP*).

- [ ] **Step 6: Commit**

```bash
git add internal/provision/steps/php.go internal/provision/steps/php_test.go
git commit -m "feat(php): managed FPM tuning drop-in with validate/reload failure compensation"
```

---

### Task 5: nginx client_max_body_size coordination

**Files:**
- Modify: `internal/provision/steps/site.go` (`nginxData` line 174, `nginxRenderData` line 179)
- Modify: `internal/templates/nginx_http.conf.tmpl` (line 11), `internal/templates/nginx_https.conf.tmpl` (line 44)
- Modify: `internal/templates/templates_test.go` (test-local `nginxData` line 47, `nginxGoldenData` line 54)
- Modify (generated): all six `internal/templates/testdata/nginx_*.golden`
- Test: `internal/provision/steps/site_test.go`

**Interfaces:**
- Consumes: `Tuning.PHPPostBodyMaxEff()` from Task 1.
- Produces: `nginxData.BodyMax string` (rendered as `client_max_body_size {{ .BodyMax }};`).

- [ ] **Step 1: Write the failing test**

In `internal/provision/steps/site_test.go`, add:

```go
func TestSiteVhostHonorsUploadMax(t *testing.T) {
	// The derived request-body cap must reach client_max_body_size in BOTH
	// vhost renders, so nginx never rejects an upload PHP would accept.
	s := &config.Server{
		Tuning: config.Tuning{PHPUploadMax: "64M"},
		Sites: []config.Site{{
			Domain: "app.example.com", DeployPath: "/home/deploy/myapp", SSL: true,
		}},
	}
	want := "client_max_body_size " + s.Tuning.PHPPostBodyMaxEff() + ";" // 64M + 5% = 70464307
	httpBody, err := renderNginxHTTP(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(httpBody), want) {
		t.Errorf("HTTP vhost missing %q; got:\n%s", want, httpBody)
	}
	httpsBody, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(httpsBody), want) {
		t.Errorf("HTTPS vhost missing %q; got:\n%s", want, httpsBody)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/provision/steps/ -run TestSiteVhostHonorsUploadMax`
Expected: FAIL — both renders still contain the hardcoded `client_max_body_size 32m;`.

- [ ] **Step 3: Implement the coordination**

(a) `internal/provision/steps/site.go` — extend `nginxData` (append to the struct doc comment: `BodyMax becomes client_max_body_size; like HSTS it derives purely from static config (tuning.php_upload_max + headroom), so site re-render and tls swap stay byte-identical.`):

```go
type nginxData struct {
	Domain, DeployPath, ACMEWebroot, Socket, CertPath, KeyPath, BodyMax string
	HTTP3, QUICReuseport, HSTS, CloudflareOnly                          bool
}
```

(b) In `nginxRenderData`, add to the returned literal (after the `CloudflareOnly` field):

```go
		// BodyMax mirrors the FPM drop-in's post_max_size (one derived cap for
		// the whole upload path); static config only, never remote state, so
		// the site↔tls byte-identical re-render invariant holds.
		BodyMax: s.Tuning.PHPPostBodyMaxEff(),
```

(c) `internal/templates/nginx_http.conf.tmpl` line 11: replace

```
    client_max_body_size 32m;
```

with

```
    client_max_body_size {{ .BodyMax }};
```

(d) `internal/templates/nginx_https.conf.tmpl` line 44 (the 443 block; the port-80 redirect block takes no bodies): the same one-line replacement as (c).

(e) `internal/templates/templates_test.go` — mirror the field in the test-local copy:

```go
type nginxData struct {
	Domain, DeployPath, ACMEWebroot, Socket, CertPath, KeyPath, BodyMax string
	HTTP3, QUICReuseport, HSTS, CloudflareOnly                          bool
}
```

and set the default derivation in `nginxGoldenData()` (add to the literal): `BodyMax: "35651584",`

- [ ] **Step 4: Regenerate the nginx goldens and inspect the diff**

```bash
go test ./internal/templates/ -update
git diff internal/templates/testdata/
```

Expected: exactly six files change (`nginx_http.golden`, `nginx_http_cloudflare.golden`, `nginx_https.golden`, `nginx_https_http3.golden`, `nginx_https_nohsts.golden`, `nginx_https_cloudflare.golden`), each with the single-line diff `client_max_body_size 32m;` → `client_max_body_size 35651584;`. Any other change is a regression — stop and investigate.

- [ ] **Step 5: Run the full package tests**

Run: `go test ./internal/templates/ ./internal/provision/steps/`
Expected: PASS — including the existing site↔tls identical-render tests in `site_test.go` (the new field keeps them byte-identical by construction).

- [ ] **Step 6: Commit**

```bash
git add internal/provision/steps/site.go internal/provision/steps/site_test.go \
  internal/templates/nginx_http.conf.tmpl internal/templates/nginx_https.conf.tmpl \
  internal/templates/templates_test.go internal/templates/testdata/
git commit -m "feat(site): derive nginx client_max_body_size from tuning.php_upload_max"
```

---

### Task 6: Wizard coverage

**Files:**
- Modify: `internal/wizard/wizard.go` (`TuningAnswers` line 60)
- Modify: `internal/wizard/validate.go` (regex var block line 88, new `optionalPHPSize`)
- Modify: `internal/wizard/prompter.go` (`ServerAdvanced` lines 80-102)
- Modify: `internal/wizard/toserver.go` (Tuning literal lines 17-21)
- Test: `internal/wizard/validate_test.go`, `internal/wizard/toserver_test.go`, `internal/wizard/matrix_test.go`

**Interfaces:**
- Consumes: `config.Tuning` fields from Task 1.
- Produces: `TuningAnswers.PHPMemoryLimit/PHPUploadMax string`, `TuningAnswers.PHPMaxExecutionTime/PHPMaxInputVars int`; `func optionalPHPSize(s string) error`.

- [ ] **Step 1: Write the failing tests**

(a) In `internal/wizard/validate_test.go`, add:

```go
func TestOptionalPHPSize(t *testing.T) {
	for _, ok := range []string{"", "256M", "32m", "1G", "512k", "134217728"} {
		if err := optionalPHPSize(ok); err != nil {
			t.Errorf("optionalPHPSize(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"0", "-1", "08M", "010M", "256MB", "1.5G", "abc", "64M; rm -rf /"} {
		if err := optionalPHPSize(bad); err == nil {
			t.Errorf("optionalPHPSize(%q) expected error, got nil", bad)
		}
	}
}
```

(b) In `internal/wizard/toserver_test.go`, add:

```go
func TestToServerCarriesPHPTuning(t *testing.T) {
	a := Answers{Tuning: TuningAnswers{
		PHPMemoryLimit: "768M", PHPUploadMax: "64M", PHPMaxExecutionTime: 120, PHPMaxInputVars: 5000,
	}}
	s := a.ToServer()
	if s.Tuning.PHPMemoryLimit != "768M" || s.Tuning.PHPUploadMax != "64M" ||
		s.Tuning.PHPMaxExecutionTime != 120 || s.Tuning.PHPMaxInputVars != 5000 {
		t.Errorf("ToServer() dropped php tuning fields: %+v", s.Tuning)
	}
}
```

(c) In `internal/wizard/matrix_test.go`: extend the existing `tuning-all-fields-set-valid` subtest (~line 1033) — full updated body:

```go
	t.Run("tuning-all-fields-set-valid", func(t *testing.T) {
		a := base("adv-tune", "vps.example.com")
		a.Valkey = true
		a.Tuning = TuningAnswers{
			ValkeyMaxmemory: "256mb", ValkeyMaxmemoryPolicy: "allkeys-lru", MariaDBBufferPool: "512M",
			PHPMemoryLimit: "768M", PHPUploadMax: "64M", PHPMaxExecutionTime: 120, PHPMaxInputVars: 5000,
		}
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.Tuning.ValkeyMaxmemory != "256mb" || srv.Tuning.ValkeyMaxmemoryPolicy != "allkeys-lru" || srv.Tuning.MariaDBBufferPool != "512M" || !srv.Valkey {
			t.Fatalf("tuning = %+v valkey=%v", srv.Tuning, srv.Valkey)
		}
		if srv.Tuning.PHPMemoryLimit != "768M" || srv.Tuning.PHPUploadMax != "64M" ||
			srv.Tuning.PHPMaxExecutionTime != 120 || srv.Tuning.PHPMaxInputVars != 5000 {
			t.Fatalf("php tuning = %+v", srv.Tuning)
		}
	})
```

and add a new invalid subtest right after the existing `tuning-bad-mariadb-buffer-suffix-invalid` one:

```go
	t.Run("tuning-bad-php-upload-invalid", func(t *testing.T) {
		a := base("adv-tune-php", "vps.example.com")
		a.Tuning = TuningAnswers{PHPUploadMax: "08M"} // octal trap: PHP would read 8 MiB, nginx 8 decimal MB
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "php_upload_max")
	})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/wizard/ 2>&1 | head -10`
Expected: compile FAIL — `undefined: optionalPHPSize`, unknown fields in `TuningAnswers`.

- [ ] **Step 3: Implement**

(a) `internal/wizard/wizard.go` — extend `TuningAnswers`:

```go
type TuningAnswers struct {
	ValkeyMaxmemory       string
	ValkeyMaxmemoryPolicy string
	MariaDBBufferPool     string
	PHPMemoryLimit        string
	PHPUploadMax          string
	PHPMaxExecutionTime   int
	PHPMaxInputVars       int
}
```

(b) `internal/wizard/validate.go` — add to the var block holding `reValkeyMem`/`reMariaDBSize` (line 88; it mirrors config's unexported regexes for inline feedback — `config.Server.Validate` stays authoritative, including the parse-and-bound 64G check that only config runs):

```go
	rePHPSize = regexp.MustCompile(`^[1-9][0-9]*[KMGkmg]?$`)
```

and after `optionalMariaDBSize`:

```go
func optionalPHPSize(s string) error {
	if s == "" || rePHPSize.MatchString(s) {
		return nil
	}
	return fmt.Errorf("%q must be a positive number optionally suffixed K/M/G, no leading zeros", s)
}
```

(c) `internal/wizard/prompter.go` — full updated `ServerAdvanced`:

```go
func (h *huhPrompter) ServerAdvanced(a *Answers) error {
	maxretry := strconv.Itoa(a.Fail2ban.Maxretry)
	execTime := strconv.Itoa(a.Tuning.PHPMaxExecutionTime)
	inputVars := strconv.Itoa(a.Tuning.PHPMaxInputVars)
	policies := []string{"", "noeviction", "allkeys-lru", "allkeys-lfu", "allkeys-random", "volatile-lru", "volatile-lfu", "volatile-random", "volatile-ttl"}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("fail2ban bantime (e.g. 1h, blank=default)").Value(&a.Fail2ban.Bantime).Validate(optionalFail2banTime),
			huh.NewInput().Title("fail2ban findtime (e.g. 10m, blank=default)").Value(&a.Fail2ban.Findtime).Validate(optionalFail2banTime),
			huh.NewInput().Title("fail2ban maxretry (1-100, blank/0=default)").Value(&maxretry).Validate(optionalInt("fail2ban.maxretry", 0, 100)),
		),
		huh.NewGroup(
			huh.NewInput().Title("Valkey maxmemory (e.g. 256mb, blank=default)").Value(&a.Tuning.ValkeyMaxmemory).Validate(optionalValkeyMem),
			huh.NewSelect[string]().Title("Valkey eviction policy (blank=default)").Options(huh.NewOptions(policies...)...).Value(&a.Tuning.ValkeyMaxmemoryPolicy),
			huh.NewInput().Title("MariaDB innodb_buffer_pool (e.g. 256M, blank=default)").Value(&a.Tuning.MariaDBBufferPool).Validate(optionalMariaDBSize),
		),
		huh.NewGroup(
			huh.NewInput().Title("PHP memory_limit (e.g. 256M, blank=default)").Value(&a.Tuning.PHPMemoryLimit).Validate(optionalPHPSize),
			huh.NewInput().Title("PHP max upload file size, body caps derived (e.g. 32M, blank=default)").Value(&a.Tuning.PHPUploadMax).Validate(optionalPHPSize),
			huh.NewInput().Title("PHP max_execution_time (1-300 s, blank/0=default)").Value(&execTime).Validate(optionalInt("tuning.php_max_execution_time", 1, 300)),
			huh.NewInput().Title("PHP max_input_vars (1-1000000, blank/0=default)").Value(&inputVars).Validate(optionalInt("tuning.php_max_input_vars", 1, 1000000)),
		),
	)
	if err := form.Run(); err != nil {
		return err
	}
	// Trim-safe like the validator (optionalInt); blank/"0" -> 0 = default, an
	// accepted " 5 " -> 5 (a raw Atoi would have dropped it to the default).
	a.Fail2ban.Maxretry, _ = parseIntInRange("fail2ban.maxretry", maxretry, 0, 100)
	a.Tuning.PHPMaxExecutionTime, _ = parseIntInRange("tuning.php_max_execution_time", execTime, 1, 300)
	a.Tuning.PHPMaxInputVars, _ = parseIntInRange("tuning.php_max_input_vars", inputVars, 1, 1000000)
	return nil
}
```

(d) `internal/wizard/toserver.go` — extend the Tuning literal:

```go
		Tuning: config.Tuning{
			ValkeyMaxmemory:       a.Tuning.ValkeyMaxmemory,
			ValkeyMaxmemoryPolicy: a.Tuning.ValkeyMaxmemoryPolicy,
			MariaDBBufferPool:     a.Tuning.MariaDBBufferPool,
			PHPMemoryLimit:        a.Tuning.PHPMemoryLimit,
			PHPUploadMax:          a.Tuning.PHPUploadMax,
			PHPMaxExecutionTime:   a.Tuning.PHPMaxExecutionTime,
			PHPMaxInputVars:       a.Tuning.PHPMaxInputVars,
		},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/wizard/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/wizard/wizard.go internal/wizard/validate.go internal/wizard/prompter.go \
  internal/wizard/toserver.go internal/wizard/validate_test.go internal/wizard/toserver_test.go \
  internal/wizard/matrix_test.go
git commit -m "feat(wizard): collect tuning.php_* in the advanced server group"
```

---

### Task 7: README

**Files:**
- Modify: `README.md` (example config lines 104-107, "Service tuning" section lines 194-216)

- [ ] **Step 1: Update the example config block (line 104)**

```yaml
tuning:                        # optional — omit any field to keep its default
  valkey_maxmemory: 256mb
  valkey_maxmemory_policy: allkeys-lru   # any Valkey eviction policy
  mariadb_innodb_buffer_pool: 256M
  php_memory_limit: 256M
  php_upload_max: 32M          # max single-file upload; body caps derived
  php_max_execution_time: 30   # seconds, 1-300
  php_max_input_vars: 1000     # 1-1000000
```

- [ ] **Step 2: Update the "Service tuning" section**

Add a third bullet after the MariaDB one (line 203):

```markdown
- **PHP-FPM** (always) — a managed FPM-only `conf.d` drop-in sets
  `memory_limit`, upload sizing, `max_execution_time`, `max_input_vars` and
  `expose_php = Off`. The CLI SAPI keeps Debian's stock unlimited values, so
  queue workers and artisan runs are unaffected. `php_upload_max` is the max
  single-file size: `post_max_size` and nginx `client_max_body_size` are
  derived slightly larger (multipart headroom), so a file of exactly that size
  uploads — note all files in one request share the derived total.
```

Extend the yaml block at line 208 with the same four `php_*` lines as Step 1, and add after the Valkey eviction note (line 216):

```markdown
`php_max_execution_time` is capped at 300 s — berth's opinionated bound; work
that runs longer belongs in queue workers, not web requests.
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document the tuning.php_* knobs"
```

---

### Task 8: Full verification + PR prep

**Files:**
- Create: `docs/pr-body-php-tuning.md` (local-only; `docs/` is gitignored — do NOT force-add this one)

- [ ] **Step 1: Full test suite, vet, formatting**

```bash
gofmt -l .          # expected: no output
go vet ./...        # expected: no output
go test -race ./... # expected: all ok
```

If `gofmt -l` lists files, run `gofmt -w` on them, re-run tests, and amend the relevant commit.

- [ ] **Step 2: Write the PR body**

Create `docs/pr-body-php-tuning.md` summarizing: the four knobs + defaults; the FPM-only drop-in; the derived `post_max_size`/`client_max_body_size` (32M → 35651584 bytes default) and why (multipart headroom, Codex #2); the strict size grammar (no `0`, no leading zeros, ≤ 64G — Codex #1); the `-t`/reload failure compensation (Codex #3); the documented double-reload on upload changes (Codex #4); wizard coverage; the migration note for hosts with a manual drop-in. Reference the spec path and its §11 review table.

- [ ] **Step 3: Hand off to the user**

Do NOT push (repo hook blocks it). Tell the user the branch `feat/php-tuning` is ready and that they can run:

```
! git push -u origin feat/php-tuning
```

then open the PR with the prepared body.

---

## Self-review notes (already applied)

- Spec coverage: §2 (config + parser) → Task 1; §2.1 (validation) → Task 2; §2.2 (derived cap) → Tasks 1/3/5; §3 (template) → Task 3; §4 + §4.1 (php step + compensation) → Task 4; §5 (nginx) → Task 5; §6 (wizard incl. matrix) → Task 6; §8 (README) → Task 7; §7 integration test is explicitly a follow-up, not a PR gate — not planned here.
- `Check` probes the tuning drop-in BEFORE the log-dir and PDO probes, so the two existing "unsatisfied later" tests need the up-to-date tuning stub (Task 4 Step 2 c/d) — FakeRunner errors on any unstubbed command.
- Names are consistent across tasks: `phpTuningDropInPath`, `renderPHPTuning`, `removePHPDropIns`, `phpSizeBytes`, `phpSizeMaxBytes`, `rePHPSize`, `optionalPHPSize`, `BodyMax`, `PHPMemoryLimitEff/PHPUploadMaxEff/PHPPostBodyMaxEff/PHPMaxExecutionTimeEff/PHPMaxInputVarsEff`.
- Derived constants used in tests all follow the arithmetic in the header: 35651584 (32M), 70464307 (64M), 1127428915 (1G).
- The golden regen in Task 5 must show ONLY the `32m` → `35651584` line in six files; anything else is a regression.



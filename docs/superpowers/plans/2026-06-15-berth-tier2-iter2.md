# Tier 2 Iteration 2 — Configurable Queue Workers + Daemon Abstraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let each site declare a tunable queue worker (#9) and arbitrary daemons (#10: Horizon/Reverb/custom), rendered as managed, dormant Supervisor programs — idempotent, tenant-isolated, and byte-identical to today when unused.

**Architecture:** New `config` types (`QueueConfig`, `Daemon`) + naming/enablement helpers + a mapstructure DecodeHook for the `queue: horizon` bare-string sugar. The `site` step builds each program's `command`/`numprocs` and writes one managed `/etc/supervisor/conf.d/berth-<pool>[-<name>].conf` per program (parametrized template), with a **global** `berth-*.conf` orphan drift-removal. The `accounts` step emits per-program narrow sudoers and content-drift-checks them. The registry installs `supervisor` whenever any worker or daemon exists.

**Tech Stack:** Go 1.25, Viper + `github.com/go-viper/mapstructure/v2` (DecodeHook), `text/template` goldens, the `bssh.FakeRunner` test double, Supervisor on Debian 13.

**Source spec:** `docs/superpowers/specs/2026-06-15-berth-tier2-iter2-design.md`
**Branch:** `feat/tier2-iter2-queue-daemons` (already created off `main`; spec committed `51ce1b2`).

**Hard contracts (enforce throughout):**
- **Byte-identical default:** a site with `Server.Queue: true` and no `queue:`/`daemons:` renders the
  exact current `supervisor.golden` and `sudoers_deploy.golden`. Tests assert this explicitly.
- **Single source of truth for program names:** `config.Server.SiteProgramNames(site)` (Task 1) is the
  ONLY place worker/daemon program names are derived; `site` and `accounts` both call it.
- **Tenant isolation:** per-program exact sudoers (`<program>\:*`), never a name-prefix glob; global
  program-name uniqueness validated at load.

---

### Task 1: config types, helpers, and the `queue: horizon` DecodeHook

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go` (add cases; create if absent)

- [ ] **Step 1: Add a direct dependency on mapstructure/v2**

Run: `go get github.com/go-viper/mapstructure/v2@v2.4.0`
Expected: `go.mod` gains `github.com/go-viper/mapstructure/v2 v2.4.0` as a **direct** require (it was already an indirect dep of Viper; this promotes it). Do NOT run `go mod tidy`.

- [ ] **Step 2: Write failing tests for decoding + helpers**

Add to `internal/config/config_test.go` (package `config`):

```go
func writeTmpConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "srv.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const baseCfg = `host: app.example.com
ssh: {user: deploy, key: ~/.ssh/id_rsa}
php: {version: "8.4"}
database: {engine: mariadb, source: mariadb}
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: app, user: app}
`

func TestQueueHorizonBareStringDecodes(t *testing.T) {
	s, err := Load(writeTmpConfig(t, baseCfg+"    queue: horizon\n"))
	if err != nil {
		t.Fatal(err)
	}
	q := s.Sites[0].Queue
	if q == nil || q.Driver != "horizon" {
		t.Fatalf("queue: horizon must decode to {Driver: horizon}; got %+v", q)
	}
}

func TestQueueMapDecodes(t *testing.T) {
	s, err := Load(writeTmpConfig(t, baseCfg+"    queue: {processes: 3, tries: 5, queue: emails}\n"))
	if err != nil {
		t.Fatal(err)
	}
	q := s.Sites[0].Queue
	if q == nil || q.Processes != 3 || q.Tries != 5 || q.Queue != "emails" {
		t.Fatalf("queue map decode wrong: %+v", q)
	}
}

func TestDaemonsDecode(t *testing.T) {
	s, err := Load(writeTmpConfig(t, baseCfg+"    daemons:\n      - {name: reverb, command: php artisan reverb:start}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Sites[0].Daemons) != 1 || s.Sites[0].Daemons[0].Name != "reverb" {
		t.Fatalf("daemons decode wrong: %+v", s.Sites[0].Daemons)
	}
}

func TestSiteProgramNamesAndEnablement(t *testing.T) {
	off := &Server{Sites: []Site{{Domain: "a.example.com", Daemons: []Daemon{{Name: "x", Command: "php artisan x"}}}}}
	// Server.Queue false, site has a daemon but no queue: no worker, one daemon program.
	if off.QueueEnabled(off.Sites[0]) {
		t.Error("no worker expected when Server.Queue false and site.Queue nil")
	}
	if !off.NeedsSupervisor() {
		t.Error("NeedsSupervisor must be true when a daemon exists")
	}
	got := off.SiteProgramNames(off.Sites[0])
	if len(got) != 1 || got[0] != "berth-a_example_com-x" {
		t.Fatalf("program names = %v, want [berth-a_example_com-x]", got)
	}
	// Server.Queue true -> worker added, worker first.
	on := &Server{Queue: true, Sites: off.Sites}
	got = on.SiteProgramNames(on.Sites[0])
	if len(got) != 2 || got[0] != "berth-a_example_com" || got[1] != "berth-a_example_com-x" {
		t.Fatalf("program names = %v, want [berth-a_example_com berth-a_example_com-x]", got)
	}
}
```

Add imports `os`, `path/filepath` to the test file if missing.

- [ ] **Step 3: Run — verify they fail to compile (types/helpers undefined)**

Run: `go test ./internal/config/ -run 'Queue|Daemon|SiteProgramNames' -v`
Expected: FAIL (compile error: `QueueConfig`, `Daemon`, `Queue`, `Daemons`, `QueueEnabled`, `NeedsSupervisor`, `SiteProgramNames` undefined).

- [ ] **Step 4: Add the types, fields, helpers, and the DecodeHook**

In `internal/config/config.go`, add the import `"reflect"` and `mapstructure "github.com/go-viper/mapstructure/v2"`, then add the types after `SiteDatabase`:

```go
// QueueConfig tunes a site's queue worker. nil => the server-default worker
// (when Server.Queue) or none. Driver "" / "work" => queue:work; "horizon" =>
// `artisan horizon` (Horizon manages its own workers; queue:work-only knobs are
// rejected by validation and numprocs is forced to 1).
type QueueConfig struct {
	Driver     string `mapstructure:"driver" yaml:"driver,omitempty"`
	Processes  int    `mapstructure:"processes" yaml:"processes,omitempty"`
	Connection string `mapstructure:"connection" yaml:"connection,omitempty"`
	Queue      string `mapstructure:"queue" yaml:"queue,omitempty"`
	Sleep      int    `mapstructure:"sleep" yaml:"sleep,omitempty"`
	Tries      int    `mapstructure:"tries" yaml:"tries,omitempty"`
	Timeout    int    `mapstructure:"timeout" yaml:"timeout,omitempty"`
	MaxMemory  int    `mapstructure:"max_memory" yaml:"max_memory,omitempty"`
}

// Daemon is an arbitrary long-running Supervisor program (Horizon/Reverb/custom).
// Command is the FULL command, run from <deploy_path>/current.
type Daemon struct {
	Name      string `mapstructure:"name" yaml:"name"`
	Command   string `mapstructure:"command" yaml:"command"`
	Processes int    `mapstructure:"processes" yaml:"processes,omitempty"`
}
```

Add to the `Site` struct (after `Scheduler`):

```go
	Queue   *QueueConfig `mapstructure:"queue" yaml:"queue,omitempty"`   // worker tuning; bare "horizon" via DecodeHook
	Daemons []Daemon     `mapstructure:"daemons" yaml:"daemons,omitempty"`
```

Add helpers (near `SchedulerEnabled`):

```go
// PoolName derives the FPM pool / supervisor program slug from a domain
// (filesystem-safe: dots -> underscores). Single source of truth shared by the
// steps package and validation so program names never diverge.
func PoolName(domain string) string { return strings.ReplaceAll(domain, ".", "_") }

// QueueEnabled reports whether a site gets a queue worker: an explicit per-site
// queue block, OR the server-wide Server.Queue default. site.Queue works
// independently of Server.Queue.
func (s *Server) QueueEnabled(site Site) bool { return site.Queue != nil || s.Queue }

// NeedsSupervisor reports whether the supervisor step must run: any site has a
// queue worker or any daemons.
func (s *Server) NeedsSupervisor() bool {
	for _, site := range s.Sites {
		if s.QueueEnabled(site) || len(site.Daemons) > 0 {
			return true
		}
	}
	return false
}

// SiteProgramNames returns the Supervisor program names a site owns, worker
// first: "berth-<pool>" iff QueueEnabled, then "berth-<pool>-<name>" per daemon.
// THE single source of truth for program naming (site render, drift-removal, and
// the per-program sudoers all call this).
func (s *Server) SiteProgramNames(site Site) []string {
	pool := PoolName(site.Domain)
	var names []string
	if s.QueueEnabled(site) {
		names = append(names, "berth-"+pool)
	}
	for _, d := range site.Daemons {
		names = append(names, "berth-"+pool+"-"+d.Name)
	}
	return names
}
```

Add the hook (bottom of the file):

```go
// stringToQueueConfigHook lets a bare string (e.g. `queue: horizon`) decode into
// a QueueConfig{Driver: <string>}. It fires only for string sources whose target
// is QueueConfig or *QueueConfig; map sources (`queue: {…}`) fall through to the
// normal struct decode.
func stringToQueueConfigHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	if f.Kind() != reflect.String {
		return data, nil
	}
	if t == reflect.TypeOf(QueueConfig{}) || t == reflect.TypeOf(&QueueConfig{}) {
		return map[string]interface{}{"driver": data}, nil
	}
	return data, nil
}
```

In `Load`, replace `if err := v.Unmarshal(&s); err != nil {` with:

```go
	if err := v.Unmarshal(&s, viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
		stringToQueueConfigHook,
	))); err != nil {
```

- [ ] **Step 5: Run — verify pass**

Run: `go test ./internal/config/ -run 'Queue|Daemon|SiteProgramNames' -v && go vet ./internal/config/`
Expected: PASS, vet clean. Also `go build ./...` exits 0.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go go.mod go.sum
git commit -m "feat(config): queue + daemons types, naming/enablement helpers, horizon decode hook

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: validation (per-field + global program-name uniqueness)

**Files:**
- Modify: `internal/config/validate.go`
- Test: `internal/config/validate_test.go` (add cases; create if absent)

- [ ] **Step 1: Write failing validation tests**

Add to `internal/config/validate_test.go` (package `config`). Each builds a minimal valid `Server` and mutates one thing; assert `Validate()` errors (or passes). Use this helper:

```go
func validQueueServer() *Server {
	return &Server{
		Host: "app.example.com",
		SSH:  SSH{Port: 22, User: "deploy", Key: "~/.ssh/id_rsa"},
		PHP:  PHP{Version: "8.4", Source: "auto"}, Nginx: Nginx{Source: "debian"},
		Database: Database{Engine: "mariadb", Source: "mariadb"},
		Sites: []Site{{Domain: "app.example.com", DeployPath: "/var/www/app",
			User: "appuser", Database: SiteDatabase{Name: "app", User: "app"}}},
	}
}

func TestValidateRejectsBadDriver(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Driver: "bogus"}
	if s.Validate() == nil {
		t.Error("expected error for unknown queue driver")
	}
}

func TestValidateRejectsControlCharInCommand(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Daemons = []Daemon{{Name: "x", Command: "php artisan x\nmalicious=1"}}
	if s.Validate() == nil {
		t.Error("expected error for newline in daemon command (config injection)")
	}
}

func TestValidateRejectsHorizonWithKnobs(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Driver: "horizon", Tries: 5}
	if s.Validate() == nil {
		t.Error("expected error for horizon combined with queue:work knobs")
	}
}

func TestValidateRejectsHorizonProcessesGtOne(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Driver: "horizon", Processes: 2}
	if s.Validate() == nil {
		t.Error("expected error for horizon with processes > 1")
	}
}

func TestValidateRejectsNegativeKnob(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Tries: -1}
	if s.Validate() == nil {
		t.Error("expected error for negative tries")
	}
}

func TestValidateRejectsBadDaemonName(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Daemons = []Daemon{{Name: "Bad Name", Command: "php artisan x"}}
	if s.Validate() == nil {
		t.Error("expected error for invalid daemon name")
	}
}

func TestValidateRejectsCrossSiteProgramCollision(t *testing.T) {
	s := validQueueServer()
	s.Queue = true // every site gets a worker
	// Site A app.example.com + daemon "x" -> berth-app_example_com-x
	s.Sites[0].Daemons = []Daemon{{Name: "x", Command: "php artisan x"}}
	// Site B app.example.com-x -> worker berth-app_example_com-x (collision)
	s.Sites = append(s.Sites, Site{Domain: "app.example.com-x", DeployPath: "/var/www/b",
		User: "buser", Database: SiteDatabase{Name: "b", User: "b"}})
	if s.Validate() == nil {
		t.Error("expected error: two sites map to the same supervisor program berth-app_example_com-x")
	}
}

func TestValidateAcceptsValidQueueAndDaemons(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Processes: 2, Queue: "default,emails", Tries: 3}
	s.Sites[0].Daemons = []Daemon{{Name: "reverb", Command: "php artisan reverb:start"}}
	if err := s.Validate(); err != nil {
		t.Errorf("valid queue+daemons must pass: %v", err)
	}
}
```

- [ ] **Step 2: Run — verify they fail**

Run: `go test ./internal/config/ -run 'Validate.*(Driver|Control|Horizon|Negative|Daemon|Collision|ValidQueue)' -v`
Expected: most FAIL (Validate currently ignores queue/daemons, so the "rejects" tests fail because no error is returned).

- [ ] **Step 3: Add validation**

In `internal/config/validate.go`, add a regex with the others:

```go
	reDaemonName = regexp.MustCompile(`^[a-z0-9-]+$`)
```

Add a `validateQueueDaemons` method and a control-char helper at the end of the file:

```go
// hasControlChars reports whether s contains a newline, carriage return, NUL, or
// other ASCII control character — rejected for any value rendered onto a single
// Supervisor/command line (config injection guard).
func hasControlChars(s string) bool {
	for _, r := range s {
		if r == 0 || r == '\n' || r == '\r' || (r < 0x20) || r == 0x7f {
			return true
		}
	}
	return false
}

func (st *Site) validateQueueDaemons() error {
	if q := st.Queue; q != nil {
		switch q.Driver {
		case "", "work", "horizon":
		default:
			return fmt.Errorf("queue.driver %q must be work or horizon", q.Driver)
		}
		for name, v := range map[string]int{"processes": q.Processes, "sleep": q.Sleep, "tries": q.Tries, "timeout": q.Timeout, "max_memory": q.MaxMemory} {
			if v < 0 {
				return fmt.Errorf("queue.%s must not be negative", name)
			}
		}
		if q.Processes > 64 {
			return fmt.Errorf("queue.processes %d exceeds the cap of 64", q.Processes)
		}
		if hasControlChars(q.Connection) || hasControlChars(q.Queue) {
			return fmt.Errorf("queue.connection/queue must be single-line (no control characters)")
		}
		if q.Driver == "horizon" {
			if q.Connection != "" || q.Queue != "" || q.Sleep != 0 || q.Tries != 0 || q.Timeout != 0 || q.MaxMemory != 0 {
				return fmt.Errorf("queue: horizon manages its own workers; remove connection/queue/sleep/tries/timeout/max_memory")
			}
			if q.Processes > 1 {
				return fmt.Errorf("queue: horizon forces numprocs=1; remove processes > 1")
			}
		}
	}
	seen := map[string]bool{}
	for i := range st.Daemons {
		d := st.Daemons[i]
		if !reDaemonName.MatchString(d.Name) {
			return fmt.Errorf("daemon %d: name %q must match [a-z0-9-]+", i, d.Name)
		}
		if seen[d.Name] {
			return fmt.Errorf("daemon name %q is duplicated within the site", d.Name)
		}
		seen[d.Name] = true
		if strings.TrimSpace(d.Command) == "" {
			return fmt.Errorf("daemon %q: command is required", d.Name)
		}
		if hasControlChars(d.Command) {
			return fmt.Errorf("daemon %q: command must be single-line (no control characters)", d.Name)
		}
		if d.Processes < 0 || d.Processes > 64 {
			return fmt.Errorf("daemon %q: processes %d out of range (0-64)", d.Name, d.Processes)
		}
	}
	return nil
}
```

Wire per-site validation into `Site.validate()` by adding before its final `return nil`:

```go
	if err := st.validateQueueDaemons(); err != nil {
		return err
	}
```

Add the cross-site program-name uniqueness inside `Server.Validate`'s site loop. Add a `seenProgram` map next to the other `seen*` maps:

```go
	seenProgram := map[string]bool{}
```

and inside the `for i := range s.Sites` loop (after the existing `dup(...)` checks), add:

```go
		for _, prog := range s.SiteProgramNames(site) {
			if err := dup(seenProgram, prog, "supervisor program"); err != nil {
				return err
			}
		}
```

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/config/ -v && go vet ./internal/config/`
Expected: PASS, vet clean.

- [ ] **Step 5: Commit**

```bash
git add internal/config/validate.go internal/config/validate_test.go
git commit -m "feat(config): validate queue/daemons + global supervisor-program uniqueness

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: parametrize the supervisor template + command builders (byte-identical default)

**Files:**
- Modify: `internal/templates/supervisor.conf.tmpl`
- Modify: `internal/provision/steps/site.go` (render functions + command builder)
- Test: `internal/templates/templates_test.go` (golden cases), `internal/provision/steps/site_test.go` (command-builder unit + default byte-identity)
- Golden: `internal/templates/testdata/supervisor.golden` (unchanged), new `supervisor_horizon.golden`, `supervisor_daemon.golden`

- [ ] **Step 1: Write the failing command-builder + byte-identity tests**

Add to `internal/provision/steps/site_test.go`:

```go
func TestQueueCommandDefaultByteIdentical(t *testing.T) {
	// No queue block, Server.Queue true -> the exact historical command line.
	s := siteServer()
	s.Queue = true
	got := queueCommand(s, s.Sites[0])
	want := "php /home/deploy/myapp/current/artisan queue:work --sleep=3 --tries=3 --max-time=3600"
	if got != want {
		t.Errorf("default queue command must be byte-identical to today\n got: %s\nwant: %s", got, want)
	}
}

func TestQueueCommandTuned(t *testing.T) {
	s := siteServer()
	s.Sites[0].Queue = &config.QueueConfig{Processes: 2, Connection: "redis", Queue: "emails", Tries: 5, Timeout: 90, MaxMemory: 128}
	got := queueCommand(s, s.Sites[0])
	want := "php /home/deploy/myapp/current/artisan queue:work redis --queue=emails --sleep=3 --tries=5 --max-time=3600 --timeout=90 --memory=128"
	if got != want {
		t.Errorf("tuned queue command wrong\n got: %s\nwant: %s", got, want)
	}
}

func TestQueueCommandHorizon(t *testing.T) {
	s := siteServer()
	s.Sites[0].Queue = &config.QueueConfig{Driver: "horizon"}
	got := queueCommand(s, s.Sites[0])
	want := "php /home/deploy/myapp/current/artisan horizon"
	if got != want {
		t.Errorf("horizon command wrong: %s", got)
	}
}
```

Add to `internal/templates/templates_test.go` (update the existing supervisor golden test struct and add two new goldens):

```go
func TestRenderSupervisorGolden(t *testing.T) {
	checkGolden(t, "supervisor.conf.tmpl", "supervisor.golden", struct {
		ProgramName, Command, DeployPath, User string
		Numprocs                               int
	}{
		ProgramName: "berth-app_example_com",
		Command:     "php /home/deploy/myapp/current/artisan queue:work --sleep=3 --tries=3 --max-time=3600",
		DeployPath:  "/home/deploy/myapp", User: "webuser", Numprocs: 1,
	})
}

func TestRenderSupervisorHorizonGolden(t *testing.T) {
	checkGolden(t, "supervisor.conf.tmpl", "supervisor_horizon.golden", struct {
		ProgramName, Command, DeployPath, User string
		Numprocs                               int
	}{
		ProgramName: "berth-app_example_com",
		Command:     "php /home/deploy/myapp/current/artisan horizon",
		DeployPath:  "/home/deploy/myapp", User: "webuser", Numprocs: 1,
	})
}

func TestRenderSupervisorDaemonGolden(t *testing.T) {
	checkGolden(t, "supervisor.conf.tmpl", "supervisor_daemon.golden", struct {
		ProgramName, Command, DeployPath, User string
		Numprocs                               int
	}{
		ProgramName: "berth-app_example_com-reverb",
		Command:     "php /home/deploy/myapp/current/artisan reverb:start",
		DeployPath:  "/home/deploy/myapp", User: "webuser", Numprocs: 2,
	})
}
```

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/provision/steps/ -run 'QueueCommand' -v`
Expected: FAIL (compile: `queueCommand` undefined).

- [ ] **Step 3: Parametrize the template and add the builders**

Replace `internal/templates/supervisor.conf.tmpl` line `command=…` and `numprocs=1` so the file reads:

```
[program:{{ .ProgramName }}]
process_name=%(program_name)s_%(process_num)02d
command={{ .Command }}
directory={{ .DeployPath }}/current
user={{ .User }}
numprocs={{ .Numprocs }}
autostart=false
autorestart=true
stopwaitsecs=3600
redirect_stderr=true
stdout_logfile=/var/log/supervisor/{{ .ProgramName }}.log
stopasgroup=true
killasgroup=true
```

In `internal/provision/steps/site.go`, replace `renderSupervisor` with a command builder + a generic program renderer:

```go
// queueCommand builds the worker command line for a site. The default (no queue
// block) is byte-identical to berth's historical worker; tuning appends flags in
// a stable order. Horizon replaces queue:work entirely.
func queueCommand(s *config.Server, site config.Site) string {
	base := "php " + site.DeployPath + "/current/artisan "
	q := site.Queue
	if q != nil && q.Driver == "horizon" {
		return base + "horizon"
	}
	sleep, tries := 3, 3
	cmd := base + "queue:work"
	if q != nil {
		if q.Connection != "" {
			cmd += " " + q.Connection
		}
		if q.Queue != "" {
			cmd += " --queue=" + q.Queue
		}
		if q.Sleep != 0 {
			sleep = q.Sleep
		}
		if q.Tries != 0 {
			tries = q.Tries
		}
	}
	cmd += fmt.Sprintf(" --sleep=%d --tries=%d --max-time=3600", sleep, tries)
	if q != nil {
		if q.Timeout != 0 {
			cmd += fmt.Sprintf(" --timeout=%d", q.Timeout)
		}
		if q.MaxMemory != 0 {
			cmd += fmt.Sprintf(" --memory=%d", q.MaxMemory)
		}
	}
	return cmd
}

// queueNumprocs is the worker process count (default 1; horizon forces 1).
func queueNumprocs(site config.Site) int {
	if q := site.Queue; q != nil && q.Driver != "horizon" && q.Processes > 0 {
		return q.Processes
	}
	return 1
}

func daemonNumprocs(d config.Daemon) int {
	if d.Processes > 0 {
		return d.Processes
	}
	return 1
}

// renderSupervisorProgram renders one Supervisor program (worker or daemon).
func renderSupervisorProgram(programName, command string, numprocs int, user, deployPath string) ([]byte, error) {
	return templates.Render("supervisor.conf.tmpl", struct {
		ProgramName, Command, DeployPath, User string
		Numprocs                               int
	}{ProgramName: programName, Command: command, DeployPath: deployPath, User: user, Numprocs: numprocs})
}

// daemonProgramName / daemonProgramPath name a site's daemon program file.
func daemonProgramName(domain, name string) string { return programName(domain) + "-" + name }
func daemonProgramPath(domain, name string) string {
	return "/etc/supervisor/conf.d/" + daemonProgramName(domain, name) + ".conf"
}
```

(Keep the existing `programName`, `supervisorProgramPath`, `poolName` helpers. `poolName` may now delegate to `config.PoolName` for the single source of truth: change it to `func poolName(domain string) string { return config.PoolName(domain) }`.)

- [ ] **Step 4: Regenerate goldens and verify**

Run: `go test -update ./internal/templates/...`
Then inspect: `git diff internal/templates/testdata/supervisor.golden` MUST be **empty** (default byte-identical). The two new goldens `supervisor_horizon.golden` / `supervisor_daemon.golden` are created.
Run: `go test ./internal/templates/... && go test ./internal/provision/steps/ -run 'QueueCommand' -v && go vet ./internal/...`
Expected: PASS, vet clean, and `git status` shows the supervisor golden UNCHANGED (only the two new goldens added).

- [ ] **Step 5: Commit**

```bash
git add internal/templates/supervisor.conf.tmpl internal/templates/testdata/ internal/templates/templates_test.go internal/provision/steps/site.go internal/provision/steps/site_test.go
git commit -m "feat(site): parametrize supervisor program (command/numprocs); byte-identical default

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: wire programs into `managedSiteFiles` + global orphan drift-removal

**Files:**
- Modify: `internal/provision/steps/site.go` (`managedSiteFiles`)
- Test: `internal/provision/steps/site_test.go`

- [ ] **Step 1: Write failing tests**

Add to `internal/provision/steps/site_test.go`:

```go
func TestManagedSiteFilesEnumeratesWorkerAndDaemons(t *testing.T) {
	s := siteServer()
	s.Queue = true
	s.Sites[0].Daemons = []config.Daemon{{Name: "reverb", Command: "php artisan reverb:start"}}
	f := bssh.NewFakeRunner()
	// No existing supervisor program files on the host (orphan listing empty).
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{ExitCode: 0, Stdout: ""})
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	var sawWorker, sawDaemon bool
	for _, mf := range mfs {
		if mf.path == "/etc/supervisor/conf.d/berth-app_example_com.conf" && !mf.remove {
			sawWorker = true
		}
		if mf.path == "/etc/supervisor/conf.d/berth-app_example_com-reverb.conf" && !mf.remove {
			sawDaemon = true
		}
	}
	if !sawWorker || !sawDaemon {
		t.Errorf("expected worker + daemon program files; worker=%v daemon=%v", sawWorker, sawDaemon)
	}
}

func TestManagedSiteFilesFlagsOrphanProgram(t *testing.T) {
	s := siteServer()
	s.Queue = true // worker berth-app_example_com is desired; berth-app_example_com-old is NOT
	f := bssh.NewFakeRunner()
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{ExitCode: 0,
		Stdout: "/etc/supervisor/conf.d/berth-app_example_com.conf\n/etc/supervisor/conf.d/berth-app_example_com-old.conf\n"})
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	var sawOrphanRemove bool
	for _, mf := range mfs {
		if mf.path == "/etc/supervisor/conf.d/berth-app_example_com-old.conf" && mf.remove {
			sawOrphanRemove = true
		}
		if mf.path == "/etc/supervisor/conf.d/berth-app_example_com.conf" && mf.remove {
			t.Error("the desired worker must NOT be flagged for removal")
		}
	}
	if !sawOrphanRemove {
		t.Error("an undesired berth-*.conf program file must be flagged for removal")
	}
}
```

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/provision/steps/ -run 'ManagedSiteFiles(Enumerates|FlagsOrphan)' -v`
Expected: FAIL (the current `managedSiteFiles` writes one unconditional `renderSupervisor` file and never lists orphans).

- [ ] **Step 3: Rewrite the supervisor portion of `managedSiteFiles`**

In `internal/provision/steps/site.go`, inside `managedSiteFiles`, replace the existing supervisor block:

```go
		prog, err := renderSupervisor(s, site)
		if err != nil {
			return nil, err
		}
		files = append(files, siteFile{path: supervisorProgramPath(site.Domain), content: prog})
```

with per-program rendering:

```go
		if s.QueueEnabled(site) {
			worker, err := renderSupervisorProgram("berth-"+poolName(site.Domain), queueCommand(s, site), queueNumprocs(site), s.SiteUser(site), site.DeployPath)
			if err != nil {
				return nil, err
			}
			files = append(files, siteFile{path: supervisorProgramPath(site.Domain), content: worker})
		}
		for _, d := range site.Daemons {
			body, err := renderSupervisorProgram(daemonProgramName(site.Domain, d.Name), d.Command, daemonNumprocs(d), s.SiteUser(site), site.DeployPath)
			if err != nil {
				return nil, err
			}
			files = append(files, siteFile{path: daemonProgramPath(site.Domain, d.Name), content: body})
		}
```

After the `for _, site := range s.Sites` loop (before the logrotate append), add the **global** orphan pass:

```go
	// Global orphan drift-removal: any berth-*.conf supervisor program file that
	// no current site desires is removed (managed files only). Global — never a
	// per-pool glob — because pool names can be prefixes of one another.
	desired := map[string]bool{}
	for _, site := range s.Sites {
		for _, name := range s.SiteProgramNames(site) {
			desired["/etc/supervisor/conf.d/"+name+".conf"] = true
		}
	}
	res, err := r.Run(ctx, "ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", nil)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		path := strings.TrimSpace(line)
		if path == "" || desired[path] {
			continue
		}
		files = append(files, siteFile{path: path, remove: true})
	}
```

Delete the now-unused `renderSupervisor` function.

- [ ] **Step 4: Run — verify pass + no regressions**

Run: `go test ./internal/provision/steps/ -v && go vet ./internal/provision/steps/`
Expected: PASS. Note: existing tests that drive `managedSiteFiles`/`site.Apply` (e.g. `stubManagedSiteFiles`, `TestSiteApplyWritesManagedFiles`) now need the `ls -1 …berth-*.conf…` command stubbed. **Update those stubs**: add `f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})` to `stubManagedSiteFiles` and to each `site.Apply` test's runner (they default `Server.Queue` false in `siteServer()`, so no worker is written unless the test sets it). If a test relied on the old unconditional worker write, set `s.Queue = true` in that test.

- [ ] **Step 5: Commit**

```bash
git add internal/provision/steps/site.go internal/provision/steps/site_test.go
git commit -m "feat(site): render per-site worker+daemon programs; global berth-*.conf orphan removal

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: registry — gate supervisor on `NeedsSupervisor()`

**Files:**
- Modify: `internal/provision/steps/registry.go`
- Test: `internal/provision/steps/registry_test.go` (add a case; create if absent)

- [ ] **Step 1: Write the failing test**

Add to `internal/provision/steps/registry_test.go` (package `steps`):

```go
func TestPipelineIncludesSupervisorForDaemonOnlySite(t *testing.T) {
	s := &config.Server{
		PHP: config.PHP{Version: "8.4"}, Nginx: config.Nginx{Source: "debian"},
		Database: config.Database{Engine: "mariadb", Source: "mariadb"},
		// Queue false, but a daemon exists -> supervisor must be included.
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/var/www/a",
			Daemons: []config.Daemon{{Name: "reverb", Command: "php artisan reverb:start"}}}},
	}
	var hasSupervisor bool
	for _, st := range Pipeline(s, secret.NewRedactor(), true) {
		if st.Name() == "supervisor" {
			hasSupervisor = true
		}
	}
	if !hasSupervisor {
		t.Error("a daemon-only site (Server.Queue false) must still include the supervisor step")
	}
}
```

Add imports `"testing"`, `config`, `secret` as needed.

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/provision/steps/ -run 'PipelineIncludesSupervisor' -v`
Expected: FAIL (current gate is `if s.Queue`).

- [ ] **Step 3: Change the gate**

In `internal/provision/steps/registry.go`, replace:

```go
	if s.Queue {
		steps = append(steps, Supervisor())
	}
```

with:

```go
	if s.NeedsSupervisor() {
		steps = append(steps, Supervisor())
	}
```

- [ ] **Step 4: Run — verify pass**

Run: `go test ./internal/provision/steps/ -v && go vet ./internal/provision/steps/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/provision/steps/registry.go internal/provision/steps/registry_test.go
git commit -m "feat(registry): install supervisor whenever any worker or daemon exists

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: accounts — per-program sudoers + content-drift convergence

**Files:**
- Modify: `internal/templates/sudoers_deploy.tmpl`
- Modify: `internal/provision/steps/accounts.go` (`renderSiteSudoers`, `accounts.Check`)
- Test: `internal/templates/templates_test.go` (sudoers goldens), `internal/provision/steps/accounts_test.go`
- Golden: `internal/templates/testdata/sudoers_deploy.golden` (unchanged), new `sudoers_deploy_daemons.golden`

- [ ] **Step 1: Write failing tests (byte-identity, multi-program, content-drift, isolation)**

Update the sudoers golden test in `internal/templates/templates_test.go`:

```go
func TestRenderSudoersDeployGolden(t *testing.T) {
	checkGolden(t, "sudoers_deploy.tmpl", "sudoers_deploy.golden", struct {
		User, PHPVersion string
		Programs         []string
	}{User: "deploy", PHPVersion: "8.4", Programs: []string{"berth-app_example_com"}})
}

func TestRenderSudoersDeployDaemonsGolden(t *testing.T) {
	checkGolden(t, "sudoers_deploy.tmpl", "sudoers_deploy_daemons.golden", struct {
		User, PHPVersion string
		Programs         []string
	}{User: "deploy", PHPVersion: "8.4", Programs: []string{"berth-app_example_com", "berth-app_example_com-reverb"}})
}
```

Add to `internal/provision/steps/accounts_test.go` (package `steps`; create if absent):

```go
func TestSiteSudoersIsolationPerProgram(t *testing.T) {
	// Two sites, two users, two distinct program sets. Site B's sudoers must not
	// grant control over site A's program.
	s := &config.Server{
		PHP: config.PHP{Version: "8.4"}, Queue: true,
		Sites: []config.Site{
			{Domain: "a.example.com", DeployPath: "/var/www/a", User: "auser"},
			{Domain: "b.example.com", DeployPath: "/var/www/b", User: "buser"},
		},
	}
	bBody, err := renderSiteSudoers(s, s.Sites[1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bBody), "berth-a_example_com") {
		t.Errorf("site B sudoers must NOT reference site A's program:\n%s", bBody)
	}
	if !strings.Contains(string(bBody), `supervisorctl restart berth-b_example_com\:*`) {
		t.Errorf("site B sudoers must control its own program:\n%s", bBody)
	}
}

func TestSiteSudoersIncludesDaemonPrograms(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}, Queue: true,
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/var/www/a", User: "auser",
			Daemons: []config.Daemon{{Name: "reverb", Command: "php artisan reverb:start"}}}}}
	body, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`start berth-a_example_com\:*`, `start berth-a_example_com-reverb\:*`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing grant %q in:\n%s", want, body)
		}
	}
}

func TestAccountsCheckUnsatisfiedWhenSudoersDrifted(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}, Queue: true, SSH: config.SSH{Key: testKeyPath(t)},
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/var/www/a", User: "auser"}}}
	f := bssh.NewFakeRunner()
	stubAccountsPresent(t, s, f) // users exist, authorized_keys up to date (helper below)
	// The site sudoers on the host is managed but STALE (different content).
	f.On("cat "+shQuote(sudoersPath("auser")), bssh.Result{ExitCode: 0, Stdout: managedMarker + "\nauser ALL=(root) NOPASSWD: /usr/bin/true\n"})
	cr, err := Accounts().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when a managed site sudoers has drifted content")
	}
}
```

NOTE: `testKeyPath`/`stubAccountsPresent` are test helpers — define `testKeyPath` to write a throwaway `<tmp>/id_rsa.pub` and return the `<tmp>/id_rsa` path (so `operatorPublicKey` resolves), and `stubAccountsPresent` to stub `id <user>` exit 0, `cat <authorized_keys>` = the managed key body, and `visudo -cf` exit 0 for every managed account. Model them on the existing accounts tests in the file; if the file has equivalents, reuse them.

- [ ] **Step 2: Run — verify failure**

Run: `go test ./internal/provision/steps/ -run 'SiteSudoers|AccountsCheck' -v && go test ./internal/templates/ -run Sudoers -v`
Expected: FAIL (single-program template/struct mismatch; Check does not yet content-drift sudoers).

- [ ] **Step 3: Parametrize the sudoers template + content-drift Check**

Replace `internal/templates/sudoers_deploy.tmpl` with:

```
{{ .User }} ALL=(root) NOPASSWD: /usr/bin/systemctl reload php{{ .PHPVersion }}-fpm
{{ .User }} ALL=(root) NOPASSWD: /usr/bin/supervisorctl reread
{{ .User }} ALL=(root) NOPASSWD: /usr/bin/supervisorctl update
{{- range .Programs }}
{{ $.User }} ALL=(root) NOPASSWD: /usr/bin/supervisorctl start {{ . }}\:*
{{ $.User }} ALL=(root) NOPASSWD: /usr/bin/supervisorctl stop {{ . }}\:*
{{ $.User }} ALL=(root) NOPASSWD: /usr/bin/supervisorctl restart {{ . }}\:*
{{- end }}
```

(The `{{- range }}` / `{{- end }}` trim the newline BEFORE each control word so that, for a single program, the output is byte-identical to today's six-line file. Verify in Step 4.)

In `internal/provision/steps/accounts.go`, change `renderSiteSudoers` to pass the program list from the single source of truth:

```go
func renderSiteSudoers(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("sudoers_deploy.tmpl", struct {
		User, PHPVersion string
		Programs         []string
	}{User: s.SiteUser(site), PHPVersion: s.PHP.Version, Programs: s.SiteProgramNames(site)})
}
```

In `accounts.Check`, replace the per-account sudoers existence+visudo block (the `p := sudoersPath(u)` … `valid` section) with content-drift detection. Precompute the desired bodies once at the top of `Check` (after `want := authorizedKeys(...)`):

```go
	sudoersWant := map[string][]byte{"berth": []byte(sudoersBerthBody)}
	for _, site := range s.Sites {
		body, err := renderSiteSudoers(s, site)
		if err != nil {
			return provision.CheckResult{}, err
		}
		sudoersWant[s.SiteUser(site)] = body
	}
```

and replace the existence+visudo lines inside the `for _, u := range managedAccounts(s)` loop with:

```go
		p := sudoersPath(u)
		state, err := checkManagedFile(ctx, r, p, sudoersWant[u])
		if err != nil {
			return provision.CheckResult{}, err
		}
		okSudo, err := managedFileSatisfied(state, p, rc.Force)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !okSudo {
			return provision.CheckResult{Satisfied: false, Reason: p + " not up to date", Changes: a.changes()}, nil
		}
```

(`Apply` is unchanged: `writeValidatedSudoers` already re-renders and runs `visudo -cf`, so a drifted file is rewritten and validated.)

- [ ] **Step 4: Regenerate goldens, verify byte-identity, run**

Run: `go test -update ./internal/templates/...`
Then: `git diff internal/templates/testdata/sudoers_deploy.golden` MUST be **empty** (single-program byte-identical). `sudoers_deploy_daemons.golden` is created.
Run: `go test ./internal/templates/... && go test ./internal/provision/steps/ -v && go vet ./internal/...`
Expected: PASS; the single-program sudoers golden UNCHANGED.

- [ ] **Step 5: Commit**

```bash
git add internal/templates/sudoers_deploy.tmpl internal/templates/testdata/ internal/templates/templates_test.go internal/provision/steps/accounts.go internal/provision/steps/accounts_test.go
git commit -m "feat(accounts): per-program sudoers + content-drift convergence; byte-identical single-program

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: full local gate + live verification on a Debian 13 host

**Files:** none (operational). The real green for the runtime contract is a live run.

- [ ] **Step 1: Full local CI-equivalent gate**

Run: `gofmt -l . && go vet ./... && go test -race ./... && go build ./...`
Expected: gofmt prints nothing; vet clean; all packages `ok`; build exits 0.

- [ ] **Step 2: Update the smoke config with a tuned worker + a daemon**

Edit the local `servers/smoke.yml` (gitignored) site to add, e.g.:

```yaml
    queue: {processes: 2, tries: 5}
    daemons:
      - {name: reverb, command: php artisan reverb:start}
```

(Keep `ssl_mode: selfsigned` so the existing #18/#30/#33 assertions still run.)

- [ ] **Step 3: Provision and assert the runtime contract**

```bash
make build && ./berth provision --no-tty servers/smoke.yml          # already-provisioned box: no --force needed
```
Then assert on the host (via ssh as the berth account):
- `supervisorctl status` lists `berth-<pool>` and `berth-<pool>-reverb` as **STOPPED** (dormant, not FATAL).
- `/etc/supervisor/conf.d/berth-<pool>.conf` shows `numprocs=2` and `--tries=5`; `…-reverb.conf` shows the reverb command.
- `sudo -n -u <siteuser> sudo -n /usr/bin/supervisorctl restart berth-<pool>-reverb:\*` is permitted; restarting another site's program is refused.

- [ ] **Step 4: Idempotency + the integration suite**

Run: `BERTH_TEST_SERVER=/Users/robson/AI/berth/servers/smoke.yml go test -tags integration -v ./test/integration/...`
Expected: PASS — every step `satisfied` on the second run except `preflight` (proves the new program files, sudoers content-drift, and orphan pass are all idempotent). Then flip the config (remove the `reverb` daemon) and re-provision: assert `/etc/supervisor/conf.d/berth-<pool>-reverb.conf` is **removed** (orphan drift-removal) and the run reconverges.

---

## Self-Review

**1. Spec coverage:**
- Config schema (QueueConfig/Daemon/Site fields) + DecodeHook → Task 1. ✓
- Helpers QueueEnabled/NeedsSupervisor/SiteProgramNames/PoolName → Task 1. ✓
- Validation incl. global program uniqueness + control-char + horizon rules → Task 2. ✓
- Byte-identical default worker + parametrized template + command builder → Task 3. ✓
- Per-site worker+daemon rendering + GLOBAL orphan drift-removal → Task 4. ✓
- Registry NeedsSupervisor gate → Task 5. ✓
- Per-program sudoers + content-drift convergence + byte-identical single-program → Task 6. ✓
- Live runtime contract (dormant programs, isolation, idempotency, orphan removal) → Task 7. ✓

**2. Placeholder scan:** no TBD/TODO; every code step has complete code; commands have expected output. The one soft spot is Task 6's `testKeyPath`/`stubAccountsPresent` helpers — explicitly instructed to model on the existing accounts tests (the file already exercises `operatorPublicKey` + account presence); the implementer reuses those patterns rather than inventing.

**3. Type consistency:** `queueCommand(s,*Server, site Site) string`, `queueNumprocs(site) int`, `daemonNumprocs(d) int`, `renderSupervisorProgram(name, command string, numprocs int, user, deployPath string)`, `daemonProgramName/Path(domain, name)`, `Server.SiteProgramNames/QueueEnabled/NeedsSupervisor`, `config.PoolName` — names/signatures are used identically across Tasks 1–6. The supervisor render struct `{ProgramName, Command, DeployPath, User string; Numprocs int}` is identical in the template test (Task 3) and `renderSupervisorProgram` (Task 3). The sudoers render struct `{User, PHPVersion string; Programs []string}` matches between Task 6's template test and `renderSiteSudoers`.

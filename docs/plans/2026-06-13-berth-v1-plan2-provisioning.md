# berth v1 — Plan 2: Provisioning Steps & Data Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the empty pipeline from Plan 1 into a working `berth provision`: a live SSH runner, the connection/auto-detection model, every idempotent provisioning step, the MariaDB engine, secret persistence, and templated config files.

**Architecture:** A real `ssh.Client` implements `ssh.Runner` over `golang.org/x/crypto/ssh` (commands with stdin) and `github.com/pkg/sftp` (atomic `WriteFile`). `connect()` auto-detects the `berth` account, falling back to the bootstrap `root`. Concrete `provision.Step`s (one file each under `internal/provision/steps/`) implement `Check`/`Apply` and are registered in dependency order. Config files are rendered from `text/template` (embedded) and written atomically. The MariaDB `database.Engine` owns DB/user/password operations (SQL via stdin).

**Tech Stack:** Same `go.mod` as Plan 1 (`golang.org/x/crypto` v0.53.0, `github.com/pkg/sftp` v1.13.10). No new dependencies.

**Spec:** `docs/design/2026-06-13-berth-design.md` (Rev 5) §3, §4, §6. Builds on Plan 1's `ssh.Runner`, `apt`, `secret`, `provision.Engine`, `config`.

**Prerequisite:** Plan 1 implemented and green.

**Module path:** `github.com/robsonek/berth`. English only; no personal data.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `internal/ssh/client.go` | Live `Runner`: dial + host-key verify, `Run` (stdin), `WriteFile` (atomic SFTP+install) |
| `internal/ssh/hostkey.go` | `HostKeyCallback`: known_hosts + TOFU + pinned fingerprint |
| `internal/ssh/connect.go` | `Connect`: auto-detect `berth` → bootstrap `root` |
| `internal/provision/steps/*.go` | One file per step (preflight, base, accounts, hardening, php, nginx, valkey, supervisor, appdirs, database, site, tls) |
| `internal/provision/steps/registry.go` | Ordered pipeline assembly + `Requires` wiring |
| `internal/database/engine.go` | `Engine` interface + registry |
| `internal/database/mariadb.go` | MariaDB engine (install steps, EnsureDatabase, EnsureUser) |
| `internal/secret/env.go` | `shared/.env` seeding + local secrets cache |
| `internal/templates/*.tmpl` + `templates.go` | Embedded config templates + render helpers |
| `cmd/provision.go` | Replace Plan 1 wiring: connect, build registry, run with live runner |

Each step file is small and single-purpose; templates live beside the renderer.

---

## Task 1: Host-key verification

**Files:**
- Create: `internal/ssh/hostkey.go`
- Test: `internal/ssh/hostkey_test.go`

- [ ] **Step 1: Write the failing test `internal/ssh/hostkey_test.go`**

```go
package ssh

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	xssh "golang.org/x/crypto/ssh"
)

func fakeHostKey(t *testing.T) xssh.PublicKey {
	t.Helper()
	// 32 zero bytes is a deterministic stand-in public key blob for fingerprinting.
	k, err := xssh.ParsePublicKey(nil)
	_ = err
	_ = k
	// Build a minimal ed25519 key instead:
	pub, _, _ := xssh.NewKeyPairForTest() // helper defined below if not present
	return pub
}

func TestPinnedFingerprintMismatchFails(t *testing.T) {
	hk := newTestKey(t)
	cb := HostKeyChecker(HostKeyPolicy{Pinned: "SHA256:doesnotmatch"})
	if err := cb("host:22", nil, hk); err == nil {
		t.Fatal("expected mismatch error for wrong pinned fingerprint")
	}
}

func TestPinnedFingerprintMatchPasses(t *testing.T) {
	hk := newTestKey(t)
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sha256.New().Sum(hk.Marshal())[:32])
	_ = fp
	want := Fingerprint(hk)
	cb := HostKeyChecker(HostKeyPolicy{Pinned: want})
	if err := cb("host:22", nil, hk); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}
```

> Implementer note: replace the sketched key helpers with a real one — generate an ed25519 key with `ssh.NewSignerFromKey` from `ed25519.GenerateKey` and take `signer.PublicKey()`. Add a `newTestKey(t)` helper returning that `xssh.PublicKey`. The test's intent (mismatch fails, match passes) is the contract.

- [ ] **Step 2: Write `internal/ssh/hostkey.go`**

```go
package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"

	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyPolicy configures how a server's host key is verified.
type HostKeyPolicy struct {
	Pinned       string // optional "SHA256:..." fingerprint; if set, must match
	KnownHosts   string // path to known_hosts (default ~/.ssh/known_hosts)
	AllowTOFU    bool   // prompt + pin on first contact when not pinned/known
	ConfirmTOFU  func(host, fingerprint string) bool // interactive confirm
}

// Fingerprint returns the SHA256 fingerprint of a public key ("SHA256:...").
func Fingerprint(k xssh.PublicKey) string { return xssh.FingerprintSHA256(k) }

// HostKeyChecker builds a HostKeyCallback. It never returns InsecureIgnoreHostKey.
// Order: pinned fingerprint (if set) → known_hosts → TOFU confirmation.
func HostKeyChecker(p HostKeyPolicy) xssh.HostKeyCallback {
	var known xssh.HostKeyCallback
	if p.KnownHosts != "" {
		if cb, err := knownhosts.New(expandHome(p.KnownHosts)); err == nil {
			known = cb
		}
	}
	return func(hostname string, remote net.Addr, key xssh.PublicKey) error {
		fp := Fingerprint(key)
		// 1) Explicit pin wins.
		if p.Pinned != "" {
			if fp != p.Pinned {
				return fmt.Errorf("host key fingerprint %s does not match pinned %s", fp, p.Pinned)
			}
			return nil
		}
		// 2) known_hosts.
		if known != nil {
			switch err := known(hostname, remote, key); {
			case err == nil:
				return nil // recognized host + key
			case isKnownHostsMismatch(err):
				return fmt.Errorf("host key mismatch for %s (%s) — refusing (possible MITM)", hostname, fp)
				// default: unknown host → fall through to TOFU
			}
		}
		// 3) TOFU with explicit confirmation, then pin to known_hosts.
		if p.AllowTOFU && p.ConfirmTOFU != nil && p.ConfirmTOFU(hostname, fp) {
			return appendKnownHost(p.KnownHosts, hostname, key)
		}
		return fmt.Errorf("unknown host key for %s (%s); pin via ssh.fingerprint or confirm interactively", hostname, fp)
	}
}

// isKnownHostsMismatch is true when the host is present with a different key.
func isKnownHostsMismatch(err error) bool {
	var ke *knownhosts.KeyError
	return errors.As(err, &ke) && len(ke.Want) > 0
}

// appendKnownHost pins a confirmed host key to the known_hosts file (0600).
func appendKnownHost(path, hostname string, key xssh.PublicKey) error {
	f, err := os.OpenFile(expandHome(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, knownhosts.Line([]string{hostname}, key))
	return err
}
```

> Implementer note: cover host-key tests for all paths — pinned match, pinned mismatch, known_hosts match, known_hosts mismatch (MITM → hard fail), and unknown+TOFU-confirmed (→ pinned). `expandHome` is shared with `connect.go`.

- [ ] **Step 3–5:** Run `go test ./internal/ssh/...` (fail → implement → pass), then commit:

```bash
git add internal/ssh/hostkey.go internal/ssh/hostkey_test.go
git commit -m "Add SSH host-key verification (pinned + known_hosts + TOFU)"
```

---

## Task 2: Live SSH client (Run + atomic WriteFile)

**Files:**
- Create: `internal/ssh/client.go`
- Test: `internal/ssh/client_test.go` (build-tagged `integration` where it needs a real sshd)

- [ ] **Step 1: Write `internal/ssh/client.go`**

```go
package ssh

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/sftp"
	xssh "golang.org/x/crypto/ssh"
)

// Client is the production Runner over a single SSH connection.
type Client struct {
	conn   *xssh.Client
	sftp   *sftp.Client
	useSudo bool // true when connected as a non-root account
}

// Dial opens an SSH connection and SFTP subsystem.
func Dial(ctx context.Context, addr string, cfg *xssh.ClientConfig, useSudo bool) (*Client, error) {
	conn, err := xssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	sc, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("sftp: %w", err)
	}
	return &Client{conn: conn, sftp: sc, useSudo: useSudo}, nil
}

func (c *Client) Close() error { c.sftp.Close(); return c.conn.Close() }

// Run executes cmd, feeding stdin, and returns stdout/stderr/exit code.
func (c *Client) Run(ctx context.Context, cmd string, stdin []byte) (Result, error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return Result{}, err
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	runErr := sess.Run(cmd)
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	if ee, ok := runErr.(*xssh.ExitError); ok {
		res.ExitCode = ee.ExitStatus()
		return res, nil // non-zero exit is a signal, not a transport error
	}
	return res, runErr
}

// WriteFile writes content with ownership/mode via an unpredictable temp file
// and a privileged `install` (which copies + sets owner/group/mode in one step).
func (c *Client) WriteFile(ctx context.Context, f FileSpec) error {
	// Unpredictable temp path (avoids /tmp symlink/predictable-name races).
	mk, err := c.Run(ctx, "mktemp", nil)
	if err != nil {
		return err
	}
	if mk.ExitCode != 0 {
		return fmt.Errorf("mktemp: %s", mk.Stderr)
	}
	tmp := strings.TrimSpace(mk.Stdout)

	w, err := c.sftp.OpenFile(tmp, os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("open temp %s: %w", tmp, err)
	}
	if _, err := w.Write(f.Content); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil { // Close flushes; surface deferred write errors
		return fmt.Errorf("flush temp %s: %w", tmp, err)
	}

	cmd, _ := installCmd(f, tmp, c.useSudo)
	if r, err := c.Run(ctx, cmd, nil); err != nil {
		return err
	} else if r.ExitCode != 0 {
		return fmt.Errorf("install %s failed: %s", f.Path, r.Stderr)
	}
	return nil
}

// installCmd builds the privileged install command; all path/owner values are
// shell-quoted (defence-in-depth on top of config validation).
func installCmd(f FileSpec, tmp string, useSudo bool) (cmd, tmpOut string) {
	mode := f.Mode
	if mode == 0 {
		mode = 0o644
	}
	owner, group := f.Owner, f.Group
	if owner == "" {
		owner = "root"
	}
	if group == "" {
		group = owner
	}
	cmd = fmt.Sprintf("install -o %s -g %s -m %o %s %s && rm -f %s",
		shQuote(owner), shQuote(group), mode.Perm(), shQuote(tmp), shQuote(f.Path), shQuote(tmp))
	if f.Sudo && useSudo {
		cmd = "sudo " + cmd
	}
	return cmd, tmp
}

// shQuote single-quotes s for safe shell use.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
```

> Implementer note (redaction, §7/§8): the `Client` holds a `*secret.Redactor`; **all verbose (`-v`) command and output logging passes through `redactor.Apply`** so secrets (DB password, keys) never reach the terminal or logs. Secret-bearing commands already use stdin (absent from the remote process list); the redactor covers the local log path. Renderers mask `Event.Sensitive` changes (Plan 1 plain renderer; Plan 3 TUI).

- [ ] **Step 2: Test (unit where possible; integration-tagged for the live path)**

Unit-test the command-string construction by extracting the `install ...` builder into a small pure function `installCmd(f FileSpec, useSudo bool) (cmd, tmp string)` and asserting its output for a `Sudo` and non-`Sudo` case. The full dial path is exercised by the Plan 2 Task 13 integration smoke test.

```go
//go:build !integration
package ssh

import "testing"

func TestInstallCmdSudoAndOwnership(t *testing.T) {
	cmd, _ := installCmd(FileSpec{Path: "/etc/nginx/sites-available/app", Owner: "root", Group: "root", Mode: 0o644, Sudo: true}, "/tmp/berth.tmp", true)
	for _, want := range []string{"sudo install", "-o 'root'", "-g 'root'", "-m 644", "'/etc/nginx/sites-available/app'"} {
		if !contains(cmd, want) {
			t.Errorf("installCmd missing %q in %q", want, cmd)
		}
	}
}
```

> Implementer note: refactor the `install ...` string in `WriteFile` into `installCmd` so it is unit-testable without a connection; `WriteFile` then calls it. Add a tiny `contains` helper or use `strings.Contains`.

- [ ] **Step 3: Commit**

```bash
git add internal/ssh/client.go internal/ssh/client_test.go
git commit -m "Add live SSH client: Run with stdin and atomic WriteFile via SFTP"
```

---

## Task 3: Connection & user auto-detection

**Files:**
- Create: `internal/ssh/connect.go`
- Test: `internal/ssh/connect_test.go`

- [ ] **Step 1: Write `internal/ssh/connect.go`**

```go
package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/robsonek/berth/internal/config"
	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Connect returns a Client, preferring the 'berth' provisioning account and
// falling back to the configured bootstrap user (typically root).
func Connect(ctx context.Context, s *config.Server, policy HostKeyPolicy) (*Client, error) {
	auth, err := authMethods(s.SSH.Key)
	if err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("%s:%d", s.Host, s.SSH.Port)

	// Try the steady-state provisioning account first.
	if c, err := Dial(ctx, addr, clientConfig("berth", auth, policy), true); err == nil {
		if r, e := c.Run(ctx, "sudo -n true", nil); e == nil && r.ExitCode == 0 {
			return c, nil
		}
		c.Close()
	}
	// Bootstrap: connect as the configured user (root on a fresh box).
	return Dial(ctx, addr, clientConfig(s.SSH.User, auth, policy), s.SSH.User != "root")
}

func clientConfig(user string, auth []xssh.AuthMethod, policy HostKeyPolicy) *xssh.ClientConfig {
	return &xssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: HostKeyChecker(policy),
		Timeout:         15 * time.Second,
	}
}

// authMethods prefers ssh-agent (SSH_AUTH_SOCK), then the configured key file.
// Passphrase-protected keys are supported by loading them into the agent.
func authMethods(keyPath string) ([]xssh.AuthMethod, error) {
	var methods []xssh.AuthMethod
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			methods = append(methods, xssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	if keyPath != "" {
		if b, err := os.ReadFile(expandHome(keyPath)); err == nil {
			signer, perr := xssh.ParsePrivateKey(b)
			if perr != nil {
				return nil, fmt.Errorf("parse ssh key %s: %w (for passphrase-protected keys, use ssh-agent)", keyPath, perr)
			}
			methods = append(methods, xssh.PublicKeys(signer))
		}
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH auth available: set ssh.key to a readable key or load one into ssh-agent")
	}
	return methods, nil
}
```

> Implementer note: implement `expandHome` (replace a leading `~` with `$HOME`). For passphrase-protected keys, fall back to `xssh.ParsePrivateKeyWithPassphrase` prompting once; out of scope for the first cut if your key is unencrypted, but leave a clear error.

- [ ] **Step 2: Test the fallback selection logic**

Extract the "which user to try" decision is implicit in `Connect`; unit-test `clientConfig` sets the right user and a non-insecure callback. The live fallback is covered by the integration smoke test (Task 13).

```go
package ssh

import "testing"

func TestClientConfigUsesCallbackNotInsecure(t *testing.T) {
	cfg := clientConfig("berth", nil, HostKeyPolicy{Pinned: "SHA256:x"})
	if cfg.User != "berth" {
		t.Errorf("user = %q", cfg.User)
	}
	if cfg.HostKeyCallback == nil {
		t.Error("HostKeyCallback must be set (never InsecureIgnoreHostKey)")
	}
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/ssh/connect.go internal/ssh/connect_test.go
git commit -m "Add SSH connect with berth→root user auto-detection"
```

---

## Task 4: Templates (embed.FS) + render + golden tests

**Files:**
- Create: `internal/templates/templates.go`
- Create: `internal/templates/nginx_http.conf.tmpl`, `nginx_https.conf.tmpl`, `fpm_pool.conf.tmpl`, `supervisor.conf.tmpl`, `env.tmpl`, `sudoers_deploy.tmpl`, `scheduler.cron.tmpl`
- Test: `internal/templates/templates_test.go` + `testdata/*.golden`

- [ ] **Step 1: Write `internal/templates/templates.go`**

```go
// Package templates renders berth-managed config files from embedded templates.
package templates

import (
	"bytes"
	"embed"
	"text/template"
)

//go:embed *.tmpl
var files embed.FS

var tmpl = template.Must(template.New("").ParseFS(files, "*.tmpl"))

// Render executes the named template (e.g. "nginx_http.conf.tmpl") with data.
func Render(name string, data any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("# managed by berth\n")
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
```

- [ ] **Step 2: Write `internal/templates/nginx_http.conf.tmpl`** (representative; others follow the same shape)

```
server {
    listen 80;
    server_name {{ .Domain }};
    root {{ .DeployPath }}/current/public;
    index index.php;

    location /.well-known/acme-challenge/ {
        root {{ .ACMEWebroot }};
    }

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php{{ .PHPVersion }}-fpm.sock;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
    }

    location ~ /\.(?!well-known).* { deny all; }
}
```

> Implementer note: author the remaining templates with the exact content berth writes — `nginx_https.conf.tmpl` (443 + cert paths + 80→443 redirect), `fpm_pool.conf.tmpl` (pool name, user `deploy`, socket), `supervisor.conf.tmpl` (`autostart=false`, `command=php {{.DeployPath}}/current/artisan queue:work`, `user=deploy`), `env.tmpl` (`APP_ENV=production`, `APP_DEBUG=false`, `APP_URL`, `DB_*`, `REDIS_*`), `sudoers_deploy.tmpl` (narrow allowlist: reload php-fpm, `supervisorctl` for the app worker), `scheduler.cron.tmpl` (`* * * * * deploy [ -f {{.DeployPath}}/current/artisan ] && cd {{.DeployPath}}/current && php artisan schedule:run >/dev/null 2>&1`).

- [ ] **Step 3: Golden test `internal/templates/templates_test.go`**

```go
package templates

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

type nginxData struct{ Domain, DeployPath, ACMEWebroot, PHPVersion string }

func TestRenderNginxHTTPGolden(t *testing.T) {
	got, err := Render("nginx_http.conf.tmpl", nginxData{
		Domain: "app.example.com", DeployPath: "/home/deploy/myapp",
		ACMEWebroot: "/var/www/berth-acme/app.example.com", PHPVersion: "8.5",
	})
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "nginx_http.golden")
	if *update {
		os.WriteFile(golden, got, 0o644)
	}
	want, _ := os.ReadFile(golden)
	if string(got) != string(want) {
		t.Errorf("render mismatch; run with -update to refresh\n got:\n%s", got)
	}
}
```

- [ ] **Step 4: Generate goldens & commit**

Run: `go test ./internal/templates/... -update && go test ./internal/templates/...`
Expected: goldens created, then PASS.

```bash
git add internal/templates
git commit -m "Add embedded config templates with golden tests"
```

---

## Task 5: MariaDB engine

**Files:**
- Create: `internal/database/engine.go`
- Create: `internal/database/mariadb.go`
- Test: `internal/database/mariadb_test.go`

- [ ] **Step 1: Write `internal/database/engine.go`**

```go
// Package database provides pluggable database engines.
package database

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

type Engine interface {
	Name() string
	InstallSteps() []provision.Step
	EnsureDatabase(ctx context.Context, r bssh.Runner, name string) error
	EnsureUser(ctx context.Context, r bssh.Runner, user, password, database string) error
}

var registry = map[string]Engine{}

func Register(e Engine) { registry[e.Name()] = e }

func Get(name string) (Engine, error) {
	e, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown database engine %q", name)
	}
	return e, nil
}
```

- [ ] **Step 2: Write the failing test `internal/database/mariadb_test.go`**

```go
package database

import (
	"context"
	"strings"
	"testing"

	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestMariaDBEnsureUserUsesStdinNotArgv(t *testing.T) {
	f := bssh.NewFakeRunner()
	// The SQL goes through stdin; the command itself must not contain the password.
	f.On("mysql --protocol=socket", bssh.Result{})
	m := MariaDB{}
	if err := m.EnsureUser(context.Background(), f, "myapp", "s3cr3t", "myapp"); err != nil {
		t.Fatalf("EnsureUser() error = %v", err)
	}
	call := f.Calls()[0]
	if strings.Contains(call.Cmd, "s3cr3t") {
		t.Error("password must not appear in the command string")
	}
	if !strings.Contains(string(call.Stdin), "CREATE USER") || !strings.Contains(string(call.Stdin), "s3cr3t") {
		t.Error("SQL with the password must be passed via stdin")
	}
	if !strings.Contains(string(call.Stdin), "ALTER USER") {
		t.Error("EnsureUser must be idempotent (ALTER to re-sync the password)")
	}
}

func TestMariaDBEnsureDatabaseIdempotent(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("mysql --protocol=socket", bssh.Result{})
	if err := (MariaDB{}).EnsureDatabase(context.Background(), f, "myapp"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(f.Calls()[0].Stdin), "CREATE DATABASE IF NOT EXISTS") {
		t.Error("expected idempotent CREATE DATABASE IF NOT EXISTS")
	}
}
```

- [ ] **Step 3: Write `internal/database/mariadb.go`**

```go
package database

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func init() { Register(MariaDB{}) }

type MariaDB struct{}

func (MariaDB) Name() string { return "mariadb" }

// InstallSteps returns steps that install and enable the server. Implemented as
// a thin step in Task 9's registry; kept here so the engine owns its packages.
func (MariaDB) InstallSteps() []provision.Step { return nil } // wired via steps.MariaDBInstall

// runSQL pipes a statement to the local socket as root (unix_socket auth on Debian).
func runSQL(ctx context.Context, r bssh.Runner, sql string) error {
	res, err := r.Run(ctx, "mysql --protocol=socket", []byte(sql))
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("mysql: %s", res.Stderr)
	}
	return nil
}

func (MariaDB) EnsureDatabase(ctx context.Context, r bssh.Runner, name string) error {
	// name is a validated SQL identifier (config.Validate); safe to interpolate as an identifier.
	return runSQL(ctx, r, fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", name))
}

func (MariaDB) EnsureUser(ctx context.Context, r bssh.Runner, user, password, database string) error {
	// user/database are validated identifiers; password is a value bound in SQL via stdin.
	sql := fmt.Sprintf(
		"CREATE USER IF NOT EXISTS '%[1]s'@'localhost' IDENTIFIED BY '%[3]s';\n"+
			"ALTER USER '%[1]s'@'localhost' IDENTIFIED BY '%[3]s';\n"+
			"GRANT ALL PRIVILEGES ON `%[2]s`.* TO '%[1]s'@'localhost';\n"+
			"FLUSH PRIVILEGES;",
		user, database, password)
	return runSQL(ctx, r, sql)
}
```

> Implementer note: `password` is generated by `secret.Generate` from an alphanumeric alphabet (no quotes/backslashes), so single-quote interpolation is safe. A password **reused from `shared/.env` is validated against the same `^[A-Za-z0-9]+$` charset before use** (reject otherwise) — defence-in-depth against SQL injection via a tampered env. Register it in the `secret.Redactor` so it is masked in any logged output. `EnsureUser`/`EnsureDatabase` are idempotent and re-sync the password on re-run.

- [ ] **Step 4–5:** Run `go test ./internal/database/...` (fail → implement → pass), then commit:

```bash
git add internal/database
git commit -m "Add pluggable database engine with MariaDB (stdin SQL, idempotent)"
```

---

## Task 6: Secret persistence (`shared/.env` + local cache)

**Files:**
- Create: `internal/secret/env.go`
- Test: `internal/secret/env_test.go`

- [ ] **Step 1: Write `internal/secret/env.go`**

```go
package secret

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EnvFile renders a .env body from key/value pairs (deterministic order).
func EnvFile(kv map[string]string) []byte {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, kv[k])
	}
	return []byte(b.String())
}

// SaveCache writes a gitignored local copy of generated secrets (mode 600).
func SaveCache(server string, secrets map[string]string) error {
	dir := ".berth"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, server+".secrets.json"), b, 0o600)
}

// LoadCache reads a previously saved secrets cache (used to reuse, not rotate).
func LoadCache(server string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(".berth", server+".secrets.json"))
	if err != nil {
		return nil, err
	}
	var m map[string]string
	return m, json.Unmarshal(b, &m)
}
```

- [ ] **Step 2: Write the failing test `internal/secret/env_test.go`**

```go
package secret

import (
	"os"
	"strings"
	"testing"
)

func TestEnvFileDeterministicAndComplete(t *testing.T) {
	got := string(EnvFile(map[string]string{"DB_PASSWORD": "p", "APP_ENV": "production"}))
	if !strings.HasPrefix(got, "APP_ENV=production\n") { // sorted
		t.Errorf("env not sorted/deterministic: %q", got)
	}
	if !strings.Contains(got, "DB_PASSWORD=p\n") {
		t.Error("missing DB_PASSWORD line")
	}
}

func TestSaveAndLoadCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)
	if err := SaveCache("srv", map[string]string{"DB_PASSWORD": "x"}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCache("srv")
	if err != nil || got["DB_PASSWORD"] != "x" {
		t.Fatalf("round-trip failed: %v %v", got, err)
	}
	if fi, _ := os.Stat(".berth/srv.secrets.json"); fi.Mode().Perm() != 0o600 {
		t.Errorf("cache mode = %v, want 0600", fi.Mode().Perm())
	}
}
```

- [ ] **Step 3–5:** Run tests (fail → implement → pass), then commit:

```bash
git add internal/secret/env.go internal/secret/env_test.go
git commit -m "Add .env rendering and gitignored secrets cache"
```

---

## Task 7: Step catalog — system-level steps

Each step is its own file under `internal/provision/steps/`, implements `provision.Step`, and is unit-tested with `FakeRunner`. The pattern for every step:

```go
func (s xxxStep) Name() string       { return "xxx" }
func (s xxxStep) Requires() []string { return []string{ /* prior step names */ } }
func (s xxxStep) Check(ctx, rc, srv, r) (provision.CheckResult, error) { /* probe real state */ }
func (s xxxStep) Apply(ctx, rc, srv, r) error { /* run commands / WriteFile */ }
// rc is provision.RunCtx{Force, SSLStaging}: steps that detect drift consult
// rc.Force (§6.5); the TLS step consults rc.SSLStaging.
```

**Check depth (every step, addressing the "shallow Check" risk):** a `Check`
verifies *functional* state, not mere presence — files via a `# managed by berth`
marker **+ content hash**; services via `systemctl is-active` **and**
`is-enabled`; sudoers via `visudo -cf`; packages via `dpkg -s`. A managed file
changed out-of-band is reconciled; an *unmanaged* conflicting resource aborts
unless `rc.Force` (§6.5).

A representative fully-coded step (use it as the concrete model; the others list their exact `Check`/`Apply` commands):

- [ ] **Step 1: Write `internal/provision/steps/preflight.go`**

```go
package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

type preflight struct{}

func Preflight() provision.Step { return preflight{} }

func (preflight) Name() string       { return "preflight" }
func (preflight) Requires() []string { return nil }

func (preflight) Check(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	res, err := r.Run(ctx, ". /etc/os-release && echo $VERSION_CODENAME", nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	codename := strings.TrimSpace(res.Stdout)
	if codename != "trixie" {
		return provision.CheckResult{}, fmt.Errorf("unsupported OS: VERSION_CODENAME=%q, berth requires Debian 13 (trixie)", codename)
	}
	// Preflight always "acts" (apt update) but reports satisfied=false so Apply runs once per run.
	return provision.CheckResult{Satisfied: false, Reason: "Debian 13 detected", Changes: []string{"apt-get update"}}, nil
}

func (preflight) Apply(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	for _, cmd := range []string{
		"sudo -n true",
		"sudo DEBIAN_FRONTEND=noninteractive apt-get update -y",
	} {
		res, err := r.Run(ctx, cmd, nil)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("preflight %q: %s", cmd, res.Stderr)
		}
	}
	return nil
}
```

- [ ] **Step 2: Write its test `internal/provision/steps/preflight_test.go`**

```go
package steps

import (
	"context"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestPreflightRejectsNonTrixie(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(". /etc/os-release && echo $VERSION_CODENAME", bssh.Result{Stdout: "bookworm\n"})
	_, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err == nil {
		t.Fatal("expected rejection of non-trixie")
	}
}

func TestPreflightAcceptsTrixie(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(". /etc/os-release && echo $VERSION_CODENAME", bssh.Result{Stdout: "trixie\n"})
	cr, err := Preflight().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("trixie should pass and report not-yet-satisfied; got cr=%+v err=%v", cr, err)
	}
}
```

- [ ] **Step 3: Implement the remaining system steps** — one file + test each, following the model above. Exact `Check`/`Apply` per step:

  - **`systembase.go` (`base`, Requires `preflight`):** Check `dpkg -s` for `curl git unzip ca-certificates gnupg unattended-upgrades`; Apply `apt-get install -y` those + `timedatectl set-timezone UTC` + enable `unattended-upgrades`.
  - **`accounts.go` (`accounts`, Requires `base`):** Check (deep): both users exist (`id berth`/`id deploy`), `/etc/sudoers.d/berth` and `/etc/sudoers.d/deploy` are present and pass `visudo -cf`, and each `authorized_keys` carries the managed marker + expected key hash. Apply: create both users (`useradd -m -s /bin/bash`), write `/etc/sudoers.d/berth` (`berth ALL=(ALL) NOPASSWD:ALL`, mode 440, validated with `visudo -cf`), write `/etc/sudoers.d/deploy` from the `sudoers_deploy.tmpl`, install operator key into both `authorized_keys`; if any site has `repository`, `ssh-keygen -t ed25519` under `~deploy/.ssh/` (skip if present) and `ssh-keyscan <git-host> >> ~deploy/.ssh/known_hosts`.
  - **`hardening.go` (`hardening`, Requires `accounts`):** Check `ufw status` is active and `sshd` has root-login/password disabled. Apply (order matters): `ufw allow <ssh.port>/tcp`, `ufw allow 80,443/tcp`, `ufw --force enable`; install `fail2ban`; **anti-lockout gate** — open a fresh session as `berth` and run `sudo -n true`; only if that succeeds, write `/etc/ssh/sshd_config.d/berth.conf` (`PermitRootLogin no`, `PasswordAuthentication no`) and `systemctl reload ssh`. If the gate check fails, return an error **without** touching sshd.

```go
// hardening anti-lockout gate (essence, inside Apply, before disabling sshd):
if err := verifyBerthAccess(ctx, srv); err != nil {
    return fmt.Errorf("anti-lockout: refusing to harden sshd, berth access not verified: %w", err)
}
```

> Implementer note: `verifyBerthAccess` dials a brand-new `ssh.Client` as `berth` and runs `sudo -n true`; it must NOT reuse the current connection (which may be root). This is the one place berth opens a second connection. Cover it in the Task 13 integration test; unit-test the ordering (allow-before-enable) by asserting the recorded command sequence on the FakeRunner.

- [ ] **Step 4: Commit**

```bash
git add internal/provision/steps/preflight.go internal/provision/steps/systembase.go internal/provision/steps/accounts.go internal/provision/steps/hardening.go internal/provision/steps/*_test.go
git commit -m "Add system steps: preflight, base, accounts, network hardening"
```

---

## Task 8: Step catalog — runtime & web steps

- [ ] **Step 1: PHP step `internal/provision/steps/php.go` (`php`, Requires `base`)** — the source-selection logic:

```go
package steps

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

const debianStockPHP = "8.4" // Debian 13 (trixie) ships PHP 8.4

type php struct{}

func PHP() provision.Step { return php{} }

func (php) Name() string       { return "php" }
func (php) Requires() []string { return []string{"base"} }

// useSury decides whether the requested version needs the Surý repo.
func useSury(p config.PHP) (bool, error) {
	switch p.Source {
	case "sury":
		return true, nil
	case "debian":
		if p.Version != debianStockPHP {
			return false, fmt.Errorf("php.source=debian cannot provide %s (Debian 13 ships %s); use auto or sury", p.Version, debianStockPHP)
		}
		return false, nil
	case "auto", "":
		return p.Version != debianStockPHP, nil
	default:
		return false, fmt.Errorf("invalid php.source %q", p.Source)
	}
}

func (php) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	res, err := r.Run(ctx, "dpkg -s php"+s.PHP.Version+"-fpm", nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if res.ExitCode == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "php" + s.PHP.Version + "-fpm installed"}, nil
	}
	return provision.CheckResult{Satisfied: false, Changes: []string{"install php" + s.PHP.Version + " + extensions"}}, nil
}

func (php) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	sury, err := useSury(s.PHP)
	if err != nil {
		return err
	}
	m := apt.New(r)
	if sury {
		if err := m.EnsureRepo(ctx, apt.Sury()); err != nil {
			return err
		}
	}
	v := s.PHP.Version
	pkgs := []string{}
	for _, ext := range []string{"fpm", "cli", "mbstring", "xml", "bcmath", "curl", "intl", "zip", "gd", "redis", "mysql"} {
		pkgs = append(pkgs, fmt.Sprintf("php%s-%s", v, ext))
	}
	return m.EnsurePackages(ctx, nil, pkgs...)
}
```

- [ ] **Step 2: Test `php_test.go`** — cover `useSury`:

```go
package steps

import (
	"testing"

	"github.com/robsonek/berth/internal/config"
)

func TestUseSury(t *testing.T) {
	cases := []struct {
		src, ver string
		want     bool
		wantErr  bool
	}{
		{"auto", "8.5", true, false},
		{"auto", "8.4", false, false},
		{"sury", "8.4", true, false},
		{"debian", "8.5", false, true},
		{"debian", "8.4", false, false},
		{"ppa", "8.5", false, true},
	}
	for _, c := range cases {
		got, err := useSury(config.PHP{Version: c.ver, Source: c.src})
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("useSury(%s,%s) = %v,%v; want %v,err=%v", c.src, c.ver, got, err, c.want, c.wantErr)
		}
	}
}
```

- [ ] **Step 3: Implement the remaining runtime/web steps** — file + test each:

  - **`nginx.go` (`nginx`, Requires `base`):** Check `dpkg -s nginx` + `systemctl is-active nginx` **and** `is-enabled nginx`. Apply `apt-get install -y nginx`, then `systemctl enable --now nginx`.
  - **`composer.go` (`composer`, Requires `php`):** Check `command -v composer`. Apply: download installer, **verify SHA-384**, `php composer-setup.php --install-dir=/usr/local/bin --filename=composer`, remove setup.
  - **`valkey.go` (`valkey`, Requires `base`, only when `srv.Valkey`):** Check `dpkg -s valkey-server` + `systemctl is-active valkey-server` + `is-enabled valkey-server` (the Debian package's unit is `valkey-server.service`, not `valkey`). Apply `apt-get install -y valkey-server` (the `php{ver}-redis` client extension is covered by the php step), then `systemctl enable --now valkey-server`.
  - **`supervisor.go` (`supervisor`, Requires `base`, only when `srv.Queue`):** Check `dpkg -s supervisor` + `systemctl is-active`/`is-enabled supervisor`. Apply `apt-get install -y supervisor`, then `systemctl enable --now supervisor`.

- [ ] **Step 4: Commit**

```bash
git add internal/provision/steps/php.go internal/provision/steps/nginx.go internal/provision/steps/composer.go internal/provision/steps/valkey.go internal/provision/steps/supervisor.go internal/provision/steps/*_test.go
git commit -m "Add runtime/web steps: php (source-aware), nginx, composer, valkey, supervisor"
```

---

## Task 9: Step catalog — app directories, database, site, TLS

- [ ] **Step 1: `appdirs.go` (`appdirs`, Requires `accounts`)** — create `deploy_path`, `shared/`, and the ACME webroot **before** secrets:

  Check: all three directories exist and are owned by `deploy`/`www-data`. Apply: `install -d -o deploy -g deploy {deploy_path} {deploy_path}/shared` and `install -d -o www-data -g www-data /var/www/berth-acme/{domain}` (per site), via `WriteFile`-style `sudo install -d`.

- [ ] **Step 2: `database.go` (`database`, Requires `base`, `appdirs`)** — install MariaDB, then persist secret, then ensure DB/user:

```go
func (d database) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if err := aptInstall(ctx, r, "mariadb-server"); err != nil { // helper around apt.EnsurePackages
		return err
	}
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		return err
	}
	// Reuse an existing password from shared/.env or the local cache; otherwise generate.
	pw, err := d.resolvePassword(ctx, s, r)
	if err != nil {
		return err
	}
	d.redactor.Add(pw) // mask in all output
	// Persist FIRST (atomic), so a crash before EnsureUser still leaves a recoverable secret.
	if err := d.seedSharedEnv(ctx, s, r, pw); err != nil {
		return err
	}
	if err := eng.EnsureDatabase(ctx, r, s.Database.Name); err != nil {
		return err
	}
	return eng.EnsureUser(ctx, r, s.Database.User, pw, s.Database.Name)
}
```

> Implementer note: `resolvePassword` reads `DB_PASSWORD` from the server's `shared/.env` (via `Run("grep ...")`) or the local cache; only `secret.Generate(32)` when none exists — re-runs must not rotate. `seedSharedEnv` renders `secret.EnvFile` and writes `{deploy_path}/shared/.env` (owner `deploy`, mode 600) and calls `secret.SaveCache`.

- [ ] **Step 3: `site.go` (`site`, Requires `php`, `nginx`, `appdirs`, `database`)** — render + write the HTTP server block, validate, reload; write the FPM pool; install the dormant Supervisor program; install the guarded cron:

  Apply (essence): `WriteFile(nginx_http.conf → /etc/nginx/sites-available/{domain})`; symlink into `sites-enabled`; `nginx -t` (fail → abort); `systemctl reload nginx`; `WriteFile(fpm_pool)`; `WriteFile(supervisor.conf)` with `autostart=false`; `WriteFile(scheduler.cron → /etc/cron.d/berth-{app})`. Check inspects the `# managed by berth` marker + content hash of each file and `nginx -t`.

- [ ] **Step 4: `tls.go` (`tls`, Requires `site`, only when site `SSL` and not `--skip-ssl`)** — DNS preflight, certbot, 443 block:

  Check: a valid cert exists for the domain (`certbot certificates` parse) and is not near expiry. Apply: resolve the domain's A record and compare to `s.Host` (skip with a logged warning on mismatch unless overridden); `apt-get install -y certbot`; `certbot certonly --webroot -w /var/www/berth-acme/{domain} -d {domain} --agree-tos -m {ssl_email} --non-interactive [--staging]`; render+write `nginx_https.conf`; `nginx -t`; reload; ensure the renew systemd timer is enabled.

- [ ] **Step 5: Tests** — each step gets a `FakeRunner` test asserting its key commands/idempotency (e.g. `site` asserts `nginx -t` runs before reload and aborts on its failure; `tls` asserts `--webroot` path and that a present valid cert short-circuits).

- [ ] **Step 6: Commit**

```bash
git add internal/provision/steps/appdirs.go internal/provision/steps/database.go internal/provision/steps/site.go internal/provision/steps/tls.go internal/provision/steps/*_test.go
git commit -m "Add appdirs, database, site, and TLS steps"
```

---

## Task 10: Pipeline registry & provision wiring

**Files:**
- Create: `internal/provision/steps/registry.go`
- Modify: `cmd/provision.go` (connect + live runner)
- Test: `internal/provision/steps/registry_test.go`

- [ ] **Step 1: Write `internal/provision/steps/registry.go`**

```go
package steps

import (
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
)

// Pipeline returns the ordered steps for a server, honoring toggles and flags.
func Pipeline(s *config.Server, red *secret.Redactor, skipSSL bool) []provision.Step {
	steps := []provision.Step{
		Preflight(), SystemBase(), Accounts(), Hardening(),
		PHP(), Nginx(), Composer(),
	}
	if s.Valkey {
		steps = append(steps, Valkey())
	}
	if s.Queue {
		steps = append(steps, Supervisor())
	}
	steps = append(steps, AppDirs(), Database(red))
	steps = append(steps, Site())
	if !skipSSL && anySiteSSL(s) {
		steps = append(steps, TLS())
	}
	return steps
}
```

- [ ] **Step 2: Test the registry honors toggles & ordering**

```go
func TestPipelineHonorsToggles(t *testing.T) {
	s := &config.Server{Valkey: false, Queue: false, Sites: []config.Site{{}}}
	names := stepNames(steps.Pipeline(s, secret.NewRedactor(), true))
	if contains(names, "valkey") || contains(names, "supervisor") || contains(names, "tls") {
		t.Errorf("disabled steps present: %v", names)
	}
	if indexOf(names, "appdirs") > indexOf(names, "database") {
		t.Error("appdirs must come before database (secrets need shared/ first)")
	}
}
```

- [ ] **Step 3: Replace `cmd/provision.go` wiring**

```go
func runProvision(cmd *cobra.Command, serverPath string, f *provisionFlags) error {
	srv, err := config.Load(serverPath)
	if err != nil {
		return err
	}
	red := secret.NewRedactor()
	client, err := bssh.Connect(cmd.Context(), srv, bssh.HostKeyPolicy{
		Pinned: srv.SSH.Fingerprint, KnownHosts: defaultKnownHosts(),
		AllowTOFU: ui.IsTTY(os.Stdin), ConfirmTOFU: confirmFingerprint(cmd),
	})
	if err != nil {
		return err
	}
	defer client.Close()

	eng := provision.New(steps.Pipeline(srv, red, f.skipSSL)...)
	events, err := eng.Run(cmd.Context(), srv, client, provision.Options{
		DryRun: f.dryRun, Only: f.only, Force: f.force, SSLStaging: f.sslStaging,
	})
	if err != nil {
		return err
	}
	var r ui.Renderer = ui.NewPlainRenderer(cmd.OutOrStdout()) // Plan 3 swaps in bubbletea on a TTY
	return r.Render(events)
}
```

> Implementer note: `defaultKnownHosts()` returns `~/.ssh/known_hosts`; `confirmFingerprint` prints the fingerprint and reads y/N from stdin. Plan 3 replaces the renderer selection with TTY-aware bubbletea/plain.

- [ ] **Step 4: Run the whole suite**

Run: `go test ./...`
Expected: PASS. `go build ./...` succeeds.

- [ ] **Step 5: Commit**

```bash
git add internal/provision/steps/registry.go internal/provision/steps/registry_test.go cmd/provision.go
git commit -m "Assemble provisioning pipeline and wire provision to the live runner"
```

---

## Task 11: Integration smoke test (release gate)

**Files:**
- Create: `test/integration/provision_test.go` (build tag `integration`)
- Create: `test/integration/README.md` (how to run against Debian 13)

- [ ] **Step 1: Write the integration test (tagged, opt-in)**

```go
//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	// berth packages
)

// TestProvisionFreshDebian13 provisions a throwaway host described by
// BERTH_TEST_SERVER (a servers/*.yml) and asserts the end state.
func TestProvisionFreshDebian13(t *testing.T) {
	cfgPath := os.Getenv("BERTH_TEST_SERVER")
	if cfgPath == "" {
		t.Skip("set BERTH_TEST_SERVER to a Debian 13 target to run")
	}
	// Load config, connect, run the full pipeline, then assert:
	//  - `systemctl is-active nginx php{ver}-fpm mariadb valkey-server` all "active"
	//  - `nginx -t` exits 0
	//  - `mysql --protocol=socket -e 'SELECT 1'` exits 0
	//  - HTTP GET / returns a response (502 is acceptable pre-deploy: no app yet)
	_ = ctxTODO()
}
```

> Implementer note: this runs against a real systemd Debian 13 (an LXD/Incus container or an ephemeral cloud VPS), not a plain Docker container (systemd, ufw, sshd needed). Document both setups in the README. The TLS phase requires real DNS, so the smoke test runs with `--skip-ssl` (TLS is exercised separately/manually).

- [ ] **Step 2: Commit**

```bash
git add test/integration
git commit -m "Add integration smoke test scaffold (build-tagged) for Debian 13"
```

---

## Self-Review

- **Spec coverage:** Connection model + host-key verification + auto-detect (Tasks 1–3, §6.1); atomic WriteFile (Task 2, §5/§6); two accounts + sudoers + deploy key (Task 7 accounts, §6.3); ufw allow-before-enable + anti-lockout gate (Task 7 hardening, §6.2); php.source/Surý (Task 8 php, §4); nginx/valkey/supervisor/composer (Task 8, §4); appdirs-before-secrets (Task 9, §6.4 fix); MariaDB engine via stdin + idempotent (Task 5, §5); secret persist + redaction + cache (Tasks 5–6, 9, §7); site (nginx+fpm+dormant supervisor+guarded cron) (Task 9, §6.4); TLS via dedicated ACME webroot (Task 9, §4/§6.4); `--only` dependency wiring via `Requires` (registry); integration release gate (Task 11, §9). ✔
- **Placeholder scan:** The catalog steps in Tasks 7–9 specify exact commands and `Check`/`Apply` behavior, with one fully-coded exemplar per group (preflight, php, database, registry) — not "same as Task N". Items explicitly deferred to Plan 3 (bubbletea renderer swap, ldflags, GoReleaser, CI) are called out. The `newKeyPairForTest`/`ctxTODO` sketches carry explicit implementer notes to replace them.
- **Type consistency:** `provision.Step`/`CheckResult`/`Engine.Run` and `ssh.Runner`/`Result`/`FileSpec` are used exactly as defined in Plan 1. `database.Engine` matches the spec signature used by the `database` step. `secret.Redactor` (Plan 1) gains `EnvFile`/cache (Task 6) — no signature changes.
- **Scope:** Each task ends green + committed; after Task 10 `berth provision <server>` is fully functional against a real host; Task 11 adds the release-gate smoke test. Produces working software.

---

## Execution Handoff

Plan 2 of 3. Plan 3 (huh wizard, bubbletea renderer, GoReleaser + release workflow, ldflags) follows. After all three plans are approved, the project gets its single clean initial commit.

package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/hostlock"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/provision/steps"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/ui"
	"github.com/spf13/cobra"
)

func writeValidConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "srv.yml")
	cfg := `id: test-machine-0001
requires_berth: v0.37.0
host: 203.0.113.10
ssh: {user: root, port: 22}
php: {version: "8.5", source: auto}
database: {engine: mariadb}
valkey: true
sites:
  - {domain: app.example.com, deploy_path: /var/www/app, database: {name: myapp, user: myapp}}
`
	if err := os.WriteFile(p, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestProvisionLoadsConfigAndAssemblesPipeline verifies the offline portion of
// `berth provision`: config load + pipeline assembly. The live ssh dial in
// runProvision can no longer run without a reachable host, so this asserts the
// pre-dial wiring directly rather than executing the cobra command.
func TestProvisionLoadsConfigAndAssemblesPipeline(t *testing.T) {
	cfgPath := writeValidConfig(t)
	srv, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load error = %v", err)
	}
	pipeline := steps.Pipeline(srv, secret.NewRedactor(), false)
	if len(pipeline) == 0 {
		t.Fatal("expected a non-empty pipeline")
	}
	// The sample config enables valkey, so the valkey step must be present.
	var hasValkey bool
	for _, s := range pipeline {
		if s.Name() == "valkey" {
			hasValkey = true
		}
	}
	if !hasValkey {
		t.Error("expected valkey step for a config with valkey: true")
	}
}

func TestProvisionHasAllowDowngradeFlag(t *testing.T) {
	fl := newProvisionCmd().Flags().Lookup("allow-downgrade")
	if fl == nil || fl.DefValue != "false" || !strings.Contains(fl.Usage, "--force does not imply") {
		t.Fatalf("allow-downgrade flag = %+v", fl)
	}
}

func TestProvisionRejectsInvalidConfigPath(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"provision", "/no/such/file.yml"})
	if err := root.Execute(); err == nil {
		t.Error("expected error for missing config file")
	}
}

func TestWantTUIDisabledForDryRunVerboseNoTTY(t *testing.T) {
	cases := []struct {
		name string
		tty  bool
		f    provisionFlags
		want bool
	}{
		{"tty plain run", true, provisionFlags{}, true},
		{"not a tty", false, provisionFlags{}, false},
		{"dry-run forces plain", true, provisionFlags{dryRun: true}, false},
		{"verbose forces plain", true, provisionFlags{verbose: true}, false},
		{"no-tty forces plain", true, provisionFlags{noTTY: true}, false},
		{"dry-run without tty stays plain", false, provisionFlags{dryRun: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wantTUI(tc.tty, &tc.f); got != tc.want {
				t.Errorf("wantTUI(%v, %+v) = %v, want %v", tc.tty, tc.f, got, tc.want)
			}
		})
	}
}

func TestConfirmFingerprintPromptNamesKeyType(t *testing.T) {
	// The printed fingerprint is what the operator pins as ssh.fingerprint;
	// the key type disambiguates it from ssh-keyscan's other output lines.
	prompt := func(answer string) (bool, string) {
		c := &cobra.Command{}
		var out bytes.Buffer
		c.SetOut(&out)
		c.SetIn(strings.NewReader(answer))
		ok := confirmFingerprint(c)("host:22", "SHA256:abc", "ecdsa-sha2-nistp256")
		return ok, out.String()
	}
	ok, out := prompt("y\n")
	if !ok {
		t.Fatal("expected y to confirm")
	}
	for _, want := range []string{"SHA256:abc", "ecdsa-sha2-nistp256"} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt missing %q; got:\n%s", want, out)
		}
	}
	if ok, _ := prompt("n\n"); ok {
		t.Error("expected n to refuse")
	}
}

func TestSessionModeForFlags(t *testing.T) {
	cases := []struct {
		name    string
		f       provisionFlags
		mode    hostlock.Mode
		command string
	}{
		{"plain run", provisionFlags{}, hostlock.Mutating, "provision"},
		{"dry-run", provisionFlags{dryRun: true}, hostlock.ReadOnly, "provision --dry-run"},
		{"only", provisionFlags{only: "site"}, hostlock.Mutating, "provision --only site"},
		{"dry-run only", provisionFlags{dryRun: true, only: "site"}, hostlock.ReadOnly, "provision --dry-run --only site"},
		// No flag bypasses or weakens the lock.
		{"force", provisionFlags{force: true}, hostlock.Mutating, "provision"},
		{"allow-downgrade", provisionFlags{allowDowngrade: true}, hostlock.Mutating, "provision"},
		{"skip-ssl", provisionFlags{skipSSL: true}, hostlock.Mutating, "provision"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, command := sessionMode(&tc.f)
			if mode != tc.mode || command != tc.command {
				t.Errorf("sessionMode(%+v) = (%v, %q), want (%v, %q)", tc.f, mode, command, tc.mode, tc.command)
			}
		})
	}
}

// The lock script's opening words per mode (hostlock.Script): only a run that
// changes the host prepares the lock file; a read-only one creates nothing.
const (
	mutatingScriptPrefix = "install -d -o root -g root -m 0755 /var/lib/berth"
	readOnlyScriptPrefix = "if [ ! -e /var/lib/berth/session.lock ]"
)

// testHolder answers every Hold by behaviour, whatever the command: hostlock's
// holder-line seams are unexported, so the exact script cannot be keyed from
// here. It records each held command for the mode assertions.
type testHolder struct {
	mu    sync.Mutex
	cmds  []string
	lease bssh.Lease // returned when non-nil
	exit  *bssh.HoldExitError
	// runner is inspected at Hold time: the lock must come before the
	// pipeline's first remote command.
	runner      *bssh.FakeRunner
	callsAtHold int
}

func (h *testHolder) Hold(_ context.Context, cmd, _ string) (bssh.Lease, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cmds = append(h.cmds, cmd)
	if h.runner != nil {
		h.callsAtHold = len(h.runner.Calls())
	}
	if h.lease != nil {
		return h.lease, nil
	}
	return nil, h.exit
}

func (h *testHolder) held() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.cmds...)
}

// fakeProvisionConn is a provisionConn without a host: commands go to the
// FakeRunner, the session lock to the testHolder.
type fakeProvisionConn struct {
	*bssh.FakeRunner
	*testHolder
	closed bool
}

func (c *fakeProvisionConn) Close() error { c.closed = true; return nil }

// stubProvisionConn makes `berth provision` drive conn instead of dialing,
// and points the local secret cache at a temp HOME so a run that reaches the
// identity step never touches the real ~/.berth.
func stubProvisionConn(t *testing.T, conn provisionConn) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows os.UserHomeDir
	orig := connectProvision
	t.Cleanup(func() { connectProvision = orig })
	connectProvision = func(context.Context, *config.Server, bssh.HostKeyPolicy) (provisionConn, error) {
		return conn, nil
	}
}

// runProvisionCmd executes `berth provision <cfg> --no-tty <extra...>`; the
// rendered output is discarded.
func runProvisionCmd(cfg string, extra ...string) error {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"provision", cfg, "--no-tty"}, extra...))
	return root.Execute()
}

func TestProvisionStopsWhenHostIsBusy(t *testing.T) {
	const holder = "berth v1.0.0 provision by ops@ws (pid 9) since 2026-11-02T09:00:00Z"
	cases := []struct {
		name   string
		flags  []string
		prefix string
	}{
		{"plain run", nil, mutatingScriptPrefix},
		{"force", []string{"--force"}, mutatingScriptPrefix},
		{"only", []string{"--only", "site"}, mutatingScriptPrefix},
		{"allow-downgrade", []string{"--allow-downgrade"}, mutatingScriptPrefix},
		{"dry-run", []string{"--dry-run"}, readOnlyScriptPrefix},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &fakeProvisionConn{
				FakeRunner: bssh.NewFakeRunner(),
				testHolder: &testHolder{exit: &bssh.HoldExitError{Code: 75, Stdout: holder + "\n"}},
			}
			stubProvisionConn(t, conn)
			err := runProvisionCmd(writeValidConfig(t), tc.flags...)
			if err == nil || !strings.HasPrefix(err.Error(), "host is busy:") {
				t.Fatalf("error = %v, want one starting with %q", err, "host is busy:")
			}
			var busy *hostlock.BusyError
			if !errors.As(err, &busy) || busy.Holder != holder {
				t.Errorf("error = %#v, want a *hostlock.BusyError naming %q", err, holder)
			}
			if calls := conn.Calls(); len(calls) != 0 {
				t.Errorf("a busy host ran %d pipeline command(s), want 0: %v", len(calls), calls)
			}
			if w := conn.Writes(); len(w) != 0 {
				t.Errorf("a busy host got %d file write(s), want 0", len(w))
			}
			held := conn.held()
			if len(held) != 1 || !strings.HasPrefix(held[0], tc.prefix) {
				t.Errorf("held commands = %q, want exactly one starting with %q", held, tc.prefix)
			}
			if !conn.closed {
				t.Error("the connection was not closed")
			}
		})
	}
}

// The pipeline runs only under the lock: the lock is held before the first
// remote command, and released when the run ends.
func TestProvisionRunsThePipelineUnderTheLock(t *testing.T) {
	runner := bssh.NewFakeRunner()
	lease := bssh.NewFakeLease()
	conn := &fakeProvisionConn{FakeRunner: runner, testHolder: &testHolder{lease: lease, runner: runner}}
	stubProvisionConn(t, conn)
	// No command is stubbed: preflight's first probe fails, which ends the run.
	err := runProvisionCmd(writeValidConfig(t))
	if err == nil {
		t.Fatal("expected the run to fail on the unstubbed preflight probe")
	}
	var busy *hostlock.BusyError
	if errors.As(err, &busy) || errors.Is(err, hostlock.ErrLost) {
		t.Fatalf("error = %v, want the pipeline's own failure", err)
	}
	if held := conn.held(); len(held) != 1 || !strings.HasPrefix(held[0], mutatingScriptPrefix) {
		t.Fatalf("held commands = %q, want exactly one Mutating lock", held)
	}
	if conn.callsAtHold != 0 {
		t.Errorf("%d remote command(s) ran before the lock was taken, want 0", conn.callsAtHold)
	}
	if len(runner.Calls()) == 0 {
		t.Error("the pipeline sent no remote command under the lock")
	}
	if !lease.Released() {
		t.Error("the lock was not released when the run ended")
	}
}

// A lock that ends while the run is still going stops the run with ErrLost,
// whatever the pipeline reported about its interrupted step.
func TestProvisionReportsLostLock(t *testing.T) {
	lease := bssh.NewFakeLease()
	lease.End() // the held command is already gone: the lease expired
	conn := &fakeProvisionConn{FakeRunner: bssh.NewFakeRunner(), testHolder: &testHolder{lease: lease}}
	stubProvisionConn(t, conn)
	err := runProvisionCmd(writeValidConfig(t))
	if !errors.Is(err, hostlock.ErrLost) {
		t.Fatalf("error = %v, want hostlock.ErrLost", err)
	}
}

// interruptConn is a provisionConn whose first remote command stays in flight
// until the run's context is cancelled, then ends the held lock command and
// returns the context's error — what the ssh layer does when its cancel path
// closes the whole connection.
type interruptConn struct {
	*fakeProvisionConn
	lease    *bssh.FakeLease
	inFlight chan struct{}
	once     sync.Once
	t        *testing.T
}

func (c *interruptConn) Run(ctx context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	first := false
	c.once.Do(func() { first = true })
	if !first {
		return c.fakeProvisionConn.Run(ctx, cmd, stdin)
	}
	close(c.inFlight)
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		c.t.Error("the run's context was never cancelled after the renderer stopped")
	}
	c.lease.End() // the cancel path closed the connection, and the held command with it
	return bssh.Result{}, ctx.Err()
}

// An operator interrupt (the TUI's ctrl+c: the renderer returns before the
// engine finished) is a shutdown, never a lost lock — even though the
// connection teardown it causes also ends the held lock command.
func TestProvisionInterruptIsNotALostLock(t *testing.T) {
	lease := bssh.NewFakeLease()
	conn := &interruptConn{
		fakeProvisionConn: &fakeProvisionConn{FakeRunner: bssh.NewFakeRunner(), testHolder: &testHolder{lease: lease}},
		lease:             lease,
		inFlight:          make(chan struct{}),
		t:                 t,
	}
	stubProvisionConn(t, conn)
	orig := renderRun
	t.Cleanup(func() { renderRun = orig })
	renderRun = func(_ *cobra.Command, _ *provisionFlags, _ <-chan provision.Event) error {
		select {
		case <-conn.inFlight: // interrupted while a remote command runs
		case <-time.After(5 * time.Second):
			t.Error("the pipeline never sent a remote command")
		}
		return ui.ErrInterrupted
	}

	err := runProvisionCmd(writeValidConfig(t))

	if !errors.Is(err, ui.ErrInterrupted) || errors.Is(err, hostlock.ErrLost) {
		t.Fatalf("error = %v, want ui.ErrInterrupted and not hostlock.ErrLost", err)
	}
	if !lease.Released() {
		t.Error("the lock was not released after the interrupt")
	}
}

func TestEngineStopped(t *testing.T) {
	closed := make(chan provision.Event)
	close(closed)
	if !engineStopped(closed) {
		t.Error("closed channel: engineStopped = false, want true")
	}
	if engineStopped(make(chan provision.Event)) {
		t.Error("open empty channel: engineStopped = true, want false")
	}
	pending := make(chan provision.Event, 1)
	pending <- provision.Event{}
	if engineStopped(pending) {
		t.Error("open channel with a pending event: engineStopped = true, want false")
	}
}

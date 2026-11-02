package status

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/hostlock"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// stubHost stubs every command a full collection issues for srv.
func stubHost(s *config.Server) *bssh.FakeRunner {
	f := bssh.NewFakeRunner()
	f.On(hostMetaCmd, bssh.Result{Stdout: "1785060000\n+0000\n---\n" +
		"# managed by berth\nVERSION=0.27.1\nPROVISIONED_AT=2026-07-21T09:14:02Z\n---\n" +
		"Filesystem 1B-blocks Used Available Capacity Mounted on\n" +
		"/dev/vda1 41000000000 16000000000 22000000000 41% /\n"})
	// The services answer is derived from the requested unit list so it is
	// COMPLETE for whatever server this fixture stubs: probeServices now
	// flags an answer missing requested units, and a truncated fixture would
	// plant that probe error in every test built on this stub.
	var rows strings.Builder
	for _, u := range unitList(s) {
		rows.WriteString(u + "\tactive\tenabled\n")
	}
	f.On(servicesCmd(unitList(s)), bssh.Result{Stdout: rows.String()})
	f.On(certsCmd([]string{"/etc/letsencrypt/live/app.example.com/fullchain.pem"}), bssh.Result{
		Stdout: "/etc/letsencrypt/live/app.example.com/fullchain.pem\tnotAfter=Sep 28 07:31:00 2026 GMT\n"})
	f.On(backupsCmd([]string{"/var/backups/berth/app_example_com"}), bssh.Result{
		Stdout: "/var/backups/berth/app_example_com\t7\t418000000\t1785060000.0\n"})
	return f
}

func collectSrv() *config.Server {
	return &config.Server{
		ID: "prod", Host: "203.0.113.10", SSH: config.SSH{Port: 22},
		PHP:      config.PHP{Version: "8.4"},
		Database: config.Database{Engine: "mariadb"},
		Backups:  config.Backups{Enabled: true, Schedule: "30 3 * * *"},
		Sites:    []config.Site{{Domain: "app.example.com", SSL: true}},
	}
}

func TestCollectHostAssemblesEveryFact(t *testing.T) {
	s := collectSrv()
	got := CollectHost(context.Background(), "servers/prod.yml", s, stubHost(s), nil, nil, false)

	if !got.Reachable || got.Error != "" {
		t.Fatalf("host = %+v, want reachable", got)
	}
	if got.ID != "prod" || got.ConfigPath != "servers/prod.yml" || got.Endpoint != "203.0.113.10:22" {
		t.Errorf("identity = %q %q %q", got.ID, got.ConfigPath, got.Endpoint)
	}
	if got.Provisioned == nil || got.Provisioned.Version != "0.27.1" {
		t.Errorf("manifest = %+v", got.Provisioned)
	}
	if len(got.Sites) != 1 || !got.Sites[0].Cert.Present || got.Sites[0].Backup.Count != 7 {
		t.Errorf("sites = %+v", got.Sites)
	}
	if got.Drift != nil {
		t.Error("no pipeline was passed, so no drift report may be produced")
	}
	if got.HostTime.IsZero() {
		t.Error("HostTime must be populated — every age is computed against it")
	}
}

// The load-bearing guarantee of the whole feature.
func TestCollectHostWritesNothing(t *testing.T) {
	s := collectSrv()
	f := stubHost(s)
	applied := false
	pipeline := []provision.Step{
		&fakeStep{name: "site", satisfied: false, changes: []string{"rewrite vhost"}, applied: &applied},
	}
	got := CollectHost(context.Background(), "servers/prod.yml", s, f, pipeline, nil, false)

	if len(f.Writes()) != 0 {
		t.Errorf("status wrote %d files; it must write none", len(f.Writes()))
	}
	if applied {
		t.Error("status reached a step's Apply")
	}
	if got.Drift == nil || got.Drift.Drifted != 1 {
		t.Errorf("drift = %+v, want 1 drifted step", got.Drift)
	}
}

// Config-derived facts must survive a failed probe: backup.enabled:false and
// cert.mode:"" are ANSWERS ("off", "no TLS"), not "unknown", and the config
// declares otherwise regardless of what the host answered. Degrading them
// made a declared-TLS site read as plain HTTP and a backed-up site as
// unprotected whenever a probe failed.
func TestCollectHostKeepsConfigFactsWhenProbesFail(t *testing.T) {
	s := collectSrv()
	f := stubHost(s)
	// Re-stub the cert and backup probes to fail; On overwrites by exact
	// command string.
	denied := bssh.Result{ExitCode: 1, Stderr: "sudo: a password is required\n"}
	f.On(certsCmd([]string{"/etc/letsencrypt/live/app.example.com/fullchain.pem"}), denied)
	f.On(backupsCmd([]string{"/var/backups/berth/app_example_com"}), denied)

	got := CollectHost(context.Background(), "servers/prod.yml", s, f, nil, nil, false)
	if !got.Reachable {
		t.Fatalf("host = %+v, want reachable", got)
	}
	if len(got.ProbeErrors) != 2 {
		t.Fatalf("ProbeErrors = %v, want the cert and backup failures recorded", got.ProbeErrors)
	}
	if len(got.Sites) != 1 {
		t.Fatalf("sites = %+v, want 1", got.Sites)
	}
	site := got.Sites[0]
	if site.Cert.Mode != "letsencrypt" {
		t.Errorf("Cert.Mode = %q, want the configured mode to survive the failed probe", site.Cert.Mode)
	}
	if site.Cert.Present || site.Cert.DaysLeft != nil {
		t.Errorf("cert facts the probe never delivered must stay unknown: %+v", site.Cert)
	}
	if !site.Backup.Enabled || site.Backup.Dir != "/var/backups/berth/app_example_com" {
		t.Errorf("Backup = %+v, want the configured enabled+dir to survive the failed probe", site.Backup)
	}
	if site.Backup.Newest != nil || site.Backup.Count != 0 {
		t.Errorf("backup facts the probe never delivered must stay unknown: %+v", site.Backup)
	}
}

// df can fail for one operand (a broken /var mount) while printing a valid
// row for the other. The parsed rows must be kept — they are real data — but
// the host was NOT fully probed, and the failure must reach ProbeErrors and
// with it the exit code, instead of rendering a reassuring root percentage.
func TestCollectHostPartialHostMetaFailureIsRecorded(t *testing.T) {
	s := collectSrv()
	f := stubHost(s)
	f.On(hostMetaCmd, bssh.Result{ExitCode: 1, Stdout: "1785060000\n+0000\n---\n" +
		"# managed by berth\nVERSION=0.27.1\nPROVISIONED_AT=2026-07-21T09:14:02Z\n---\n" +
		"Filesystem 1B-blocks Used Available Capacity Mounted on\n" +
		"/dev/vda1 41000000000 16000000000 22000000000 41% /\n"})

	got := CollectHost(context.Background(), "servers/prod.yml", s, f, nil, nil, false)
	if !got.Reachable {
		t.Fatalf("host = %+v, want reachable — a partial df is not a dead host", got)
	}
	if len(got.Disk) != 1 || got.Disk[0].Path != "/" {
		t.Errorf("disk = %+v, want the successfully parsed row kept", got.Disk)
	}
	var found bool
	for _, pe := range got.ProbeErrors {
		if strings.Contains(pe, "host") {
			found = true
		}
	}
	if !found {
		t.Errorf("ProbeErrors = %v, want the df failure recorded", got.ProbeErrors)
	}
}

// systemctl answering for only SOME of the requested units (at exit 0) is an
// incomplete answer, not a smaller server: every requested unit must still
// appear (an unanswered unit reads as down), and the truncation must reach
// ProbeErrors — otherwise the table says "1 ok" for a seven-unit server.
func TestCollectHostReportsTruncatedServicesAnswer(t *testing.T) {
	s := collectSrv()
	f := stubHost(s)
	f.On(servicesCmd(unitList(s)), bssh.Result{Stdout: "nginx\tactive\tenabled\n"})

	got := CollectHost(context.Background(), "servers/prod.yml", s, f, nil, nil, false)
	if want := len(unitList(s)); len(got.Services) != want {
		t.Errorf("services = %d entries, want all %d requested units", len(got.Services), want)
	}
	var found bool
	for _, pe := range got.ProbeErrors {
		if strings.Contains(pe, "services") {
			found = true
		}
	}
	if !found {
		t.Errorf("ProbeErrors = %v, want the truncated services answer recorded", got.ProbeErrors)
	}
}

func TestCollectHostSurfacesAProbeFailure(t *testing.T) {
	s := collectSrv()
	f := bssh.NewFakeRunner() // nothing stubbed: the first probe errors
	got := CollectHost(context.Background(), "servers/prod.yml", s, f, nil, nil, false)
	if got.Reachable || got.Error == "" {
		t.Errorf("host = %+v, want unreachable with a reason", got)
	}
	if got.ProbedAt.IsZero() {
		t.Error("ProbedAt must be set even on a failed collection")
	}
}

func TestCollectIsolatesAFailedHost(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yml")
	bad := filepath.Join(dir, "bad.yml")
	body := "id: %s\nrequires_berth: v0.37.0\nhost: 203.0.113.10\nssh:\n  user: berth\n  port: 22\n  key: ~/.ssh/id_ed25519\nphp:\n  version: \"8.4\"\ndatabase:\n  engine: mariadb\nsites:\n  - domain: app.example.com\n    deploy_path: /var/www/app\n    database:\n      name: app\n      user: app\n"
	if err := os.WriteFile(good, []byte(fmt.Sprintf(body, "good")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte(fmt.Sprintf(body, "bad")), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := dial
	t.Cleanup(func() { dial = orig })
	dial = func(_ context.Context, s *config.Server, _ string) (bssh.Conn, func() error, error) {
		if s.ID == "bad" {
			return nil, nil, errors.New("dial tcp: no route to host")
		}
		return &lockConn{FakeRunner: stubHost(s), lock: &answerLock{}}, func() error { return nil }, nil
	}

	got := Collect(context.Background(), []string{good, bad}, Options{Parallel: 2})

	if len(got) != 2 {
		t.Fatalf("got %d hosts, want 2", len(got))
	}
	// Order follows the input, not completion order, so the table is stable.
	if got[0].ID != "good" || got[1].ID != "bad" {
		t.Errorf("order = %q,%q, want good,bad", got[0].ID, got[1].ID)
	}
	if !got[0].Reachable {
		t.Errorf("the healthy host must still be reported: %+v", got[0])
	}
	if got[1].Reachable || got[1].Error == "" {
		t.Errorf("the dead host = %+v, want unreachable with a reason", got[1])
	}
}

func TestCollectReportsAnUnloadableConfig(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.yml")
	if err := os.WriteFile(broken, []byte("this: [is not: valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Collect(context.Background(), []string{broken}, Options{})
	if len(got) != 1 || got[0].Reachable || got[0].Error == "" {
		t.Fatalf("got %+v, want one entry with an error", got)
	}
	if got[0].ConfigPath != broken {
		t.Errorf("ConfigPath = %q, want %q", got[0].ConfigPath, broken)
	}
}

// Pins the per-host budget resolution: an explicit Timeout wins, then the
// drift default, then the cheap-probe default. (Also keeps Options.timeout
// referenced before Task 11 calls it — the unused linter is a hard gate.)
func TestOptionsTimeoutResolution(t *testing.T) {
	if got := (Options{}).timeout(); got != defaultProbeTimeout {
		t.Errorf("timeout() = %v, want %v", got, defaultProbeTimeout)
	}
	if got := (Options{Drift: true}).timeout(); got != defaultDriftTimeout {
		t.Errorf("drift timeout() = %v, want %v", got, defaultDriftTimeout)
	}
	if got := (Options{Drift: true, Timeout: 3 * time.Second}).timeout(); got != 3*time.Second {
		t.Errorf("explicit timeout() = %v, want 3s", got)
	}
}

// lockConn is what a stubbed dial returns: commands go to the embedded
// FakeRunner, holds to lock. gate, when set, runs before every command — the
// tests use it to keep a scan inside its lock for a while.
type lockConn struct {
	*bssh.FakeRunner
	lock bssh.Holder
	gate func(ctx context.Context, cmd string)
}

func (c *lockConn) Hold(ctx context.Context, cmd, ready string) (bssh.Lease, error) {
	return c.lock.Hold(ctx, cmd, ready)
}

func (c *lockConn) Run(ctx context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	if c.gate != nil {
		c.gate(ctx, cmd)
	}
	return c.FakeRunner.Run(ctx, cmd, stdin)
}

// answerLock is a TEST-LOCAL Holder that gives every hold the same answer and
// records the scripts it was asked to hold. It answers by behaviour and
// ignores the script itself: hostlock's holder line carries a pid and a
// timestamp, so a FakeHolder keyed by the exact command cannot be stubbed
// from here. A nil answer fails the hold.
type answerLock struct {
	mu     sync.Mutex
	cmds   []string
	answer func() (bssh.Lease, error)
}

func (l *answerLock) Hold(_ context.Context, cmd, _ string) (bssh.Lease, error) {
	l.mu.Lock()
	l.cmds = append(l.cmds, cmd)
	l.mu.Unlock()
	if l.answer == nil {
		return nil, errors.New("answerLock: unexpected hold")
	}
	return l.answer()
}

func (l *answerLock) calls() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.cmds...)
}

// stubDial makes every dial in the test return conn(s) and a no-op close.
func stubDial(t *testing.T, conn func(s *config.Server) bssh.Conn) {
	t.Helper()
	orig := dial
	t.Cleanup(func() { dial = orig })
	dial = func(_ context.Context, s *config.Server, _ string) (bssh.Conn, func() error, error) {
		return conn(s), func() error { return nil }, nil
	}
}

// isolateHome points the local secret cache at an empty directory: a drift
// scan runs the real pipeline, whose identity step reads ~/.berth.
func isolateHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows os.UserHomeDir
}

// writeCollectConfig writes a loadable config for host: one TLS site with
// backups on, so every probe stubHost answers has a fact to report.
func writeCollectConfig(t *testing.T, dir, id, host string) string {
	t.Helper()
	body := fmt.Sprintf("id: %s\nrequires_berth: v0.37.0\nhost: %s\nssh:\n  user: berth\n  port: 22\n  key: ~/.ssh/id_ed25519\n"+
		"php:\n  version: \"8.4\"\ndatabase:\n  engine: mariadb\nbackups:\n  enabled: true\n"+
		"sites:\n  - domain: app.example.com\n    deploy_path: /var/www/app\n    ssl: true\n    ssl_email: ops@example.com\n"+
		"    database:\n      name: app\n      user: app\n", id, host)
	p := filepath.Join(dir, id+".yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A drift scan holds the lock ReadOnly (it never creates the lock file) and
// names itself `status --drift` in the holder line.
func assertReadOnlyDriftHold(t *testing.T, cmds []string) {
	t.Helper()
	if len(cmds) != 1 {
		t.Fatalf("holds = %d, want exactly 1", len(cmds))
	}
	if !strings.HasPrefix(cmds[0], "if [ ! -e "+hostlock.Path+" ]") {
		t.Errorf("hold script is not the ReadOnly one (it must never create the lock file):\n%s", cmds[0])
	}
	if !strings.Contains(cmds[0], " status --drift by ") {
		t.Errorf("holder line must name the command `status --drift`:\n%s", cmds[0])
	}
}

// assertProbesOnly checks that h carries every cheap-probe fact and that the
// host saw nothing but those probes: the drift scan never ran.
func assertProbesOnly(t *testing.T, h HostStatus, s *config.Server, r *bssh.FakeRunner) {
	t.Helper()
	if !h.Reachable || h.Error != "" {
		t.Fatalf("host = %+v, want reachable — the lock only gates the drift scan", h)
	}
	if len(h.ProbeErrors) != 0 {
		t.Errorf("ProbeErrors = %v, want none", h.ProbeErrors)
	}
	if h.Provisioned == nil || h.Provisioned.Version != "0.27.1" || len(h.Disk) != 1 {
		t.Errorf("host facts missing: manifest=%+v disk=%+v", h.Provisioned, h.Disk)
	}
	if len(h.Services) != len(unitList(s)) {
		t.Errorf("services = %d, want %d", len(h.Services), len(unitList(s)))
	}
	if len(h.Sites) != 1 || !h.Sites[0].Cert.Present || h.Sites[0].Backup.Count != 7 {
		t.Errorf("sites = %+v, want the probed cert and backups", h.Sites)
	}
	// The same four commands stubHost answers.
	probes := map[string]bool{
		hostMetaCmd:              true,
		servicesCmd(unitList(s)): true,
		certsCmd([]string{"/etc/letsencrypt/live/app.example.com/fullchain.pem"}): true,
		backupsCmd([]string{"/var/backups/berth/app_example_com"}):                true,
	}
	for _, c := range r.Calls() {
		if !probes[c.Cmd] {
			t.Errorf("a command beyond the cheap probes reached the host: %q", c.Cmd)
		}
	}
}

// Review focus: plain `status` never takes the host session lock. It compares
// nothing against the config, so it has nothing to protect, and it must keep
// answering while a provision holds the host.
func TestCollectWithoutDriftNeverTakesTheLock(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		writeCollectConfig(t, dir, "web1", "203.0.113.10"),
		writeCollectConfig(t, dir, "web2", "203.0.113.10"),
	}
	// Busy if asked — so a hold would also show up as a drift error.
	lock := &answerLock{answer: func() (bssh.Lease, error) { return nil, &bssh.HoldExitError{Code: 75} }}
	stubDial(t, func(s *config.Server) bssh.Conn { return &lockConn{FakeRunner: stubHost(s), lock: lock} })

	got := Collect(context.Background(), paths, Options{Parallel: 2})

	if n := len(lock.calls()); n != 0 {
		t.Errorf("Hold called %d times, want 0 — plain status must never take the lock", n)
	}
	for _, h := range got {
		if !h.Reachable || h.Drift != nil || len(h.ProbeErrors) != 0 {
			t.Errorf("host = %+v, want reachable, no drift report, no probe errors", h)
		}
	}
}

// A busy host is an INCOMPLETE scan, never a dead host: the cheap probes
// still run (outside the lock) and the drift report carries the busy message
// with no StoppedAt, which the views render as "scan did not run" and the
// exit code treats as "could not be fully probed".
func TestCollectDriftBusyReportsDriftErrorAndKeepsProbes(t *testing.T) {
	isolateHome(t)
	path := writeCollectConfig(t, t.TempDir(), "prod", "203.0.113.10")
	const holder = "berth 0.37.0 provision by ops@ws (pid 4711) since 2026-11-02T09:32:00Z"
	lock := &answerLock{answer: func() (bssh.Lease, error) {
		return nil, &bssh.HoldExitError{Code: 75, Stdout: holder + "\n"}
	}}
	var (
		srv *config.Server
		r   *bssh.FakeRunner
	)
	stubDial(t, func(s *config.Server) bssh.Conn {
		srv, r = s, stubHost(s)
		return &lockConn{FakeRunner: r, lock: lock}
	})

	got := Collect(context.Background(), []string{path}, Options{Drift: true})

	if len(got) != 1 {
		t.Fatalf("got %d hosts, want 1", len(got))
	}
	h := got[0]
	assertReadOnlyDriftHold(t, lock.calls())
	assertProbesOnly(t, h, srv, r)
	if h.Drift == nil {
		t.Fatal("Drift = nil, want a report carrying the busy message")
	}
	if !strings.HasPrefix(h.Drift.Error, "host is busy:") || !strings.Contains(h.Drift.Error, holder) {
		t.Errorf("Drift.Error = %q, want the busy message naming the holder", h.Drift.Error)
	}
	if h.Drift.StoppedAt != "" || len(h.Drift.Steps) != 0 || h.Drift.Drifted != 0 {
		t.Errorf("Drift = %+v, want a scan that never ran (no StoppedAt, no steps)", h.Drift)
	}
}

// Any other failure to take the lock is treated like busy: fail closed — no
// drift scan without the lock — but keep every cheap-probe fact.
func TestCollectDriftLockFailureKeepsProbes(t *testing.T) {
	isolateHome(t)
	path := writeCollectConfig(t, t.TempDir(), "prod", "203.0.113.10")
	lock := &answerLock{answer: func() (bssh.Lease, error) {
		return nil, errors.New("ssh: rejected: administratively prohibited")
	}}
	var (
		srv *config.Server
		r   *bssh.FakeRunner
	)
	stubDial(t, func(s *config.Server) bssh.Conn {
		srv, r = s, stubHost(s)
		return &lockConn{FakeRunner: r, lock: lock}
	})

	h := Collect(context.Background(), []string{path}, Options{Drift: true})[0]

	assertProbesOnly(t, h, srv, r)
	if h.Drift == nil || !strings.HasPrefix(h.Drift.Error, "host session lock:") || h.Drift.StoppedAt != "" {
		t.Errorf("Drift = %+v, want a scan that never ran, naming the lock failure", h.Drift)
	}
}

// No lock file (a fresh or pre-lock host): the ReadOnly hold answers
// "absent" and the scan runs without the lock — nothing is created.
func TestCollectDriftAbsentLockScansWithoutLock(t *testing.T) {
	isolateHome(t)
	path := writeCollectConfig(t, t.TempDir(), "prod", "203.0.113.10")
	lock := &answerLock{answer: func() (bssh.Lease, error) {
		return nil, &bssh.HoldExitError{Code: 0, Stdout: "absent\n"}
	}}
	var r *bssh.FakeRunner
	stubDial(t, func(s *config.Server) bssh.Conn {
		r = stubHost(s)
		return &lockConn{FakeRunner: r, lock: lock}
	})

	h := Collect(context.Background(), []string{path}, Options{Drift: true})[0]

	assertReadOnlyDriftHold(t, lock.calls())
	if !h.Reachable {
		t.Fatalf("host = %+v, want reachable", h)
	}
	if h.Drift == nil {
		t.Fatal("Drift = nil, want the scan to have run")
	}
	if strings.HasPrefix(h.Drift.Error, "host is busy") || strings.HasPrefix(h.Drift.Error, "host session lock") {
		t.Errorf("Drift.Error = %q, want no lock failure on a host without the lock file", h.Drift.Error)
	}
	// stubHost answers no pipeline command, so the scan stops at the first
	// step that asks the host something — proof that it ran.
	if h.Drift.StoppedAt == "" && len(h.Drift.Steps) == 0 {
		t.Errorf("Drift = %+v, want a scan that reached the pipeline", h.Drift)
	}
	if n := len(r.Calls()); n <= 4 {
		t.Errorf("host saw %d commands, want the four probes plus the scan's", n)
	}
	if len(r.Writes()) != 0 {
		t.Errorf("a scan without the lock wrote %d files; it must write none", len(r.Writes()))
	}
}

// A lock lost mid-scan means another session may have changed the host while
// it was being compared: the scan's verdicts are discarded, never reported as
// a (possibly mixed) drift answer, and the probe facts are collected afresh.
func TestCollectDriftLostLockDiscardsTheScan(t *testing.T) {
	isolateHome(t)
	path := writeCollectConfig(t, t.TempDir(), "prod", "203.0.113.10")
	lease := bssh.NewFakeLease()
	lock := &answerLock{answer: func() (bssh.Lease, error) { return lease, nil }}
	var once sync.Once
	stubDial(t, func(s *config.Server) bssh.Conn {
		// The held command ends on its own while the scan runs (lease
		// expired, process killed on the host).
		return &lockConn{FakeRunner: stubHost(s), lock: lock, gate: func(context.Context, string) { once.Do(lease.End) }}
	})

	h := Collect(context.Background(), []string{path}, Options{Drift: true})[0]

	if !h.Reachable || len(h.Sites) != 1 || !h.Sites[0].Cert.Present {
		t.Fatalf("host = %+v, want reachable with the probe facts", h)
	}
	if len(h.ProbeErrors) != 0 {
		t.Errorf("ProbeErrors = %v, want the facts re-collected cleanly outside the lock", h.ProbeErrors)
	}
	if h.Drift == nil || h.Drift.Error != hostlock.ErrLost.Error() || h.Drift.StoppedAt != "" || len(h.Drift.Steps) != 0 {
		t.Errorf("Drift = %+v, want only the lost-lock error", h.Drift)
	}
}

// endpointLocks is a TEST-LOCAL host session lock shared by every connection
// to the same endpoint. It answers by behaviour and ignores the script: busy
// while a lease on that endpoint is live, otherwise a fresh lease that lives
// until hostlock releases it. It records every lease, the busy answers, the
// most endpoints ever held at once, and the per-host budget left at each hold.
type endpointLocks struct {
	mu      sync.Mutex
	live    map[string]*bssh.FakeLease
	holds   map[string]int
	leases  []*bssh.FakeLease
	busy    int
	maxLive int
	budgets []time.Duration
	// two closes once two different endpoints have been held.
	two     chan struct{}
	twoOnce sync.Once
}

func newEndpointLocks() *endpointLocks {
	return &endpointLocks{live: map[string]*bssh.FakeLease{}, holds: map[string]int{}, two: make(chan struct{})}
}

// endpointHold is one connection's view of endpointLocks; first is set when
// its hold was the first on its endpoint.
type endpointHold struct {
	locks *endpointLocks
	ep    string
	first atomic.Bool
}

func (h *endpointHold) Hold(ctx context.Context, _, _ string) (bssh.Lease, error) {
	l := h.locks
	l.mu.Lock()
	defer l.mu.Unlock()
	if d, ok := ctx.Deadline(); ok {
		l.budgets = append(l.budgets, time.Until(d))
	}
	if cur := l.live[h.ep]; cur != nil && !leaseEnded(cur) {
		l.busy++
		return nil, &bssh.HoldExitError{Code: 75, Stdout: "berth 0.37.0 status --drift by ops@ws (pid 4711) since 2026-11-02T09:32:00Z\n"}
	}
	lease := bssh.NewFakeLease()
	l.live[h.ep] = lease
	l.leases = append(l.leases, lease)
	l.holds[h.ep]++
	h.first.Store(l.holds[h.ep] == 1)
	n := 0
	for _, x := range l.live {
		if !leaseEnded(x) {
			n++
		}
	}
	l.maxLive = max(l.maxLive, n)
	if len(l.holds) >= 2 {
		l.twoOnce.Do(func() { close(l.two) })
	}
	return lease, nil
}

func leaseEnded(l *bssh.FakeLease) bool {
	select {
	case <-l.Done():
		return true
	default:
		return false
	}
}

// pause waits d, or less if ctx ends first.
func pause(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// Configs sharing host:port are scanned one after another, so a sweep never
// reports "busy" against itself (several servers/*.yml may point at one box),
// while a config for another endpoint is not queued behind them. Each config
// still gets its own result, in input order.
func TestCollectSerializesConfigsOfOneEndpoint(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	paths := []string{
		writeCollectConfig(t, dir, "web1", "203.0.113.10"),
		writeCollectConfig(t, dir, "web2", "203.0.113.10"),
		writeCollectConfig(t, dir, "other", "203.0.113.20"),
	}
	locks := newEndpointLocks()
	stubDial(t, func(s *config.Server) bssh.Conn {
		hold := &endpointHold{locks: locks, ep: fmt.Sprintf("%s:%d", s.Host, s.SSH.Port)}
		return &lockConn{FakeRunner: stubHost(s), lock: hold, gate: func(ctx context.Context, cmd string) {
			if cmd != hostMetaCmd || !hold.first.Load() {
				return
			}
			// The first scan of each endpoint waits, holding its lock, until
			// the other endpoint is held too. Bounded, so a config queued
			// behind this one (by a global queue, or by a waiting sibling
			// sitting on the last slot) is a failure, not a hang.
			select {
			case <-locks.two:
			case <-time.After(3 * time.Second):
				t.Errorf("%s held its lock for 3s and the other endpoint never started — it was queued behind this endpoint's configs", s.ID)
			case <-ctx.Done():
			}
			// The pair's first scan then lingers under its lock, long enough
			// for an unserialized sibling to try the same endpoint and be
			// answered busy.
			if s.Host == "203.0.113.10" {
				pause(ctx, 100*time.Millisecond)
			}
		}}
	})

	got := Collect(context.Background(), paths, Options{Parallel: 2, Drift: true})

	if len(got) != 3 {
		t.Fatalf("got %d hosts, want 3", len(got))
	}
	for i, id := range []string{"web1", "web2", "other"} {
		if got[i].ID != id || got[i].ConfigPath != paths[i] {
			t.Errorf("result %d = %q (%s), want %q — output order must follow the input", i, got[i].ID, got[i].ConfigPath, id)
		}
	}
	for _, h := range got {
		if !h.Reachable || h.Drift == nil {
			t.Errorf("%s: host = %+v, want reachable with a drift report", h.ID, h)
			continue
		}
		if strings.HasPrefix(h.Drift.Error, "host is busy") || strings.HasPrefix(h.Drift.Error, "host session lock") {
			t.Errorf("%s: Drift.Error = %q — the sweep collided with itself", h.ID, h.Drift.Error)
		}
	}
	locks.mu.Lock()
	defer locks.mu.Unlock()
	if locks.busy != 0 {
		t.Errorf("busy answers = %d, want 0 — configs of one endpoint overlapped", locks.busy)
	}
	if len(locks.leases) != 3 {
		t.Errorf("holds = %d, want one per config", len(locks.leases))
	}
	if locks.maxLive != 2 {
		t.Errorf("most endpoints held at once = %d, want 2 — the other endpoint was queued behind the pair", locks.maxLive)
	}
	for i, l := range locks.leases {
		if !l.Released() {
			t.Errorf("lease %d was never released", i)
		}
	}
}

// Waiting for a same-endpoint predecessor is not the waiting config's own
// time: its per-host budget starts when its turn comes, or a slow first scan
// would time out every later config of that host.
func TestCollectEndpointTurnDoesNotConsumeTheHostBudget(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	paths := []string{
		writeCollectConfig(t, dir, "web1", "203.0.113.10"),
		writeCollectConfig(t, dir, "web2", "203.0.113.10"),
	}
	const (
		budget = time.Minute
		linger = 300 * time.Millisecond
	)
	locks := newEndpointLocks()
	stubDial(t, func(s *config.Server) bssh.Conn {
		hold := &endpointHold{locks: locks, ep: fmt.Sprintf("%s:%d", s.Host, s.SSH.Port)}
		return &lockConn{FakeRunner: stubHost(s), lock: hold, gate: func(ctx context.Context, cmd string) {
			if cmd == hostMetaCmd && hold.first.Load() {
				pause(ctx, linger) // the first scan is slow
			}
		}}
	})

	got := Collect(context.Background(), paths, Options{Parallel: 2, Drift: true, Timeout: budget})

	for _, h := range got {
		if h.Drift == nil || strings.HasPrefix(h.Drift.Error, "host is busy") {
			t.Errorf("%s: Drift = %+v, want a scan that ran", h.ID, h.Drift)
		}
	}
	locks.mu.Lock()
	defer locks.mu.Unlock()
	if len(locks.budgets) != 2 {
		t.Fatalf("budgets recorded = %d, want one per hold", len(locks.budgets))
	}
	for i, left := range locks.budgets {
		if left < budget-linger/2 {
			t.Errorf("hold %d had %v of its %v budget left — the wait for its turn was charged to it", i, left, budget)
		}
	}
}

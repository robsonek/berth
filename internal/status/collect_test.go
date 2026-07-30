package status

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
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
	f.On(servicesCmd(unitList(s)), bssh.Result{Stdout: "nginx\tactive\tenabled\nssh\tactive\tenabled\n"})
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
	body := "id: %s\nhost: 203.0.113.10\nssh:\n  user: berth\n  port: 22\n  key: ~/.ssh/id_ed25519\nphp:\n  version: \"8.4\"\ndatabase:\n  engine: mariadb\nsites:\n  - domain: app.example.com\n    deploy_path: /var/www/app\n    database:\n      name: app\n      user: app\n"
	if err := os.WriteFile(good, []byte(fmt.Sprintf(body, "good")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte(fmt.Sprintf(body, "bad")), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := dial
	t.Cleanup(func() { dial = orig })
	dial = func(_ context.Context, s *config.Server, _ string) (bssh.Runner, func() error, error) {
		if s.ID == "bad" {
			return nil, nil, errors.New("dial tcp: no route to host")
		}
		return stubHost(s), func() error { return nil }, nil
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

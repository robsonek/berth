package status

import (
	"context"
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

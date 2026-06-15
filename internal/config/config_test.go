package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadValid(t *testing.T) {
	s, err := Load("testdata/valid.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.Host != "203.0.113.10" {
		t.Errorf("Host = %q, want 203.0.113.10", s.Host)
	}
	if s.SSH.Port != 22 {
		t.Errorf("SSH.Port = %d, want 22", s.SSH.Port)
	}
	if s.PHP.Source != "auto" {
		t.Errorf("PHP.Source = %q, want auto", s.PHP.Source)
	}
	if len(s.Sites) != 1 || s.Sites[0].Domain != "app.example.com" {
		t.Errorf("Sites = %+v, want one site app.example.com", s.Sites)
	}
}

func TestLoadDefaultsPort(t *testing.T) {
	// minimal.yml omits ssh.port → default 22 applies (created inline below).
	s, err := Load("testdata/valid.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.SSH.Port == 0 {
		t.Error("expected default ssh.port to be applied")
	}
}

func TestLoadFail2banDefaults(t *testing.T) {
	s, err := Load("testdata/defaults.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.Fail2ban.Bantime != "1h" || s.Fail2ban.Findtime != "10m" || s.Fail2ban.Maxretry != 5 {
		t.Errorf("fail2ban defaults not applied: %+v", s.Fail2ban)
	}
}

func TestLoadSchedulerDefaultsOn(t *testing.T) {
	s, err := Load("testdata/defaults.yml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !s.Scheduler {
		t.Error("scheduler should default to true when the key is absent")
	}
}

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
	on := &Server{Queue: true, Sites: off.Sites}
	got = on.SiteProgramNames(on.Sites[0])
	if len(got) != 2 || got[0] != "berth-a_example_com" || got[1] != "berth-a_example_com-x" {
		t.Fatalf("program names = %v, want [berth-a_example_com berth-a_example_com-x]", got)
	}
}

func TestServerYAMLOmitsEmptyOptionalFields(t *testing.T) {
	s := &Server{
		Host: "h.example", SSH: SSH{User: "root", Port: 22, Key: "~/.ssh/id_ed25519"},
		PHP: PHP{Version: "8.5", Source: "auto"}, Nginx: Nginx{Source: "debian"},
		Database: Database{Engine: "mariadb", Source: "debian"},
		Sites:    []Site{{Domain: "a.example", DeployPath: "/srv/a", Database: SiteDatabase{Name: "app", User: "app"}}},
	}
	b, err := yaml.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, absent := range []string{"fingerprint:", "ssl_mode:", "ssl_email:", "repository:"} {
		if strings.Contains(out, absent) {
			t.Errorf("expected %q to be omitted, got:\n%s", absent, out)
		}
	}
	if strings.Contains(out, "name: \"\"") || strings.Contains(out, "user: \"\"") {
		t.Errorf("empty top-level database name/user should be omitted:\n%s", out)
	}
	dir := t.TempDir()
	p := dir + "/s.yml"
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("re-Load failed: %v", err)
	}
}

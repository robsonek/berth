package config

import "testing"

// Every value pinned here is BAKED INTO MANAGED FILES ON LIVE HOSTS (jail
// config, FPM pool and drop-ins, valkey units, backup crons) or gates
// on-host artifacts (scheduler). Changing ANY of them re-renders and reloads
// the affected file on EVERY host at its next provision — a fleet-wide
// change for users who never set the knob. That can be a legitimate
// decision, but never an incidental one: if this test fails, write a
// BREAKING CHANGELOG entry explaining the fleet-wide effect, then update
// the pin in the same commit.
func TestOnHostDefaultsAreFrozen(t *testing.T) {
	var f Fail2ban
	if f.BantimeEff() != "1h" || f.FindtimeEff() != "10m" || f.MaxretryEff() != 5 {
		t.Errorf("fail2ban defaults changed: %s %s %d", f.BantimeEff(), f.FindtimeEff(), f.MaxretryEff())
	}
	var tn Tuning
	if tn.ValkeyMaxmemoryEff() != "256mb" || tn.ValkeyMaxmemoryPolicyEff() != "allkeys-lru" {
		t.Errorf("valkey defaults changed: %s %s", tn.ValkeyMaxmemoryEff(), tn.ValkeyMaxmemoryPolicyEff())
	}
	if tn.MariaDBBufferPoolEff() != "256M" || tn.MariaDBLongQueryTimeEff() != 2 {
		t.Errorf("mariadb defaults changed: %s %d", tn.MariaDBBufferPoolEff(), tn.MariaDBLongQueryTimeEff())
	}
	if tn.PHPMemoryLimitEff() != "256M" || tn.PHPUploadMaxEff() != "32M" ||
		tn.PHPMaxExecutionTimeEff() != 30 || tn.PHPMaxInputVarsEff() != 1000 ||
		tn.PHPFPMMaxChildrenEff() != 10 {
		t.Error("php tuning defaults changed")
	}
	// Derived default rendered into BOTH the PHP drop-in and every nginx
	// vhost (post_max_size / client_max_body_size).
	if got := tn.PHPPostBodyMaxEff(); got != "35651584" {
		t.Errorf("PHPPostBodyMaxEff default changed: %s", got)
	}
	var b Backups
	if b.RetentionDaysEff() != 7 || b.ScheduleEff() != "30 3 * * *" {
		t.Errorf("backups defaults changed: %d %q", b.RetentionDaysEff(), b.ScheduleEff())
	}
}

// The Load()-path defaults with on-host consequences: scheduler=true gates
// the per-site cron's existence; php.source="auto" resolves against
// debianStockPHP, i.e. its MEANING is pinned to Debian 13; the source
// defaults are baked into apt sources on the host.
func TestLoadDefaultsAreFrozen(t *testing.T) {
	s, err := Load(writeTmpConfig(t, `id: frozen-defaults
host: 203.0.113.10
php:
  version: "8.5"
database:
  engine: mariadb
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !s.Scheduler {
		t.Error("scheduler default changed: want true")
	}
	if s.PHP.Source != "auto" {
		t.Errorf("php.source default changed: %q, want auto", s.PHP.Source)
	}
	if s.Nginx.Source != "debian" {
		t.Errorf("nginx.source default changed: %q, want debian", s.Nginx.Source)
	}
	if s.Database.Source != "debian" {
		t.Errorf("database.source default changed: %q, want debian", s.Database.Source)
	}
	if s.SSH.Port != 22 {
		t.Errorf("ssh.port default changed: %d, want 22", s.SSH.Port)
	}
	if s.SSH.User != "root" {
		t.Errorf("ssh.user default changed: %q, want root", s.SSH.User)
	}
}

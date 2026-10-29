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
	// The queue instance's cap renders into berth-valkey-<pool>-queue.service.
	if tn.ValkeyQueueMaxmemoryEff() != "256mb" {
		t.Errorf("valkey queue default changed: %s", tn.ValkeyQueueMaxmemoryEff())
	}
	if (&Server{}).ValkeyQueue {
		t.Error("valkey_queue default changed: want off")
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
	// workers gates whether Supervisor programs autostart and get started by
	// berth; apt.upstream_updates gates the unattended-upgrades origins
	// drop-in for berth's upstream repos.
	if (&Server{}).WorkersRunning(Site{}) {
		t.Error("workers default changed: want dormant (programs never started by berth)")
	}
	if !(Apt{}).UpstreamAutoUpdates() {
		t.Error("apt.upstream_updates default changed: want automatic upstream updates")
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
	// The first-deploy knobs have NO Load default on purpose: their zero
	// value IS the pre-knob behaviour (programs dormant, upstream updates
	// automatic), so a SetDefault here would change what an existing config
	// means and rewrite every host's files on the next run.
	if s.Workers != "" {
		t.Errorf("workers must stay empty after Load (zero value = dormant); got %q", s.Workers)
	}
	if s.Sites[0].Workers != "" {
		t.Errorf("sites[].workers must stay empty after Load (zero value = inherit); got %q", s.Sites[0].Workers)
	}
	if s.Apt.UpstreamUpdates != "" {
		t.Errorf("apt.upstream_updates must stay empty after Load (zero value = auto); got %q", s.Apt.UpstreamUpdates)
	}
}

// nginx.gzip gates the conf.d gzip drop-in (compression of dynamic HTML/JSON
// responses): unset means ON, so a config that never mentions it gets the
// file written. Flipping this default adds or removes a managed file on
// every host — a BREAKING entry, like every pin above.
func TestNginxGzipDefaultIsFrozen(t *testing.T) {
	if !(Nginx{}).GzipEnabled() {
		t.Error("nginx.gzip default changed: want on (unset = gzip drop-in written)")
	}
}

// firewall.enabled gates ufw itself: unset means ON (today's ufw with the
// built-in SSH/80,443 rules), so a config that never mentions it keeps its
// firewall. Flipping this default would disable the firewall on every host
// that does not spell the knob out — a BREAKING entry, like every pin above.
func TestFirewallEnabledDefaultIsFrozen(t *testing.T) {
	if !(Firewall{}).IsEnabled() {
		t.Error("firewall.enabled default changed: want on (unset = ufw enabled with the built-in rules)")
	}
}

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
	// Defaults live in the *Eff accessors, not in Load(): omitted fields stay
	// zero in the struct, and the accessors supply 1h/10m/5 at render time.
	if s.Fail2ban.Bantime != "" || s.Fail2ban.Findtime != "" || s.Fail2ban.Maxretry != 0 {
		t.Errorf("Load must not inject fail2ban defaults: %+v", s.Fail2ban)
	}
	if s.Fail2ban.BantimeEff() != "1h" || s.Fail2ban.FindtimeEff() != "10m" || s.Fail2ban.MaxretryEff() != 5 {
		t.Errorf("accessor defaults wrong: %q/%q/%d",
			s.Fail2ban.BantimeEff(), s.Fail2ban.FindtimeEff(), s.Fail2ban.MaxretryEff())
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

const baseCfg = `id: test-machine-0001
host: app.example.com
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

func TestQueueEnabledDriverNoneOverridesServerDefault(t *testing.T) {
	s := &Server{Queue: true, Sites: []Site{
		{Domain: "a.example.com", Queue: &QueueConfig{Driver: "none"}},
		{Domain: "b.example.com"},
	}}
	if s.QueueEnabled(s.Sites[0]) {
		t.Fatal("queue: none must opt the site out of the server-wide worker")
	}
	if !s.QueueEnabled(s.Sites[1]) {
		t.Fatal("sites without a queue block keep inheriting the server default")
	}
}

func TestQueueNoneBareStringDecodes(t *testing.T) {
	s, err := Load(writeTmpConfig(t, baseCfg+"    queue: none\n"))
	if err != nil {
		t.Fatal(err)
	}
	q := s.Sites[0].Queue
	if q == nil || q.Driver != "none" {
		t.Fatalf("queue: none must decode to {Driver: none}; got %+v", q)
	}
	if s.QueueEnabled(s.Sites[0]) {
		t.Error("a decoded queue: none site must not get a worker")
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
		ID:   "test-machine-0001",
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
	dir := t.TempDir()
	p := dir + "/s.yml"
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("re-Load failed: %v", err)
	}
}

func TestCloudflareOnlyEnabled(t *testing.T) {
	tru, fls := true, false
	s := &Server{CloudflareOnly: false, Sites: []Site{
		{Domain: "a"},                       // nil override -> inherits server (false)
		{Domain: "b", CloudflareOnly: &tru}, // per-site true beats server false
	}}
	if s.CloudflareOnlyEnabled(s.Sites[0]) {
		t.Error("nil override should inherit server default false")
	}
	if !s.CloudflareOnlyEnabled(s.Sites[1]) {
		t.Error("per-site true override should win over server false")
	}
	s.CloudflareOnly = true
	s.Sites = append(s.Sites, Site{Domain: "c", CloudflareOnly: &fls})
	if !s.CloudflareOnlyEnabled(s.Sites[0]) {
		t.Error("nil override should inherit server default true")
	}
	if s.CloudflareOnlyEnabled(s.Sites[2]) {
		t.Error("per-site false override should win over server true")
	}
}

func TestAnyCloudflareOnly(t *testing.T) {
	fls := false
	none := &Server{CloudflareOnly: false, Sites: []Site{{Domain: "a"}}}
	if none.AnyCloudflareOnly() {
		t.Error("no site enabled -> AnyCloudflareOnly false")
	}
	mixed := &Server{CloudflareOnly: true, Sites: []Site{
		{Domain: "a", CloudflareOnly: &fls}, {Domain: "b"},
	}}
	if !mixed.AnyCloudflareOnly() {
		t.Error("one inheriting site enabled -> true")
	}
	allOff := &Server{CloudflareOnly: true, Sites: []Site{
		{Domain: "a", CloudflareOnly: &fls}, {Domain: "b", CloudflareOnly: &fls},
	}}
	if allOff.AnyCloudflareOnly() {
		t.Error("all sites overridden off -> false even with server true")
	}
}

func TestCloudflareOnlyDecodes(t *testing.T) {
	s, err := Load(writeTmpConfig(t, "cloudflare_only: true\n"+baseCfg+"    cloudflare_only: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.CloudflareOnly {
		t.Error("server cloudflare_only should decode true")
	}
	if s.Sites[0].CloudflareOnly == nil || *s.Sites[0].CloudflareOnly {
		t.Fatalf("site cloudflare_only should decode to *false; got %v", s.Sites[0].CloudflareOnly)
	}
}

func TestSiteUserDerivation(t *testing.T) {
	// A single site WITHOUT an explicit user derives from the domain — the
	// legacy fallback to a shared "deploy" account is gone (pack 9): identity
	// must not depend on how many sites the config lists.
	single := &Server{Sites: []Site{{Domain: "app.example.com", DeployPath: "/var/www/app"}}}
	if got, want := single.SiteUser(single.Sites[0]), DerivedSiteUser("app.example.com"); got != want {
		t.Errorf("single-site without user: SiteUser = %q, want derived %q", got, want)
	}
	// An explicit user always wins, including the literal "deploy" pin that
	// keeps a pre-pack-9 installation on its old account.
	pinned := &Server{Sites: []Site{{Domain: "app.example.com", DeployPath: "/var/www/app", User: "deploy"}}}
	if got := pinned.SiteUser(pinned.Sites[0]); got != "deploy" {
		t.Errorf("explicit user: SiteUser = %q, want deploy", got)
	}
	// Multi-site derivation is unchanged.
	two := &Server{Sites: []Site{
		{Domain: "app.example.com", DeployPath: "/var/www/app"},
		{Domain: "other.example.com", DeployPath: "/var/www/other"},
	}}
	if got, want := two.SiteUser(two.Sites[0]), DerivedSiteUser("app.example.com"); got != want {
		t.Errorf("multi-site: SiteUser = %q, want %q", got, want)
	}
}

// writeCfg writes a config file into a temp dir and returns its path.
func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "server.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	// Strict decoding: an unknown key must be an error, never a silent default.
	// A typo in a safety-relevant key would otherwise leave the operator
	// convinced they configured something berth never read. All four nesting
	// levels are covered because viper flattens the tree and it is not obvious
	// from the call site that every level is checked.
	base := `id: test-machine-0001
host: 203.0.113.10
ssh:
  user: root
  key: ~/.ssh/id_ed25519
php:
  version: "8.5"
database:
  engine: mariadb
sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`
	for name, body := range map[string]string{
		"root key":            base + "clouflare_only: true\n",
		"nested block key":    strings.Replace(base, "  user: root\n", "  user: root\n  prot: 2222\n", 1),
		"site key":            base + "    schedular: false\n",
		"block inside a site": base + "    databse:\n      name: other\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeCfg(t, body))
			if err == nil {
				t.Fatal("Load() accepted an unknown key; a typo must not fall back to the default")
			}
			if !strings.Contains(err.Error(), "parse config") {
				t.Errorf("err = %v, want the parse-stage rejection", err)
			}
		})
	}
}

func TestLoadStillAcceptsEveryKnownKey(t *testing.T) {
	// The counterweight to the test above: strictness must not reject a config
	// that only uses documented keys. valid.yml exercises the common ones.
	if _, err := Load("testdata/valid.yml"); err != nil {
		t.Fatalf("a fully known config must still load; got %v", err)
	}
}

func TestLoadRejectsLegacyTopLevelDatabaseNameUser(t *testing.T) {
	// The pre-release top-level database.name/user fields are gone; a config
	// still carrying them must fail loudly at parse time (UnmarshalExact),
	// never silently ignore the keys. Each key must be rejected on its own —
	// restoring only one of them may not regress silently.
	cases := []struct {
		name    string
		legacy  string // lines injected into the top-level database block
		wantKey string // the offending key the error must name
	}{
		{"both-keys", "  name: myapp\n  user: myapp\n", "name"},
		{"name-only", "  name: myapp\n", "name"},
		{"user-only", "  user: myapp\n", "user"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "legacy.yml")
			yml := `id: test-machine-0001
host: 203.0.113.10
php:
  version: "8.5"
database:
  engine: mariadb
` + c.legacy + `sites:
  - domain: app.example.com
    deploy_path: /var/www/app
    database: {name: myapp, user: myapp}
`
			if err := os.WriteFile(path, []byte(yml), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("legacy top-level database.%s must fail to load, got nil", c.wantKey)
			}
			// Anchor on the mapstructure unknown-key marker: the error text
			// starts with the TempDir config path, which contains the SUBTEST
			// name ("name-only", ...), so a bare Contains(wantKey) would pass
			// via the path even if the error stopped naming the key.
			msg := err.Error()
			idx := strings.Index(msg, "invalid keys:")
			if idx < 0 || !strings.Contains(msg[idx:], c.wantKey) {
				t.Fatalf("legacy top-level database.%s must fail with an unknown-key error naming it, got %v", c.wantKey, err)
			}
		})
	}
}

func TestCacheKey(t *testing.T) {
	s := &Server{Host: "h.example.com"}
	if got := s.CacheKey(); got != "h.example.com" {
		t.Errorf("CacheKey without id = %q, want the host", got)
	}
	s.ID = "prod-web-1a2b3c"
	if got := s.CacheKey(); got != "prod-web-1a2b3c" {
		t.Errorf("CacheKey with id = %q, want the id", got)
	}
}

// These derivations name OS users, FPM sockets, systemd units, supervisor
// programs and the role names inside PostgreSQL dumps on every live host.
// FROZEN FOREVER as of the first real deployment: changing either function
// re-identifies every implicitly-named tenant — the owner guard would
// refuse loudly rather than corrupt, but the config would stop converging.
func TestDerivationsAreFrozen(t *testing.T) {
	if got := DerivedSiteUser("app.example.com"); got != "b_appexamplecom_dd46c94b" {
		t.Fatalf("DerivedSiteUser derivation changed: %s", got)
	}
	if got := PoolName("app.example.com"); got != "app_example_com" {
		t.Fatalf("PoolName derivation changed: %s", got)
	}
	if got := FPMSocketPath("app_example_com"); got != "/run/php/berth-app_example_com.sock" {
		t.Fatalf("FPMSocketPath derivation changed: %s", got)
	}
	if got := ValkeySocketPath("app_example_com"); got != "/run/berth-valkey/app_example_com/valkey.sock" {
		t.Fatalf("ValkeySocketPath derivation changed: %s", got)
	}
	if ValkeyStateBase != "/var/lib/berth-valkey" {
		t.Fatalf("ValkeyStateBase changed: %s", ValkeyStateBase)
	}
	if got := SiteWorkerProgram("app.example.com"); got != "berth-app_example_com" {
		t.Fatalf("SiteWorkerProgram derivation changed: %s", got)
	}
	if got := SiteDaemonProgram("app.example.com", "pulse"); got != "berth-app_example_com-pulse" {
		t.Fatalf("SiteDaemonProgram derivation changed: %s", got)
	}
	if got := DeployKeyPath("b_appexamplecom_dd46c94b"); got != "/home/b_appexamplecom_dd46c94b/.ssh/id_ed25519" {
		t.Fatalf("DeployKeyPath derivation changed: %s", got)
	}
}

func TestOffsiteRepositoryAndDefaults(t *testing.T) {
	s3 := &Offsite{Backend: "s3", Endpoint: "s3.example.com", Bucket: "bkt"}
	if got, want := s3.Repository("box-1"), "s3:https://s3.example.com/bkt/berth/box-1"; got != want {
		t.Errorf("s3 Repository = %q, want %q", got, want)
	}
	s3.Prefix = "custom/prefix"
	if got, want := s3.Repository("box-1"), "s3:https://s3.example.com/bkt/custom/prefix"; got != want {
		t.Errorf("s3 Repository with prefix = %q, want %q", got, want)
	}
	sftp := &Offsite{Backend: "sftp", Host: "backup.example.net", User: "off", Path: "/srv/berth/box-1"}
	if got, want := sftp.Repository("box-1"), "sftp:off@backup.example.net:/srv/berth/box-1"; got != want {
		t.Errorf("sftp Repository = %q, want %q", got, want)
	}
	var o Offsite
	if o.ScheduleEff() != "15 4 * * *" {
		t.Errorf("ScheduleEff default = %q", o.ScheduleEff())
	}
	if o.PortEff() != 22 {
		t.Errorf("PortEff default = %d", o.PortEff())
	}
	if d, w, m := o.Keep.DailyEff(), o.Keep.WeeklyEff(), o.Keep.MonthlyEff(); d != 7 || w != 4 || m != 6 {
		t.Errorf("Keep defaults = %d/%d/%d, want 7/4/6", d, w, m)
	}
	srv := &Server{}
	if srv.OffsiteEnabled() {
		t.Error("nil offsite must read as disabled")
	}
	srv.Backups.Offsite = s3
	if !srv.OffsiteEnabled() {
		t.Error("non-nil offsite must read as enabled")
	}
}

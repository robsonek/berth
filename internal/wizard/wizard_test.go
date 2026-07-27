package wizard

import (
	"os"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

// validSingle returns answers for one MariaDB-on-Debian site.
func validSingle() Answers {
	a := defaults()
	a.Name = "example"
	a.Host = "203.0.113.10"
	a.Sites = []SiteAnswers{{
		Domain: "app.example.com", DeployPath: "/var/www/app",
		DBName: "myapp", DBUser: "myapp", SchedulerOverride: "inherit",
	}}
	return a
}

// writeAndLoad writes the answers and loads them back through config.Load,
// chdir-ing into a temp dir so servers/<name>.yml lands there.
func writeAndLoad(t *testing.T, a Answers) *config.Server {
	t.Helper()
	dir := t.TempDir()
	old, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(old) })
	os.Chdir(dir)
	path, err := a.Write()
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	srv, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load(%s) error = %v", path, err)
	}
	return srv
}

func TestRoundTripSingleSite(t *testing.T) {
	srv := writeAndLoad(t, validSingle())
	if srv.Database.Engine != "mariadb" || srv.Database.Source != "debian" {
		t.Errorf("db = %+v", srv.Database)
	}
	if got := srv.Sites[0]; got.Domain != "app.example.com" || got.Database.Name != "myapp" {
		t.Errorf("site = %+v", got)
	}
	// Single site: the OS user derives from the domain and is emitted
	// explicitly (pack 9 removed the legacy shared "deploy" fallback).
	if want := config.DerivedSiteUser(srv.Sites[0].Domain); srv.Sites[0].User != want {
		t.Errorf("Sites[0].User = %q, want explicit derived %q", srv.Sites[0].User, want)
	}
}

func TestRoundTripMultiSite(t *testing.T) {
	a := validSingle()
	a.Sites = []SiteAnswers{
		{Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit"},
		{Domain: "b.example.com", DeployPath: "/srv/b", DBName: "bdb", DBUser: "busr", SchedulerOverride: "inherit"},
	}
	srv := writeAndLoad(t, a)
	if len(srv.Sites) != 2 {
		t.Fatalf("want 2 sites, got %d", len(srv.Sites))
	}
	// No site sets user => each derives a distinct, non-"deploy" name (multi-site).
	u0, u1 := srv.SiteUser(srv.Sites[0]), srv.SiteUser(srv.Sites[1])
	if u0 == u1 || u0 == "deploy" || u1 == "deploy" {
		t.Errorf("derived users not distinct: %q %q", u0, u1)
	}
}

func TestRoundTripPostgres(t *testing.T) {
	a := validSingle()
	a.DBEngine, a.DBSource = "postgres", "pgdg"
	srv := writeAndLoad(t, a)
	if srv.Database.Engine != "postgres" || srv.Database.Source != "pgdg" {
		t.Errorf("db = %+v", srv.Database)
	}
}

func TestRoundTripNginxHTTP3SelfSigned(t *testing.T) {
	a := validSingle()
	a.NginxSource = "nginx"
	a.Sites[0].SSL = true
	a.Sites[0].SSLMode = "selfsigned" // no email required
	a.Sites[0].HTTP3 = true
	srv := writeAndLoad(t, a)
	if srv.Nginx.Source != "nginx" || !srv.Sites[0].HTTP3 || srv.Sites[0].CertMode() != "selfsigned" {
		t.Errorf("got nginx=%q http3=%v mode=%q", srv.Nginx.Source, srv.Sites[0].HTTP3, srv.Sites[0].CertMode())
	}
}

func TestWriteRejectsLetsEncryptWithoutEmail(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(old) })
	os.Chdir(dir)
	a := validSingle()
	a.Sites[0].SSL = true
	a.Sites[0].SSLMode = "letsencrypt" // email omitted
	if _, err := a.Write(); err == nil {
		t.Error("expected Write to fail: letsencrypt without ssl_email")
	}
}

func TestRoundTripQueueWork(t *testing.T) {
	a := validSingle()
	a.Sites[0].Queue = &QueueAnswers{Driver: "work", Processes: 2, Tries: 5, Sleep: 7, MaxMemory: 128}
	srv := writeAndLoad(t, a)
	q := srv.Sites[0].Queue
	if q == nil || q.Processes != 2 || q.Tries != 5 || q.Sleep != 7 || q.MaxMemory != 128 {
		t.Errorf("queue = %+v", q)
	}
}

func TestRoundTripQueueHorizon(t *testing.T) {
	a := validSingle()
	a.Sites[0].Queue = &QueueAnswers{Driver: "horizon"} // no work-only knobs
	srv := writeAndLoad(t, a)
	if srv.Sites[0].Queue == nil || srv.Sites[0].Queue.Driver != "horizon" {
		t.Errorf("queue = %+v", srv.Sites[0].Queue)
	}
}

func TestRoundTripDaemons(t *testing.T) {
	a := validSingle()
	a.Sites[0].Daemons = []DaemonAnswers{
		{Name: "reverb", Command: "php artisan reverb:start", Processes: 1},
	}
	srv := writeAndLoad(t, a)
	if len(srv.Sites[0].Daemons) != 1 || srv.Sites[0].Daemons[0].Name != "reverb" {
		t.Errorf("daemons = %+v", srv.Sites[0].Daemons)
	}
}

func TestRoundTripAdvancedServer(t *testing.T) {
	a := validSingle()
	a.Fingerprint = "SHA256:oP7LMMAE8JnXUfq6N8eUvsvdyIBNTXhcLAnNynp9BfA"
	a.Fail2ban = Fail2banAnswers{Bantime: "2h", Findtime: "10m", Maxretry: 3}
	a.Tuning = TuningAnswers{ValkeyMaxmemory: "512mb", ValkeyMaxmemoryPolicy: "allkeys-lru", MariaDBBufferPool: "512M"}
	off := "off"
	a.Sites[0].SchedulerOverride = off
	srv := writeAndLoad(t, a)
	if srv.SSH.Fingerprint == "" || srv.Fail2ban.Maxretry != 3 || srv.Tuning.MariaDBBufferPool != "512M" {
		t.Errorf("advanced server fields lost: %+v / %+v / %+v", srv.SSH, srv.Fail2ban, srv.Tuning)
	}
	if srv.Sites[0].Scheduler == nil || *srv.Sites[0].Scheduler != false {
		t.Errorf("scheduler override not applied: %v", srv.Sites[0].Scheduler)
	}
}

func TestRoundTripNoFingerprintOmitted(t *testing.T) {
	a := validSingle() // Fingerprint == ""
	srv := writeAndLoad(t, a)
	if srv.SSH.Fingerprint != "" {
		t.Errorf("expected empty fingerprint, got %q", srv.SSH.Fingerprint)
	}
}

func TestWriteRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(old) })
	os.Chdir(dir)
	if _, err := validSingle().Write(); err != nil {
		t.Fatal(err)
	}
	if _, err := validSingle().Write(); err == nil {
		t.Error("expected refusal to overwrite existing config")
	}
}

func TestWriteRejectsPathEscapingNames(t *testing.T) {
	// The RAW name is validated (filepath.Join would clean "../x" first and
	// hide the escape); today's barriers against writing outside servers/ are
	// accidental (refuse-existing + ENOENT on nested paths), not a validator.
	dir := t.TempDir()
	old, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(old) })
	os.Chdir(dir)
	for _, name := range []string{"../evil", "a/b", `a\b`, "..", ".hidden", "-lead", ""} {
		a := validSingle()
		a.Name = name
		if _, err := a.Write(); err == nil {
			t.Errorf("Name %q must be rejected", name)
		}
	}
	// The shared validator is also what the prompt uses.
	if err := validConfigName("../evil"); err == nil {
		t.Error("prompt validator must reject the raw escape too")
	}
	if err := validConfigName("good-name.v2"); err != nil {
		t.Errorf("dots/dashes are legal: %v", err)
	}
}

func TestWriteUsesExclusiveCreate(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(old) })
	os.Chdir(dir)
	a := validSingle()
	a.Name = "dup"
	if _, err := a.Write(); err != nil {
		t.Fatalf("first write: %v", err)
	}
	_, err := a.Write()
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second write must refuse with the friendly message; got %v", err)
	}
}

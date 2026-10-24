package wizard

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

// validSingle returns answers for one MariaDB-on-Debian site. The id is set
// explicitly: production answers get it from run()'s auto-generation, which
// these Answers-literal tests bypass.
func validSingle() Answers {
	a := defaults()
	a.Name = "example"
	a.ID = "test-machine-0001"
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
	srv, _ := writeAndLoadRaw(t, a)
	return srv
}

// writeAndLoadRaw is writeAndLoad that also returns the YAML written to disk,
// for assertions on what the file omits.
func writeAndLoadRaw(t *testing.T, a Answers) (*config.Server, string) {
	t.Helper()
	t.Chdir(t.TempDir())
	path, err := a.Write()
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	srv, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load(%s) error = %v", path, err)
	}
	return srv, string(raw)
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
	t.Chdir(t.TempDir())
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

func TestRoundTripAptReposAndPackages(t *testing.T) {
	// The serialization leg no other test covers: the wizard-WRITTEN apt block
	// must survive config.Load field-for-field (a yaml-tag typo would pass
	// ToServer().Validate() and the decode-side pins yet silently drop the
	// field from the written file).
	a := validSingle()
	a.AptRepos = []AptRepoAnswers{{
		Name:        "signal-cli",
		URI:         "https://packaging.gitlab.io/signal-cli",
		Suite:       "signalcli",
		Components:  "main extra",
		KeyURL:      "https://packaging.gitlab.io/signal-cli/gpg.key",
		Fingerprint: "02BD5FB7BA4650D50ED69002797DFE3F4F80269B",
	}}
	a.AptPackages = "signal-cli-native htop"
	srv := writeAndLoad(t, a)
	want := config.Apt{
		Repos: []config.AptRepo{{
			Name:        "signal-cli",
			URI:         "https://packaging.gitlab.io/signal-cli",
			Suite:       "signalcli",
			Components:  []string{"main", "extra"},
			KeyURL:      "https://packaging.gitlab.io/signal-cli/gpg.key",
			Fingerprint: "02BD5FB7BA4650D50ED69002797DFE3F4F80269B",
		}},
		Packages: []string{"signal-cli-native", "htop"},
	}
	if !reflect.DeepEqual(srv.Apt, want) {
		t.Errorf("apt block did not survive the Write->Load round trip:\n got %+v\nwant %+v", srv.Apt, want)
	}
	if err := srv.Validate(); err != nil {
		t.Errorf("loaded config must validate: %v", err)
	}
}

func TestRoundTripFirstDeployKnobs(t *testing.T) {
	// Every first-deploy knob the wizard collects must survive the
	// Write -> config.Load round trip field for field (a yaml-tag slip would
	// pass ToServer().Validate() yet silently drop the key from the file).
	t.Run("set", func(t *testing.T) {
		a := validSingle()
		a.AptUpstreamUpdates = "manual"
		a.Workers = "running"
		a.Sites = []SiteAnswers{
			{
				Domain: "app.example.com", DeployPath: "/var/www/app", DBName: "app", DBUser: "appuser",
				Repository: "git@github.com:acme/app.git", RepositoryKey: "~/keys/app-deploy",
				SchedulerOverride: "inherit", WorkersOverride: "dormant",
			},
			{
				Domain: "api.example.com", DeployPath: "/var/www/api", DBName: "api", DBUser: "apiuser",
				SchedulerOverride: "inherit", WorkersOverride: "inherit",
			},
		}
		srv, raw := writeAndLoadRaw(t, a)
		if srv.Apt.UpstreamUpdates != "manual" {
			t.Errorf("apt.upstream_updates = %q, want manual", srv.Apt.UpstreamUpdates)
		}
		if srv.Workers != "running" {
			t.Errorf("workers = %q, want running", srv.Workers)
		}
		if got := srv.Sites[0]; got.RepositoryKey != "~/keys/app-deploy" || got.Repository != "git@github.com:acme/app.git" {
			t.Errorf("site 0 repository/repository_key = %q / %q", got.Repository, got.RepositoryKey)
		}
		if srv.Sites[0].Workers != "dormant" {
			t.Errorf("sites[0].workers = %q, want dormant", srv.Sites[0].Workers)
		}
		if srv.Sites[1].Workers != "" || srv.Sites[1].RepositoryKey != "" {
			t.Errorf("site 1 must inherit workers and carry no key: workers=%q key=%q", srv.Sites[1].Workers, srv.Sites[1].RepositoryKey)
		}
		if srv.WorkersRunning(srv.Sites[0]) || !srv.WorkersRunning(srv.Sites[1]) {
			t.Errorf("WorkersRunning = %v/%v, want false (override dormant) / true (inherits running)",
				srv.WorkersRunning(srv.Sites[0]), srv.WorkersRunning(srv.Sites[1]))
		}
		if strings.Count(raw, "workers:") != 2 {
			t.Errorf("want exactly the server key and site 0's override as workers: lines, got:\n%s", raw)
		}
		if err := srv.Validate(); err != nil {
			t.Errorf("loaded config must validate: %v", err)
		}
	})
	t.Run("defaults-omitted", func(t *testing.T) {
		// The defaults (auto updates, dormant programs, generated key) are the
		// zero values: the written YAML must not mention the keys at all.
		srv, raw := writeAndLoadRaw(t, validSingle())
		for _, key := range []string{"upstream_updates", "workers", "repository_key"} {
			if strings.Contains(raw, key) {
				t.Errorf("default answers must omit %q from the YAML, got:\n%s", key, raw)
			}
		}
		if srv.Apt.UpstreamUpdates != "" || srv.Workers != "" || srv.Sites[0].Workers != "" || srv.Sites[0].RepositoryKey != "" {
			t.Errorf("defaults must load as zero values: apt=%+v workers=%q site=%+v", srv.Apt, srv.Workers, srv.Sites[0])
		}
	})
}

func TestRoundTripNoFingerprintOmitted(t *testing.T) {
	a := validSingle() // Fingerprint == ""
	srv := writeAndLoad(t, a)
	if srv.SSH.Fingerprint != "" {
		t.Errorf("expected empty fingerprint, got %q", srv.SSH.Fingerprint)
	}
}

func TestWriteRefusesOverwrite(t *testing.T) {
	t.Chdir(t.TempDir())
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
	t.Chdir(t.TempDir())
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
	t.Chdir(t.TempDir())
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

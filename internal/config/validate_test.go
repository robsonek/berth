package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func base() *Server {
	return &Server{
		Host:     "203.0.113.10",
		SSH:      SSH{User: "root", Port: 22},
		PHP:      PHP{Version: "8.5", Source: "auto"},
		Nginx:    Nginx{Source: "debian"},
		Database: Database{Engine: "mariadb", Name: "myapp", User: "myapp", Source: "debian"},
		Sites:    []Site{{Domain: "app.example.com", DeployPath: "/home/deploy/myapp"}},
	}
}

func TestValidateOK(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidatePostgresEngine(t *testing.T) {
	// postgres + pgdg upstream is valid.
	s := base()
	s.Database.Engine = "postgres"
	s.Database.Source = "pgdg"
	if err := s.Validate(); err != nil {
		t.Errorf("postgres + pgdg should be valid; got %v", err)
	}
	// postgres + debian is valid too.
	s.Database.Source = "debian"
	if err := s.Validate(); err != nil {
		t.Errorf("postgres + debian should be valid; got %v", err)
	}
}

func TestValidateValkeySiteCap(t *testing.T) {
	mk := func(n int) *Server {
		s := base()
		s.Valkey = true
		s.Sites = nil
		for i := 0; i < n; i++ {
			s.Sites = append(s.Sites, Site{
				Domain:     fmt.Sprintf("s%d.example.com", i),
				DeployPath: fmt.Sprintf("/var/www/s%d", i),
				Database:   SiteDatabase{Name: fmt.Sprintf("db%d", i), User: fmt.Sprintf("u%d", i)},
			})
		}
		return s
	}
	if err := mk(17).Validate(); err == nil {
		t.Error("expected error: valkey with 17 sites exceeds the 16 Redis logical DBs")
	}
	if err := mk(16).Validate(); err != nil {
		t.Errorf("16 sites with valkey should pass the cap; got %v", err)
	}
}

func TestValidateHTTP3OK(t *testing.T) {
	s := base()
	s.Nginx.Source = "nginx"
	s.Sites[0].SSL = true
	s.Sites[0].SSLEmail = "ops@example.com"
	s.Sites[0].HTTP3 = true
	if err := s.Validate(); err != nil {
		t.Fatalf("valid http3 config rejected: %v", err)
	}
}

func multiSite() *Server {
	return &Server{
		Host: "203.0.113.10", SSH: SSH{User: "root", Port: 22},
		PHP: PHP{Version: "8.5", Source: "auto"}, Nginx: Nginx{Source: "debian"},
		Database: Database{Engine: "mariadb", Source: "debian"},
		Sites: []Site{
			{Domain: "one.example.com", DeployPath: "/var/www/one", Database: SiteDatabase{Name: "one_db", User: "one_user"}},
			{Domain: "two.example.com", DeployPath: "/var/www/two", Database: SiteDatabase{Name: "two_db", User: "two_user"}},
		},
	}
}

func TestValidateMultiSite(t *testing.T) {
	// Two sites, each with its own database — valid, and they resolve to
	// distinct, derived OS users.
	s := multiSite()
	if err := s.Validate(); err != nil {
		t.Fatalf("valid multi-site rejected: %v", err)
	}
	if u0, u1 := s.SiteUser(s.Sites[0]), s.SiteUser(s.Sites[1]); u0 == u1 || u0 == "deploy" {
		t.Errorf("multi-site users must be distinct & derived; got %q, %q", u0, u1)
	}

	// Two sites both relying on the legacy top-level database -> ambiguous -> error.
	bad := multiSite()
	bad.Sites[0].Database = SiteDatabase{}
	bad.Sites[1].Database = SiteDatabase{}
	bad.Database.Name, bad.Database.User = "shared", "shared"
	if err := bad.Validate(); err == nil {
		t.Error("expected error when multiple sites have no database block")
	}

	// Two sites sharing a database user -> rejected (isolation).
	dupUser := multiSite()
	dupUser.Sites[1].Database.User = "one_user"
	if err := dupUser.Validate(); err == nil {
		t.Error("expected error when two sites share a database user")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Server){
		"bad php version":  func(s *Server) { s.PHP.Version = "9.9" },
		"bad php source":   func(s *Server) { s.PHP.Source = "ppa" },
		"bad db name":      func(s *Server) { s.Database.Name = "my-app; DROP" },
		"bad engine":       func(s *Server) { s.Database.Engine = "oracle" },
		"bad nginx source": func(s *Server) { s.Nginx.Source = "openresty" },
		"bad db source":    func(s *Server) { s.Database.Source = "percona" },
		"pg with mariadb source": func(s *Server) {
			s.Database.Engine = "postgres"
			s.Database.Source = "mariadb" // wrong upstream for postgres
		},
		"relative path":   func(s *Server) { s.Sites[0].DeployPath = "deploy/x" },
		"shell meta path": func(s *Server) { s.Sites[0].DeployPath = "/home/$(whoami)" },
		"quote in path":   func(s *Server) { s.Sites[0].DeployPath = `/srv/a"b` },
		"glob in path":    func(s *Server) { s.Sites[0].DeployPath = "/srv/*" },
		"ssl no email":    func(s *Server) { s.Sites[0].SSL = true },
		"ssl bad email": func(s *Server) {
			s.Sites[0].SSL = true
			s.Sites[0].SSLEmail = "x@y.com; reboot"
		},
		"bad port": func(s *Server) { s.SSH.Port = 0 },
		"no sites": func(s *Server) { s.Sites = nil },
		// Reserved Debian system accounts must be refused as a site OS user:
		// "sync" ships with home /bin, "www-data" owns the web stack, and
		// "berth" is berth's own provisioning account.
		"reserved os user sync":     func(s *Server) { s.Sites[0].User = "sync" },
		"reserved os user www-data": func(s *Server) { s.Sites[0].User = "www-data" },
		"reserved os user berth":    func(s *Server) { s.Sites[0].User = "berth" },
		// HTTP/3 requires ssl AND the nginx.org source.
		"http3 without ssl": func(s *Server) { s.Nginx.Source = "nginx"; s.Sites[0].HTTP3 = true },
		"http3 with debian nginx": func(s *Server) {
			s.Sites[0].SSL = true
			s.Sites[0].SSLEmail = "ops@example.com"
			s.Sites[0].HTTP3 = true
		},
		"bad fail2ban bantime":           func(s *Server) { s.Fail2ban.Bantime = "5 minutes" },
		"bad fail2ban maxretry":          func(s *Server) { s.Fail2ban.Maxretry = 9999 },
		"bad fail2ban maxretry negative": func(s *Server) { s.Fail2ban.Maxretry = -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := base()
			mutate(s)
			if err := s.Validate(); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestSchedulerEnabled(t *testing.T) {
	s := base()
	s.Scheduler = true
	site := s.Sites[0]
	if !s.SchedulerEnabled(site) {
		t.Error("server default true, no per-site override -> enabled")
	}
	off := false
	site.Scheduler = &off
	if s.SchedulerEnabled(site) {
		t.Error("per-site false must override the server default")
	}
	on := true
	site.Scheduler = &on
	s.Scheduler = false
	if !s.SchedulerEnabled(site) {
		t.Error("per-site true must override server default false")
	}
}

func validQueueServer() *Server {
	return &Server{
		Host: "app.example.com",
		SSH:  SSH{Port: 22, User: "deploy", Key: "~/.ssh/id_rsa"},
		PHP:  PHP{Version: "8.4", Source: "auto"}, Nginx: Nginx{Source: "debian"},
		Database: Database{Engine: "mariadb", Source: "mariadb"},
		Sites: []Site{{Domain: "app.example.com", DeployPath: "/var/www/app",
			User: "appuser", Database: SiteDatabase{Name: "app", User: "app"}}},
	}
}

func TestValidateRejectsBadDriver(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Driver: "bogus"}
	if s.Validate() == nil {
		t.Error("expected error for unknown queue driver")
	}
}

func TestValidateRejectsControlCharInCommand(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Daemons = []Daemon{{Name: "x", Command: "php artisan x\nmalicious=1"}}
	if s.Validate() == nil {
		t.Error("expected error for newline in daemon command (config injection)")
	}
}

func TestValidateRejectsHorizonWithKnobs(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Driver: "horizon", Tries: 5}
	if s.Validate() == nil {
		t.Error("expected error for horizon combined with queue:work knobs")
	}
}

func TestValidateRejectsHorizonProcessesGtOne(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Driver: "horizon", Processes: 2}
	if s.Validate() == nil {
		t.Error("expected error for horizon with processes > 1")
	}
}

func TestValidateRejectsNegativeKnob(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Tries: -1}
	if s.Validate() == nil {
		t.Error("expected error for negative tries")
	}
}

func TestValidateRejectsBadDaemonName(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Daemons = []Daemon{{Name: "Bad Name", Command: "php artisan x"}}
	if s.Validate() == nil {
		t.Error("expected error for invalid daemon name")
	}
}

func TestValidateRejectsCrossSiteProgramCollision(t *testing.T) {
	s := validQueueServer()
	s.Queue = true
	s.Sites[0].Daemons = []Daemon{{Name: "x", Command: "php artisan x"}}
	s.Sites = append(s.Sites, Site{Domain: "app.example.com-x", DeployPath: "/var/www/b",
		User: "buser", Database: SiteDatabase{Name: "b", User: "b"}})
	if s.Validate() == nil {
		t.Error("expected error: two sites map to the same supervisor program berth-app_example_com-x")
	}
}

func TestValidateAcceptsValidQueueAndDaemons(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Processes: 2, Queue: "default,emails", Tries: 3}
	s.Sites[0].Daemons = []Daemon{{Name: "reverb", Command: "php artisan reverb:start"}}
	if err := s.Validate(); err != nil {
		t.Errorf("valid queue+daemons must pass: %v", err)
	}
}

func TestGitHost(t *testing.T) {
	for in, want := range map[string]string{
		"git@github.com:owner/repo.git":        "github.com",
		"https://github.com/owner/repo.git":    "github.com",
		"ssh://git@example.org:22/owner/r.git": "example.org",
	} {
		got, err := GitHost(in)
		if err != nil || got != want {
			t.Errorf("GitHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestDatabaseChoices(t *testing.T) {
	got := DatabaseChoices()
	want := []DatabaseChoice{
		{Engine: "mariadb", Source: "debian", Label: "MariaDB (Debian)"},
		{Engine: "mariadb", Source: "mariadb", Label: "MariaDB (mariadb.org)"},
		{Engine: "postgres", Source: "debian", Label: "PostgreSQL (Debian)"},
		{Engine: "postgres", Source: "pgdg", Label: "PostgreSQL (pgdg)"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DatabaseChoices() =\n %+v\nwant\n %+v", got, want)
	}
	for _, c := range got {
		s := &Server{
			Host: "h.example", SSH: SSH{Port: 22}, PHP: PHP{Version: "8.5", Source: "auto"},
			Nginx: Nginx{Source: "debian"}, Database: Database{Engine: c.Engine, Source: c.Source},
			Sites: []Site{{Domain: "a.example", DeployPath: "/srv/a", Database: SiteDatabase{Name: "a", User: "a"}}},
		}
		if err := s.Validate(); err != nil {
			t.Errorf("choice %+v rejected by Validate: %v", c, err)
		}
	}
}

func TestValidFingerprint(t *testing.T) {
	cases := []struct {
		fp string
		ok bool
	}{
		{"", true},
		{"SHA256:oP7LMMAE8JnXUfq6N8eUvsvdyIBNTXhcLAnNynp9BfA", true},
		{"oP7LMMAE8JnXUfq6N8eUvsvdyIBNTXhcLAnNynp9BfA", false},
		{"SHA256:not-base64-$$$", false},
		{"SHA256:YWJj", false},
		{"MD5:aa:bb:cc", false},
	}
	for _, c := range cases {
		err := ValidFingerprint(c.fp)
		if (err == nil) != c.ok {
			t.Errorf("ValidFingerprint(%q) err=%v, want ok=%v", c.fp, err, c.ok)
		}
	}
}

func TestSystemValidate(t *testing.T) {
	cases := []struct {
		name    string
		sys     System
		wantErr bool
	}{
		{"empty is off", System{}, false},
		{"sysctl only", System{Sysctl: true}, false},
		{"swap 2G", System{Swap: "2G"}, false},
		{"swap 512M", System{Swap: "512M"}, false},
		{"swap lowercase g", System{Swap: "2g"}, false},
		{"swap lowercase m", System{Swap: "512m"}, false},
		{"swap zero", System{Swap: "0G"}, true},
		{"swap no unit", System{Swap: "2"}, true},
		{"swap GB two letters", System{Swap: "2GB"}, true},
		{"swap trailing space", System{Swap: "2G "}, true},
		{"swap negative", System{Swap: "-1G"}, true},
		{"swap kilobytes unit", System{Swap: "1024K"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sys.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateCloudflareOnlyLetsEncrypt(t *testing.T) {
	base := func() *Server {
		s := validQueueServer()
		s.Sites[0].SSL = true
		s.Sites[0].SSLEmail = "ops@example.com"
		return s
	}
	on, off := true, false
	cases := []struct {
		name    string
		mutate  func(*Server)
		wantErr bool
	}{
		{"server-wide cloudflare_only with default letsencrypt", func(s *Server) { s.CloudflareOnly = true }, true},
		{"per-site override on with explicit letsencrypt", func(s *Server) { s.Sites[0].CloudflareOnly = &on; s.Sites[0].SSLMode = "letsencrypt" }, true},
		{"cloudflare_only with selfsigned", func(s *Server) { s.CloudflareOnly = true; s.Sites[0].SSLMode = "selfsigned" }, false},
		{"cloudflare_only without ssl", func(s *Server) { s.CloudflareOnly = true; s.Sites[0].SSL = false; s.Sites[0].SSLEmail = "" }, false},
		{"per-site override off under server-wide on", func(s *Server) { s.CloudflareOnly = true; s.Sites[0].CloudflareOnly = &off }, false},
		{"cloudflare_only with default letsencrypt and no email reports the pairing", func(s *Server) { s.CloudflareOnly = true; s.Sites[0].SSLEmail = "" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mutate(s)
			err := s.Validate()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "cloudflare_only") {
					t.Fatalf("Validate() = %v, want cloudflare_only pairing error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

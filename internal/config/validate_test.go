package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func base() *Server {
	return &Server{
		ID:       "test-machine-0001",
		Host:     "203.0.113.10",
		SSH:      SSH{User: "root", Port: 22},
		PHP:      PHP{Version: "8.5", Source: "auto"},
		Nginx:    Nginx{Source: "debian"},
		Database: Database{Engine: "mariadb", Source: "debian"},
		Sites:    []Site{{Domain: "app.example.com", DeployPath: "/var/www/app", Database: SiteDatabase{Name: "myapp", User: "myapp"}}},
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

func TestValidateAllowsManyValkeySites(t *testing.T) {
	s := base()
	s.Valkey = true
	s.Sites = nil
	for i := range 17 {
		s.Sites = append(s.Sites, Site{
			Domain:     fmt.Sprintf("site%02d.example.com", i),
			DeployPath: fmt.Sprintf("/var/www/site%02d", i),
			Database:   SiteDatabase{Name: fmt.Sprintf("db%02d", i), User: fmt.Sprintf("u%02d", i)},
		})
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("17 valkey sites must validate (per-site instances have no shared index space): %v", err)
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
		ID:   "test-machine-0001",
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

	// Sites without their own database blocks -> rejected (there is no
	// top-level fallback to inherit from).
	bad := multiSite()
	bad.Sites[0].Database = SiteDatabase{}
	bad.Sites[1].Database = SiteDatabase{}
	if err := bad.Validate(); err == nil {
		t.Error("expected error when sites have no database block")
	}

	// Two sites sharing a database user -> rejected (isolation).
	dupUser := multiSite()
	dupUser.Sites[1].Database.User = "one_user"
	if err := dupUser.Validate(); err == nil {
		t.Error("expected error when two sites share a database user")
	}
}

func TestValidateSiteMissingDatabaseBlock(t *testing.T) {
	// Every site must carry its own full database block; there is no top-level
	// fallback to inherit from. The refusal fires before the SQL-identifier
	// checks so the message names the real problem.
	cases := []struct {
		name string
		db   SiteDatabase
	}{
		{"missing-both", SiteDatabase{}},
		{"missing-user", SiteDatabase{Name: "myapp"}},
		{"missing-name", SiteDatabase{User: "myapp"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := base()
			s.Sites[0].Database = c.db
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), "missing database block") {
				t.Fatalf("%s: a site without a full database: {name, user} must be rejected, got %v", c.name, err)
			}
		})
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Server){
		"bad php version":  func(s *Server) { s.PHP.Version = "9.9" },
		"bad php source":   func(s *Server) { s.PHP.Source = "ppa" },
		"bad db name":      func(s *Server) { s.Sites[0].Database.Name = "my-app; DROP" },
		"bad engine":       func(s *Server) { s.Database.Engine = "oracle" },
		"bad nginx source": func(s *Server) { s.Nginx.Source = "openresty" },
		"bad db source":    func(s *Server) { s.Database.Source = "percona" },
		"pg with mariadb source": func(s *Server) {
			s.Database.Engine = "postgres"
			s.Database.Source = "mariadb" // wrong upstream for postgres
		},
		"relative path":          func(s *Server) { s.Sites[0].DeployPath = "deploy/x" },
		"shell meta path":        func(s *Server) { s.Sites[0].DeployPath = "/home/$(whoami)" },
		"quote in path":          func(s *Server) { s.Sites[0].DeployPath = `/srv/a"b` },
		"glob in path":           func(s *Server) { s.Sites[0].DeployPath = "/srv/*" },
		"unclean trailing slash": func(s *Server) { s.Sites[0].DeployPath = "/var/www/app/" },
		"unclean dotdot":         func(s *Server) { s.Sites[0].DeployPath = "/var/www/../etc/app" },
		"top-level path":         func(s *Server) { s.Sites[0].DeployPath = "/app" },
		"system tree etc":        func(s *Server) { s.Sites[0].DeployPath = "/etc/nginx" },
		"system tree usr":        func(s *Server) { s.Sites[0].DeployPath = "/usr/local/app" },
		"home tree":              func(s *Server) { s.Sites[0].DeployPath = "/home/deploy/app" },
		"home root":              func(s *Server) { s.Sites[0].DeployPath = "/home/deploy" },
		"var non-www lib":        func(s *Server) { s.Sites[0].DeployPath = "/var/lib/app" },
		"var non-www crash":      func(s *Server) { s.Sites[0].DeployPath = "/var/crash/app" },
		"var non-www snap":       func(s *Server) { s.Sites[0].DeployPath = "/var/snap/app" },
		"shared web root":        func(s *Server) { s.Sites[0].DeployPath = "/var/www" },
		"acme webroot subtree":   func(s *Server) { s.Sites[0].DeployPath = "/var/www/berth-acme/x" },
		"ssl no email":           func(s *Server) { s.Sites[0].SSL = true },
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
		"uppercase domain":               func(s *Server) { s.Sites[0].Domain = "App.Example.com" },
		// U+017F (long s) case-folds to 's' under (?i), so it used to sneak
		// through BOTH the hostname regex and the lowercase guard
		// (ToLower(U+017F) == U+017F). Explicit ASCII classes reject it.
		"unicode long-s domain": func(s *Server) { s.Sites[0].Domain = "eſample.com" },
		"unicode long-s host":   func(s *Server) { s.Host = "eſample.com" },
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

func TestDomainErrorMessages(t *testing.T) {
	up := base()
	up.Sites[0].Domain = "App.Example.com"
	if err := up.Validate(); err == nil || !strings.Contains(err.Error(), "must be lowercase") {
		t.Fatalf("uppercase domain must keep the lowercase hint; got %v", err)
	}
	folded := base()
	folded.Sites[0].Domain = "eſample.com"
	if err := folded.Validate(); err == nil || !strings.Contains(err.Error(), "not a valid hostname") {
		t.Fatalf("U+017F domain must fail the hostname regex; got %v", err)
	}
}

func TestValidateAcceptsLowercaseDomain(t *testing.T) {
	s := base()
	s.Sites[0].Domain = "app.example.com"
	if err := s.Validate(); err != nil {
		t.Errorf("a lowercase domain must validate, got %v", err)
	}
}

// TestValidateDomainLengthBoundary pins the derived-artifact length guard.
// berth derives on-host names from the domain (poolName only swaps dots for
// underscores, so len(pool) == len(domain)); an over-long but RFC-valid
// hostname used to pass validation and then EVERY Apply failed permanently
// creating the derived socket/cron artifacts. The longest accepted length
// must pass and one more character must fail.
func TestValidateDomainLengthBoundary(t *testing.T) {
	// The cap must be the TRUE universal hard bound, not a headroom pick: the
	// tightest budget is the per-site Valkey socket path against sun_path,
	// 107 - 30 = 77 (unconditionally, so a config never turns invalid the day
	// valkey: true is switched on). A lower cap rejects working 71-77 char
	// domains; recompute before moving this.
	if maxSiteDomainLen != 77 {
		t.Fatalf("maxSiteDomainLen = %d, want the universal hard bound 77 (= 107-byte sun_path - 30-byte Valkey socket overhead)", maxSiteDomainLen)
	}
	// 63-char label + "." + filler label + ".com" -> total is 68 + len(filler).
	domain := func(total int) string {
		return strings.Repeat("a", 63) + "." + strings.Repeat("b", total-68) + ".com"
	}
	ok := base()
	ok.Sites[0].Domain = domain(maxSiteDomainLen)
	if len(ok.Sites[0].Domain) != maxSiteDomainLen {
		t.Fatalf("fixture bug: built a %d-char domain, want %d", len(ok.Sites[0].Domain), maxSiteDomainLen)
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a %d-char domain must validate: %v", maxSiteDomainLen, err)
	}
	bad := base()
	bad.Sites[0].Domain = domain(maxSiteDomainLen + 1)
	err := bad.Validate()
	if err == nil {
		t.Fatalf("a %d-char domain must be rejected: its derived artifact names exceed kernel limits", maxSiteDomainLen+1)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(maxSiteDomainLen)) {
		t.Errorf("the error must state the limit; got %v", err)
	}
}

// TestDomainCapMatchesPrefixArithmetic derives the domain cap from the LIVE
// name-prefix constants instead of restating 77: growing a prefix must break
// this test at build time, not re-open the every-Apply-fails bug the cap fixed
// (an accepted domain whose derived socket path exceeds sun_path).
func TestDomainCapMatchesPrefixArithmetic(t *testing.T) {
	// poolName only swaps dots for underscores, so len(pool) == len(domain).
	// The tightest budget is the per-site Valkey socket against the 107 usable
	// sun_path bytes; it applies unconditionally (a domain must never turn
	// invalid the day valkey: true is switched on).
	valkeyBudget := 107 - len(ValkeyRunBase+"/") - len("/valkey.sock")
	if maxSiteDomainLen != valkeyBudget {
		t.Errorf("maxSiteDomainLen = %d, want %d = 107 - len(%q+\"/\") - len(\"/valkey.sock\")",
			maxSiteDomainLen, valkeyBudget, ValkeyRunBase)
	}
	// The FPM socket budget must stay at least as loose, or the Valkey budget
	// is no longer the tightest bound and the cap needs recomputing.
	fpmBudget := 107 - len(FPMSocketPrefix) - len(".sock")
	if fpmBudget < maxSiteDomainLen {
		t.Errorf("FPM socket budget %d (from FPMSocketPrefix %q) is tighter than maxSiteDomainLen %d — recompute the cap",
			fpmBudget, FPMSocketPrefix, maxSiteDomainLen)
	}
}

func TestValidateDeployPathDeniesEverySystemRoot(t *testing.T) {
	// Every entry of the deny-list must be refused both as an exact path (the
	// depth>=2 rule catches single-component roots) and as a parent of the
	// deploy_path (the prefix branch).
	for _, root := range []string{
		"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
		"/libx32", "/media", "/mnt", "/proc", "/root", "/run", "/sbin", "/sys",
		"/tmp", "/usr",
	} {
		for _, p := range []string{root, root + "/app"} {
			s := base()
			s.Sites[0].DeployPath = p
			if err := s.Validate(); err == nil {
				t.Errorf("deploy_path %s must be rejected", p)
			}
		}
	}
}

func TestValidateDeployPathIsolation(t *testing.T) {
	// Accepted: disjoint sibling paths that merely share a string prefix.
	ok := multiSite()
	ok.Sites[0].DeployPath = "/var/www/app-one"
	ok.Sites[1].DeployPath = "/var/www/app-two"
	if err := ok.Validate(); err != nil {
		t.Errorf("sibling deploy_paths sharing a string prefix must pass, got %v", err)
	}

	// Rejected: one site's deploy_path nested inside another's (either order).
	nested := multiSite()
	nested.Sites[0].DeployPath = "/var/www/app"
	nested.Sites[1].DeployPath = "/var/www/app/blog"
	if err := nested.Validate(); err == nil {
		t.Error("expected error for nested deploy_paths (child after parent)")
	}
	reversed := multiSite()
	reversed.Sites[0].DeployPath = "/var/www/app/blog"
	reversed.Sites[1].DeployPath = "/var/www/app"
	if err := reversed.Validate(); err == nil {
		t.Error("expected error for nested deploy_paths (parent after child)")
	}
}

func TestValidateDeployPathAcceptsCommonLayouts(t *testing.T) {
	for _, p := range []string{"/var/www/app", "/srv/app", "/opt/apps/site", "/data/app"} {
		s := base()
		s.Sites[0].DeployPath = p
		if err := s.Validate(); err != nil {
			t.Errorf("deploy_path %s should validate, got %v", p, err)
		}
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
		ID:   "test-machine-0001",
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

func TestValidateQueueDriverNone(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Driver: "none"}
	if err := s.Validate(); err != nil {
		t.Errorf("driver none alone must be valid: %v", err)
	}

	s = validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Driver: "none", Processes: 2}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "queue: none disables the worker") {
		t.Errorf("none + processes must be rejected with the none-excludes-knobs message; got %v", err)
	}

	s = validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Driver: "none", Connection: "redis"}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "queue: none disables the worker") {
		t.Errorf("none + connection must be rejected with the none-excludes-knobs message; got %v", err)
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

func TestValidateRejectsNegativePHPTuning(t *testing.T) {
	s := validQueueServer()
	s.Tuning = Tuning{PHPMaxExecutionTime: -5}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "php_max_execution_time") {
		t.Errorf("negative php_max_execution_time must be rejected; got %v", err)
	}

	s = validQueueServer()
	s.Tuning = Tuning{PHPMaxInputVars: -1}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "php_max_input_vars") {
		t.Errorf("negative php_max_input_vars must be rejected; got %v", err)
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

func TestValidateAcceptsRedisClusterHashTagQueue(t *testing.T) {
	// Redis Cluster requires all of a queue's keys in one slot; Laravel's
	// documented form is a hash-tagged name like {default}. Braces are inert on
	// the supervisor command line (no shell, whitespace-only word split).
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Queue: "{default}"}
	if err := s.Validate(); err != nil {
		t.Errorf("hash-tagged queue name must validate: %v", err)
	}
}

func TestValidateRejectsSpaceInQueueName(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Queue: "high default"}
	if s.Validate() == nil {
		t.Error("expected error: a space in queue.queue splits the supervisor command line into extra argv tokens")
	}
}

func TestValidateRejectsSpaceInQueueConnection(t *testing.T) {
	s := validQueueServer()
	s.Sites[0].Queue = &QueueConfig{Connection: "redis extra"}
	if s.Validate() == nil {
		t.Error("expected error: a space in queue.connection splits the supervisor command line into extra argv tokens")
	}
}

func TestGitEndpoint(t *testing.T) {
	for _, tc := range []struct {
		in, host, port string
	}{
		{"git@github.com:owner/repo.git", "github.com", ""},
		{"ssh://git@example.com/x.git", "example.com", ""},
		{"ssh://git@example.com:2222/x.git", "example.com", "2222"},
		// An explicit :22 is OpenSSH's default: known_hosts stores it under the
		// bare hostname, so the port must normalize away or a "[host]:22" probe
		// would never match what ssh-keyscan -p 22 writes.
		{"ssh://git@example.org:22/owner/r.git", "example.org", ""},
	} {
		host, port, err := GitEndpoint(tc.in)
		if err != nil || host != tc.host || port != tc.port {
			t.Errorf("GitEndpoint(%q) = %q, %q, %v; want %q, %q", tc.in, host, port, err, tc.host, tc.port)
		}
	}
	if _, _, err := GitEndpoint("not-a-git-url"); err == nil {
		t.Error("expected an error for an unparseable repository string")
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
			ID:   "test-machine-0001",
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

func TestIsValidSiteOSUser(t *testing.T) {
	for name, want := range map[string]bool{
		"deploy":         true,
		"b_app_1a2b3c4d": true,
		"root":           false, // reserved
		"www-data":       false, // reserved
		"berth":          false, // reserved
		"UNKNOWN":        false, // stat %U for a deleted owner — uppercase fails the regex
		"1003":           false, // numeric uid
		"":               false,
	} {
		if got := IsValidSiteOSUser(name); got != want {
			t.Errorf("IsValidSiteOSUser(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestValidateServerID(t *testing.T) {
	// Field-level: "" is deliberately legal HERE — the wizard validates the
	// prompt BEFORE auto-generating an id, so blank means "generate one".
	// Only Server.Validate (TestValidateRequiresID) rejects an empty id.
	if err := ValidateServerID(""); err != nil {
		t.Errorf(`ValidateServerID("") must stay nil (wizard pre-generation layer): %v`, err)
	}
	ok := []string{"ab", "prod-web-1a2b3c", "a.b_c-9", "x0"}
	for _, id := range ok {
		if err := ValidateServerID(id); err != nil {
			t.Errorf("ValidateServerID(%q) = %v, want nil", id, err)
		}
		s := base()
		s.ID = id
		if err := s.Validate(); err != nil {
			t.Errorf("id %q must validate: %v", id, err)
		}
	}
	bad := []string{"a", "A-upper", "-lead", "trail-", "spa ce", "zażółć", strings.Repeat("x", 65)}
	for _, id := range bad {
		if err := ValidateServerID(id); err == nil {
			t.Errorf("ValidateServerID(%q) = nil, want error", id)
		}
		s := base()
		s.ID = id
		if err := s.Validate(); err == nil {
			t.Errorf("id %q must be rejected", id)
		}
	}
}

func TestValidateRequiresID(t *testing.T) {
	s := base()
	s.ID = ""
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "id") || !strings.Contains(err.Error(), "berth init") {
		t.Fatalf("an empty id must be rejected with `berth init` advice; got %v", err)
	}
}

func TestParseSwapBytesBoundaries(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"2G", 2 << 30, true},
		{"512M", 512 << 20, true},
		{"1024G", 1 << 40, true},    // exactly 1 TiB
		{"1048576M", 1 << 40, true}, // exactly 1 TiB in MiB
		{"1025G", 0, false},         // one unit over the cap
		{"1048577M", 0, false},
		{"9999999999G", 0, false}, // would overflow int64 without the cap
		{"0G", 0, false},
		{"2T", 0, false},
		{"", 0, false},
	} {
		got, err := ParseSwapBytes(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("ParseSwapBytes(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("ParseSwapBytes(%q) must be rejected", c.in)
		}
	}
	// The authoritative path: a config with an overflowing swap fails Validate.
	s := base()
	s.System.Swap = "9999999999G"
	if err := s.Validate(); err == nil {
		t.Error("Validate must reject an overflowing system.swap")
	}
}

func TestOffsiteValidate(t *testing.T) {
	s3Valid := func() *Offsite {
		return &Offsite{Backend: "s3", Endpoint: "s3.example.com", Bucket: "b"}
	}
	sftpValid := func() *Offsite {
		return &Offsite{
			Backend: "sftp", Host: "h.example.net", User: "u", Path: "/srv/b",
			HostKey: "h.example.net ssh-ed25519 AAAA",
		}
	}
	mutS3 := func(f func(*Offsite)) *Offsite { o := s3Valid(); f(o); return o }
	mutSFTP := func(f func(*Offsite)) *Offsite { o := sftpValid(); f(o); return o }
	cases := []struct {
		name       string
		offsite    *Offsite
		backupsOff bool   // leave server-wide backups.enabled false (default: on)
		wantErr    string // "" = the config must validate
	}{
		{name: "s3-valid", offsite: s3Valid()},
		{name: "sftp-valid", offsite: sftpValid()},
		{name: "unknown-backend", offsite: &Offsite{Backend: "rsync"}, wantErr: "backups.offsite.backend"},
		{name: "s3-missing-bucket", offsite: &Offsite{Backend: "s3", Endpoint: "e.example.com"}, wantErr: "requires endpoint and bucket"},
		{name: "sftp-missing-hostkey", offsite: &Offsite{Backend: "sftp", Host: "h.example.net", User: "u", Path: "/srv/b"}, wantErr: "requires host, user, path and host_key"},
		{name: "sftp-relative-path", offsite: mutSFTP(func(o *Offsite) { o.Path = "srv/b" }), wantErr: "must be absolute"},
		{name: "s3-field-on-sftp", offsite: mutSFTP(func(o *Offsite) { o.Bucket = "b" }), wantErr: "only valid for backend s3"},
		{name: "sftp-field-on-s3", offsite: mutS3(func(o *Offsite) { o.Host = "h.example.net" }), wantErr: "only valid for backend sftp"},
		{name: "quote-injection", offsite: mutS3(func(o *Offsite) { o.Bucket = "b'x" }), wantErr: "must not contain"},
		{name: "whitespace-endpoint", offsite: mutS3(func(o *Offsite) { o.Endpoint = "e x.example.com" }), wantErr: "must not contain"},
		{name: "bad-schedule", offsite: mutS3(func(o *Offsite) { o.Schedule = "often" }), wantErr: "backups.offsite.schedule"},
		{name: "bad-port", offsite: mutSFTP(func(o *Offsite) { o.Port = 70000 }), wantErr: "backups.offsite.port"},
		{name: "bad-keep", offsite: mutS3(func(o *Offsite) { o.Keep = OffsiteKeep{Daily: -1} }), wantErr: "backups.offsite.keep"},
		{name: "hostkey-wrong-host", offsite: mutSFTP(func(o *Offsite) { o.HostKey = "other.example.net ssh-ed25519 AAAA" }), wantErr: "host_key must pin"},
		{name: "hostile-host", offsite: mutSFTP(func(o *Offsite) { o.Host = "h|e" }), wantErr: "must be a lowercase hostname"},
		{name: "sftp-user-leading-dash", offsite: mutSFTP(func(o *Offsite) { o.User = "-oProxyCommand=x" }), wantErr: "must be a plain login name"},
		{name: "sftp-user-dollar-brace", offsite: mutSFTP(func(o *Offsite) { o.User = "a${IFS}b" }), wantErr: "must be a plain login name"},
		{name: "custom-port-needs-bracket-token", offsite: mutSFTP(func(o *Offsite) { o.Port = 2222 }), wantErr: "host_key must pin"},
		{name: "custom-port-bracket-token-valid", offsite: mutSFTP(func(o *Offsite) {
			o.Port = 2222
			o.HostKey = "[h.example.net]:2222 ssh-ed25519 AAAA"
		})},
		{name: "offsite-without-backups", offsite: s3Valid(), backupsOff: true, wantErr: "requires backups to be enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			s.Backups.Enabled = !tc.backupsOff
			s.Backups.Offsite = tc.offsite
			err := s.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

package wizard

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
)

var reLinuxUserHarness = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// TestConfigMatrix is a table-driven matrix exercising the init wizard across the
// full supported config surface. Each subtest drives one of two paths:
//
//   - ANSWERS: build an Answers, chdir into a temp dir, call a.Write() (which runs
//     ToServer + Validate + serialize), then config.Load() the result. Valid cases
//     assert both succeed plus a property of the loaded *config.Server; invalid
//     cases assert a.Write() returns an error whose message contains an expected
//     substring grounded in internal/config/validate.go.
//   - RUN: script a fakePrompter, call run(), and assert the collected Answers and
//     the recorded f.errors (re-prompt / cap notes).
func TestConfigMatrix(t *testing.T) {
	// ---- answers-path helpers ----

	// chdirTemp chdirs into a fresh temp dir for the duration of the subtest so
	// servers/<name>.yml lands there and is discarded.
	chdirTemp := func(t *testing.T) {
		t.Helper()
		dir := t.TempDir()
		old, _ := os.Getwd()
		t.Cleanup(func() { _ = os.Chdir(old) })
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("chdir: %v", err)
		}
	}

	// writeValid asserts a.Write + config.Load succeed and returns the loaded
	// server plus the raw YAML written to disk.
	writeValid := func(t *testing.T, a Answers) (*config.Server, string) {
		t.Helper()
		chdirTemp(t)
		path, err := a.Write()
		if err != nil {
			t.Fatalf("Write() error = %v (expected valid)", err)
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("ReadFile(%s): %v", path, rerr)
		}
		srv, lerr := config.Load(path)
		if lerr != nil {
			t.Fatalf("config.Load(%s) error = %v", path, lerr)
		}
		return srv, string(raw)
	}

	// writeInvalid asserts a.Write returns a non-nil error and no servers/<name>.yml
	// is written. Returns the error for optional message assertions.
	writeInvalid := func(t *testing.T, a Answers) error {
		t.Helper()
		chdirTemp(t)
		_, err := a.Write()
		if err == nil {
			t.Fatalf("Write() = nil, expected an error (invalid config)")
		}
		if _, sterr := os.Stat("servers/" + a.Name + ".yml"); sterr == nil {
			t.Fatalf("servers/%s.yml was written despite invalid config", a.Name)
		}
		return err
	}

	mustContain := func(t *testing.T, err error, sub string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), sub) {
			t.Fatalf("error %v does not contain %q", err, sub)
		}
	}

	// base builds a defaults()-seeded Answers with a name/host.
	base := func(name, host string) Answers {
		a := defaults()
		a.Name = name
		a.Host = host
		return a
	}

	// validSingleSite returns a minimal valid single-site Answers with the per-site
	// override tristates seeded to "inherit" (the run-path default). Mirrors the
	// neighboring valid cases' construction so the ops/* subtests only have to flip
	// the one block under test.
	validSingleSite := func(t *testing.T) Answers {
		t.Helper()
		a := base("ops", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr",
			SchedulerOverride: "inherit", CloudflareOverride: "inherit", BackupsOverride: "inherit",
		}}
		return a
	}

	// ===================== DB engine x source x nginx x valkey =====================

	t.Run("mariadb-debian-nginxdebian-novalkey", func(t *testing.T) {
		a := base("m1", "db1.example.com")
		a.Sites = []SiteAnswers{{
			Domain: "app1.example.com", DeployPath: "/var/www/app1",
			DBName: "app1", DBUser: "app1", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.Database.Engine != "mariadb" || srv.Database.Source != "debian" || srv.Nginx.Source != "debian" {
			t.Fatalf("db/nginx = %+v / %+v", srv.Database, srv.Nginx)
		}
		if srv.Valkey {
			t.Fatalf("valkey should be false")
		}
		if u := srv.SiteUser(srv.Sites[0]); u != "deploy" {
			t.Fatalf("SiteUser = %q, want deploy", u)
		}
	})

	t.Run("mariadb-debian-nginxorg-novalkey", func(t *testing.T) {
		a := base("m2", "db2.example.com")
		a.NginxSource = "nginx"
		a.Sites = []SiteAnswers{{
			Domain: "app2.example.com", DeployPath: "/var/www/app2",
			DBName: "app2", DBUser: "app2", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.Database.Engine != "mariadb" || srv.Database.Source != "debian" || srv.Nginx.Source != "nginx" || srv.Valkey {
			t.Fatalf("db=%+v nginx=%+v valkey=%v", srv.Database, srv.Nginx, srv.Valkey)
		}
	})

	t.Run("mariadb-mariadborg-nginxdebian-valkey", func(t *testing.T) {
		a := base("m3", "db3.example.com")
		a.DBSource = "mariadb"
		a.Valkey = true
		a.Sites = []SiteAnswers{{
			Domain: "app3.example.com", DeployPath: "/var/www/app3",
			DBName: "app3", DBUser: "app3", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.Database.Engine != "mariadb" || srv.Database.Source != "mariadb" || srv.Nginx.Source != "debian" || !srv.Valkey {
			t.Fatalf("db=%+v nginx=%+v valkey=%v", srv.Database, srv.Nginx, srv.Valkey)
		}
	})

	t.Run("mariadb-mariadborg-nginxorg-valkey", func(t *testing.T) {
		a := base("m4", "db4.example.com")
		a.DBSource = "mariadb"
		a.NginxSource = "nginx"
		a.Valkey = true
		a.Sites = []SiteAnswers{{
			Domain: "app4.example.com", DeployPath: "/var/www/app4",
			DBName: "app4", DBUser: "app4", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "selfsigned", HTTP3: true,
		}}
		srv, _ := writeValid(t, a)
		if srv.Database.Source != "mariadb" || srv.Nginx.Source != "nginx" || !srv.Valkey {
			t.Fatalf("db=%+v nginx=%+v valkey=%v", srv.Database, srv.Nginx, srv.Valkey)
		}
		if !srv.Sites[0].HTTP3 || !srv.Sites[0].SSL || srv.Sites[0].SSLMode != "selfsigned" {
			t.Fatalf("site tls = %+v", srv.Sites[0])
		}
	})

	t.Run("postgres-debian-nginxdebian-novalkey", func(t *testing.T) {
		a := base("p1", "db5.example.com")
		a.DBEngine, a.DBSource = "postgres", "debian"
		a.Sites = []SiteAnswers{{
			Domain: "app5.example.com", DeployPath: "/var/www/app5",
			DBName: "app5", DBUser: "app5", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.Database.Engine != "postgres" || srv.Database.Source != "debian" || srv.Nginx.Source != "debian" || srv.Valkey {
			t.Fatalf("db=%+v nginx=%+v valkey=%v", srv.Database, srv.Nginx, srv.Valkey)
		}
	})

	t.Run("postgres-debian-nginxorg-valkey", func(t *testing.T) {
		a := base("p2", "db6.example.com")
		a.DBEngine, a.DBSource = "postgres", "debian"
		a.NginxSource = "nginx"
		a.Valkey = true
		a.Sites = []SiteAnswers{{
			Domain: "app6.example.com", DeployPath: "/var/www/app6",
			DBName: "app6", DBUser: "app6", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "letsencrypt", SSLEmail: "ops@example.com",
		}}
		srv, _ := writeValid(t, a)
		if srv.Database.Engine != "postgres" || srv.Database.Source != "debian" || srv.Nginx.Source != "nginx" || !srv.Valkey {
			t.Fatalf("db=%+v nginx=%+v valkey=%v", srv.Database, srv.Nginx, srv.Valkey)
		}
		if !srv.Sites[0].SSL || srv.Sites[0].CertMode() != "letsencrypt" || srv.Sites[0].SSLEmail != "ops@example.com" {
			t.Fatalf("site tls = %+v", srv.Sites[0])
		}
	})

	t.Run("postgres-pgdg-nginxdebian-novalkey", func(t *testing.T) {
		a := base("p3", "db7.example.com")
		a.DBEngine, a.DBSource = "postgres", "pgdg"
		a.Sites = []SiteAnswers{{
			Domain: "app7.example.com", DeployPath: "/var/www/app7",
			DBName: "app7", DBUser: "app7", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.Database.Engine != "postgres" || srv.Database.Source != "pgdg" || srv.Nginx.Source != "debian" || srv.Valkey {
			t.Fatalf("db=%+v nginx=%+v valkey=%v", srv.Database, srv.Nginx, srv.Valkey)
		}
	})

	t.Run("postgres-pgdg-nginxorg-valkey-2site", func(t *testing.T) {
		a := base("p4", "db8.example.com")
		a.DBEngine, a.DBSource = "postgres", "pgdg"
		a.NginxSource = "nginx"
		a.Valkey = true
		a.Sites = []SiteAnswers{
			{Domain: "a8.example.com", DeployPath: "/var/www/a8", DBName: "a8", DBUser: "a8",
				SchedulerOverride: "inherit", SSL: true, SSLMode: "selfsigned", HTTP3: true},
			{Domain: "b8.example.com", DeployPath: "/var/www/b8", DBName: "b8", DBUser: "b8",
				SchedulerOverride: "inherit"},
		}
		srv, _ := writeValid(t, a)
		if srv.Database.Source != "pgdg" || srv.Nginx.Source != "nginx" || !srv.Valkey {
			t.Fatalf("db=%+v nginx=%+v valkey=%v", srv.Database, srv.Nginx, srv.Valkey)
		}
		if len(srv.Sites) != 2 {
			t.Fatalf("want 2 sites, got %d", len(srv.Sites))
		}
		u0, u1 := srv.SiteUser(srv.Sites[0]), srv.SiteUser(srv.Sites[1])
		if u0 == u1 {
			t.Fatalf("derived users collide: %q", u0)
		}
		if srv.Sites[0].Database.Name == srv.Sites[1].Database.Name {
			t.Fatalf("db names collide")
		}
	})

	// ===================== TLS branches =====================

	t.Run("single-site-no-tls", func(t *testing.T) {
		a := base("notls", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "plain.example.com", DeployPath: "/srv/plain",
			DBName: "plaindb", DBUser: "plainusr", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.Sites[0].SSL {
			t.Fatalf("SSL should be false")
		}
		if u := srv.SiteUser(srv.Sites[0]); u != "deploy" {
			t.Fatalf("SiteUser = %q, want deploy", u)
		}
		if srv.Sites[0].SSLEmail != "" {
			t.Fatalf("SSLEmail = %q, want empty", srv.Sites[0].SSLEmail)
		}
	})

	t.Run("single-site-letsencrypt-with-email", func(t *testing.T) {
		a := base("le", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "le.example.com", DeployPath: "/srv/le",
			DBName: "ledb", DBUser: "leusr", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "letsencrypt", SSLEmail: "admin@example.com",
		}}
		srv, _ := writeValid(t, a)
		if !srv.Sites[0].SSL || srv.Sites[0].CertMode() != "letsencrypt" || srv.Sites[0].SSLEmail != "admin@example.com" || srv.Sites[0].HTTP3 {
			t.Fatalf("site = %+v", srv.Sites[0])
		}
	})

	t.Run("single-site-letsencrypt-default-mode-empty-sslmode", func(t *testing.T) {
		a := base("ledefault", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "def.example.com", DeployPath: "/srv/def",
			DBName: "defdb", DBUser: "defusr", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "", SSLEmail: "ops@example.com",
		}}
		srv, _ := writeValid(t, a)
		if srv.Sites[0].SSLMode != "" || srv.Sites[0].CertMode() != "letsencrypt" || srv.Sites[0].SSLEmail != "ops@example.com" {
			t.Fatalf("site = %+v certmode=%q", srv.Sites[0], srv.Sites[0].CertMode())
		}
	})

	t.Run("single-site-letsencrypt-missing-email-invalid", func(t *testing.T) {
		a := base("lenomail", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "nomail.example.com", DeployPath: "/srv/nomail",
			DBName: "nmdb", DBUser: "nmusr", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "letsencrypt",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "ssl_email is required when ssl is true with letsencrypt")
	})

	t.Run("single-site-selfsigned-no-email", func(t *testing.T) {
		a := base("selfsigned", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "self.example.com", DeployPath: "/srv/self",
			DBName: "selfdb", DBUser: "selfusr", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "selfsigned",
		}}
		srv, _ := writeValid(t, a)
		if !srv.Sites[0].SSL || srv.Sites[0].CertMode() != "selfsigned" || srv.Sites[0].SSLEmail != "" {
			t.Fatalf("site = %+v", srv.Sites[0])
		}
	})

	t.Run("single-site-http3-with-nginx-upstream-ssl", func(t *testing.T) {
		a := base("http3ok", "203.0.113.10")
		a.NginxSource = "nginx"
		a.Sites = []SiteAnswers{{
			Domain: "h3.example.com", DeployPath: "/srv/h3",
			DBName: "h3db", DBUser: "h3usr", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "letsencrypt", SSLEmail: "tls@example.com", HTTP3: true,
		}}
		srv, _ := writeValid(t, a)
		if srv.Nginx.Source != "nginx" || !srv.Sites[0].HTTP3 || !srv.Sites[0].SSL ||
			srv.Sites[0].CertMode() != "letsencrypt" || srv.Sites[0].SSLEmail != "tls@example.com" {
			t.Fatalf("nginx=%q site=%+v", srv.Nginx.Source, srv.Sites[0])
		}
	})

	t.Run("single-site-http3-with-debian-nginx-invalid", func(t *testing.T) {
		a := base("h3debian", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "h3deb.example.com", DeployPath: "/srv/h3deb",
			DBName: "h3ddb", DBUser: "h3dusr", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "letsencrypt", SSLEmail: "tls@example.com", HTTP3: true,
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "http3 requires nginx.source: nginx")
	})

	t.Run("single-site-http3-without-ssl-invalid", func(t *testing.T) {
		a := base("h3nossl", "203.0.113.10")
		a.NginxSource = "nginx"
		a.Sites = []SiteAnswers{{
			Domain: "h3nossl.example.com", DeployPath: "/srv/h3nossl",
			DBName: "h3ndb", DBUser: "h3nusr", SchedulerOverride: "inherit",
			SSL: false, HTTP3: true,
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "http3 requires ssl: true")
	})

	t.Run("multi-site-mixed-tls-selfsigned-and-letsencrypt", func(t *testing.T) {
		a := base("mixedtls", "203.0.113.10")
		a.Sites = []SiteAnswers{
			{Domain: "le.example.com", DeployPath: "/srv/le", DBName: "ledb", DBUser: "leusr",
				SchedulerOverride: "inherit", SSL: true, SSLMode: "letsencrypt", SSLEmail: "le@example.com"},
			{Domain: "self.example.com", DeployPath: "/srv/self", DBName: "selfdb", DBUser: "selfusr",
				SchedulerOverride: "inherit", SSL: true, SSLMode: "selfsigned"},
		}
		srv, _ := writeValid(t, a)
		if len(srv.Sites) != 2 {
			t.Fatalf("want 2 sites")
		}
		if srv.Sites[0].CertMode() != "letsencrypt" || srv.Sites[0].SSLEmail != "le@example.com" {
			t.Fatalf("site0 = %+v", srv.Sites[0])
		}
		if srv.Sites[1].CertMode() != "selfsigned" || srv.Sites[1].SSLEmail != "" {
			t.Fatalf("site1 = %+v", srv.Sites[1])
		}
		u0, u1 := srv.SiteUser(srv.Sites[0]), srv.SiteUser(srv.Sites[1])
		if u0 == "deploy" || u1 == "deploy" || u0 == u1 {
			t.Fatalf("derived users wrong: %q %q", u0, u1)
		}
	})

	t.Run("multi-site-mixed-tls-one-http3-nginx-upstream", func(t *testing.T) {
		a := base("mixedh3", "203.0.113.10")
		a.NginxSource = "nginx"
		a.Sites = []SiteAnswers{
			{Domain: "h3.example.com", DeployPath: "/srv/h3", DBName: "h3db", DBUser: "h3usr",
				SchedulerOverride: "inherit", SSL: true, SSLMode: "letsencrypt", SSLEmail: "h3@example.com", HTTP3: true},
			{Domain: "self.example.com", DeployPath: "/srv/self", DBName: "selfdb", DBUser: "selfusr",
				SchedulerOverride: "inherit", SSL: true, SSLMode: "selfsigned"},
		}
		srv, _ := writeValid(t, a)
		if srv.Nginx.Source != "nginx" {
			t.Fatalf("nginx = %q", srv.Nginx.Source)
		}
		if !srv.Sites[0].HTTP3 || srv.Sites[0].CertMode() != "letsencrypt" || srv.Sites[0].SSLEmail != "h3@example.com" {
			t.Fatalf("site0 = %+v", srv.Sites[0])
		}
		if srv.Sites[1].HTTP3 || srv.Sites[1].CertMode() != "selfsigned" || srv.Sites[1].SSLEmail != "" {
			t.Fatalf("site1 = %+v", srv.Sites[1])
		}
	})

	// ===================== RUN-path http3 switch =====================

	t.Run("run-http3-accept-switches-nginx-then-valid", func(t *testing.T) {
		f := &fakePrompter{
			serverCore: func(a *Answers) { baseServer(a); a.NginxSource = "debian" },
			siteCore: []func(int, *SiteAnswers){
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "ad", "au"
					sa.SSL, sa.SSLMode, sa.SSLEmail, sa.HTTP3 = true, "letsencrypt", "x@y.com", true
				},
			},
			confirms: []bool{false, true, false, false},
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if a.NginxSource != "nginx" || !a.Sites[0].HTTP3 {
			t.Fatalf("nginx=%q http3=%v", a.NginxSource, a.Sites[0].HTTP3)
		}
		if verr := a.ToServer().Validate(); verr != nil {
			t.Fatalf("validate = %v", verr)
		}
		if len(f.errors) != 0 {
			t.Fatalf("unexpected errors: %v", f.errors)
		}
	})

	t.Run("run-http3-decline-drops-http3-stays-valid", func(t *testing.T) {
		f := &fakePrompter{
			serverCore: func(a *Answers) { baseServer(a); a.NginxSource = "debian" },
			siteCore: []func(int, *SiteAnswers){
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "ad", "au"
					sa.SSL, sa.SSLMode, sa.SSLEmail, sa.HTTP3 = true, "letsencrypt", "x@y.com", true
				},
			},
			confirms: []bool{false, false, false, false},
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if a.NginxSource != "debian" || a.Sites[0].HTTP3 {
			t.Fatalf("nginx=%q http3=%v", a.NginxSource, a.Sites[0].HTTP3)
		}
		if !a.Sites[0].SSL || a.Sites[0].SSLMode != "letsencrypt" || a.Sites[0].SSLEmail != "x@y.com" {
			t.Fatalf("tls intact? %+v", a.Sites[0])
		}
		if verr := a.ToServer().Validate(); verr != nil {
			t.Fatalf("validate = %v", verr)
		}
		if len(f.errors) != 0 {
			t.Fatalf("unexpected errors: %v", f.errors)
		}
	})

	// ===================== OS-user derivation / isolation =====================

	t.Run("two-sites-derived-distinct-users", func(t *testing.T) {
		a := base("twoderive", "203.0.113.10")
		a.Sites = []SiteAnswers{
			{Domain: "alpha.example.com", DeployPath: "/srv/alpha", DBName: "alpha_db", DBUser: "alpha_usr", SchedulerOverride: "inherit"},
			{Domain: "beta.example.com", DeployPath: "/srv/beta", DBName: "beta_db", DBUser: "beta_usr", SchedulerOverride: "inherit"},
		}
		srv, _ := writeValid(t, a)
		if len(srv.Sites) != 2 {
			t.Fatalf("want 2 sites")
		}
		u0 := srv.SiteUser(srv.Sites[0])
		u1 := srv.SiteUser(srv.Sites[1])
		if u0 != config.DerivedSiteUser("alpha.example.com") || u1 != config.DerivedSiteUser("beta.example.com") {
			t.Fatalf("derivation mismatch: %q %q", u0, u1)
		}
		for _, u := range []string{u0, u1} {
			if !strings.HasPrefix(u, "b_") || u == "deploy" {
				t.Fatalf("user %q not derived", u)
			}
			if !reLinuxUserHarness.MatchString(u) {
				t.Fatalf("user %q invalid linux name", u)
			}
		}
		if u0 == u1 {
			t.Fatalf("users not distinct")
		}
	})

	t.Run("single-site-blank-user-is-deploy", func(t *testing.T) {
		a := base("onesite", "203.0.113.11")
		a.Sites = []SiteAnswers{{
			Domain: "solo.example.com", DeployPath: "/srv/solo",
			DBName: "solo_db", DBUser: "solo_usr", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if len(srv.Sites) != 1 {
			t.Fatalf("want 1 site")
		}
		if u := srv.SiteUser(srv.Sites[0]); u != "deploy" {
			t.Fatalf("SiteUser = %q, want deploy", u)
		}
	})

	t.Run("three-sites-explicit-hyphenated-users", func(t *testing.T) {
		a := base("threesplit", "203.0.113.12")
		a.DBEngine, a.DBSource = "postgres", "pgdg"
		a.Sites = []SiteAnswers{
			{Domain: "one.example.com", DeployPath: "/srv/one", User: "app-one", DBName: "one_db", DBUser: "one_usr", SchedulerOverride: "inherit"},
			{Domain: "two.example.com", DeployPath: "/srv/two", User: "app-two", DBName: "two_db", DBUser: "two_usr", SchedulerOverride: "inherit"},
			{Domain: "three.example.com", DeployPath: "/srv/three", User: "app-sync", DBName: "three_db", DBUser: "three_usr", SchedulerOverride: "inherit"},
		}
		srv, _ := writeValid(t, a)
		if len(srv.Sites) != 3 {
			t.Fatalf("want 3 sites")
		}
		want := []string{"app-one", "app-two", "app-sync"}
		for i, w := range want {
			if u := srv.SiteUser(srv.Sites[i]); u != w {
				t.Fatalf("SiteUser[%d] = %q, want %q", i, u, w)
			}
		}
	})

	t.Run("two-sites-mixed-derived-and-explicit", func(t *testing.T) {
		a := base("mixedusers", "203.0.113.13")
		a.DBSource = "mariadb"
		a.Sites = []SiteAnswers{
			{Domain: "derived.example.com", DeployPath: "/srv/derived", DBName: "derived_db", DBUser: "derived_usr", SchedulerOverride: "inherit"},
			{Domain: "pinned.example.com", DeployPath: "/srv/pinned", User: "app_pinned", DBName: "pinned_db", DBUser: "pinned_usr", SchedulerOverride: "inherit"},
		}
		srv, _ := writeValid(t, a)
		u0 := srv.SiteUser(srv.Sites[0])
		u1 := srv.SiteUser(srv.Sites[1])
		if u0 != config.DerivedSiteUser("derived.example.com") || !strings.HasPrefix(u0, "b_") {
			t.Fatalf("site0 user = %q", u0)
		}
		if u1 != "app_pinned" {
			t.Fatalf("site1 user = %q", u1)
		}
		if u0 == u1 {
			t.Fatalf("users not distinct")
		}
	})

	t.Run("valkey-exactly-16-sites", func(t *testing.T) {
		a := base("valkey16", "203.0.113.14")
		a.Valkey = true
		for k := 0; k < 16; k++ {
			n := strconv.Itoa(k)
			a.Sites = append(a.Sites, SiteAnswers{
				Domain: "s" + n + ".example.com", DeployPath: "/srv/s" + n,
				DBName: "db_s" + n, DBUser: "usr_s" + n, SchedulerOverride: "inherit",
			})
		}
		srv, _ := writeValid(t, a)
		if len(srv.Sites) != 16 || !srv.Valkey {
			t.Fatalf("sites=%d valkey=%v", len(srv.Sites), srv.Valkey)
		}
		seen := map[string]bool{}
		for i := range srv.Sites {
			u := srv.SiteUser(srv.Sites[i])
			if !strings.HasPrefix(u, "b_") || u == "deploy" || seen[u] {
				t.Fatalf("user %q bad/dup", u)
			}
			seen[u] = true
		}
	})

	t.Run("valkey-17-sites-over-cap", func(t *testing.T) {
		a := base("valkey17", "203.0.113.15")
		a.Valkey = true
		for k := 0; k < 17; k++ {
			n := strconv.Itoa(k)
			a.Sites = append(a.Sites, SiteAnswers{
				Domain: "s" + n + ".example.com", DeployPath: "/srv/s" + n,
				DBName: "db_s" + n, DBUser: "usr_s" + n, SchedulerOverride: "inherit",
			})
		}
		err := writeInvalid(t, a)
		mustContain(t, err, "valkey: true supports at most 16 sites")
		mustContain(t, err, "got 17")
	})

	t.Run("no-valkey-17-sites-allowed", func(t *testing.T) {
		a := base("novalkey17", "203.0.113.16")
		a.Valkey = false
		for k := 0; k < 17; k++ {
			n := strconv.Itoa(k)
			a.Sites = append(a.Sites, SiteAnswers{
				Domain: "s" + n + ".example.com", DeployPath: "/srv/s" + n,
				DBName: "db_s" + n, DBUser: "usr_s" + n, SchedulerOverride: "inherit",
			})
		}
		srv, _ := writeValid(t, a)
		if len(srv.Sites) != 17 || srv.Valkey {
			t.Fatalf("sites=%d valkey=%v", len(srv.Sites), srv.Valkey)
		}
		seen := map[string]bool{}
		for i := range srv.Sites {
			u := srv.SiteUser(srv.Sites[i])
			if !strings.HasPrefix(u, "b_") || seen[u] {
				t.Fatalf("user %q bad/dup", u)
			}
			seen[u] = true
		}
	})

	t.Run("two-sites-duplicate-derived-user-via-same-domain", func(t *testing.T) {
		a := base("dupderive", "203.0.113.17")
		a.Sites = []SiteAnswers{
			{Domain: "same.example.com", DeployPath: "/srv/one", DBName: "one_db", DBUser: "one_usr", SchedulerOverride: "inherit"},
			{Domain: "same.example.com", DeployPath: "/srv/two", DBName: "two_db", DBUser: "two_usr", SchedulerOverride: "inherit"},
		}
		err := writeInvalid(t, a)
		mustContain(t, err, "domain")
	})

	t.Run("two-sites-explicit-user-collision", func(t *testing.T) {
		a := base("dupexplicit", "203.0.113.18")
		a.Sites = []SiteAnswers{
			{Domain: "first.example.com", DeployPath: "/srv/first", User: "shared_app", DBName: "first_db", DBUser: "first_usr", SchedulerOverride: "inherit"},
			{Domain: "second.example.com", DeployPath: "/srv/second", User: "shared_app", DBName: "second_db", DBUser: "second_usr", SchedulerOverride: "inherit"},
		}
		err := writeInvalid(t, a)
		mustContain(t, err, "same os user")
		mustContain(t, err, "shared_app")
	})

	t.Run("two-sites-one-blank-db-rejected-empty-sqlident", func(t *testing.T) {
		a := base("blankdb", "203.0.113.19")
		a.Sites = []SiteAnswers{
			{Domain: "x.example.com", DeployPath: "/srv/x", DBName: "", DBUser: "", SchedulerOverride: "inherit"},
			{Domain: "y.example.com", DeployPath: "/srv/y", DBName: "y_db", DBUser: "y_usr", SchedulerOverride: "inherit"},
		}
		err := writeInvalid(t, a)
		// Only ONE site has a blank database block (no top-level legacy db is set by
		// ToServer), so inheritLegacyDB == 1 and the "ambiguous, give each site its
		// own database block" branch never fires. The actual rejection is earlier:
		// SiteDBName("") resolves to "" (no legacy top-level name to inherit), and ""
		// is not a valid SQL identifier.
		mustContain(t, err, "is not a valid SQL identifier")
	})

	// ===================== RUN-path valkey cap / re-prompt =====================

	t.Run("run-valkey-16-cap-breaks-loop", func(t *testing.T) {
		cores := make([]func(int, *SiteAnswers), 16)
		for i := range cores {
			cores[i] = func(j int, sa *SiteAnswers) {
				n := strconv.Itoa(j)
				sa.Domain, sa.DeployPath = "s"+n+".example.com", "/srv/s"+n
				sa.DBName, sa.DBUser = "db_s"+n, "usr_s"+n
			}
		}
		confirms := []bool{false} // server-advanced?
		for i := 0; i < 16; i++ {
			confirms = append(confirms, false) // site-advanced?
			if i < 15 {
				confirms = append(confirms, true) // add another?
			}
		}
		f := &fakePrompter{
			serverCore: func(a *Answers) { baseServer(a); a.Valkey = true },
			siteCore:   cores,
			confirms:   confirms,
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if len(a.Sites) != 16 {
			t.Fatalf("want 16 sites, got %d", len(a.Sites))
		}
		if len(f.errors) != 1 {
			t.Fatalf("want exactly 1 cap note, got %v", f.errors)
		}
		if verr := a.ToServer().Validate(); verr != nil {
			t.Fatalf("16-site valkey should validate: %v", verr)
		}
	})

	t.Run("run-multisite-dup-osuser-reprompts-same-site", func(t *testing.T) {
		f := &fakePrompter{
			serverCore: baseServer,
			siteCore: []func(int, *SiteAnswers){
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser, sa.User = "a.example.com", "/srv/a", "a_db", "a_usr", "app_one"
				},
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser, sa.User = "b.example.com", "/srv/b", "b_db", "b_usr", "app_one" // dup user
				},
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser, sa.User = "b.example.com", "/srv/b", "b_db", "b_usr", "app_two" // fixed
				},
			},
			confirms: []bool{false, false, true, false, false},
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if len(a.Sites) != 2 {
			t.Fatalf("want 2 sites, got %d", len(a.Sites))
		}
		if a.Sites[0].User != "app_one" || a.Sites[1].User != "app_two" {
			t.Fatalf("users = %q %q", a.Sites[0].User, a.Sites[1].User)
		}
		if len(f.errors) != 1 {
			t.Fatalf("want exactly 1 error, got %v", f.errors)
		}
		if verr := a.ToServer().Validate(); verr != nil {
			t.Fatalf("validate = %v", verr)
		}
	})

	// ===================== Queue / daemon depth =====================

	t.Run("work-driver-all-knobs-roundtrip", func(t *testing.T) {
		a := base("qd1", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Queue: &QueueAnswers{Driver: "work", Processes: 4, Connection: "redis", Queue: "default,emails", Sleep: 3, Tries: 5, Timeout: 120, MaxMemory: 256},
		}}
		srv, _ := writeValid(t, a)
		q := srv.Sites[0].Queue
		if q == nil || q.Driver != "work" || q.Processes != 4 || q.Connection != "redis" ||
			q.Queue != "default,emails" || q.Sleep != 3 || q.Tries != 5 || q.Timeout != 120 || q.MaxMemory != 256 {
			t.Fatalf("queue = %+v", q)
		}
		if u := srv.SiteUser(srv.Sites[0]); u != "deploy" {
			t.Fatalf("SiteUser = %q", u)
		}
	})

	t.Run("horizon-driver-clean-valid", func(t *testing.T) {
		a := base("qd2", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Queue: &QueueAnswers{Driver: "horizon", Processes: 1},
		}}
		srv, _ := writeValid(t, a)
		q := srv.Sites[0].Queue
		if q == nil || q.Driver != "horizon" || q.Processes != 1 ||
			q.Connection != "" || q.Queue != "" || q.Sleep != 0 || q.Tries != 0 || q.Timeout != 0 || q.MaxMemory != 0 {
			t.Fatalf("queue = %+v", q)
		}
	})

	t.Run("horizon-stray-connection-invalid", func(t *testing.T) {
		a := base("qd3", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Queue: &QueueAnswers{Driver: "horizon", Processes: 1, Connection: "redis"},
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "horizon manages its own workers")
	})

	t.Run("horizon-processes-two-invalid", func(t *testing.T) {
		a := base("qd4", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Queue: &QueueAnswers{Driver: "horizon", Processes: 2},
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "horizon forces numprocs=1")
	})

	t.Run("queue-and-daemons-together-multi-daemon", func(t *testing.T) {
		a := base("qd5", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Queue: &QueueAnswers{Driver: "work", Processes: 2, Sleep: 2, Tries: 3, Timeout: 60, MaxMemory: 128},
			Daemons: []DaemonAnswers{
				{Name: "reverb", Command: "php artisan reverb:start", Processes: 1},
				{Name: "horizon", Command: "php artisan horizon", Processes: 1},
			},
		}}
		srv, _ := writeValid(t, a)
		if srv.Sites[0].Queue == nil || srv.Sites[0].Queue.Driver != "work" || srv.Sites[0].Queue.Processes != 2 {
			t.Fatalf("queue = %+v", srv.Sites[0].Queue)
		}
		d := srv.Sites[0].Daemons
		if len(d) != 2 || d[0].Name != "reverb" || d[0].Command != "php artisan reverb:start" || d[1].Name != "horizon" {
			t.Fatalf("daemons = %+v", d)
		}
		progs := srv.SiteProgramNames(srv.Sites[0])
		want := []string{"berth-a_example_com", "berth-a_example_com-reverb", "berth-a_example_com-horizon"}
		if !eqStrings(progs, want) {
			t.Fatalf("programs = %v, want %v", progs, want)
		}
	})

	t.Run("server-wide-queue-inherited-no-site-block", func(t *testing.T) {
		a := base("qd6", "203.0.113.10")
		a.Queue = true
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if !srv.Queue {
			t.Fatalf("server queue should be true")
		}
		if srv.Sites[0].Queue != nil {
			t.Fatalf("site queue should be nil")
		}
		if !srv.QueueEnabled(srv.Sites[0]) {
			t.Fatalf("QueueEnabled should be true (inherited)")
		}
		progs := srv.SiteProgramNames(srv.Sites[0])
		if !eqStrings(progs, []string{"berth-a_example_com"}) {
			t.Fatalf("programs = %v", progs)
		}
	})

	t.Run("multisite-distinct-queues-and-daemons", func(t *testing.T) {
		a := base("qd7", "203.0.113.10")
		a.DBEngine, a.DBSource = "postgres", "pgdg"
		a.Sites = []SiteAnswers{
			{Domain: "a.example.com", DeployPath: "/srv/a", User: "appa", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
				Queue:   &QueueAnswers{Driver: "horizon", Processes: 1},
				Daemons: []DaemonAnswers{{Name: "reverb", Command: "php artisan reverb:start", Processes: 1}}},
			{Domain: "b.example.com", DeployPath: "/srv/b", User: "appb", DBName: "bdb", DBUser: "busr", SchedulerOverride: "inherit",
				Queue:   &QueueAnswers{Driver: "work", Processes: 3, Connection: "redis", Queue: "default", Sleep: 1, Tries: 2, Timeout: 90, MaxMemory: 200},
				Daemons: []DaemonAnswers{{Name: "reverb", Command: "php artisan reverb:start", Processes: 2}}},
		}
		srv, _ := writeValid(t, a)
		if srv.Sites[0].Queue.Driver != "horizon" || srv.Sites[1].Queue.Driver != "work" {
			t.Fatalf("drivers = %q %q", srv.Sites[0].Queue.Driver, srv.Sites[1].Queue.Driver)
		}
		p0 := srv.SiteProgramNames(srv.Sites[0])
		p1 := srv.SiteProgramNames(srv.Sites[1])
		if !eqStrings(p0, []string{"berth-a_example_com", "berth-a_example_com-reverb"}) {
			t.Fatalf("site0 programs = %v", p0)
		}
		if !eqStrings(p1, []string{"berth-b_example_com", "berth-b_example_com-reverb"}) {
			t.Fatalf("site1 programs = %v", p1)
		}
	})

	t.Run("work-driver-negative-tries-invalid", func(t *testing.T) {
		a := base("qd8", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Queue: &QueueAnswers{Driver: "work", Processes: 2, Tries: -1},
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "queue.tries must not be negative")
	})

	t.Run("work-driver-processes-over-cap-invalid", func(t *testing.T) {
		a := base("qd9", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Queue: &QueueAnswers{Driver: "work", Processes: 65},
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "exceeds the cap of 64")
	})

	t.Run("daemon-blank-command-invalid", func(t *testing.T) {
		a := base("qd10", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Daemons: []DaemonAnswers{{Name: "worker", Command: "   ", Processes: 1}},
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "command is required")
	})

	t.Run("run-queue-and-daemons-orchestration", func(t *testing.T) {
		f := &fakePrompter{
			serverCore: baseServer,
			siteCore: []func(int, *SiteAnswers){
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
				},
			},
			siteOverrides: func(sa *SiteAnswers) { sa.SchedulerOverride = "inherit" },
			queue: func(q *QueueAnswers) {
				q.Driver, q.Processes, q.Connection, q.Queue, q.Sleep, q.Tries, q.Timeout, q.MaxMemory = "work", 2, "redis", "default", 3, 5, 60, 128
			},
			daemons: []func(*DaemonAnswers){
				func(d *DaemonAnswers) { d.Name, d.Command, d.Processes = "reverb", "php artisan reverb:start", 1 },
			},
			// srv-adv? site-adv? dedicated-queue? add-daemon? another-daemon? add-site?
			confirms: []bool{false, true, true, true, false, false},
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if len(a.Sites) != 1 {
			t.Fatalf("want 1 site")
		}
		q := a.Sites[0].Queue
		if q == nil || q.Driver != "work" || q.Processes != 2 || q.Connection != "redis" ||
			q.Queue != "default" || q.Sleep != 3 || q.Tries != 5 || q.Timeout != 60 || q.MaxMemory != 128 {
			t.Fatalf("queue = %+v", q)
		}
		if len(a.Sites[0].Daemons) != 1 || a.Sites[0].Daemons[0].Name != "reverb" {
			t.Fatalf("daemons = %+v", a.Sites[0].Daemons)
		}
		if a.Sites[0].SchedulerOverride != "inherit" {
			t.Fatalf("scheduler = %q", a.Sites[0].SchedulerOverride)
		}
		if len(f.errors) != 0 {
			t.Fatalf("unexpected errors: %v", f.errors)
		}
		if verr := a.ToServer().Validate(); verr != nil {
			t.Fatalf("validate = %v", verr)
		}
	})

	t.Run("run-inherited-server-queue-no-site-advanced", func(t *testing.T) {
		f := &fakePrompter{
			serverCore: func(a *Answers) { baseServer(a); a.Queue = true },
			siteCore: []func(int, *SiteAnswers){
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
				},
			},
			confirms: []bool{false, false, false},
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if len(a.Sites) != 1 {
			t.Fatalf("want 1 site")
		}
		if a.Sites[0].Queue != nil || len(a.Sites[0].Daemons) != 0 {
			t.Fatalf("site queue/daemons should be empty: %+v", a.Sites[0])
		}
		if !a.Queue {
			t.Fatalf("server queue should be true")
		}
		if len(f.errors) != 0 {
			t.Fatalf("unexpected errors: %v", f.errors)
		}
		srv := a.ToServer()
		if srv.Sites[0].Queue != nil {
			t.Fatalf("server site queue should be nil")
		}
		if !srv.QueueEnabled(srv.Sites[0]) {
			t.Fatalf("QueueEnabled should be true (inherited)")
		}
		if !eqStrings(srv.SiteProgramNames(srv.Sites[0]), []string{"berth-a_example_com"}) {
			t.Fatalf("programs = %v", srv.SiteProgramNames(srv.Sites[0]))
		}
	})

	// ===================== Advanced server: fail2ban / tuning / fingerprint / scheduler =====================

	t.Run("advanced-all-empty-defaults-via-accessors", func(t *testing.T) {
		a := base("adv-empty", "vps.example.com")
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		srv, yml := writeValid(t, a)
		// The scenario's intent: an all-empty advanced gate round-trips and relies
		// on runtime defaults. The genuinely-empty artifact is the YAML on disk: the
		// fail2ban/tuning keys are omitted (omitempty over an all-zero block), and
		// the SSH fingerprint is omitted (TOFU). config.Load() then injects the
		// fail2ban defaults (SetDefault bantime=1h/findtime=10m/maxretry=5) — this is
		// documented Load behavior, NOT a wizard surprise — so we assert the empty
		// state on the on-disk YAML, and the validity/nil-scheduler on the loaded srv.
		if strings.Contains(yml, "fail2ban:") {
			t.Fatalf("YAML should omit fail2ban block:\n%s", yml)
		}
		if strings.Contains(yml, "tuning:") {
			t.Fatalf("YAML should omit tuning block:\n%s", yml)
		}
		if strings.Contains(yml, "fingerprint:") {
			t.Fatalf("YAML should omit fingerprint (TOFU):\n%s", yml)
		}
		// Loaded server: fingerprint stays empty (no Load default for it); single
		// site with SchedulerOverride "inherit" maps to a nil *bool.
		if srv.SSH.Fingerprint != "" {
			t.Fatalf("fingerprint not empty: %q", srv.SSH.Fingerprint)
		}
		if len(srv.Sites) != 1 || srv.Sites[0].Scheduler != nil {
			t.Fatalf("site scheduler should be nil: %+v", srv.Sites[0].Scheduler)
		}
	})

	t.Run("fail2ban-all-fields-set-valid", func(t *testing.T) {
		a := base("adv-f2b", "203.0.113.20")
		a.Fail2ban = Fail2banAnswers{Bantime: "1h", Findtime: "10m", Maxretry: 5}
		a.Sites = []SiteAnswers{{
			Domain: "site.example.com", DeployPath: "/srv/site", DBName: "sitedb", DBUser: "siteuser", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.Fail2ban.Bantime != "1h" || srv.Fail2ban.Findtime != "10m" || srv.Fail2ban.Maxretry != 5 {
			t.Fatalf("fail2ban = %+v", srv.Fail2ban)
		}
	})

	t.Run("fail2ban-maxretry-over-100-invalid", func(t *testing.T) {
		a := base("adv-f2b-bad", "vps.example.com")
		a.Fail2ban = Fail2banAnswers{Bantime: "30m", Maxretry: 101}
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "fail2ban.maxretry")
		mustContain(t, err, "out of range")
	})

	t.Run("fail2ban-bantime-bad-suffix-invalid", func(t *testing.T) {
		a := base("adv-f2b-time", "vps.example.com")
		a.Fail2ban = Fail2banAnswers{Bantime: "1y"}
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "fail2ban.bantime")
	})

	t.Run("tuning-all-fields-set-valid", func(t *testing.T) {
		a := base("adv-tune", "vps.example.com")
		a.Valkey = true
		a.Tuning = TuningAnswers{ValkeyMaxmemory: "256mb", ValkeyMaxmemoryPolicy: "allkeys-lru", MariaDBBufferPool: "512M"}
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.Tuning.ValkeyMaxmemory != "256mb" || srv.Tuning.ValkeyMaxmemoryPolicy != "allkeys-lru" || srv.Tuning.MariaDBBufferPool != "512M" || !srv.Valkey {
			t.Fatalf("tuning = %+v valkey=%v", srv.Tuning, srv.Valkey)
		}
	})

	t.Run("tuning-bad-valkey-policy-invalid", func(t *testing.T) {
		a := base("adv-tune-bad", "vps.example.com")
		a.Valkey = true
		a.Tuning = TuningAnswers{ValkeyMaxmemory: "256mb", ValkeyMaxmemoryPolicy: "lru"}
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "valkey_maxmemory_policy")
	})

	t.Run("tuning-bad-mariadb-buffer-suffix-invalid", func(t *testing.T) {
		a := base("adv-tune-mdb", "vps.example.com")
		a.Tuning = TuningAnswers{MariaDBBufferPool: "512MB"}
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "mariadb_innodb_buffer_pool")
	})

	t.Run("fingerprint-valid-32-byte-present", func(t *testing.T) {
		a := base("adv-fp", "vps.example.com")
		a.Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.SSH.Fingerprint != "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
			t.Fatalf("fingerprint = %q", srv.SSH.Fingerprint)
		}
	})

	t.Run("fingerprint-malformed-no-prefix-invalid", func(t *testing.T) {
		a := base("adv-fp-bad", "vps.example.com")
		a.Fingerprint = "deadbeef"
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "ssh.fingerprint")
		mustContain(t, err, "SHA256:<base64>")
	})

	t.Run("fingerprint-prefix-wrong-length-invalid", func(t *testing.T) {
		a := base("adv-fp-len", "vps.example.com")
		a.Fingerprint = "SHA256:AAAA"
		a.Sites = []SiteAnswers{{
			Domain: "vps.example.com", DeployPath: "/srv/app", DBName: "appdb", DBUser: "appuser", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "not a valid SHA256 fingerprint")
	})

	t.Run("scheduler-override-on-off-tristate-multisite-valid", func(t *testing.T) {
		a := base("adv-sched", "vps.example.com")
		a.Sites = []SiteAnswers{
			{Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "auser", SchedulerOverride: "on"},
			{Domain: "b.example.com", DeployPath: "/srv/b", DBName: "bdb", DBUser: "buser", SchedulerOverride: "off"},
			{Domain: "c.example.com", DeployPath: "/srv/c", DBName: "cdb", DBUser: "cuser", SchedulerOverride: "inherit"},
		}
		srv, _ := writeValid(t, a)
		if len(srv.Sites) != 3 {
			t.Fatalf("want 3 sites")
		}
		if srv.Sites[0].Scheduler == nil || *srv.Sites[0].Scheduler != true {
			t.Fatalf("site0 scheduler = %v", srv.Sites[0].Scheduler)
		}
		if srv.Sites[1].Scheduler == nil || *srv.Sites[1].Scheduler != false {
			t.Fatalf("site1 scheduler = %v", srv.Sites[1].Scheduler)
		}
		if srv.Sites[2].Scheduler != nil {
			t.Fatalf("site2 scheduler should be nil")
		}
	})

	t.Run("run-advanced-server-then-fingerprint-scheduler-on", func(t *testing.T) {
		f := &fakePrompter{
			serverCore: func(a *Answers) {
				baseServer(a)
				a.Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			},
			serverAdvanced: func(a *Answers) {
				a.Fail2ban = Fail2banAnswers{Bantime: "15m", Findtime: "5m", Maxretry: 4}
				a.Tuning = TuningAnswers{ValkeyMaxmemory: "128mb", ValkeyMaxmemoryPolicy: "noeviction", MariaDBBufferPool: "256M"}
			},
			siteCore: []func(int, *SiteAnswers){
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "one.example.com", "/srv/one", "onedb", "oneuser"
				},
			},
			siteOverrides: func(sa *SiteAnswers) { sa.SchedulerOverride = "on" },
			// server-advanced? (yes) | site-advanced? (no) | add-another? (no)
			confirms: []bool{true, false, false},
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if a.Fingerprint != "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
			t.Fatalf("fingerprint = %q", a.Fingerprint)
		}
		if a.Fail2ban.Maxretry != 4 || a.Fail2ban.Bantime != "15m" || a.Tuning.ValkeyMaxmemoryPolicy != "noeviction" {
			t.Fatalf("advanced server = %+v / %+v", a.Fail2ban, a.Tuning)
		}
		if len(a.Sites) != 1 {
			t.Fatalf("want 1 site")
		}
		// site-advanced gate was false so SiteOverrides never ran: stays "inherit".
		if a.Sites[0].SchedulerOverride != "inherit" {
			t.Fatalf("scheduler override = %q, want inherit", a.Sites[0].SchedulerOverride)
		}
		if len(f.errors) != 0 {
			t.Fatalf("unexpected errors: %v", f.errors)
		}
		if srv := a.ToServer(); srv.Sites[0].Scheduler != nil {
			t.Fatalf("scheduler should map to nil")
		}
	})

	t.Run("run-site-advanced-scheduler-off-applied", func(t *testing.T) {
		f := &fakePrompter{
			serverCore: baseServer,
			siteCore: []func(int, *SiteAnswers){
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "two.example.com", "/srv/two", "twodb", "twouser"
				},
			},
			siteOverrides: func(sa *SiteAnswers) { sa.SchedulerOverride = "off" },
			// server-advanced? (no) | site-advanced? (yes) | dedicated-queue? (no) | add-daemon? (no) | add-another? (no)
			confirms: []bool{false, true, false, false, false},
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if len(a.Sites) != 1 || a.Sites[0].SchedulerOverride != "off" {
			t.Fatalf("scheduler override = %q", a.Sites[0].SchedulerOverride)
		}
		if a.Sites[0].Queue != nil || a.Sites[0].Daemons != nil {
			t.Fatalf("queue/daemons should be empty: %+v", a.Sites[0])
		}
		srv := a.ToServer()
		if srv.Sites[0].Scheduler == nil || *srv.Sites[0].Scheduler != false {
			t.Fatalf("scheduler should map to false")
		}
		if len(f.errors) != 0 {
			t.Fatalf("unexpected errors: %v", f.errors)
		}
	})

	// ===================== Cross-site duplication (answers path) =====================

	t.Run("answers-dup-domain-two-sites", func(t *testing.T) {
		a := base("dup-dom", "203.0.113.10")
		a.Sites = []SiteAnswers{
			{Domain: "a.example.com", DeployPath: "/srv/a", User: "usra", DBName: "ad0", DBUser: "au0", SchedulerOverride: "inherit"},
			{Domain: "a.example.com", DeployPath: "/srv/b", User: "usrb", DBName: "bd1", DBUser: "bu1", SchedulerOverride: "inherit"},
		}
		err := writeInvalid(t, a)
		mustContain(t, err, `same domain "a.example.com"`)
	})

	t.Run("answers-dup-osuser-explicit-two-sites", func(t *testing.T) {
		a := base("dup-user", "203.0.113.10")
		a.Sites = []SiteAnswers{
			{Domain: "a.example.com", DeployPath: "/srv/a", User: "shareduser", DBName: "ad0", DBUser: "au0", SchedulerOverride: "inherit"},
			{Domain: "b.example.com", DeployPath: "/srv/b", User: "shareduser", DBName: "bd1", DBUser: "bu1", SchedulerOverride: "inherit"},
		}
		err := writeInvalid(t, a)
		mustContain(t, err, `same os user "shareduser"`)
	})

	t.Run("answers-dup-dbname-two-sites", func(t *testing.T) {
		a := base("dup-dbname", "203.0.113.10")
		a.DBEngine, a.DBSource = "postgres", "pgdg"
		a.Sites = []SiteAnswers{
			{Domain: "a.example.com", DeployPath: "/srv/a", User: "usra", DBName: "shared_db", DBUser: "au0", SchedulerOverride: "inherit"},
			{Domain: "b.example.com", DeployPath: "/srv/b", User: "usrb", DBName: "shared_db", DBUser: "bu1", SchedulerOverride: "inherit"},
		}
		err := writeInvalid(t, a)
		mustContain(t, err, `same database name "shared_db"`)
	})

	t.Run("answers-dup-dbuser-two-sites", func(t *testing.T) {
		a := base("dup-dbuser", "203.0.113.10")
		a.DBSource = "mariadb"
		a.Sites = []SiteAnswers{
			{Domain: "a.example.com", DeployPath: "/srv/a", User: "usra", DBName: "ad0", DBUser: "shared_usr", SchedulerOverride: "inherit"},
			{Domain: "b.example.com", DeployPath: "/srv/b", User: "usrb", DBName: "bd1", DBUser: "shared_usr", SchedulerOverride: "inherit"},
		}
		err := writeInvalid(t, a)
		mustContain(t, err, `same database user "shared_usr"`)
	})

	t.Run("answers-dup-deploypath-two-sites", func(t *testing.T) {
		a := base("dup-path", "203.0.113.10")
		a.Sites = []SiteAnswers{
			{Domain: "a.example.com", DeployPath: "/srv/shared", User: "usra", DBName: "ad0", DBUser: "au0", SchedulerOverride: "inherit"},
			{Domain: "b.example.com", DeployPath: "/srv/shared", User: "usrb", DBName: "bd1", DBUser: "bu1", SchedulerOverride: "inherit"},
		}
		err := writeInvalid(t, a)
		mustContain(t, err, `same deploy_path "/srv/shared"`)
	})

	t.Run("answers-letsencrypt-missing-email", func(t *testing.T) {
		a := base("le-noemail", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "ad0", DBUser: "au0", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "ssl_email is required when ssl is true with letsencrypt")
	})

	t.Run("answers-letsencrypt-malformed-email", func(t *testing.T) {
		a := base("le-bademail", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "ad0", DBUser: "au0", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "letsencrypt", SSLEmail: "not-an-email",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, `ssl_email "not-an-email" is not a valid email address`)
	})

	t.Run("answers-http3-with-nginx-debian-static", func(t *testing.T) {
		a := base("h3-debian", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "ad0", DBUser: "au0", SchedulerOverride: "inherit",
			SSL: true, SSLMode: "selfsigned", HTTP3: true,
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "http3 requires nginx.source: nginx")
	})

	t.Run("answers-invalid-sql-ident-dbname", func(t *testing.T) {
		a := base("bad-dbname", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "app-db", DBUser: "au0", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, `database name "app-db" is not a valid SQL identifier`)
	})

	t.Run("answers-reserved-osuser-www-data", func(t *testing.T) {
		a := base("reserved-user", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", User: "www-data", DBName: "ad0", DBUser: "au0", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, `os user "www-data" is reserved by the system`)
	})

	t.Run("answers-valkey-17-sites", func(t *testing.T) {
		a := base("valkey17", "203.0.113.10")
		a.Valkey = true
		for k := 0; k < 17; k++ {
			n := strconv.Itoa(k)
			a.Sites = append(a.Sites, SiteAnswers{
				Domain: "s" + n + ".example.com", DeployPath: "/srv/" + n,
				User: "user" + n, DBName: "d" + n, DBUser: "u" + n, SchedulerOverride: "inherit",
			})
		}
		err := writeInvalid(t, a)
		mustContain(t, err, "valkey: true supports at most 16 sites")
		mustContain(t, err, "got 17")
	})

	// ===================== RUN-path duplicate / http3 (extra set) =====================

	t.Run("run-http3-accept-switches-nginx-valid", func(t *testing.T) {
		f := &fakePrompter{
			serverCore: func(a *Answers) { baseServer(a); a.NginxSource = "debian" },
			siteCore: []func(int, *SiteAnswers){
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "ad", "au"
					sa.SSL, sa.SSLMode, sa.SSLEmail, sa.HTTP3 = true, "selfsigned", "", true
				},
			},
			confirms: []bool{false, true, false, false},
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if a.NginxSource != "nginx" || !a.Sites[0].HTTP3 || len(a.Sites) != 1 {
			t.Fatalf("nginx=%q http3=%v sites=%d", a.NginxSource, a.Sites[0].HTTP3, len(a.Sites))
		}
		if len(f.errors) != 0 {
			t.Fatalf("unexpected errors: %v", f.errors)
		}
		if verr := a.ToServer().Validate(); verr != nil {
			t.Fatalf("validate = %v", verr)
		}
	})

	t.Run("run-http3-decline-drops-http3-valid", func(t *testing.T) {
		f := &fakePrompter{
			serverCore: func(a *Answers) { baseServer(a); a.NginxSource = "debian" },
			siteCore: []func(int, *SiteAnswers){
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "ad", "au"
					sa.SSL, sa.SSLMode, sa.SSLEmail, sa.HTTP3 = true, "letsencrypt", "x@y.com", true
				},
			},
			confirms: []bool{false, false, false, false},
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if a.NginxSource != "debian" || a.Sites[0].HTTP3 || len(a.Sites) != 1 {
			t.Fatalf("nginx=%q http3=%v sites=%d", a.NginxSource, a.Sites[0].HTTP3, len(a.Sites))
		}
		if len(f.errors) != 0 {
			t.Fatalf("unexpected errors: %v", f.errors)
		}
		if verr := a.ToServer().Validate(); verr != nil {
			t.Fatalf("validate = %v", verr)
		}
	})

	t.Run("run-duplicate-domain-reprompts-then-succeeds", func(t *testing.T) {
		f := &fakePrompter{
			serverCore: baseServer,
			siteCore: []func(int, *SiteAnswers){
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "ad", "au"
				},
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/b", "bd", "bu" // dup
				},
				func(_ int, sa *SiteAnswers) {
					sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "b.example.com", "/srv/b", "bd", "bu" // fixed
				},
			},
			confirms: []bool{false, false, true, false, false},
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if len(a.Sites) != 2 || a.Sites[1].Domain != "b.example.com" {
			t.Fatalf("sites = %+v", a.Sites)
		}
		if len(f.errors) != 1 {
			t.Fatalf("want exactly 1 error, got %v", f.errors)
		}
	})

	t.Run("run-valkey-gated-at-16th-no-add-another", func(t *testing.T) {
		cores := make([]func(int, *SiteAnswers), 16)
		for i := range cores {
			cores[i] = func(j int, sa *SiteAnswers) {
				n := strconv.Itoa(j)
				sa.Domain, sa.DeployPath = "s"+n+".example.com", "/srv/"+n
				sa.DBName, sa.DBUser, sa.User = "d"+n, "u"+n, "user"+n
			}
		}
		confirms := []bool{false}
		for i := 0; i < 16; i++ {
			confirms = append(confirms, false)
			if i < 15 {
				confirms = append(confirms, true)
			}
		}
		f := &fakePrompter{
			serverCore: func(a *Answers) { baseServer(a); a.Valkey = true },
			siteCore:   cores,
			confirms:   confirms,
		}
		a, err := run(f)
		if err != nil {
			t.Fatalf("run error = %v", err)
		}
		if len(a.Sites) != 16 {
			t.Fatalf("want 16 sites, got %d", len(a.Sites))
		}
		if len(f.errors) != 1 {
			t.Fatalf("want exactly 1 cap note, got %v", f.errors)
		}
		if verr := a.ToServer().Validate(); verr != nil {
			t.Fatalf("validate = %v", verr)
		}
	})

	// ===================== Ops blocks: system / cloudflare / backups =====================

	t.Run("ops/system swap+sysctl", func(t *testing.T) {
		a := validSingleSite(t) // minimal valid Answers
		a.System = SystemAnswers{Swap: "2G", Sysctl: true}
		srv, raw := writeValid(t, a)
		if srv.System.Swap != "2G" || !srv.System.Sysctl {
			t.Errorf("system = %+v", srv.System)
		}
		if !strings.Contains(raw, "swap: 2G") {
			t.Errorf("yaml missing swap:\n%s", raw)
		}
	})

	t.Run("ops/system bad swap", func(t *testing.T) {
		a := validSingleSite(t)
		a.System = SystemAnswers{Swap: "2TB"}
		err := writeInvalid(t, a)
		mustContain(t, err, "swap")
	})

	t.Run("ops/cloudflare server + per-site override", func(t *testing.T) {
		a := validSingleSite(t)
		a.CloudflareOnly = true
		a.Sites[0].CloudflareOverride = "off"
		srv, _ := writeValid(t, a)
		if !srv.CloudflareOnly {
			t.Error("server CloudflareOnly should be true")
		}
		if srv.Sites[0].CloudflareOnly == nil || *srv.Sites[0].CloudflareOnly {
			t.Error("site CloudflareOnly should be *false")
		}
	})

	t.Run("ops/backups enabled + retention + schedule + per-site override", func(t *testing.T) {
		a := validSingleSite(t)
		a.Backups = BackupsAnswers{Enabled: true, RetentionDays: 14, Schedule: "0 2 * * 0"}
		a.Sites[0].BackupsOverride = "on"
		srv, _ := writeValid(t, a)
		if !srv.Backups.Enabled || srv.Backups.Retention != 14 || srv.Backups.Schedule != "0 2 * * 0" {
			t.Errorf("backups = %+v", srv.Backups)
		}
		if srv.Sites[0].Backups == nil || !*srv.Sites[0].Backups {
			t.Error("site Backups should be *true")
		}
	})

	t.Run("ops/backups bad schedule", func(t *testing.T) {
		a := validSingleSite(t)
		a.Backups = BackupsAnswers{Enabled: true, Schedule: "30 3 * * mon"}
		err := writeInvalid(t, a)
		mustContain(t, err, "schedule")
	})

	// ===================== Gap closure: coverage the adversarial review flagged =====================
	addGapScenarios(t, writeValid, writeInvalid, mustContain, base)
}

// addGapScenarios holds the scenarios added to close the coverage gaps an
// adversarial review of the original matrix found. It takes the parent test's
// closures so every case shares the same Write -> Load / Write-error harness.
// Every "invalid" expectation is grounded in internal/config/validate.go.
func addGapScenarios(
	t *testing.T,
	writeValid func(*testing.T, Answers) (*config.Server, string),
	writeInvalid func(*testing.T, Answers) error,
	mustContain func(*testing.T, error, string),
	base func(name, host string) Answers,
) {
	// ---- Gap 1: repository (SSH git URL only) ----

	t.Run("gap-repository-valid-ssh-url-roundtrips", func(t *testing.T) {
		a := base("gap-repo-ok", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr",
			SchedulerOverride: "inherit", Repository: "git@github.com:acme/app.git",
		}}
		srv, _ := writeValid(t, a)
		if srv.Sites[0].Repository != "git@github.com:acme/app.git" {
			t.Fatalf("repository = %q", srv.Sites[0].Repository)
		}
	})

	t.Run("gap-repository-https-url-rejected", func(t *testing.T) {
		a := base("gap-repo-https", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr",
			SchedulerOverride: "inherit", Repository: "https://github.com/acme/app.git",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "must be an SSH git URL")
	})

	// ---- Gap 2: non-default PHP version/source ----

	for _, ver := range []string{"8.2", "8.3", "8.4"} {
		ver := ver
		t.Run("gap-php-version-"+ver+"-roundtrips", func(t *testing.T) {
			a := base("gap-php-"+strings.ReplaceAll(ver, ".", ""), "203.0.113.10")
			a.PHPVersion = ver
			a.Sites = []SiteAnswers{{
				Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			}}
			srv, _ := writeValid(t, a)
			if srv.PHP.Version != ver {
				t.Fatalf("php.version = %q, want %q", srv.PHP.Version, ver)
			}
		})
	}

	for _, src := range []string{"sury", "debian"} {
		src := src
		t.Run("gap-php-source-"+src+"-roundtrips", func(t *testing.T) {
			a := base("gap-phpsrc-"+src, "203.0.113.10")
			a.PHPSource = src
			a.Sites = []SiteAnswers{{
				Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			}}
			srv, _ := writeValid(t, a)
			if srv.PHP.Source != src {
				t.Fatalf("php.source = %q, want %q", srv.PHP.Source, src)
			}
		})
	}

	t.Run("gap-php-version-bad-rejected", func(t *testing.T) {
		a := base("gap-php-bad", "203.0.113.10")
		a.PHPVersion = "9.9"
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "php.version")
		mustContain(t, err, "is not an allowed version")
	})

	t.Run("gap-php-source-bad-rejected", func(t *testing.T) {
		a := base("gap-phpsrc-bad", "203.0.113.10")
		a.PHPSource = "ondrej"
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "php.source")
		mustContain(t, err, "must be auto, sury, or debian")
	})

	// ---- Gap 3: SSH connection fields ----

	t.Run("gap-ssh-nondefault-fields-roundtrip", func(t *testing.T) {
		a := base("gap-ssh", "203.0.113.10")
		a.Port = 2222
		a.SSHUser = "deployer"
		a.Key = "~/.ssh/custom_ed25519"
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
		}}
		srv, _ := writeValid(t, a)
		if srv.SSH.Port != 2222 || srv.SSH.User != "deployer" || srv.SSH.Key != "~/.ssh/custom_ed25519" {
			t.Fatalf("ssh = %+v", srv.SSH)
		}
	})

	for _, port := range []int{0, 70000} {
		port := port
		t.Run("gap-ssh-port-out-of-range-"+strconv.Itoa(port)+"-rejected", func(t *testing.T) {
			a := base("gap-port-"+strconv.Itoa(port), "203.0.113.10")
			a.Port = port
			a.Sites = []SiteAnswers{{
				Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			}}
			err := writeInvalid(t, a)
			mustContain(t, err, "ssh.port")
			mustContain(t, err, "out of range")
		})
	}

	// ---- Gap 4: db engine/source negatives ----

	t.Run("gap-db-mariadb-pgdg-mismatch-rejected", func(t *testing.T) {
		a := base("gap-db-mm-pgdg", "203.0.113.10")
		a.DBEngine, a.DBSource = "mariadb", "pgdg"
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "invalid for engine")
	})

	t.Run("gap-db-postgres-mariadb-mismatch-rejected", func(t *testing.T) {
		a := base("gap-db-pg-mm", "203.0.113.10")
		a.DBEngine, a.DBSource = "postgres", "mariadb"
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "invalid for engine")
	})

	t.Run("gap-db-mysql-engine-unsupported-rejected", func(t *testing.T) {
		a := base("gap-db-mysql", "203.0.113.10")
		a.DBEngine, a.DBSource = "mysql", "debian"
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "unsupported")
	})

	// ---- Gap 5: nginx.source invalid ----

	t.Run("gap-nginx-source-openresty-rejected", func(t *testing.T) {
		a := base("gap-nginx-bad", "203.0.113.10")
		a.NginxSource = "openresty"
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "must be debian or nginx")
	})

	// ---- Gap 6: queue.driver invalid ----

	t.Run("gap-queue-driver-sync-rejected", func(t *testing.T) {
		a := base("gap-q-sync", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Queue: &QueueAnswers{Driver: "sync", Processes: 1},
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "must be work or horizon")
	})

	// ---- Gap 7: daemon negatives ----

	t.Run("gap-daemon-duplicate-name-rejected", func(t *testing.T) {
		a := base("gap-dmn-dup", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Daemons: []DaemonAnswers{
				{Name: "worker", Command: "php artisan a", Processes: 1},
				{Name: "worker", Command: "php artisan b", Processes: 1},
			},
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "duplicated within the site")
	})

	t.Run("gap-daemon-bad-name-rejected", func(t *testing.T) {
		a := base("gap-dmn-name", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Daemons: []DaemonAnswers{{Name: "Bad_Name", Command: "php artisan x", Processes: 1}},
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "must match [a-z0-9-]+")
	})

	t.Run("gap-daemon-processes-over-cap-rejected", func(t *testing.T) {
		a := base("gap-dmn-proc", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Daemons: []DaemonAnswers{{Name: "worker", Command: "php artisan x", Processes: 65}},
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "out of range")
	})

	// ---- Gap 8: queue work boundary ----

	t.Run("gap-queue-work-processes-64-boundary-valid", func(t *testing.T) {
		a := base("gap-q-64", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Queue: &QueueAnswers{Driver: "work", Processes: 64},
		}}
		srv, _ := writeValid(t, a)
		if srv.Sites[0].Queue == nil || srv.Sites[0].Queue.Processes != 64 {
			t.Fatalf("queue = %+v", srv.Sites[0].Queue)
		}
	})

	// Each non-tries numeric knob (sleep, timeout, max_memory) is independently
	// guarded against negatives by validateQueueDaemons.
	for _, knob := range []struct {
		name string
		set  func(*QueueAnswers)
		msg  string
	}{
		{"sleep", func(q *QueueAnswers) { q.Sleep = -1 }, "queue.sleep must not be negative"},
		{"timeout", func(q *QueueAnswers) { q.Timeout = -1 }, "queue.timeout must not be negative"},
		{"max_memory", func(q *QueueAnswers) { q.MaxMemory = -1 }, "queue.max_memory must not be negative"},
	} {
		knob := knob
		t.Run("gap-queue-work-negative-"+knob.name+"-rejected", func(t *testing.T) {
			a := base("gap-q-neg-"+strings.ReplaceAll(knob.name, "_", ""), "203.0.113.10")
			q := &QueueAnswers{Driver: "work", Processes: 2}
			knob.set(q)
			a.Sites = []SiteAnswers{{
				Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
				Queue: q,
			}}
			err := writeInvalid(t, a)
			mustContain(t, err, knob.msg)
			mustContain(t, err, "must not be negative")
		})
	}

	// ---- Gap 9: server-wide + per-site queue together ----

	t.Run("gap-serverwide-and-site-queue-single-worker-program", func(t *testing.T) {
		a := base("gap-q-both", "203.0.113.10")
		a.Queue = true // server-wide default worker
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/srv/a", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
			Queue: &QueueAnswers{Driver: "work", Processes: 2}, // ALSO its own block
		}}
		srv, _ := writeValid(t, a)
		if !srv.Queue || srv.Sites[0].Queue == nil {
			t.Fatalf("expected both server.Queue and site queue set: server=%v site=%+v", srv.Queue, srv.Sites[0].Queue)
		}
		if !srv.QueueEnabled(srv.Sites[0]) {
			t.Fatalf("QueueEnabled should be true")
		}
		// SiteProgramNames must emit the worker "berth-<pool>" exactly once — the
		// server-wide flag and the per-site block must not both append it.
		progs := srv.SiteProgramNames(srv.Sites[0])
		worker := "berth-" + config.PoolName(srv.Sites[0].Domain)
		count := 0
		for _, p := range progs {
			if p == worker {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("worker %q appears %d times in %v, want exactly 1", worker, count, progs)
		}
	})

	// ---- Gap 10: deploy_path negatives ----

	t.Run("gap-deploypath-relative-rejected", func(t *testing.T) {
		a := base("gap-path-rel", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "var/www/app", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "absolute path without shell metacharacters")
	})

	t.Run("gap-deploypath-shell-metachar-rejected", func(t *testing.T) {
		a := base("gap-path-meta", "203.0.113.10")
		a.Sites = []SiteAnswers{{
			Domain: "a.example.com", DeployPath: "/var/www/a;b", DBName: "adb", DBUser: "ausr", SchedulerOverride: "inherit",
		}}
		err := writeInvalid(t, a)
		mustContain(t, err, "absolute path without shell metacharacters")
	})

	// ---- Gap 11: derived-user truncation stays distinct ----

	// A true derived-user collision between two DIFFERENT domains is structurally
	// prevented: DerivedSiteUser hashes the FULL domain (fnv-32a) into the 8-hex
	// suffix, so even when the sanitized slug prefixes are truncated to the same
	// 21 chars, the suffixes differ and the names stay distinct.
	t.Run("gap-derived-user-long-domains-distinct-valid", func(t *testing.T) {
		d0 := "verylongtenantname-one.example.com"
		d1 := "verylongtenantname-two.example.com"
		a := base("gap-derive-long", "203.0.113.10")
		a.Sites = []SiteAnswers{
			{Domain: d0, DeployPath: "/srv/one", DBName: "one_db", DBUser: "one_usr", SchedulerOverride: "inherit"},
			{Domain: d1, DeployPath: "/srv/two", DBName: "two_db", DBUser: "two_usr", SchedulerOverride: "inherit"},
		}
		srv, _ := writeValid(t, a)
		u0 := srv.SiteUser(srv.Sites[0])
		u1 := srv.SiteUser(srv.Sites[1])
		if u0 != config.DerivedSiteUser(d0) || u1 != config.DerivedSiteUser(d1) {
			t.Fatalf("derivation mismatch: %q %q", u0, u1)
		}
		for _, u := range []string{u0, u1} {
			if len(u) > 32 {
				t.Fatalf("derived user %q exceeds 32 chars (%d)", u, len(u))
			}
			if !reLinuxUserHarness.MatchString(u) {
				t.Fatalf("derived user %q is not a valid Linux username", u)
			}
		}
		if u0 == u1 {
			t.Fatalf("derived users for distinct domains collided: %q", u0)
		}
	})
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

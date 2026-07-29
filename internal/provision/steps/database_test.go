package steps

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func databaseServer() *config.Server {
	return &config.Server{
		Host:     "app.example.com",
		SSH:      config.SSH{Port: 22},
		Database: config.Database{Engine: "mariadb", Source: "debian"},
		Sites: []config.Site{{
			Domain:     "app.example.com",
			DeployPath: "/var/www/myapp",
			User:       "deploy",
			SSL:        true,
			Database:   config.SiteDatabase{Name: "myapp", User: "myapp"},
		}},
	}
}

// chdirTemp isolates the local secret cache under a throwaway HOME (the cache
// lives at $HOME/.berth; Go reads USERPROFILE on Windows) and a throwaway
// working directory.
func chdirTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

func TestDatabaseRequiresBaseAndAppdirs(t *testing.T) {
	got := Database(secret.NewRedactor()).Requires()
	if len(got) != 2 || got[0] != "base" || got[1] != "appdirs" {
		t.Fatalf("Requires() = %v, want [base appdirs]", got)
	}
}

// envPath returns the absolute server-side shared/.env path for a server.
func envPath(s *config.Server) string {
	return s.Sites[0].DeployPath + "/shared/.env"
}

// stubClientAuthAbsent stubs the per-site client-credentials existence probe
// as absent (Apply then seeds the file) for every site of s.
func stubClientAuthAbsent(f *bssh.FakeRunner, s *config.Server, name string) {
	for _, site := range s.Sites {
		f.On("test -e "+shQuote("/home/"+s.SiteUser(site)+"/"+name), bssh.Result{ExitCode: 1})
	}
}

// stubEnvSeed stubs the tenant-run write that seeds shared/.env (executed as
// the site user) for every site of s.
func stubEnvSeed(f *bssh.FakeRunner, s *config.Server) {
	for _, site := range s.Sites {
		f.On(writeAsUserCmd(s.SiteUser(site), sharedEnvPath(site)), bssh.Result{})
	}
}

// stubClientAuthSeed stubs the tenant-run write that seeds the per-site
// client-credentials file (executed as the site user) for every site of s.
func stubClientAuthSeed(f *bssh.FakeRunner, s *config.Server, name string) {
	for _, site := range s.Sites {
		f.On(writeAsUserCmd(s.SiteUser(site), clientAuthPath(s, site, name)), bssh.Result{})
	}
}

// stubEngineRepoAbsent makes the engine's upstream source-list probe read
// back as absent: the debian-source paths (ownRepoLingers/removeOwnRepo) see
// nothing to sweep, and the upstream-source Apply path (ensureOwnRepo)
// proceeds to the full EnsureRepo chain.
func stubEngineRepoAbsent(f *bssh.FakeRunner, repo apt.Repo) {
	f.On("cat "+shQuote(repo.SourceListPath()), bssh.Result{ExitCode: 1})
}

func TestDatabaseApplyGeneratesPersistsAndEnsures(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	red := secret.NewRedactor()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	stubClientAuthAbsent(f, s, ".my.cnf")
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".my.cnf")
	f.On("mysql --protocol=socket", bssh.Result{})

	if err := Database(red).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	for _, w := range f.Writes() {
		if w.Path == envPath(s) {
			t.Error(".env must not be written through the root WriteFile path — shared/ is tenant-owned")
		}
	}
	// shared/.env must have been written by the site user (mode 0600) and
	// contain DB_PASSWORD.
	body := string(writtenContent(f, envPath(s)))
	if body == "" {
		t.Fatal("shared/.env was not written")
	}
	var seed string
	for _, c := range callCmds(f) {
		if strings.Contains(c, shQuote(envPath(s))) && strings.Contains(c, "mv -f") {
			seed = c
		}
	}
	if !strings.HasPrefix(seed, "sudo -u deploy ") || !strings.Contains(seed, "chmod 600") {
		t.Errorf("shared/.env must be written by deploy with mode 600; got %q", seed)
	}
	if !strings.Contains(body, "DB_PASSWORD=") {
		t.Error("shared/.env must contain DB_PASSWORD")
	}
	if !strings.Contains(body, "APP_KEY=base64:") {
		t.Error("shared/.env must contain a generated APP_KEY")
	}

	// The password must reach the SQL via stdin, never the command string.
	var sawCreateDB, sawCreateUser bool
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "mysql") {
			if strings.Contains(string(c.Stdin), "CREATE DATABASE IF NOT EXISTS") {
				sawCreateDB = true
			}
			if strings.Contains(string(c.Stdin), "CREATE USER") {
				sawCreateUser = true
			}
		}
	}
	if !sawCreateDB {
		t.Error("expected EnsureDatabase to run CREATE DATABASE via stdin")
	}
	if !sawCreateUser {
		t.Error("expected EnsureUser to run CREATE USER via stdin")
	}

	// The cache must hold the generated password (for reuse on re-run).
	cache, err := secret.LoadCache(s.Host)
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if cache[s.SiteDBUser(s.Sites[0])] == "" {
		t.Error("cache missing the site's database password (keyed by DB user)")
	}
}

func TestDatabaseApplyOnlyTenantMutatesSharedEnv(t *testing.T) {
	// shared/.env is inside tenant territory: no privileged write may target it.
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	stubClientAuthAbsent(f, s, ".my.cnf")
	f.On("mysql --protocol=socket", bssh.Result{})
	f.On(writeAsUserCmd("deploy", envPath(s)), bssh.Result{})
	f.On(writeAsUserCmd("deploy", clientAuthPath(s, s.Sites[0], ".my.cnf")), bssh.Result{})
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	assertOnlyTenantMutates(t, f, "deploy", envPath(s), clientAuthPath(s, s.Sites[0], ".my.cnf"))
	if len(writtenContent(f, envPath(s))) == 0 {
		t.Fatal("the .env must still be seeded")
	}
	if len(writtenContent(f, clientAuthPath(s, s.Sites[0], ".my.cnf"))) == 0 {
		t.Fatal("the client-auth file must still be seeded")
	}
}

func TestDatabaseApplySeedsRedisWhenValkey(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	s.Valkey = true
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	body := string(writtenContent(f, envPath(s)))
	if body == "" {
		t.Fatal("shared/.env was not written")
	}
	for _, want := range []string{
		"CACHE_DRIVER=redis\n", "CACHE_STORE=redis\n", "SESSION_DRIVER=redis\n", "QUEUE_CONNECTION=redis\n",
		"REDIS_CLIENT=phpredis\n",
		"REDIS_HOST=/run/berth-valkey/app_example_com/valkey.sock\n",
		"REDIS_PORT=0\n", "REDIS_DB=0\n", "REDIS_CACHE_DB=1\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("with Valkey, shared/.env must contain %q; got:\n%s", want, body)
		}
	}
	if strings.Contains(body, "REDIS_PREFIX") {
		t.Errorf("REDIS_PREFIX must not be seeded for a private per-site instance; got:\n%s", body)
	}
}

func TestDatabaseApplyKeepsDatabaseDriverWithoutValkey(t *testing.T) {
	chdirTemp(t)
	s := databaseServer() // Valkey defaults to false
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	body := string(writtenContent(f, envPath(s)))
	if body == "" {
		t.Fatal("shared/.env was not written")
	}
	if strings.Contains(body, "CACHE_DRIVER=redis") ||
		strings.Contains(body, "CACHE_STORE=redis") {
		t.Errorf("without Valkey, redis drivers must NOT be seeded; got:\n%s", body)
	}
}

func TestDatabaseApplyHealsFromExistingEnvWithoutRewriting(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env already present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Reused123\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // absent -> not backfilled
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	stubClientAuthSeed(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if writtenContent(f, envPath(s)) != nil {
		t.Fatal("an existing shared/.env must never be rewritten")
	}
	var sawEnsureUser bool
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "mysql") && strings.Contains(string(c.Stdin), "Reused123") {
			sawEnsureUser = true
		}
	}
	if !sawEnsureUser {
		t.Fatal("EnsureUser must re-sync the password read from the live .env")
	}
}

func TestDatabaseApplyFailsWhenExistingEnvLacksPassword(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"}) // guard passes; the missing password fails later
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})                                    // key absent
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "has no DB_PASSWORD") {
		t.Fatalf("err = %v, want the pointed no-DB_PASSWORD error", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "mysql") {
			t.Fatal("no SQL may run when the existing .env cannot supply the password")
		}
	}
}

func TestDatabaseCheckSatisfiedDoesNotReseedExistingEnv(t *testing.T) {
	// Once installed + .env + database + user are all present the step is
	// satisfied, so flipping valkey: true on an already-provisioned host does
	// NOT re-seed the Redis keys (and Apply never rewrites an existing .env).
	chdirTemp(t)
	s := databaseServer()
	s.Valkey = true
	seedCache(t, s, map[string]string{s.SiteDBUser(s.Sites[0]): "pw123"})
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present, driver matches
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("LC_ALL=C; export LC_ALL; grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
	f.On(mariadbGrantProbe, bssh.Result{Stdout: "1\n"})
	f.On("test -e "+shQuote("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 0}) // client creds already seeded
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 1})                             // no berth-format APP_KEY -> no backup required
	f.On(envValueMatchScript(envPath(s), "DB_PASSWORD"), bssh.Result{ExitCode: 0})
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected Satisfied (installed + .env + db + user present); got %+v", cr)
	}
}

const (
	mariadbDBProbe    = `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='myapp'"`
	mariadbGrantProbe = `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='myapp' AND GRANTEE='''myapp''@''localhost''' LIMIT 1"`
)

// stubGreenRemote stubs every REMOTE probe of a fully provisioned single-site
// mariadb host (installed, .env with matching driver and a valid credential,
// database + grant present, client auth seeded) — the state in which only the
// local-cache checks can still make Check unsatisfied.
func stubGreenRemote(f *bssh.FakeRunner, s *config.Server) {
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("LC_ALL=C; export LC_ALL; grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
	f.On(mariadbGrantProbe, bssh.Result{Stdout: "1\n"})
	f.On("test -e "+shQuote("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 0})
}

// appKeyProbe is Check's exact-shape APP_KEY probe command for the test
// server's env (exit-code only, FIRST-line semantics; must match
// envHasBerthAppKey verbatim — kept a literal, not a call into the production
// builder, so an accidental command change still trips these stubs).
func appKeyProbe(s *config.Server) string {
	return "LC_ALL=C; export LC_ALL; line=$(grep -m1 '^APP_KEY=' " + shQuote(envPath(s)) + "); s=$?; " +
		"if [ $s -eq 1 ]; then exit 1; elif [ $s -ne 0 ]; then exit 2; fi; " +
		`printf '%s' "$line" | sed 's/[[:space:]]*$//' | grep -Eq '^APP_KEY=base64:[A-Za-z0-9+/]{43}=$' && exit 0; exit 3`
}

// Pins the real shell semantics of envHasBerthAppKey's script — in particular
// that a berth-shaped key with trailing ASCII whitespace still reads as a
// berth key: appKeyFromEnv trims that whitespace before caching, so a
// no-trim probe would silently skip both the cache requirement and the
// agreement comparison for exactly the keys Apply DOES back up.
func TestEnvBerthAppKeyShellScript(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	const key = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	cases := []struct {
		name, fileLine string
		exit           int
	}{
		{"berth-key", "APP_KEY=" + key + "\n", 0},
		{"berth-key-trailing-ws", "APP_KEY=" + key + " \t\n", 0},
		{"non-berth-key", "APP_KEY=base64:short\n", 3},
		{"empty-placeholder", "APP_KEY=\n", 3},
		{"missing-key", "OTHER=x\n", 1},
		{"first-line-wins", "APP_KEY=\nAPP_KEY=" + key + "\n", 3},
		// Unicode whitespace (U+2003) after the key must NOT be trimmed:
		// appKeyFromEnv keeps it (ASCII-only trim), sees a non-berth shape
		// and treats the key as absent — the probe must agree (exit 3), or
		// Check would demand a cache entry Apply never writes.
		{"unicode-ws-not-berth", "APP_KEY=" + key + "\u2003\n", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(env, []byte(c.fileLine), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := shellExit(t, envBerthAppKeyScript(env), ""); got != c.exit {
				t.Fatalf("exit = %d, want %d", got, c.exit)
			}
		})
	}
}

func TestDatabaseCheckUnsatisfiedWhenCacheMissingCredential(t *testing.T) {
	// A fully green REMOTE with an empty local cache (new workstation, upgrade
	// from the old CWD-relative cache, crash before the final save) must
	// re-trigger Apply so the recovery copy is backfilled — otherwise a later
	// .env loss re-seeds with fresh secrets and encrypted data is gone.
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("a green remote with an empty local cache must be unsatisfied (the recovery copy is part of convergence)")
	}
	if !strings.Contains(cr.Reason, "local secret cache missing the DB credential") {
		t.Errorf("Reason = %q", cr.Reason)
	}
}

func TestDatabaseCheckSatisfiedWithFullCache(t *testing.T) {
	// This is also the values-AGREE pin for the agreement probes: both stubs
	// answer 0 (live .env == cache), so the step must stay green.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{
		dbUser:             "pw123",
		"appkey:" + dbUser: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 0}) // live env holds a berth-format APP_KEY
	f.On(envValueMatchScript(envPath(s), "DB_PASSWORD"), bssh.Result{ExitCode: 0})
	f.On(envValueMatchScript(envPath(s), "APP_KEY"), bssh.Result{ExitCode: 0})
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied with both the credential and APP_KEY backup cached; got %+v", cr)
	}
}

func TestDatabaseCheckSatisfiedWhenEnvAppKeyNotBerthFormat(t *testing.T) {
	// Probe exit 1: APP_KEY absent, or in a shape berth does not generate (an
	// operator-managed key). No backup is required then — requiring one would
	// make Apply fail on every run (it refuses to cache a malformed key),
	// bricking the step with no operator recourse.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "pw123"})
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 1})
	f.On(envValueMatchScript(envPath(s), "DB_PASSWORD"), bssh.Result{ExitCode: 0})
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("no APP_KEY backup may be required when the env key is not berth-format; got %+v", cr)
	}
}

func TestDatabaseCheckSatisfiedWhenFirstAppKeyLineNotBerthFormat(t *testing.T) {
	// Probe exit 3: the FIRST APP_KEY line is non-berth (e.g. the stock empty
	// "APP_KEY=" placeholder) even if a berth-format key sits on a LATER line.
	// Apply's appKeyFromEnv reads only the first line (grep -m1, phpdotenv's
	// first-occurrence-wins), treats it as absent or refuses loudly, and never
	// caches — so Check demanding a cache entry here would drift forever.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "pw123"})
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 3})
	f.On(envValueMatchScript(envPath(s), "DB_PASSWORD"), bssh.Result{ExitCode: 0})
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("a non-berth FIRST APP_KEY line must not require a backup (Apply never caches it); got %+v", cr)
	}
}

func TestDatabaseCheckUnsatisfiedWhenAppKeyBackupMissing(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "pw123"})
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 0}) // berth-format APP_KEY live, no local backup
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("a live berth-format APP_KEY without a local backup must be unsatisfied")
	}
	if !strings.Contains(cr.Reason, "APP_KEY backup") {
		t.Errorf("Reason = %q", cr.Reason)
	}
}

func TestDatabaseCheckFailsWhenAppKeyProbeErrors(t *testing.T) {
	// grep exit >= 2 is an I/O failure, not "no key" — it must be loud.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "pw123"})
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 2, Stderr: "grep: input: Permission denied"})
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("Check() = %v, want a hard error surfacing the probe stderr", err)
	}
}

// A restored (older) .env whose DB_PASSWORD disagrees with the local cache
// must re-trigger Apply — this is the order-insensitive-restore probe: after
// a disaster-recovery restore lands an older .env over a freshly provisioned
// host, every presence probe stays green, and only value agreement can flag
// that the role/cache and the file the app reads have parted ways.
func TestDatabaseCheckFlagsEnvCachePasswordDisagreement(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{
		dbUser:             "cachedPW1",
		"appkey:" + dbUser: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 0})
	f.On(envValueMatchScript(envPath(s), "DB_PASSWORD"), bssh.Result{ExitCode: 1}) // present but different
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("a .env/cache password disagreement must be unsatisfied")
	}
	if !strings.Contains(cr.Reason, "disagrees") {
		t.Errorf("Reason = %q, want it to name the disagreement", cr.Reason)
	}
	// The expected value travels via stdin ONLY — never the command string.
	var probed bool
	for _, c := range f.Calls() {
		if c.Cmd == envValueMatchScript(envPath(s), "DB_PASSWORD") {
			probed = true
			if got := string(c.Stdin); got != "DB_PASSWORD=cachedPW1\n" {
				t.Errorf("probe stdin = %q, want %q", got, "DB_PASSWORD=cachedPW1\n")
			}
		}
		if strings.Contains(c.Cmd, "cachedPW1") {
			t.Errorf("the cached secret leaked into a command string: %q", c.Cmd)
		}
	}
	if !probed {
		t.Fatal("the DB_PASSWORD agreement probe never ran")
	}
}

func TestDatabaseCheckFlagsEnvCacheAppKeyDisagreement(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{
		dbUser:             "cachedPW1",
		"appkey:" + dbUser: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	})
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 0})
	f.On(envValueMatchScript(envPath(s), "DB_PASSWORD"), bssh.Result{ExitCode: 0}) // password agrees
	f.On(envValueMatchScript(envPath(s), "APP_KEY"), bssh.Result{ExitCode: 1})     // APP_KEY does not
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("a .env/cache APP_KEY disagreement must be unsatisfied")
	}
	if !strings.Contains(cr.Reason, "APP_KEY") || !strings.Contains(cr.Reason, "disagrees") {
		t.Errorf("Reason = %q, want it to name the APP_KEY disagreement", cr.Reason)
	}
}

func TestDatabaseCheckRefusesCorruptCachedAppKeyWhenLiveKeyOperatorShaped(t *testing.T) {
	// With an operator-shaped live APP_KEY the probe answers non-berth, the
	// agreement block never runs, and inline validation living inside it let a
	// hand-corrupted cached APP_KEY keep every run green. The preflight
	// validator must refuse loudly instead: the corrupt backup is unusable the
	// day the .env is lost, and green runs would hide that until then.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{
		dbUser:             "pw123",
		"appkey:" + dbUser: "base64:corrupt",
	})
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 3}) // live key present but not berth-shaped
	f.On(envValueMatchScript(envPath(s), "DB_PASSWORD"), bssh.Result{ExitCode: 0})
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("Check() = %v, want the malformed-cached-APP_KEY refusal", err)
	}
}

func TestDatabaseCheckRefusesCorruptCachedPasswordBeforeUnsatisfiedReturn(t *testing.T) {
	// An earlier unsatisfied condition (here: the client-auth file is missing)
	// must not mask cache corruption behind an unrelated reason and hand the
	// corrupt value straight to Apply — the preflight validator hard-errors
	// before ANY unsatisfied early-return.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "\nsneaky"})
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On("test -e "+shQuote("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 1}) // unsatisfied condition ahead of the old inline check
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "outside the allowed charset") {
		t.Fatalf("Check() = %v, want the charset refusal for a corrupt cached password", err)
	}
}

func TestDatabasePreflightRefusalDiagnosticNotRedactedByCorruptValue(t *testing.T) {
	// A corrupt cached value must NOT reach the redactor: the refusal
	// diagnostic names only the cache key, so there is nothing to leak — but
	// a corrupt value colliding with innocent wording (here: the refusal text
	// itself) would mask pieces of the very message explaining the refusal.
	// Only validated values may register.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "outside the allowed charset"}) // invalid (spaces) AND a diagnostic substring
	f := bssh.NewFakeRunner()
	red := secret.NewRedactor()
	_, err := Database(red).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "outside the allowed charset") {
		t.Fatalf("Check() = %v, want the charset refusal", err)
	}
	if got := red.Apply(err.Error()); got != err.Error() {
		t.Errorf("refusal diagnostic garbled by a corrupt-value redaction:\n%q", got)
	}
}

func TestDatabaseCheckRefusesCorruptCacheWhenPackageMissing(t *testing.T) {
	// The missing-package/source early return used to happen BEFORE the cache
	// was even loaded, so validation placed after the load was not preflight:
	// a first run on a fresh host sailed past a corrupt cache and Apply
	// consumed it. Check must load + validate ahead of that return.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "bad value!"})
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // no .env, engine guard passes
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 1})       // not installed
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "outside the allowed charset") {
		t.Fatalf("Check() = %v, want a hard error instead of the not-installed unsatisfied result", err)
	}
}

// shellExit runs a production-built probe script through the local /bin/sh
// with the given stdin and returns its exit code — a FakeRunner stub can only
// echo back what we assume, so these tests pin the ACTUAL shell semantics.
func shellExit(t *testing.T, script, stdin string) int {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell required")
	}
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Stdin = strings.NewReader(stdin)
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0
}

// Pins the actual shell semantics of envValueMatches' script — a FakeRunner
// stub can only echo back what we assume, and the first draft of this
// command was a plausible-looking pipeline that could never match.
func TestEnvValueMatchesShellScript(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	cases := []struct {
		name, fileLine, want string
		exit                 int
	}{
		{"match", "DB_PASSWORD=abc123\n", "abc123", 0},
		{"match-trailing-ws", "DB_PASSWORD=abc123 \t\n", "abc123", 0},
		{"mismatch", "DB_PASSWORD=other999\n", "abc123", 1},
		{"missing-key", "OTHER=x\n", "abc123", 3},
		{"first-line-wins", "DB_PASSWORD=abc123\nDB_PASSWORD=other999\n", "abc123", 0},
		// Unicode whitespace (U+2003 EM SPACE) must NOT be trimmed: Go's
		// passwordFromEnv trims ASCII only, so trimming it here would let
		// Check compare equal a value Apply refuses — the locale pin makes
		// this deterministic regardless of the host's LANG.
		{"unicode-ws-not-trimmed", "DB_PASSWORD=abc123\u2003\n", "abc123", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(env, []byte(c.fileLine), 0o600); err != nil {
				t.Fatal(err)
			}
			got := shellExit(t, envValueMatchScript(env, "DB_PASSWORD"), "DB_PASSWORD="+c.want+"\n")
			if got != c.exit {
				t.Fatalf("exit = %d, want %d", got, c.exit)
			}
		})
	}
}

// Pins the real shell semantics of envCredentialPresent's script: only a
// charset-valid FIRST DB_PASSWORD line answers 0, trailing ASCII whitespace
// is tolerated (passwordFromEnv trims it), and Unicode whitespace is NOT —
// it stays in the value, fails the charset check here exactly as it fails
// reDBPassword in Apply (no false-green Check over a value Apply refuses).
func TestEnvCredentialPresentShellScript(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	cases := []struct {
		name, fileLine string
		exit           int
	}{
		{"valid", "DB_PASSWORD=abc123\n", 0},
		{"valid-trailing-ascii-ws", "DB_PASSWORD=abc123 \t\n", 0},
		{"unicode-ws-rejected", "DB_PASSWORD=abc123\u2003\n", 1},
		{"empty-value", "DB_PASSWORD=\n", 1},
		{"invalid-charset", "DB_PASSWORD=abc-123\n", 1},
		{"missing-key", "OTHER=x\n", 1},
		{"first-line-wins", "DB_PASSWORD=\nDB_PASSWORD=abc123\n", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(env, []byte(c.fileLine), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := shellExit(t, envCredentialPresentScript(env), ""); got != c.exit {
				t.Fatalf("exit = %d, want %d", got, c.exit)
			}
		})
	}
}

// Every whitespace-sensitive probe script must pin the C locale itself: the
// live boxes run LANG=C.UTF-8, where grep/sed's [[:space:]] also matches
// Unicode whitespace while the Go side (passwordFromEnv, appKeyFromEnv)
// trims ASCII only — left unpinned, that divergence can produce a false-green
// password agreement or endless APP_KEY drift. The prefix bytes are pinned
// here literally (not via the production constant) so a prefix change is a
// conscious decision in both places.
func TestProbeScriptsPinTheCLocale(t *testing.T) {
	for name, script := range map[string]string{
		"envValueMatch":        envValueMatchScript("/tmp/e", "DB_PASSWORD"),
		"envBerthAppKey":       envBerthAppKeyScript("/tmp/e"),
		"envCredentialPresent": envCredentialPresentScript("/tmp/e"),
	} {
		if !strings.HasPrefix(script, "LC_ALL=C; export LC_ALL; ") {
			t.Errorf("%s script does not pin the C locale: %q", name, script)
		}
	}
}

func TestDatabaseCheckSkipsAgreementWhenCacheEmpty(t *testing.T) {
	// With no cached credential Check already returns the missing-cache reason
	// BEFORE any agreement probe: there is nothing to compare, and probing with
	// an empty expected value would be a meaningless secret-shaped remote call.
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied || !strings.Contains(cr.Reason, "local secret cache missing") {
		t.Fatalf("want the missing-cache reason, got %+v", cr)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "IFS= read -r want") {
			t.Fatalf("no agreement probe may run with an empty cache; saw %q", c.Cmd)
		}
	}
}

// envWriteSpy wraps a FakeRunner: at the exact moment shared/.env is written it
// loads the LOCAL cache from disk and records whether it already holds EXACTLY
// the DB_PASSWORD and APP_KEY values being written (the
// persist-before-remote-seed ordering; non-empty alone would also pass with
// stale mismatched entries).
type envWriteSpy struct {
	*bssh.FakeRunner
	host, dbUser, envPath string
	wrote                 bool
	pwCached, keyCached   bool
}

func (s *envWriteSpy) record(content []byte) {
	s.wrote = true
	var envPW, envKey string
	for _, line := range strings.Split(string(content), "\n") {
		if v, ok := strings.CutPrefix(line, "DB_PASSWORD="); ok {
			envPW = v
		}
		if v, ok := strings.CutPrefix(line, "APP_KEY="); ok {
			envKey = v
		}
	}
	if cache, err := secret.LoadCache(s.host); err == nil {
		s.pwCached = envPW != "" && cache[s.dbUser] == envPW
		s.keyCached = envKey != "" && cache["appkey:"+s.dbUser] == envKey
	}
}

// Run intercepts the tenant-run write (the .env no longer goes through
// WriteFile), matching the same command shape writeFileAsUser emits.
func (s *envWriteSpy) Run(ctx context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	if strings.Contains(cmd, shQuote(s.envPath)) && strings.Contains(cmd, "mv -fT --") {
		s.record(stdin)
	}
	return s.FakeRunner.Run(ctx, cmd, stdin)
}

// WriteFile keeps recording too, so a regression back to the root write path
// cannot silently blind this spy's invariant.
func (s *envWriteSpy) WriteFile(ctx context.Context, spec bssh.FileSpec) error {
	if spec.Path == s.envPath {
		s.record(spec.Content)
	}
	return s.FakeRunner.WriteFile(ctx, spec)
}

func TestDatabaseApplyCachesSecretsBeforeSeedingEnv(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	stubClientAuthAbsent(f, s, ".my.cnf")
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".my.cnf")
	f.On("mysql --protocol=socket", bssh.Result{})
	spy := &envWriteSpy{FakeRunner: f, host: s.Host, dbUser: s.SiteDBUser(s.Sites[0]), envPath: envPath(s)}
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, spy); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !spy.wrote {
		t.Fatal("shared/.env was never written")
	}
	if !spy.pwCached || !spy.keyCached {
		t.Errorf("secrets must be persisted locally BEFORE the remote seed (pw cached: %v, APP_KEY cached: %v)", spy.pwCached, spy.keyCached)
	}
}

func TestDatabaseApplyFailsWhenAppKeyGrepErrors(t *testing.T) {
	// An I/O failure reading APP_KEY from an existing .env must be a hard error
	// — treating it as "absent" would silently skip the backup.
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=existingpw\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 2, Stderr: "grep: input: I/O error"})
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "I/O error") {
		t.Fatalf("Apply() = %v, want a hard error surfacing the grep stderr", err)
	}
}

func TestDatabaseCheckUnsatisfiedWhenDatabaseMissing(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present, driver matches
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("LC_ALL=C; export LC_ALL; grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0}) // credential present
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On(mariadbDBProbe, bssh.Result{Stdout: ""}) // database absent
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("a present .env must not satisfy Check when the database is missing")
	}
	if !strings.Contains(cr.Reason, "database for app.example.com missing") {
		t.Errorf("Reason = %q", cr.Reason)
	}
}

func TestDatabaseCheckUnsatisfiedWhenUserOrGrantMissing(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present, driver matches
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("LC_ALL=C; export LC_ALL; grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On(mariadbGrantProbe, bssh.Result{Stdout: ""}) // role or its grant absent
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("a present database must not satisfy Check when the user/grant is missing")
	}
	if !strings.Contains(cr.Reason, "database user/grant for app.example.com missing") {
		t.Errorf("Reason = %q", cr.Reason)
	}
}

func TestDatabaseCheckUnsatisfiedWhenEnvLacksValidPassword(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present, driver matches
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("LC_ALL=C; export LC_ALL; grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 1}) // no valid DB_PASSWORD on the first line (or key absent — same outcome)
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("an env without a valid DB_PASSWORD must not satisfy Check — Apply's pointed error must get its chance to run")
	}
	if !strings.Contains(cr.Reason, "credential for app.example.com not yet persisted") {
		t.Errorf("Reason = %q", cr.Reason)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "mysql") {
			t.Fatalf("no DB probe may run once the credential is missing; saw %q", c.Cmd)
		}
	}
}

func TestDatabaseCheckSkipsProbesWhenNotInstalled(t *testing.T) {
	chdirTemp(t) // Check preflight-reads the local secret cache
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env, guard passes
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 1})       // not installed
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("missing server package must be unsatisfied")
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "mysql") {
			t.Fatalf("no probe may run without an installed server; saw %q", c.Cmd)
		}
	}
}

func TestDatabaseCheckSourceMariaDBRequiresRepo(t *testing.T) {
	chdirTemp(t) // Check preflight-reads the local secret cache
	s := databaseServer()
	s.Database.Source = "mariadb"
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env, guard passes
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	// mariadb.org repo not yet registered -> not satisfied (before any per-site probe).
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("source=mariadb must be unsatisfied until the mariadb.org repo is registered")
	}
}

func TestDatabaseCheckSourceMariaDBConvergedRepoSatisfied(t *testing.T) {
	// The mirror direction of TestDatabaseCheckSourceMariaDBRequiresRepo: with
	// the upstream repo fully converged (managed byte-exact list + keyring
	// holding exactly the pinned key) the repo probe must not hold the step
	// unsatisfied — a green remote with a full cache reads Satisfied.
	chdirTemp(t)
	s := databaseServer()
	s.Database.Source = "mariadb"
	repo := apt.MariaDBOrg()
	seedCache(t, s, map[string]string{s.SiteDBUser(s.Sites[0]): "pw123"})
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	// Override stubGreenRemote's absent-repo default with the converged pair.
	f.On("cat "+shQuote(repo.SourceListPath()), bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, repo))})
	f.On("gpg --show-keys --with-colons "+repo.KeyringPath(), bssh.Result{ExitCode: 0, Stdout: gpgColonsFor(repo.Fingerprint)})
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 1}) // no berth-format APP_KEY -> no backup required
	f.On(envValueMatchScript(envPath(s), "DB_PASSWORD"), bssh.Result{ExitCode: 0})
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("source=mariadb with a converged repo must be satisfied; got %+v", cr)
	}
}

func TestDatabaseCheckUpstreamDriftedListUnsatisfied(t *testing.T) {
	chdirTemp(t) // Check preflight-reads the local secret cache
	s := databaseServer()
	s.Database.Source = "mariadb"
	repo := apt.MariaDBOrg()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env, guard passes
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	// A HISTORICAL deb.mariadb.org variant — adoption must catch old fleets too.
	f.On("cat "+shQuote(repo.SourceListPath()),
		bssh.Result{ExitCode: 0, Stdout: repo.LegacySourceContents()[1]})
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a legacy marker-less mariadb-org list must adopt (unsatisfied, Apply re-runs), not read as converged")
	}
}

func TestDatabaseCheckDebianSourceFlagsLingeringRepo(t *testing.T) {
	chdirTemp(t)          // Check preflight-reads the local secret cache
	s := databaseServer() // source: debian
	repo := apt.MariaDBOrg()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env, guard passes
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(repo.SourceListPath()),
		bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, repo))})
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a lingering berth-owned mariadb-org list must be unsatisfied under source=debian")
	}
}

func TestDatabaseApplyDebianSourceRemovesLingeringRepo(t *testing.T) {
	chdirTemp(t)
	s := databaseServer() // source: debian
	repo := apt.MariaDBOrg()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	f.On("cat "+shQuote(repo.SourceListPath()),
		bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, repo))})
	f.On("rm -f "+repo.SourceListPath()+" "+repo.KeyringPath(), bssh.Result{ExitCode: 0})
	f.On("apt-get update", bssh.Result{ExitCode: 0})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("mysql --protocol=socket", bssh.Result{})
	stubClientAuthAbsent(f, s, ".my.cnf")
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".my.cnf")
	var warns []string
	rc := provision.RunCtx{Warn: func(msg string) { warns = append(warns, msg) }}
	if err := Database(secret.NewRedactor()).Apply(context.Background(), rc, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var sawRM, sawUpdate bool
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+repo.SourceListPath()+" "+repo.KeyringPath() {
			sawRM = true
		}
		if c.Cmd == "apt-get update" {
			sawUpdate = true
		}
	}
	if !sawRM || !sawUpdate {
		t.Errorf("the lingering repo must be swept and the indexes refreshed; rm ran: %v, update ran: %v", sawRM, sawUpdate)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "upstream versions") {
		t.Fatalf("want one upstream-versions warning, got %v", warns)
	}
}

func TestDatabaseApplySourceMariaDBAddsRepo(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	s.Database.Source = "mariadb"
	repo := apt.MariaDBOrg()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, repo) // list absent -> ensureOwnRepo runs the full EnsureRepo chain
	stubEnsureRepoChain(f, repo)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "mariadb.org/mariadb_release_signing_key.asc") {
		t.Errorf("source=mariadb must fetch the mariadb.org signing key; calls:\n%s", strings.Join(cmds, "\n"))
	}
	var sourceListWritten bool
	for _, w := range f.Writes() {
		if w.Path == "/etc/apt/sources.list.d/mariadb-org.list" {
			sourceListWritten = true
		}
	}
	if !sourceListWritten {
		t.Error("expected the mariadb-org apt source list to be written")
	}
}

func TestDatabaseApplyPostgresFromPGDG(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	s.Database.Engine = "postgres"
	s.Database.Source = "pgdg"
	repo := apt.PostgresPGDG()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, repo) // list absent -> ensureOwnRepo runs the full EnsureRepo chain
	stubEnsureRepoChain(f, repo)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	f.On("sudo -u postgres psql -v ON_ERROR_STOP=1", bssh.Result{})

	stubClientAuthAbsent(f, s, ".pgpass")
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".pgpass")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "postgresql.org/media/keys/ACCC4CF8.asc") {
		t.Errorf("source=pgdg must fetch the PGDG signing key; calls:\n%s", strings.Join(cmds, "\n"))
	}
	var pgdgListWritten bool
	for _, w := range f.Writes() {
		if w.Path == "/etc/apt/sources.list.d/pgdg.list" {
			pgdgListWritten = true
		}
	}
	if !pgdgListWritten {
		t.Error("expected the pgdg apt source list to be written")
	}
	envBody := string(writtenContent(f, envPath(s)))
	if !strings.Contains(envBody, "DB_CONNECTION=pgsql") || !strings.Contains(envBody, "DB_PORT=5432") {
		t.Errorf("shared/.env must use the pgsql driver on port 5432; got:\n%s", envBody)
	}
}

func TestDatabaseApplyRejectsTamperedPassword(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	red := secret.NewRedactor()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env already present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	// A tampered env value containing a quote must be rejected (defence-in-depth).
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{Stdout: "DB_PASSWORD=bad'value\n"})

	err := Database(red).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("expected rejection of a reused password outside the allowed charset")
	}
}

func TestDatabaseApplyRejectsLeadingSpacePassword(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env already present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	// A leading-space value fails Check's probe, so laundering it here would
	// oscillate forever (Check unsatisfied, Apply "succeeds"). It must instead
	// fail loudly with the charset refusal.
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD= Good123\n"})
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "outside the allowed charset") {
		t.Fatalf("err = %v, want the charset refusal for a leading-space value", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "mysql") {
			t.Fatal("no SQL may run when the reused password is rejected")
		}
	}
}

func TestDatabaseApplyRejectsTrailingUnicodeSpacePassword(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env already present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	// A trailing NBSP (U+00A0) is NOT [[:space:]] to the Check probe's C-locale
	// grep, so Check rejects this line; trimming it away here would oscillate
	// forever. It must stay in the value and fail the charset refusal.
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Good123\u00a0\n"})
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "outside the allowed charset") {
		t.Fatalf("err = %v, want the charset refusal for a trailing-NBSP value", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "mysql") {
			t.Fatal("no SQL may run when the reused password is rejected")
		}
	}
}

func TestDatabaseApplyAcceptsTrailingASCIIWhitespacePassword(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env already present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	// A trailing vertical tab IS [[:space:]] to the Check probe (POSIX C-locale
	// set), so Apply must trim it the same way and reuse the value.
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Good123\v\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // absent -> not backfilled
	f.On("mysql --protocol=socket", bssh.Result{})
	stubClientAuthAbsent(f, s, ".my.cnf")
	stubClientAuthSeed(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var sawEnsureUser bool
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "mysql") && strings.Contains(string(c.Stdin), "Good123") {
			sawEnsureUser = true
		}
	}
	if !sawEnsureUser {
		t.Fatal("EnsureUser must reuse the trimmed password from the live .env")
	}
}

func TestSeedSharedEnvMariaDBUsesSocket(t *testing.T) {
	f := bssh.NewFakeRunner()
	d := database{redactor: secret.NewRedactor()}
	eng, _ := dbpkg.Get("mariadb")
	driver, host, port, socket := eng.EnvConnection()
	s := &config.Server{Database: config.Database{Engine: "mariadb"}, Sites: []config.Site{{Domain: "x.example.com", DeployPath: "/srv/x"}}}
	stubEnvSeed(f, s)
	if err := d.seedSharedEnv(context.Background(), f, s, s.Sites[0], "db", "u", "pw", "appkey", driver, host, port, socket); err != nil {
		t.Fatal(err)
	}
	env := string(writtenContent(f, sharedEnvPath(s.Sites[0])))
	if !strings.Contains(env, "DB_HOST=localhost") {
		t.Errorf("mariadb .env should use DB_HOST=localhost; got:\n%s", env)
	}
	if !strings.Contains(env, "DB_SOCKET=/run/mysqld/mysqld.sock") {
		t.Errorf("mariadb .env should set DB_SOCKET; got:\n%s", env)
	}
}

func TestSeedSharedEnvPostgresUsesTCPNoSocket(t *testing.T) {
	f := bssh.NewFakeRunner()
	d := database{redactor: secret.NewRedactor()}
	eng, _ := dbpkg.Get("postgres")
	driver, host, port, socket := eng.EnvConnection()
	s := &config.Server{Database: config.Database{Engine: "postgres"}, Sites: []config.Site{{Domain: "x.example.com", DeployPath: "/srv/x"}}}
	stubEnvSeed(f, s)
	if err := d.seedSharedEnv(context.Background(), f, s, s.Sites[0], "db", "u", "pw", "appkey", driver, host, port, socket); err != nil {
		t.Fatal(err)
	}
	env := string(writtenContent(f, sharedEnvPath(s.Sites[0])))
	if !strings.Contains(env, "DB_HOST=127.0.0.1") {
		t.Errorf("postgres .env should use DB_HOST=127.0.0.1; got:\n%s", env)
	}
	if strings.Contains(env, "DB_SOCKET=") {
		t.Errorf("postgres .env must NOT set DB_SOCKET; got:\n%s", env)
	}
}

func TestSeedSharedEnvUsesPerSiteSocket(t *testing.T) {
	s := &config.Server{
		Valkey: true,
		Sites:  []config.Site{{Domain: "app.example.com", User: "tenant1", DeployPath: "/var/www/app"}},
	}
	f := bssh.NewFakeRunner()
	d := database{redactor: secret.NewRedactor()}
	stubEnvSeed(f, s)
	if err := d.seedSharedEnv(context.Background(), f, s, s.Sites[0],
		"appdb", "appuser", "pw123", "base64:key", "mysql", "127.0.0.1", "3306", "/run/mysqld/mysqld.sock"); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, shQuote(sharedEnvPath(s.Sites[0]))) && strings.Contains(c.Cmd, "mv -f") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one .env write, got %d", n)
	}
	env := string(writtenContent(f, sharedEnvPath(s.Sites[0])))
	for _, want := range []string{
		"REDIS_CLIENT=phpredis\n",
		"REDIS_HOST=/run/berth-valkey/app_example_com/valkey.sock\n",
		"REDIS_PORT=0\n",
		"REDIS_DB=0\n",
		"REDIS_CACHE_DB=1\n",
		"CACHE_DRIVER=redis\n", // Laravel 10 reads CACHE_DRIVER...
		"CACHE_STORE=redis\n",  // ...Laravel 11/12 read CACHE_STORE
		"SESSION_DRIVER=redis\n",
		"QUEUE_CONNECTION=redis\n",
	} {
		if !strings.Contains(env, want) {
			t.Errorf(".env missing %q:\n%s", want, env)
		}
	}
	if strings.Contains(env, "REDIS_PREFIX") {
		t.Error("REDIS_PREFIX must not be seeded for a private per-site instance")
	}
}

func TestDatabaseApplySeedsClientAuthFile(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})   // fresh box: no .env yet
	f.On("test -e '/home/deploy/.my.cnf'", bssh.Result{ExitCode: 1}) // fresh box: no client creds yet
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".my.cnf")
	f.On("mysql --protocol=socket", bssh.Result{})

	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	env := writtenContent(f, envPath(s))
	auth := writtenContent(f, "/home/deploy/.my.cnf")
	if env == nil || auth == nil {
		t.Fatalf("expected both shared/.env and ~/.my.cnf written; env=%v auth=%v", env != nil, auth != nil)
	}
	// The file sits in tenant territory, so the account itself must write it.
	var seed string
	for _, c := range callCmds(f) {
		if strings.Contains(c, shQuote("/home/deploy/.my.cnf")) && strings.Contains(c, "mv -f") {
			seed = c
		}
	}
	if !strings.HasPrefix(seed, "sudo -u deploy ") || !strings.Contains(seed, "chmod 600") {
		t.Errorf("~/.my.cnf must be written by deploy with mode 600; got %q", seed)
	}
	body := string(auth)
	if !strings.Contains(body, "[client]") || !strings.Contains(body, "user = myapp") {
		t.Errorf("~/.my.cnf must carry the [client] credential; got:\n%s", body)
	}
	// The credential must be the same one seeded into shared/.env.
	var envPW string
	for _, line := range strings.Split(string(env), "\n") {
		if pw, ok := strings.CutPrefix(line, "DB_PASSWORD="); ok {
			envPW = pw
		}
	}
	if envPW == "" || !strings.Contains(body, "password = "+envPW) {
		t.Error("~/.my.cnf must hold the same password as shared/.env")
	}
}

func TestDatabaseApplyClientAuthFileNeverRewritten(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env already present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Reused123\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // absent -> not backfilled
	f.On("test -e '/home/deploy/.my.cnf'", bssh.Result{ExitCode: 0})            // already seeded (possibly operator-customized)
	f.On("mysql --protocol=socket", bssh.Result{})

	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if writtenContent(f, "/home/deploy/.my.cnf") != nil {
		t.Fatal("an existing ~/.my.cnf must never be rewritten")
	}
}

// divergedAppKey is the berth-shaped APP_KEY stubDivergedEnv plants in the
// restored .env — the "new" key Apply must reconcile the cache toward.
const divergedAppKey = "base64:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

// stubDivergedEnv stubs an Apply fixture where the restored .env disagrees
// with the seeded cache: install done, .env present with NEW password and NEW
// berth APP_KEY (divergedAppKey), client-auth file already seeded (holding
// whatever the cache held), SQL stubbed.
func stubDivergedEnv(f *bssh.FakeRunner, s *config.Server, newPW string) {
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=" + newPW + "\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "APP_KEY=" + divergedAppKey + "\n"})
	f.On("test -e "+shQuote("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 0})
	f.On("mysql --protocol=socket", bssh.Result{})
}

// Divergence heals end to end: Check flags it (pinned above), Apply ALTERs
// the role to the .env password, backfills the cache, and refreshes a
// client-auth file that provably held the old berth credential.
func TestDatabaseApplyReconcilesRoleAndCacheTowardEnv(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	const oldKey = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	seedCache(t, s, map[string]string{dbUser: "OldPass1", "appkey:" + dbUser: oldKey})
	f := bssh.NewFakeRunner()
	stubDivergedEnv(f, s, "NewPass2")
	f.On(clientAuthContainsScript("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 0}) // file holds the OLD berth credential
	f.On(writeAsUserCmd("deploy", "/home/deploy/.my.cnf"), bssh.Result{})
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	// The role reconciles toward the live .env, and no secret rides argv.
	var sawEnsureUser bool
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "mysql") && strings.Contains(string(c.Stdin), "NewPass2") {
			sawEnsureUser = true
		}
		if c.Cmd == clientAuthContainsScript("/home/deploy/.my.cnf") {
			if got := string(c.Stdin); got != "OldPass1\n" {
				t.Errorf("containment probe stdin = %q, want the OLD cached password", got)
			}
		}
		if strings.Contains(c.Cmd, "OldPass1") || strings.Contains(c.Cmd, "NewPass2") {
			t.Errorf("a secret leaked into a command string: %q", c.Cmd)
		}
	}
	if !sawEnsureUser {
		t.Fatal("EnsureUser must move the role to the .env password")
	}
	// The stranded client-auth file is refreshed with the NEW credential.
	auth := string(writtenContent(f, "/home/deploy/.my.cnf"))
	if !strings.Contains(auth, "NewPass2") {
		t.Errorf("~/.my.cnf must be rewritten with the reconciled credential; got %q", auth)
	}
	// The cache backfills to the .env values — the next Check goes green.
	cache, err := secret.LoadCache(s.Host)
	if err != nil {
		t.Fatal(err)
	}
	if cache[dbUser] != "NewPass2" {
		t.Errorf("cache password = %q, want the .env value", cache[dbUser])
	}
	if cache["appkey:"+dbUser] != divergedAppKey {
		t.Errorf("cache APP_KEY = %q, want the .env value", cache["appkey:"+dbUser])
	}
}

func TestDatabaseApplyLeavesOperatorClientAuthAlone(t *testing.T) {
	// The same divergence, but the client-auth file does NOT contain berth's
	// old credential — an operator customized it, and berth keeps the same
	// seed-if-absent respect shared/.env gets: probe, then hands off.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "OldPass1"})
	f := bssh.NewFakeRunner()
	stubDivergedEnv(f, s, "NewPass2")
	f.On(clientAuthContainsScript("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 1}) // old credential NOT inside
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if writtenContent(f, "/home/deploy/.my.cnf") != nil {
		t.Fatal("an operator-customized client-auth file must never be rewritten")
	}
}

func TestDatabaseApplyRefusesCorruptCachedPasswordBeforeContainmentProbe(t *testing.T) {
	// A manually corrupted cached password whose FIRST LINE is empty would
	// feed the containment probe's grep -F -f - an EMPTY pattern — which
	// matches EVERY line (exit 0) and would rewrite an operator-customized
	// client-auth file. This now pins the PREFLIGHT validator: Apply refuses
	// before ANY remote command, not merely before the probe.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "\nsneaky"})
	f := bssh.NewFakeRunner()
	stubDivergedEnv(f, s, "ValidPW123")
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "outside the allowed charset") {
		t.Fatalf("Apply() = %v, want the charset refusal for a corrupt cached password", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Fatalf("Apply must refuse before any remote command; ran %d (first: %q)", n, f.Calls()[0].Cmd)
	}
	if writtenContent(f, "/home/deploy/.my.cnf") != nil {
		t.Fatal("the client-auth file must not be rewritten on the refusal path")
	}
}

func TestDatabaseApplyRefusesCorruptCachedAppKeyBeforeAnyRemoteCall(t *testing.T) {
	// Fresh host, corrupt cached APP_KEY: the preflight validator must refuse
	// before ANY remote command — deliberately nothing is stubbed, and the
	// call log must stay empty (no repo, no apt-get, no SQL, no seeds).
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{"appkey:" + dbUser: "base64:tampered"})
	f := bssh.NewFakeRunner()
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("Apply() = %v, want the malformed-cached-APP_KEY refusal", err)
	}
	if n := len(f.Calls()); n != 0 {
		t.Fatalf("Apply must refuse before any remote command; ran %d (first: %q)", n, f.Calls()[0].Cmd)
	}
	if len(f.Writes()) != 0 {
		t.Fatal("Apply must not write any remote file on the refusal path")
	}
}

func TestDatabaseApplyFailsWhenClientAuthProbeErrors(t *testing.T) {
	// grep exit >= 2 is an I/O failure, not "old credential absent" — silently
	// skipping the refresh would strand the client file with no signal.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "OldPass1"})
	f := bssh.NewFakeRunner()
	stubDivergedEnv(f, s, "NewPass2")
	f.On(clientAuthContainsScript("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 2, Stderr: "grep: /home/deploy/.my.cnf: I/O error"})
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "I/O error") {
		t.Fatalf("Apply() = %v, want a hard error surfacing the probe stderr", err)
	}
}

func TestDatabaseApplySkipsContainmentProbeWhenCacheAgrees(t *testing.T) {
	// No divergence (cache already holds the .env password): the containment
	// probe must not run at all — the reconciliation is strictly for the
	// password-moved case.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "SamePass1"})
	f := bssh.NewFakeRunner()
	stubDivergedEnv(f, s, "SamePass1")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "IFS= read -r old") {
			t.Fatalf("no containment probe may run when cache and .env agree; saw %q", c.Cmd)
		}
	}
}

// Pins the real shell semantics of clientAuthContainsScript: the OLD password
// arrives via stdin, `read` puts it in a shell variable, printf pipes it to
// grep as the PATTERN (-f -) while the auth file is grep's named INPUT —
// pattern-from-pipe and data-from-file are separate fds in this direction.
func TestClientAuthContainsShellScript(t *testing.T) {
	dir := t.TempDir()
	auth := filepath.Join(dir, ".my.cnf")
	cases := []struct {
		name, content, old string
		exit               int
	}{
		{"contains", "[client]\nuser = myapp\npassword = OldPass1\n", "OldPass1", 0},
		{"not-contains", "[client]\nuser = myapp\npassword = OperatorPW9\n", "OldPass1", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(auth, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := shellExit(t, clientAuthContainsScript(auth), c.old+"\n"); got != c.exit {
				t.Fatalf("exit = %d, want %d", got, c.exit)
			}
		})
	}
}

func TestDatabaseCheckUnsatisfiedWhenClientAuthMissing(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present, driver matches
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("LC_ALL=C; export LC_ALL; grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
	f.On(mariadbGrantProbe, bssh.Result{Stdout: "1\n"})
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("test -e '/home/deploy/.my.cnf'", bssh.Result{ExitCode: 1}) // creds file missing
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Fatal("a missing client-credentials file must not satisfy Check (a crash between EnsureUser and the seed must heal)")
	}
	if !strings.Contains(cr.Reason, "client DB credentials") {
		t.Errorf("Reason = %q", cr.Reason)
	}
}

func TestDatabaseCheckFailsLoudlyOnEngineEnvConflict(t *testing.T) {
	chdirTemp(t)          // Check preflight-reads the local secret cache
	s := databaseServer() // engine mariadb -> seeds DB_CONNECTION=mysql
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=pgsql\n"})
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("expected a loud error when DB_CONNECTION disagrees with database.engine")
	}
	for _, want := range []string{"DB_CONNECTION=pgsql", "mariadb", "mysql", envPath(s)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestDatabaseCheckConflictGuardIgnoresForce(t *testing.T) {
	chdirTemp(t) // Check preflight-reads the local secret cache
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=pgsql\n"})
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{Force: true}, s, f)
	if err == nil || !strings.Contains(err.Error(), "DB_CONNECTION") {
		t.Fatalf("Check() = %v; --force must not override the engine/env conflict guard", err)
	}
}

func TestDatabaseCheckFailsWhenExistingEnvLacksDBConnection(t *testing.T) {
	chdirTemp(t) // Check preflight-reads the local secret cache
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})                    // .env present...
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // ...but no DB_CONNECTION line
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "DB_CONNECTION") {
		t.Fatalf("Check() = %v, want an error naming the missing DB_CONNECTION key", err)
	}
}

func TestDatabaseCheckFailsLoudlyOnEngineEnvConflictPostgres(t *testing.T) {
	chdirTemp(t) // Check preflight-reads the local secret cache
	s := databaseServer()
	s.Database = config.Database{Engine: "postgres", Source: "debian"}
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "pgsql") {
		t.Fatalf("Check() = %v, want a conflict naming the expected driver pgsql", err)
	}
}

func TestDatabaseApplyFailsOnEngineEnvConflictBeforeMutating(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env exists
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=pgsql\n"})
	// NOTE: apt install is deliberately NOT stubbed — the guard must fire before it.
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "DB_CONNECTION") {
		t.Fatalf("Apply() = %v, want the engine/env conflict error", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "apt-get") || strings.HasPrefix(c.Cmd, "mysql") {
			t.Errorf("Apply must not install or mutate anything after detecting the conflict; ran %q", c.Cmd)
		}
	}
}

func TestDatabaseApplyPreScansAllSitesBeforeMutating(t *testing.T) {
	// The conflict is on the SECOND site; the pre-scan must find it before any
	// apt/SQL runs for the first (clean) site.
	chdirTemp(t)
	s := &config.Server{
		Host:     "app.example.com",
		Database: config.Database{Engine: "mariadb", Source: "debian"},
		Sites: []config.Site{
			{Domain: "one.example.com", DeployPath: "/var/www/one", Database: config.SiteDatabase{Name: "one_db", User: "one_user"}},
			{Domain: "two.example.com", DeployPath: "/var/www/two", Database: config.SiteDatabase{Name: "two_db", User: "two_user"}},
		},
	}
	env0, env1 := "/var/www/one/shared/.env", "/var/www/two/shared/.env"
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(env0), bssh.Result{ExitCode: 1})                                                     // first site: no .env -> guard passes
	f.On("test -e "+shQuote(env1), bssh.Result{ExitCode: 0})                                                     // second site: .env exists...
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(env1), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=pgsql\n"}) // ...conflicts
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "two.example.com") {
		t.Fatalf("Apply() = %v, want the conflict error naming the second site", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "apt-get") || strings.HasPrefix(c.Cmd, "mysql") {
			t.Errorf("no site may be installed or mutated when a later site conflicts; ran %q", c.Cmd)
		}
	}
}

func TestDatabaseCheckFailsWhenGrepErrors(t *testing.T) {
	chdirTemp(t) // Check preflight-reads the local secret cache
	// grep exit >= 2 (unreadable input / I/O error) must be a hard error, not
	// silently treated as "key absent".
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 2, Stderr: "grep: input: Permission denied"})
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("Check() = %v, want a hard error surfacing the grep stderr", err)
	}
}

func TestDatabaseCheckPassesWhenDBConnectionMatchesOrFileAbsent(t *testing.T) {
	// A matching driver, and an ABSENT file, both stay silent; Check then
	// proceeds to its normal flow (here: the not-installed early return). An
	// existing file that merely lacks the key is covered separately (it errors).
	// Trailing space, vertical tab, and form feed after the value are all
	// trimmed (mirrors passwordFromEnv's ASCII set), so they still match.
	chdirTemp(t) // Check preflight-reads the local secret cache
	cases := map[string]struct {
		envExists int // test -e exit code
		grep      *bssh.Result
	}{
		"matching driver":       {0, &bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"}},
		"trailing space":        {0, &bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql \n"}},
		"trailing vertical tab": {0, &bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\v\n"}},
		"trailing form feed":    {0, &bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\f\n"}},
		"file absent":           {1, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := databaseServer()
			f := bssh.NewFakeRunner()
			f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: tc.envExists})
			if tc.grep != nil {
				f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), *tc.grep)
			}
			f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 1}) // not installed -> early unsatisfied
			stubEngineRepoAbsent(f, apt.MariaDBOrg())
			cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if cr.Satisfied {
				t.Error("expected unsatisfied (server not installed), not an error")
			}
		})
	}
}

func TestDatabaseApplyRecoversAppKeyFromCache(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	const wantKey = "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{dbUser: "cachedpw", "appkey:" + dbUser: wantKey})
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // no .env -> re-seed path
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	stubClientAuthAbsent(f, s, ".my.cnf")
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".my.cnf")
	f.On("mysql --protocol=socket", bssh.Result{})
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	env := writtenContent(f, envPath(s))
	if env == nil || !strings.Contains(string(env), "APP_KEY="+wantKey) {
		t.Errorf("re-seeded .env must reuse the cached APP_KEY %q", wantKey)
	}
}

func TestDatabaseApplyCachesGeneratedAppKey(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	stubClientAuthAbsent(f, s, ".my.cnf")
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".my.cnf")
	f.On("mysql --protocol=socket", bssh.Result{})
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	cache, err := secret.LoadCache(s.Host)
	if err != nil {
		t.Fatal(err)
	}
	if got := cache["appkey:"+s.SiteDBUser(s.Sites[0])]; !strings.HasPrefix(got, "base64:") {
		t.Errorf("a freshly generated APP_KEY must be cached; got %q", got)
	}
}

func TestDatabaseApplyBackfillsAppKeyFromExistingEnv(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	const envKey = "base64:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=existingpw\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "APP_KEY=" + envKey + "\n"})
	f.On("test -e "+shQuote("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 0}) // client creds present
	f.On("mysql --protocol=socket", bssh.Result{})
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	cache, err := secret.LoadCache(s.Host)
	if err != nil {
		t.Fatal(err)
	}
	if cache["appkey:"+s.SiteDBUser(s.Sites[0])] != envKey {
		t.Errorf("an existing .env APP_KEY must be backfilled into the cache; got %q", cache["appkey:"+s.SiteDBUser(s.Sites[0])])
	}
}

func TestDatabaseApplySkipsNonBerthEnvAppKey(t *testing.T) {
	// A present APP_KEY in a shape berth does not generate (no "base64:"
	// prefix, wrong length, an operator's AES-128 key) is simply not berth's
	// to back up: shape alone cannot distinguish an operator-managed
	// Laravel-legal key from a corrupt berth key, and the old hard error
	// bricked Apply on operator-keyed hosts for ANY trigger. The key must be
	// treated as absent — never cached, never fatal.
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=existingpw\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "APP_KEY=base64:short\n"})
	f.On("test -e "+shQuote("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 0})
	f.On("mysql --protocol=socket", bssh.Result{})
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() = %v; a non-berth APP_KEY must not brick Apply", err)
	}
	cache, err := secret.LoadCache(s.Host)
	if err != nil {
		t.Fatal(err)
	}
	if got := cache["appkey:"+s.SiteDBUser(s.Sites[0])]; got != "" {
		t.Errorf("a non-berth APP_KEY must never be cached; got %q", got)
	}
}

func TestDatabaseApplyRejectsMalformedCachedAppKey(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{"appkey:" + dbUser: "base64:tampered"})
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("Apply() = %v, want a malformed-cached-APP_KEY refusal", err)
	}
}

func TestDatabaseApplyPostgresSeedsPgpass(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	s.Database.Engine = "postgres"
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.PostgresPGDG())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})   // fresh box: no .env yet
	f.On("test -e '/home/deploy/.pgpass'", bssh.Result{ExitCode: 1}) // fresh box: no client creds yet
	stubEnvSeed(f, s)
	stubClientAuthSeed(f, s, ".pgpass")
	f.On("sudo -u postgres psql -v ON_ERROR_STOP=1", bssh.Result{})

	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	auth := writtenContent(f, "/home/deploy/.pgpass")
	if auth == nil {
		t.Fatal("~/.pgpass was not written")
	}
	var seed string
	for _, c := range callCmds(f) {
		if strings.Contains(c, shQuote("/home/deploy/.pgpass")) && strings.Contains(c, "mv -f") {
			seed = c
		}
	}
	if !strings.HasPrefix(seed, "sudo -u deploy ") || !strings.Contains(seed, "chmod 600") {
		t.Errorf("~/.pgpass must be written by deploy with mode 600 (libpq refuses anything else); got %q", seed)
	}
	if !strings.HasPrefix(string(auth), "*:*:myapp:myapp:") {
		t.Errorf("~/.pgpass = %q, want the wildcard db/user line", auth)
	}
}

func TestDatabaseApplyRegistersPasswordBeforeAppKeyAcquisitionFails(t *testing.T) {
	// The redaction property is TEMPORAL: each secret registers the moment it
	// is acquired, BEFORE the next fallible operation. With the pre-P15
	// ordering (Add after the whole branch) this test fails: the password
	// read from the live .env would stay unregistered when appKeyFromEnv
	// dies, and the run's error output could carry it unmasked.
	chdirTemp(t)
	s := databaseServer()
	red := secret.NewRedactor()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Hunter22pw\n"})
	f.OnError("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), errors.New("connection lost"))

	err := Database(red).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("Apply must fail when the APP_KEY read dies")
	}
	if got := red.Apply("leak Hunter22pw leak"); strings.Contains(got, "Hunter22pw") {
		t.Fatalf("the password must already be registered when a LATER acquisition fails; Apply => %q", got)
	}
}

func TestDatabaseApplyRegistersCachedPasswordBeforeCachedAppKeyValidationFails(t *testing.T) {
	// The malformed cached APP_KEY aborts in loadValidatedSecrets' preflight
	// (the fresh-seed branch and recoverOrNewAppKey are never reached), and
	// the cached password, validated and registered just before it, must
	// already redact.
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	seedCache(t, s, map[string]string{
		dbUser:             "Hunter22pw",
		"appkey:" + dbUser: "garbage-not-an-app-key",
	})
	red := secret.NewRedactor()
	f := bssh.NewFakeRunner()
	stubEngineRepoAbsent(f, apt.MariaDBOrg())
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh: no .env

	err := Database(red).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "APP_KEY") {
		t.Fatalf("Apply must fail on the malformed cached APP_KEY; got %v", err)
	}
	if got := red.Apply("leak Hunter22pw leak"); strings.Contains(got, "Hunter22pw") {
		t.Fatalf("the password must already be registered when cached APP_KEY validation fails; Apply => %q", got)
	}
}

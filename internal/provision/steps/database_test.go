package steps

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func databaseServer() *config.Server {
	return &config.Server{
		Host:     "app.example.com",
		Database: config.Database{Engine: "mariadb", Name: "myapp", User: "myapp", Source: "debian"},
		Sites: []config.Site{{
			Domain:     "app.example.com",
			DeployPath: "/home/deploy/myapp",
			SSL:        true,
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

// stubRepoKeyTrust stubs apt.EnsureRepo's key-trust command sequence for an
// upstream repo, ending in a keyring holding exactly the pinned primary key.
func stubRepoKeyTrust(f *bssh.FakeRunner, name, keyURL, fpr string) {
	tmpKey, tmpRing := "/run/berth/key-"+name, "/run/berth/keyring-"+name+".gpg"
	keyring := "/usr/share/keyrings/" + name + ".gpg"
	f.On("install -d -m 700 /run/berth", bssh.Result{})
	f.On("curl -fsSL "+keyURL+" -o "+tmpKey, bssh.Result{})
	f.On("gpg --yes -o "+tmpRing+" --dearmor "+tmpKey, bssh.Result{})
	f.On("gpg --no-default-keyring --keyring "+tmpRing+" --yes -o "+keyring+" --export "+fpr, bssh.Result{})
	f.On("gpg --show-keys --with-colons "+keyring,
		bssh.Result{Stdout: "pub:-:4096:1:0000000000000000:0::-:::scSC::::::23::0:\nfpr:::::::::" + fpr + ":\n"})
	f.On("rm -f "+tmpKey+" "+tmpRing, bssh.Result{})
}

func TestDatabaseApplyGeneratesPersistsAndEnsures(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	red := secret.NewRedactor()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	stubClientAuthAbsent(f, s, ".my.cnf")
	f.On("mysql --protocol=socket", bssh.Result{})

	if err := Database(red).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// shared/.env must have been written (owner deploy, mode 0600) and contain DB_PASSWORD.
	var env *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == envPath(s) {
			env = &f.Writes()[i]
		}
	}
	if env == nil {
		t.Fatal("shared/.env was not written")
	}
	if env.Owner != "deploy" || env.Mode.Perm() != 0o600 {
		t.Errorf("shared/.env owner/mode = %s/%v, want deploy/0600", env.Owner, env.Mode.Perm())
	}
	if !strings.Contains(string(env.Content), "DB_PASSWORD=") {
		t.Error("shared/.env must contain DB_PASSWORD")
	}
	if !strings.Contains(string(env.Content), "APP_KEY=base64:") {
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

func TestDatabaseApplySeedsRedisWhenValkey(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	s.Valkey = true
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var env *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == envPath(s) {
			env = &f.Writes()[i]
		}
	}
	if env == nil {
		t.Fatal("shared/.env was not written")
	}
	body := string(env.Content)
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
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var env *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == envPath(s) {
			env = &f.Writes()[i]
		}
	}
	if env == nil {
		t.Fatal("shared/.env was not written")
	}
	if strings.Contains(string(env.Content), "CACHE_DRIVER=redis") ||
		strings.Contains(string(env.Content), "CACHE_STORE=redis") {
		t.Errorf("without Valkey, redis drivers must NOT be seeded; got:\n%s", env.Content)
	}
}

func TestDatabaseApplyHealsFromExistingEnvWithoutRewriting(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env already present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Reused123\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // absent -> not backfilled
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, w := range f.Writes() {
		if w.Path == envPath(s) {
			t.Fatal("an existing shared/.env must never be rewritten")
		}
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
	if err := secret.SaveCache(s.Host, map[string]string{s.SiteDBUser(s.Sites[0]): "pw123"}); err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present, driver matches
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
	f.On(mariadbGrantProbe, bssh.Result{Stdout: "1\n"})
	f.On("test -e "+shQuote("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 0}) // client creds already seeded
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 1})                             // no berth-format APP_KEY -> no backup required
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
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
	f.On(mariadbGrantProbe, bssh.Result{Stdout: "1\n"})
	f.On("test -e "+shQuote("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 0})
}

// appKeyProbe is Check's exact-shape APP_KEY probe command for the test
// server's env (exit-code only, FIRST-line semantics; must match
// envHasBerthAppKey verbatim).
func appKeyProbe(s *config.Server) string {
	return "line=$(grep -m1 '^APP_KEY=' " + shQuote(envPath(s)) + "); s=$?; " +
		"if [ $s -eq 1 ]; then exit 1; elif [ $s -ne 0 ]; then exit 2; fi; " +
		`printf '%s' "$line" | grep -Eq '^APP_KEY=base64:[A-Za-z0-9+/]{43}=$' && exit 0; exit 3`
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
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	if err := secret.SaveCache(s.Host, map[string]string{
		dbUser:             "pw123",
		"appkey:" + dbUser: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}); err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 0}) // live env holds a berth-format APP_KEY
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
	if err := secret.SaveCache(s.Host, map[string]string{dbUser: "pw123"}); err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 1})
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
	if err := secret.SaveCache(s.Host, map[string]string{dbUser: "pw123"}); err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 3})
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
	if err := secret.SaveCache(s.Host, map[string]string{dbUser: "pw123"}); err != nil {
		t.Fatal(err)
	}
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
	if err := secret.SaveCache(s.Host, map[string]string{dbUser: "pw123"}); err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubGreenRemote(f, s)
	f.On(appKeyProbe(s), bssh.Result{ExitCode: 2, Stderr: "grep: input: Permission denied"})
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("Check() = %v, want a hard error surfacing the probe stderr", err)
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

func (s *envWriteSpy) WriteFile(ctx context.Context, spec bssh.FileSpec) error {
	if spec.Path == s.envPath {
		s.wrote = true
		var envPW, envKey string
		for _, line := range strings.Split(string(spec.Content), "\n") {
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
	return s.FakeRunner.WriteFile(ctx, spec)
}

func TestDatabaseApplyCachesSecretsBeforeSeedingEnv(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	stubClientAuthAbsent(f, s, ".my.cnf")
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
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0}) // credential present
	f.On(mariadbDBProbe, bssh.Result{Stdout: ""})                                                                                          // database absent
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
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
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
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 1}) // no valid DB_PASSWORD on the first line (or key absent — same outcome)
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
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env, guard passes
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 1})       // not installed
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
	s := databaseServer()
	s.Database.Source = "mariadb"
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env, guard passes
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	// mariadb.org repo not yet registered -> not satisfied (before any per-site probe).
	f.On("test -e "+shQuote("/etc/apt/sources.list.d/mariadb-org.list"), bssh.Result{ExitCode: 1})
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("source=mariadb must be unsatisfied until the mariadb.org repo is registered")
	}
}

func TestDatabaseApplySourceMariaDBAddsRepo(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	s.Database.Source = "mariadb"
	f := bssh.NewFakeRunner()
	stubRepoKeyTrust(f, "mariadb-org", "https://mariadb.org/mariadb_release_signing_key.asc", "177F4010FE56CA3336300305F1656F24C74CD1D8")
	f.On("apt-get update", bssh.Result{})
	f.On("apt-get update -o Dir::Etc::sourcelist=sources.list.d/mariadb-org.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any", bssh.Result{ExitCode: 0})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
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
	f := bssh.NewFakeRunner()
	stubRepoKeyTrust(f, "pgdg", "https://www.postgresql.org/media/keys/ACCC4CF8.asc", "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8")
	f.On("apt-get update", bssh.Result{})
	f.On("apt-get update -o Dir::Etc::sourcelist=sources.list.d/pgdg.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any", bssh.Result{ExitCode: 0})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // fresh box: no .env yet
	f.On("sudo -u postgres psql -v ON_ERROR_STOP=1", bssh.Result{})

	stubClientAuthAbsent(f, s, ".pgpass")
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
	var envBody string
	for _, w := range f.Writes() {
		if w.Path == "/etc/apt/sources.list.d/pgdg.list" {
			pgdgListWritten = true
		}
		if w.Path == envPath(s) {
			envBody = string(w.Content)
		}
	}
	if !pgdgListWritten {
		t.Error("expected the pgdg apt source list to be written")
	}
	if !strings.Contains(envBody, "DB_CONNECTION=pgsql") || !strings.Contains(envBody, "DB_PORT=5432") {
		t.Errorf("shared/.env must use the pgsql driver on port 5432; got:\n%s", envBody)
	}
}

func TestDatabaseApplyRejectsTamperedPassword(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	red := secret.NewRedactor()
	f := bssh.NewFakeRunner()
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
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env already present
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	// A trailing vertical tab IS [[:space:]] to the Check probe (POSIX C-locale
	// set), so Apply must trim it the same way and reuse the value.
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Good123\v\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // absent -> not backfilled
	f.On("mysql --protocol=socket", bssh.Result{})
	stubClientAuthAbsent(f, s, ".my.cnf")
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
	if err := d.seedSharedEnv(context.Background(), f, s, s.Sites[0], "db", "u", "pw", "appkey", driver, host, port, socket); err != nil {
		t.Fatal(err)
	}
	env := string(f.Writes()[0].Content)
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
	if err := d.seedSharedEnv(context.Background(), f, s, s.Sites[0], "db", "u", "pw", "appkey", driver, host, port, socket); err != nil {
		t.Fatal(err)
	}
	env := string(f.Writes()[0].Content)
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
	if err := d.seedSharedEnv(context.Background(), f, s, s.Sites[0],
		"appdb", "appuser", "pw123", "base64:key", "mysql", "127.0.0.1", "3306", "/run/mysqld/mysqld.sock"); err != nil {
		t.Fatal(err)
	}
	if len(f.Writes()) != 1 {
		t.Fatalf("expected exactly one write, got %d", len(f.Writes()))
	}
	env := string(f.Writes()[0].Content)
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
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})   // fresh box: no .env yet
	f.On("test -e '/home/deploy/.my.cnf'", bssh.Result{ExitCode: 1}) // fresh box: no client creds yet
	f.On("mysql --protocol=socket", bssh.Result{})

	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var env, auth *bssh.FileSpec
	for i := range f.Writes() {
		switch f.Writes()[i].Path {
		case envPath(s):
			env = &f.Writes()[i]
		case "/home/deploy/.my.cnf":
			auth = &f.Writes()[i]
		}
	}
	if env == nil || auth == nil {
		t.Fatalf("expected both shared/.env and ~/.my.cnf written; env=%v auth=%v", env != nil, auth != nil)
	}
	if auth.Owner != "deploy" || auth.Group != "deploy" || auth.Mode.Perm() != 0o600 {
		t.Errorf("~/.my.cnf owner/group/mode = %s/%s/%v, want deploy/deploy/0600", auth.Owner, auth.Group, auth.Mode.Perm())
	}
	body := string(auth.Content)
	if !strings.Contains(body, "[client]") || !strings.Contains(body, "user = myapp") {
		t.Errorf("~/.my.cnf must carry the [client] credential; got:\n%s", body)
	}
	// The credential must be the same one seeded into shared/.env.
	var envPW string
	for _, line := range strings.Split(string(env.Content), "\n") {
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
	for _, w := range f.Writes() {
		if w.Path == "/home/deploy/.my.cnf" {
			t.Fatal("an existing ~/.my.cnf must never be rewritten")
		}
	}
}

func TestDatabaseCheckUnsatisfiedWhenClientAuthMissing(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env present, driver matches
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
	f.On(mariadbGrantProbe, bssh.Result{Stdout: "1\n"})
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
	s := databaseServer()
	s.Database = config.Database{Engine: "postgres", Name: "myapp", User: "myapp", Source: "debian"}
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
	if err := secret.SaveCache(s.Host, map[string]string{dbUser: "cachedpw", "appkey:" + dbUser: wantKey}); err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // no .env -> re-seed path
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	stubClientAuthAbsent(f, s, ".my.cnf")
	f.On("mysql --protocol=socket", bssh.Result{})
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var env *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == envPath(s) {
			env = &f.Writes()[i]
		}
	}
	if env == nil || !strings.Contains(string(env.Content), "APP_KEY="+wantKey) {
		t.Errorf("re-seeded .env must reuse the cached APP_KEY %q", wantKey)
	}
}

func TestDatabaseApplyCachesGeneratedAppKey(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	stubClientAuthAbsent(f, s, ".my.cnf")
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

func TestDatabaseApplyRejectsMalformedEnvAppKey(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=existingpw\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "APP_KEY=base64:short\n"})
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("Apply() = %v, want a malformed-APP_KEY refusal", err)
	}
}

func TestDatabaseApplyRejectsMalformedCachedAppKey(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	dbUser := s.SiteDBUser(s.Sites[0])
	if err := secret.SaveCache(s.Host, map[string]string{"appkey:" + dbUser: "base64:tampered"}); err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
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
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})   // fresh box: no .env yet
	f.On("test -e '/home/deploy/.pgpass'", bssh.Result{ExitCode: 1}) // fresh box: no client creds yet
	f.On("sudo -u postgres psql -v ON_ERROR_STOP=1", bssh.Result{})

	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var auth *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == "/home/deploy/.pgpass" {
			auth = &f.Writes()[i]
		}
	}
	if auth == nil {
		t.Fatal("~/.pgpass was not written")
	}
	if auth.Mode.Perm() != 0o600 {
		t.Errorf("~/.pgpass mode = %v, want 0600 (libpq refuses anything else)", auth.Mode.Perm())
	}
	if !strings.HasPrefix(string(auth.Content), "*:*:myapp:myapp:") {
		t.Errorf("~/.pgpass = %q, want the wildcard db/user line", auth.Content)
	}
}

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

// chdirTemp moves into a throwaway working directory so the local secrets cache
// (.berth/) is created under a temp dir, not the repo.
func chdirTemp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
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

func TestDatabaseApplyGeneratesPersistsAndEnsures(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	red := secret.NewRedactor()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	// No existing password: grep of shared/.env returns non-zero.
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
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
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
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
	if env == nil {
		t.Fatal("shared/.env was not written")
	}
	body := string(env.Content)
	for _, want := range []string{
		"CACHE_STORE=redis", "SESSION_DRIVER=redis", "QUEUE_CONNECTION=redis",
		"REDIS_CLIENT=phpredis", "REDIS_DB=0", "REDIS_CACHE_DB=0", "REDIS_PREFIX=app_example_com_",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("with Valkey, shared/.env must contain %q; got:\n%s", want, body)
		}
	}
}

func TestDatabaseApplyKeepsDatabaseDriverWithoutValkey(t *testing.T) {
	chdirTemp(t)
	s := databaseServer() // Valkey defaults to false
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
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
	if env == nil {
		t.Fatal("shared/.env was not written")
	}
	if strings.Contains(string(env.Content), "CACHE_STORE=redis") {
		t.Errorf("without Valkey, redis drivers must NOT be seeded; got:\n%s", env.Content)
	}
}

func TestDatabaseApplyReusesExistingPasswordWithoutRotating(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	red := secret.NewRedactor()
	f := bssh.NewFakeRunner()
	const existing = "ReUsedPassword123"
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{Stdout: "DB_PASSWORD=" + existing + "\n"})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("mysql --protocol=socket", bssh.Result{})

	if err := Database(red).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// The reused password (not a fresh one) must be used in the SQL.
	var found bool
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "mysql") && strings.Contains(string(c.Stdin), existing) {
			found = true
		}
	}
	if !found {
		t.Error("expected the existing password to be reused (no rotation)")
	}
}

func TestDatabaseApplyReusesExistingAppKeyWithoutRotating(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	const existingKey = "base64:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK="
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{Stdout: "APP_KEY=" + existingKey + "\n"})
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
	if env == nil {
		t.Fatal("shared/.env was not written")
	}
	if !strings.Contains(string(env.Content), "APP_KEY="+existingKey) {
		t.Errorf("existing APP_KEY must be reused (no rotation); got:\n%s", env.Content)
	}
}

func TestDatabaseCheckSatisfiedDoesNotReseedExistingEnv(t *testing.T) {
	// Documents the first-provision-only wiring: once shared/.env exists the
	// database step is satisfied, so flipping valkey: true on an already-provisioned
	// host does NOT re-seed the Redis keys (operator removes/re-seeds .env by hand).
	s := databaseServer()
	s.Valkey = true
	f := bssh.NewFakeRunner()
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})       // server installed
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // shared/.env already present
	cr, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected Satisfied (installed + .env exists); got %+v — existing env is intentionally not re-seeded", cr)
	}
}

func TestDatabaseCheckSourceMariaDBRequiresRepo(t *testing.T) {
	s := databaseServer()
	s.Database.Source = "mariadb"
	f := bssh.NewFakeRunner()
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0})
	// mariadb.org repo not yet registered -> not satisfied.
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
	f.On("curl -fsSL https://mariadb.org/mariadb_release_signing_key.asc | gpg --dearmor --yes -o /usr/share/keyrings/mariadb-org.gpg", bssh.Result{})
	f.On("gpg --show-keys --with-colons /usr/share/keyrings/mariadb-org.gpg", bssh.Result{Stdout: "fpr:::::::::177F4010FE56CA3336300305F1656F24C74CD1D8:\n"})
	f.On("apt-get update", bssh.Result{})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("mysql --protocol=socket", bssh.Result{})

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
	f.On("curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor --yes -o /usr/share/keyrings/pgdg.gpg", bssh.Result{})
	f.On("gpg --show-keys --with-colons /usr/share/keyrings/pgdg.gpg", bssh.Result{Stdout: "fpr:::::::::B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8:\n"})
	f.On("apt-get update", bssh.Result{})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql", bssh.Result{})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("grep -m1 '^APP_KEY=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1})
	f.On("sudo -u postgres psql -v ON_ERROR_STOP=1", bssh.Result{})

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
	// A tampered env value containing a quote must be rejected (defence-in-depth).
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{Stdout: "DB_PASSWORD=bad'value\n"})

	err := Database(red).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("expected rejection of a reused password outside the allowed charset")
	}
}

func TestSeedSharedEnvMariaDBUsesSocket(t *testing.T) {
	f := bssh.NewFakeRunner()
	d := database{redactor: secret.NewRedactor()}
	eng, _ := dbpkg.Get("mariadb")
	driver, host, port, socket := eng.EnvConnection()
	s := &config.Server{Database: config.Database{Engine: "mariadb"}, Sites: []config.Site{{Domain: "x.example.com", DeployPath: "/srv/x"}}}
	if err := d.seedSharedEnv(context.Background(), f, s, s.Sites[0], 0, "db", "u", "pw", "appkey", driver, host, port, socket); err != nil {
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
	if err := d.seedSharedEnv(context.Background(), f, s, s.Sites[0], 0, "db", "u", "pw", "appkey", driver, host, port, socket); err != nil {
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

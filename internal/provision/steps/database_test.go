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

// redisIdxProbe is the Redis-index pre-pass command Apply runs per site.
func redisIdxProbe(env string) string {
	return "grep -E '^REDIS_(CACHE_)?DB=' " + shQuote(env)
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
	f.On(redisIdxProbe(envPath(s)), bssh.Result{ExitCode: 2})      // index pre-pass: no .env yet
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
		"CACHE_STORE=redis", "SESSION_DRIVER=redis", "QUEUE_CONNECTION=redis",
		"REDIS_CLIENT=phpredis", "REDIS_DB=0", "REDIS_CACHE_DB=0", "REDIS_PREFIX=app_example_com_",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("with Valkey, shared/.env must contain %q; got:\n%s", want, body)
		}
	}
}

func TestDatabaseApplyRedisDBSkipsIndicesUsedByExistingEnvs(t *testing.T) {
	chdirTemp(t)
	// A site prepended BEFORE an already-provisioned one: the fresh site's Redis
	// logical DB must skip the index persisted in the existing site's .env.
	// Positional allocation would hand out 0 here, colliding with the existing
	// tenant and letting its neighbour's cache:clear (FLUSHDB) wipe it.
	s := databaseServer()
	s.Valkey = true
	existing := s.Sites[0]
	fresh := config.Site{Domain: "new.example.com", DeployPath: "/srv/new", SSL: true}
	s.Sites = []config.Site{fresh, existing}
	newEnv := "/srv/new/shared/.env"
	exEnv := existing.DeployPath + "/shared/.env"

	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	// Index pre-pass: the fresh site has no .env yet (grep exits 2 on a missing
	// file), the existing site's .env persists REDIS_DB=0.
	f.On(redisIdxProbe(newEnv), bssh.Result{ExitCode: 2})
	f.On(redisIdxProbe(exEnv), bssh.Result{ExitCode: 0, Stdout: "REDIS_DB=0\nREDIS_CACHE_DB=0\n"})
	f.On("test -e "+shQuote(newEnv), bssh.Result{ExitCode: 1}) // fresh: gets seeded
	f.On("test -e "+shQuote(exEnv), bssh.Result{ExitCode: 0})  // existing: never rewritten
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(exEnv), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Reused123\n"})
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var body string
	for _, w := range f.Writes() {
		if w.Path == newEnv {
			body = string(w.Content)
		}
	}
	if body == "" {
		t.Fatal("fresh site's shared/.env was not written")
	}
	if strings.Contains(body, "\nREDIS_DB=0\n") {
		t.Errorf("fresh site must not reuse Redis DB 0 already held by %s; got:\n%s", existing.Domain, body)
	}
	for _, want := range []string{"\nREDIS_DB=1\n", "\nREDIS_CACHE_DB=1\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("fresh site's .env must contain %q (lowest free index); got:\n%s", strings.TrimSpace(want), body)
		}
	}
}

func TestDatabaseApplyRedisDBFillsLowestGap(t *testing.T) {
	chdirTemp(t)
	// Existing sites persist indices 0 and 2 (e.g. a middle site was removed);
	// a fresh site PREPENDED to the list must take the lowest free index, 1.
	// (Prepended so the old positional allocator — which would hand out 0 —
	// cannot pass this test.)
	s := databaseServer()
	s.Valkey = true
	first := s.Sites[0]
	third := config.Site{Domain: "c.example.com", DeployPath: "/srv/c", SSL: true}
	fresh := config.Site{Domain: "new.example.com", DeployPath: "/srv/new", SSL: true}
	s.Sites = []config.Site{fresh, first, third}
	firstEnv := first.DeployPath + "/shared/.env"
	thirdEnv := "/srv/c/shared/.env"
	newEnv := "/srv/new/shared/.env"

	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On(redisIdxProbe(firstEnv), bssh.Result{ExitCode: 0, Stdout: "REDIS_DB=0\nREDIS_CACHE_DB=0\n"})
	f.On(redisIdxProbe(thirdEnv), bssh.Result{ExitCode: 0, Stdout: "REDIS_DB=2\nREDIS_CACHE_DB=2\n"})
	f.On(redisIdxProbe(newEnv), bssh.Result{ExitCode: 2})
	f.On("test -e "+shQuote(firstEnv), bssh.Result{ExitCode: 0})
	f.On("test -e "+shQuote(thirdEnv), bssh.Result{ExitCode: 0})
	f.On("test -e "+shQuote(newEnv), bssh.Result{ExitCode: 1})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(firstEnv), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=ReusedA1\n"})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(thirdEnv), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=ReusedC1\n"})
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var body string
	for _, w := range f.Writes() {
		if w.Path == newEnv {
			body = string(w.Content)
		}
	}
	if body == "" {
		t.Fatal("fresh site's shared/.env was not written")
	}
	if !strings.Contains(body, "\nREDIS_DB=1\n") || !strings.Contains(body, "\nREDIS_CACHE_DB=1\n") {
		t.Errorf("fresh site must fill the lowest gap (1); got:\n%s", body)
	}
}

func TestDatabaseApplyRedisDBReservesDivergedCacheIndex(t *testing.T) {
	chdirTemp(t)
	// The live .env is operator-editable: REDIS_CACHE_DB may have been pointed
	// at a different logical DB than REDIS_DB. Both are occupied and both must
	// be reserved — a fresh site landing on the diverged cache index would be
	// wiped by that tenant's cache:clear.
	s := databaseServer()
	s.Valkey = true
	existing := s.Sites[0]
	fresh := config.Site{Domain: "new.example.com", DeployPath: "/srv/new", SSL: true}
	s.Sites = []config.Site{fresh, existing}
	newEnv := "/srv/new/shared/.env"
	exEnv := existing.DeployPath + "/shared/.env"

	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On(redisIdxProbe(newEnv), bssh.Result{ExitCode: 2})
	f.On(redisIdxProbe(exEnv), bssh.Result{ExitCode: 0, Stdout: "REDIS_CACHE_DB=0\nREDIS_DB=5\n"})
	f.On("test -e "+shQuote(newEnv), bssh.Result{ExitCode: 1})
	f.On("test -e "+shQuote(exEnv), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(exEnv), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Reused123\n"})
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var body string
	for _, w := range f.Writes() {
		if w.Path == newEnv {
			body = string(w.Content)
		}
	}
	if body == "" {
		t.Fatal("fresh site's shared/.env was not written")
	}
	if !strings.Contains(body, "\nREDIS_DB=1\n") {
		t.Errorf("fresh site must skip both 0 (diverged REDIS_CACHE_DB) and 5 (REDIS_DB); got:\n%s", body)
	}
}

func TestDatabaseApplyRedisDBReservesQuotedIndex(t *testing.T) {
	chdirTemp(t)
	// `REDIS_DB="0"` is a legal .env spelling Laravel reads as 0; the index is
	// occupied and must be reserved, not silently skipped as unparsable.
	s := databaseServer()
	s.Valkey = true
	existing := s.Sites[0]
	fresh := config.Site{Domain: "new.example.com", DeployPath: "/srv/new", SSL: true}
	s.Sites = []config.Site{fresh, existing}
	newEnv := "/srv/new/shared/.env"
	exEnv := existing.DeployPath + "/shared/.env"

	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On(redisIdxProbe(newEnv), bssh.Result{ExitCode: 2})
	f.On(redisIdxProbe(exEnv), bssh.Result{ExitCode: 0, Stdout: "REDIS_DB=\"0\"\nREDIS_CACHE_DB=\"0\"\n"})
	f.On("test -e "+shQuote(newEnv), bssh.Result{ExitCode: 1})
	f.On("test -e "+shQuote(exEnv), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(exEnv), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Reused123\n"})
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var body string
	for _, w := range f.Writes() {
		if w.Path == newEnv {
			body = string(w.Content)
		}
	}
	if body == "" {
		t.Fatal("fresh site's shared/.env was not written")
	}
	if !strings.Contains(body, "\nREDIS_DB=1\n") {
		t.Errorf("fresh site must treat quoted \"0\" as occupied and take 1; got:\n%s", body)
	}
}

func TestDatabaseApplyRedisDBFailsOnUnparsableIndex(t *testing.T) {
	chdirTemp(t)
	// An unparsable REDIS_DB in an authoritative .env must fail loudly: berth
	// cannot know which logical DB that tenant occupies, so silently allocating
	// around it risks the very collision this mechanism prevents.
	s := databaseServer()
	s.Valkey = true
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On(redisIdxProbe(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "REDIS_DB=whoops\n"})
	err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "unparsable REDIS_DB") {
		t.Fatalf("err = %v, want a pointed unparsable-REDIS_DB error", err)
	}
}

func TestDatabaseApplyRedisDBDistinctForMultipleFreshSites(t *testing.T) {
	chdirTemp(t)
	// Two sites seeded in one run around an existing tenant holding 0: they
	// must get distinct free indices (1 and 2), not their slice positions
	// (0 and 2 — position 0 would collide with the existing tenant).
	s := databaseServer()
	s.Valkey = true
	existing := s.Sites[0]
	freshX := config.Site{Domain: "x.example.com", DeployPath: "/srv/x", SSL: true}
	freshY := config.Site{Domain: "y.example.com", DeployPath: "/srv/y", SSL: true}
	s.Sites = []config.Site{freshX, existing, freshY}
	xEnv, yEnv := "/srv/x/shared/.env", "/srv/y/shared/.env"
	exEnv := existing.DeployPath + "/shared/.env"

	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On(redisIdxProbe(xEnv), bssh.Result{ExitCode: 2})
	f.On(redisIdxProbe(yEnv), bssh.Result{ExitCode: 2})
	f.On(redisIdxProbe(exEnv), bssh.Result{ExitCode: 0, Stdout: "REDIS_DB=0\nREDIS_CACHE_DB=0\n"})
	f.On("test -e "+shQuote(xEnv), bssh.Result{ExitCode: 1})
	f.On("test -e "+shQuote(yEnv), bssh.Result{ExitCode: 1})
	f.On("test -e "+shQuote(exEnv), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(exEnv), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Reused123\n"})
	f.On("mysql --protocol=socket", bssh.Result{})

	stubClientAuthAbsent(f, s, ".my.cnf")
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	got := map[string]string{}
	for _, w := range f.Writes() {
		got[w.Path] = string(w.Content)
	}
	if !strings.Contains(got[xEnv], "\nREDIS_DB=1\n") {
		t.Errorf("first fresh site must take 1 (0 is held by the existing tenant); got:\n%s", got[xEnv])
	}
	if !strings.Contains(got[yEnv], "\nREDIS_DB=2\n") {
		t.Errorf("second fresh site must take the next free index 2; got:\n%s", got[yEnv])
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
	if strings.Contains(string(env.Content), "CACHE_STORE=redis") {
		t.Errorf("without Valkey, redis drivers must NOT be seeded; got:\n%s", env.Content)
	}
}

func TestDatabaseApplyHealsFromExistingEnvWithoutRewriting(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server", bssh.Result{})
	f.On("test -e "+shQuote(envPath(s)), bssh.Result{ExitCode: 0}) // .env already present
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Reused123\n"})
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
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 1}) // key absent
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
	s := databaseServer()
	s.Valkey = true
	f := bssh.NewFakeRunner()
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 0})
	f.On(mariadbDBProbe, bssh.Result{Stdout: "1\n"})
	f.On(mariadbGrantProbe, bssh.Result{Stdout: "1\n"})
	f.On("test -e "+shQuote("/home/deploy/.my.cnf"), bssh.Result{ExitCode: 0}) // client creds already seeded
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

func TestDatabaseCheckUnsatisfiedWhenDatabaseMissing(t *testing.T) {
	s := databaseServer()
	f := bssh.NewFakeRunner()
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
	s := databaseServer()
	f := bssh.NewFakeRunner()
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
	s := databaseServer()
	f := bssh.NewFakeRunner()
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s))+" | grep -Eq '^DB_PASSWORD=[A-Za-z0-9]+[[:space:]]*$'", bssh.Result{ExitCode: 1}) // no valid DB_PASSWORD on the first line (or key/file absent — same outcome)
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
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 1}) // not installed
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
	// A trailing vertical tab IS [[:space:]] to the Check probe (POSIX C-locale
	// set), so Apply must trim it the same way and reuse the value.
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Good123\v\n"})
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
	f.On("grep -m1 '^DB_PASSWORD=' "+shQuote(envPath(s)), bssh.Result{ExitCode: 0, Stdout: "DB_PASSWORD=Reused123\n"})
	f.On("test -e '/home/deploy/.my.cnf'", bssh.Result{ExitCode: 0}) // already seeded (possibly operator-customized)
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
	s := databaseServer()
	f := bssh.NewFakeRunner()
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

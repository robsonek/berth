package steps

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// upstreamSourceList is the apt source file an engine's producer repo is written
// to; its presence is how Check knows the configured upstream source is in effect.
func upstreamSourceList(repo apt.Repo) string {
	return "/etc/apt/sources.list.d/" + repo.Name + ".list"
}

// dbPasswordKey is the .env key under which the database password lives.
const dbPasswordKey = "DB_PASSWORD"

// appKeyKey is the .env key under which Laravel's application encryption key
// lives. berth seeds one so a Laravel app boots after its first deploy without
// manual intervention.
const appKeyKey = "APP_KEY"

// dbPasswordLen is the length of a freshly generated database password.
const dbPasswordLen = 32

// reDBPassword is the alphanumeric charset secret.Generate uses. A password
// reused from a host shared/.env (or the local cache) is re-validated against it
// before interpolation into SQL — defence-in-depth against a tampered env
// injecting quotes/metacharacters (design §7).
var reDBPassword = regexp.MustCompile(`^[A-Za-z0-9]+$`)

type database struct {
	redactor *secret.Redactor
}

// Database installs the database server once, then for each site persists the
// credential to that site's shared/.env, ensures the site's database + user,
// and seeds the site user's client-credentials file (~/.my.cnf / ~/.pgpass).
// It takes the redactor so generated passwords are masked in any logged output.
func Database(red *secret.Redactor) provision.Step { return database{redactor: red} }

func (database) Name() string       { return "database" }
func (database) Requires() []string { return []string{"base", "appdirs"} }

// sharedEnvPath is the server-side path of a site's shared .env.
func sharedEnvPath(site config.Site) string {
	return site.DeployPath + "/shared/.env"
}

// clientAuthPath is the server-side path of a site user's engine
// client-credentials file (~/.my.cnf or ~/.pgpass). The /home/<user> layout is
// the same assumption ensureUser enforces for every managed account.
func clientAuthPath(s *config.Server, site config.Site, name string) string {
	return "/home/" + s.SiteUser(site) + "/" + name
}

// envCredentialPresent reports whether the FIRST DB_PASSWORD line of a site's
// shared/.env carries a charset-valid value — the same line passwordFromEnv
// reads, so Check and Apply always judge the same credential (a valid value on
// a later duplicate line must not satisfy Check when Apply would read the
// first). grep -m1 selects that line (a missing file or key yields empty
// input); the second grep validates it strictly and only its exit code
// answers (-q), so the secret never enters stdout.
func envCredentialPresent(ctx context.Context, r bssh.Runner, site config.Site) (bool, error) {
	res, err := r.Run(ctx, "grep -m1 '^"+dbPasswordKey+"=' "+shQuote(sharedEnvPath(site))+" | grep -Eq '^"+dbPasswordKey+"=[A-Za-z0-9]+[[:space:]]*$'", nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

func (d database) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		return provision.CheckResult{}, err
	}
	installed, err := pkgInstalled(ctx, r, eng.ServerPackage())
	if err != nil {
		return provision.CheckResult{}, err
	}
	// When an upstream source is configured, the engine's producer repo must be
	// registered; this makes a source switch (debian -> upstream) re-trigger Apply.
	sourceOK := true
	if s.Database.Source != "debian" {
		if repo, ok := eng.UpstreamRepo(); ok {
			sourceOK, err = fileExists(ctx, r, upstreamSourceList(repo))
			if err != nil {
				return provision.CheckResult{}, err
			}
		}
	}
	if !installed || !sourceOK {
		// No server to probe yet (or the wrong source): Apply reconciles.
		return d.unsatisfied(eng, "database server or configured source not yet provisioned"), nil
	}
	// The server is installed: every site needs its credential persisted AND
	// its database + user actually present. Probing real state (not just the
	// .env file) lets a re-run heal a provision that failed between the .env
	// write and EnsureUser.
	for _, site := range s.Sites {
		// The credential must be PRESENT AND VALID in shared/.env, not merely the
		// file: an operator-preseeded or truncated env without DB_PASSWORD would
		// otherwise read as converged while the app has no credential. Exit-code
		// only (-q) so the secret never enters the command output. The pattern
		// mirrors passwordFromEnv's accept set (alphanumeric, trailing whitespace
		// tolerated); anything murkier fails here and Apply reports the pointed
		// error.
		credOK, err := envCredentialPresent(ctx, r, site)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !credOK {
			return d.unsatisfied(eng, "credential for "+site.Domain+" not yet persisted"), nil
		}
		dbExists, err := eng.DatabaseExists(ctx, r, s.SiteDBName(site))
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !dbExists {
			return d.unsatisfied(eng, "database for "+site.Domain+" missing"), nil
		}
		granted, err := eng.UserGranted(ctx, r, s.SiteDBUser(site), s.SiteDBName(site))
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !granted {
			return d.unsatisfied(eng, "database user/grant for "+site.Domain+" missing"), nil
		}
		// Existence only (no content drift): the file bears a secret, so Check
		// stays exit-code-only, and it is seed-if-absent like shared/.env — an
		// operator-customized file must keep satisfying Check forever.
		authOK, err := fileExists(ctx, r, clientAuthPath(s, site, eng.ClientAuthFileName()))
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !authOK {
			return d.unsatisfied(eng, "client DB credentials for "+site.Domain+" not yet seeded"), nil
		}
	}
	return provision.CheckResult{Satisfied: true, Reason: eng.ServerPackage() + " installed (" + s.Database.Source + "); per-site databases, users and credentials present"}, nil
}

// unsatisfied builds this step's standard not-yet-converged result.
func (d database) unsatisfied(eng dbpkg.Engine, reason string) provision.CheckResult {
	return provision.CheckResult{Satisfied: false, Reason: reason, Changes: d.changes(eng), Sensitive: true}
}

func (database) changes(eng dbpkg.Engine) []string {
	return []string{
		"install " + eng.ServerPackage(),
		"per site: persist DB credential to shared/.env and ~/" + eng.ClientAuthFileName() + " (when absent), ensure database + user",
	}
}

func (d database) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		return err
	}
	// Install the server once (optionally from its producer repo).
	if s.Database.Source != "debian" {
		if repo, ok := eng.UpstreamRepo(); ok {
			if err := apt.New(r).EnsureRepo(ctx, repo); err != nil {
				return fmt.Errorf("add %s repo: %w", repo.Name, err)
			}
		}
	}
	if err := aptInstall(ctx, r, eng.ServerPackage()); err != nil {
		return fmt.Errorf("install %s: %w", eng.ServerPackage(), err)
	}

	driver, host, port, socket := eng.EnvConnection()
	// Accumulate per-site secrets and write the local cache once at the end so
	// sites do not clobber each other's cached passwords. A cache that cannot
	// be READ is a hard error, not an empty map — saving over it would clobber
	// every credential it held (LoadCache treats only never-written as empty).
	cache, err := secret.LoadCache(s.Host)
	if err != nil {
		return fmt.Errorf("load local secret cache: %w", err)
	}
	var redisUsed map[int]bool
	if s.Valkey {
		if redisUsed, err = usedRedisDBs(ctx, r, s); err != nil {
			return err
		}
	}
	for _, site := range s.Sites {
		dbName, dbUser := s.SiteDBName(site), s.SiteDBUser(site)
		envExists, err := fileExists(ctx, r, sharedEnvPath(site))
		if err != nil {
			return err
		}
		var pw string
		if envExists {
			// An existing .env is never rewritten: WriteFile is atomic, so a
			// present file is complete, and rewriting would clobber
			// operator-added keys and the site's persisted REDIS_DB assignment.
			// The role's password must therefore come from the file the app reads.
			pw, err = d.passwordFromEnv(ctx, r, site)
			if err != nil {
				return err
			}
		} else {
			pw, err = newPassword(dbUser, cache)
			if err != nil {
				return err
			}
			appKey, err := secret.AppKey()
			if err != nil {
				return err
			}
			d.redactor.Add(appKey)
			redisDB := 0
			if s.Valkey {
				redisDB = freeRedisDB(redisUsed)
			}
			// Persist FIRST (atomic), so a crash before EnsureUser still leaves a
			// recoverable secret on the host.
			if err := d.seedSharedEnv(ctx, r, s, site, redisDB, dbName, dbUser, pw, appKey, driver, host, port, socket); err != nil {
				return err
			}
		}
		d.redactor.Add(pw)
		if err := eng.EnsureDatabase(ctx, r, dbName); err != nil {
			return err
		}
		if err := eng.EnsureUser(ctx, r, dbUser, pw, dbName); err != nil {
			return err
		}
		authPath := clientAuthPath(s, site, eng.ClientAuthFileName())
		authExists, err := fileExists(ctx, r, authPath)
		if err != nil {
			return err
		}
		if !authExists {
			// Seed-if-absent, like shared/.env: the password is reused (never
			// rotated) and the operator may customize the file, so a present
			// file is never rewritten. Written AFTER EnsureUser so the
			// credential it holds is live; a crash in between heals on the
			// next run via Check's existence probe.
			user := s.SiteUser(site)
			if err := r.WriteFile(ctx, bssh.FileSpec{
				Path: authPath, Content: eng.ClientAuthFile(dbName, dbUser, pw),
				Owner: user, Group: user, Mode: 0o600, Sudo: true,
			}); err != nil {
				return fmt.Errorf("write %s: %w", authPath, err)
			}
		}
		cache[dbUser] = pw
	}
	if err := secret.SaveCache(s.Host, cache); err != nil {
		return fmt.Errorf("cache database secrets: %w", err)
	}
	return nil
}

// passwordFromEnv reads DB_PASSWORD from a site's existing shared/.env. The
// file is authoritative once present: a missing value is a hard error, because
// silently generating a new password would desync the role from the file the
// app reads. Only trailing ASCII whitespace (the same set Check's probe
// accepts) is trimmed off the value — anything else, leading or Unicode, is
// NOT laundered away: it fails the charset check just as Check's probe rejects
// that line (laundering it would make Check unsatisfied forever while Apply
// "succeeds"). A reused password is re-validated against the allowed charset
// (defence-in-depth against a tampered env injecting SQL metacharacters).
func (d database) passwordFromEnv(ctx context.Context, r bssh.Runner, site config.Site) (string, error) {
	env := sharedEnvPath(site)
	res, err := r.Run(ctx, "grep -m1 '^"+dbPasswordKey+"=' "+shQuote(env), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode == 0 {
		// Trailing trim uses exactly the ASCII set the Check probe's
		// grep [[:space:]] accepts in the C locale — Unicode whitespace
		// stays in the value and fails the charset check, matching
		// Check's rejection (no Check-rejects/Apply-succeeds path).
		// grep '^DB_PASSWORD=' anchors the line start, so no leading trim
		// is needed; res.Stdout is exactly the matched line + newline.
		line := strings.TrimRight(res.Stdout, " \t\n\v\f\r")
		if pw := strings.TrimPrefix(line, dbPasswordKey+"="); pw != "" && pw != line {
			if !reDBPassword.MatchString(pw) {
				return "", fmt.Errorf("reused %s from %s is outside the allowed charset; refusing to use it", dbPasswordKey, env)
			}
			return pw, nil
		}
	}
	return "", fmt.Errorf("%s for %s exists but has no %s; add one or remove the file to have berth re-seed it", env, site.Domain, dbPasswordKey)
}

// newPassword returns the locally cached password for dbUser or generates a
// fresh one. The cache hit covers the documented re-seed flow: an operator
// removes shared/.env to have berth re-seed it, and the password from the
// prior successful run is reused so the existing role keeps working.
func newPassword(dbUser string, cache map[string]string) (string, error) {
	if pw := cache[dbUser]; pw != "" {
		if !reDBPassword.MatchString(pw) {
			return "", fmt.Errorf("cached password for %s is outside the allowed charset; refusing to use it", dbUser)
		}
		return pw, nil
	}
	pw, err := secret.Generate(dbPasswordLen)
	if err != nil {
		return "", fmt.Errorf("generate database password: %w", err)
	}
	return pw, nil
}

// usedRedisDBs collects the Redis logical-DB indices already persisted in the
// sites' existing shared/.env files. The live file is authoritative (the same
// rule passwordFromEnv follows): an index must never be derived from the
// site's position in the YAML, which shifts when sites are added, removed or
// reordered — a fresh seed reusing a persisted index would let one tenant's
// cache:clear (FLUSHDB) wipe another's data. Both REDIS_DB and REDIS_CACHE_DB
// are reserved (berth seeds them equal, but the operator-editable file may
// have diverged them). A missing file or key exits non-zero and reserves
// nothing. An unparsable value is a hard error, not a skip: berth cannot know
// which logical DB that tenant occupies, so allocating around it risks the
// very collision this pre-pass prevents.
func usedRedisDBs(ctx context.Context, r bssh.Runner, s *config.Server) (map[int]bool, error) {
	used := map[int]bool{}
	for _, site := range s.Sites {
		env := sharedEnvPath(site)
		res, err := r.Run(ctx, "grep -E '^REDIS_(CACHE_)?DB=' "+shQuote(env), nil)
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			continue
		}
		for _, line := range strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n") {
			key, val, ok := strings.Cut(line, "=")
			if !ok {
				continue // unreachable: every matched line contains '='
			}
			// Tolerate the .env spellings Laravel reads as a number: ASCII
			// whitespace padding and one layer of matching quotes.
			val = strings.Trim(val, " \t\v\f\r")
			if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
				val = val[1 : len(val)-1]
			}
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("%s has an unparsable %s value %q; fix or remove that line so berth can allocate collision-free Redis DB indices", env, key, val)
			}
			used[n] = true
		}
	}
	return used, nil
}

// freeRedisDB returns the lowest non-negative index not yet reserved and
// reserves it, so multiple sites seeded in one run get distinct indices.
func freeRedisDB(used map[int]bool) int {
	n := 0
	for used[n] {
		n++
	}
	used[n] = true
	return n
}

// seedSharedEnv renders a site's shared/.env and writes it atomically, owned by
// that site's OS user (mode 0600) so other site users cannot read it.
func (d database) seedSharedEnv(ctx context.Context, r bssh.Runner, s *config.Server, site config.Site, redisDB int, dbName, dbUser, pw, appKey, driver, host, port, socket string) error {
	user := s.SiteUser(site)
	kv := map[string]string{
		"APP_ENV":       "production",
		"APP_DEBUG":     "false",
		"APP_URL":       appURL(site),
		appKeyKey:       appKey,
		"DB_CONNECTION": driver,
		"DB_HOST":       host,
		"DB_PORT":       port,
		"DB_DATABASE":   dbName,
		"DB_USERNAME":   dbUser,
		dbPasswordKey:   pw,
		"REDIS_HOST":    "127.0.0.1",
		"REDIS_PORT":    "6379",
	}
	if socket != "" {
		kv["DB_SOCKET"] = socket
	}
	// When Valkey is provisioned, use it for cache, session and queue (Laravel
	// otherwise falls back to the database driver). Each site gets its own Redis
	// logical DB (allocated by freeRedisDB against the indices persisted on the
	// host) and a key prefix so one tenant's cache:clear (FLUSHDB) cannot wipe
	// another's data. Note: cache, session and queue share the site's DB, so
	// that site's own `cache:clear` also clears its sessions/queue — an accepted
	// single-tenant trade-off; cross-tenant isolation is preserved.
	if s.Valkey {
		db := strconv.Itoa(redisDB)
		kv["CACHE_STORE"] = "redis"
		kv["SESSION_DRIVER"] = "redis"
		kv["QUEUE_CONNECTION"] = "redis"
		kv["REDIS_CLIENT"] = "phpredis"
		kv["REDIS_PREFIX"] = poolName(site.Domain) + "_"
		kv["REDIS_DB"] = db
		kv["REDIS_CACHE_DB"] = db
	}
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: sharedEnvPath(site), Content: secret.EnvFile(kv),
		Owner: user, Group: user, Mode: 0o600, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", sharedEnvPath(site), err)
	}
	return nil
}

// appURL derives the application URL from a site (https when SSL is enabled).
func appURL(site config.Site) string {
	scheme := "http"
	if site.SSL {
		scheme = "https"
	}
	return scheme + "://" + site.Domain
}

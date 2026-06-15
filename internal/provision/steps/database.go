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
// credential to that site's shared/.env and ensures the site's database + user.
// It takes the redactor so generated passwords are masked in any logged output.
func Database(red *secret.Redactor) provision.Step { return database{redactor: red} }

func (database) Name() string       { return "database" }
func (database) Requires() []string { return []string{"base", "appdirs"} }

// sharedEnvPath is the server-side path of a site's shared .env.
func sharedEnvPath(site config.Site) string {
	return site.DeployPath + "/shared/.env"
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
	// Each site's shared/.env (carrying its credential) must exist.
	for _, site := range s.Sites {
		envExists, err := fileExists(ctx, r, sharedEnvPath(site))
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !envExists {
			return provision.CheckResult{
				Satisfied: false,
				Reason:    "credential for " + site.Domain + " not yet persisted",
				Changes:   d.changes(eng),
				Sensitive: true,
			}, nil
		}
	}
	if installed && sourceOK {
		return provision.CheckResult{Satisfied: true, Reason: eng.ServerPackage() + " installed (" + s.Database.Source + "); per-site credentials persisted"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "database server or configured source not yet provisioned",
		Changes:   d.changes(eng),
		Sensitive: true,
	}, nil
}

func (database) changes(eng dbpkg.Engine) []string {
	return []string{
		"install " + eng.ServerPackage(),
		"per site: persist DB credential to shared/.env, ensure database + user",
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
	// sites do not clobber each other's cached passwords.
	cache, _ := secret.LoadCache(s.Host)
	if cache == nil {
		cache = map[string]string{}
	}
	for i, site := range s.Sites {
		dbName, dbUser := s.SiteDBName(site), s.SiteDBUser(site)
		pw, err := d.resolvePassword(ctx, r, site, dbUser, cache)
		if err != nil {
			return err
		}
		d.redactor.Add(pw)
		appKey, err := d.resolveAppKey(ctx, r, site)
		if err != nil {
			return err
		}
		d.redactor.Add(appKey)
		// Persist FIRST (atomic), so a crash before EnsureUser still leaves a
		// recoverable secret on the host. i is the site's per-site Redis logical
		// DB index when Valkey is enabled.
		if err := d.seedSharedEnv(ctx, r, s, site, i, dbName, dbUser, pw, appKey, driver, host, port, socket); err != nil {
			return err
		}
		if err := eng.EnsureDatabase(ctx, r, dbName); err != nil {
			return err
		}
		if err := eng.EnsureUser(ctx, r, dbUser, pw, dbName); err != nil {
			return err
		}
		cache[dbUser] = pw
	}
	if err := secret.SaveCache(s.Host, cache); err != nil {
		return fmt.Errorf("cache database secrets: %w", err)
	}
	return nil
}

// resolvePassword returns a site's database password, preferring an existing one
// (the site's host shared/.env, then the local cache keyed by DB user) and only
// generating a new one when none exists. A reused password is re-validated.
func (d database) resolvePassword(ctx context.Context, r bssh.Runner, site config.Site, dbUser string, cache map[string]string) (string, error) {
	env := sharedEnvPath(site)
	res, err := r.Run(ctx, "grep -m1 '^"+dbPasswordKey+"=' "+shQuote(env), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode == 0 {
		pw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(res.Stdout), dbPasswordKey+"="))
		if pw != "" {
			if !reDBPassword.MatchString(pw) {
				return "", fmt.Errorf("reused %s from %s is outside the allowed charset; refusing to use it", dbPasswordKey, env)
			}
			return pw, nil
		}
	}
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

// resolveAppKey returns a site's Laravel APP_KEY, preferring one already present
// in the site's shared/.env (so an operator may pre-seed the real key for a data
// restore and re-runs never rotate it, which would invalidate encrypted data)
// and generating a fresh key only when none exists.
func (d database) resolveAppKey(ctx context.Context, r bssh.Runner, site config.Site) (string, error) {
	env := sharedEnvPath(site)
	res, err := r.Run(ctx, "grep -m1 '^"+appKeyKey+"=' "+shQuote(env), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode == 0 {
		if key := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(res.Stdout), appKeyKey+"=")); key != "" {
			return key, nil
		}
	}
	return secret.AppKey()
}

// seedSharedEnv renders a site's shared/.env and writes it atomically, owned by
// that site's OS user (mode 0600) so other site users cannot read it.
func (d database) seedSharedEnv(ctx context.Context, r bssh.Runner, s *config.Server, site config.Site, siteIdx int, dbName, dbUser, pw, appKey, driver, host, port, socket string) error {
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
	// logical DB (siteIdx) and a key prefix so one tenant's cache:clear (FLUSHDB)
	// cannot wipe another's data. Note: cache, session and queue share the site's
	// DB, so that site's own `cache:clear` also clears its sessions/queue — an
	// accepted single-tenant trade-off; cross-tenant isolation is preserved.
	if s.Valkey {
		db := strconv.Itoa(siteIdx)
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

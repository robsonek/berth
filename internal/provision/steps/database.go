package steps

import (
	"context"
	"fmt"
	"regexp"
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

// dbConnectionKey is the .env key naming the Laravel database driver.
const dbConnectionKey = "DB_CONNECTION"

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

// envDBConnection reads the first DB_CONNECTION line of a site's shared/.env.
// The caller must have confirmed the file exists (assertEnvEngineMatch does).
// hasKey is false only when the file has no DB_CONNECTION line (grep exit 1);
// a grep exit >= 2 (unreadable input, I/O error) is a hard error rather than
// silent absence. Unlike the DB_PASSWORD probes the value is not a secret, so
// it may be read into memory and echoed in error messages. Only trailing ASCII
// whitespace is trimmed (the exact set passwordFromEnv uses); no quote
// stripping — the comparison downstream is strict and raw.
func envDBConnection(ctx context.Context, r bssh.Runner, site config.Site) (string, bool, error) {
	res, err := r.Run(ctx, "grep -m1 '^"+dbConnectionKey+"=' "+shQuote(sharedEnvPath(site)), nil)
	if err != nil {
		return "", false, err
	}
	switch res.ExitCode {
	case 0:
		line := strings.TrimRight(strings.SplitN(res.Stdout, "\n", 2)[0], " \t\n\v\f\r")
		return strings.TrimPrefix(line, dbConnectionKey+"="), true, nil
	case 1:
		return "", false, nil // no DB_CONNECTION line
	default:
		return "", false, fmt.Errorf("probe %s in %s: %s", dbConnectionKey, sharedEnvPath(site), res.Stderr)
	}
}

// assertEnvEngineMatch fails loudly when a site's shared/.env disagrees with
// the configured database engine. A fresh box (no .env) is fine: the seed will
// be consistent. An existing .env must carry a DB_CONNECTION matching the
// engine's driver — its absence, or a different driver, is a hard error,
// because .env is seed-if-absent and never rewritten, so a mismatch would
// leave the app on the old engine while backups dump the empty new one and the
// run still reports green. Deliberately NOT overridable by --force: the only
// safe fixes are migrating the data and updating the env, or reverting config.
func assertEnvEngineMatch(ctx context.Context, r bssh.Runner, s *config.Server, site config.Site, driver string) error {
	exists, err := fileExists(ctx, r, sharedEnvPath(site))
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	val, hasKey, err := envDBConnection(ctx, r, site)
	if err != nil {
		return err
	}
	if !hasKey {
		return fmt.Errorf("shared/.env for %s exists but has no %s; berth always seeds it, so its absence leaves the app's effective database engine unknown — set %s=%s (matching database.engine %s) or remove %s to have berth re-seed it",
			site.Domain, dbConnectionKey, dbConnectionKey, driver, s.Database.Engine, sharedEnvPath(site))
	}
	if val != driver {
		return fmt.Errorf("shared/.env for %s has %s=%s but database.engine %s seeds %s=%s: the app keeps talking to the old engine while backups would dump the empty new one; migrate the data and update %s, or revert database.engine (--force does not override this check)",
			site.Domain, dbConnectionKey, val, s.Database.Engine, dbConnectionKey, driver, sharedEnvPath(site))
	}
	return nil
}

func (d database) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		return provision.CheckResult{}, err
	}
	// Engine/env conflict is checked FIRST — before the installed probe —
	// because an engine switch makes Check early-return on the missing new
	// server package and never reach the per-site probes otherwise.
	driver, _, _, _ := eng.EnvConnection()
	for _, site := range s.Sites {
		if err := assertEnvEngineMatch(ctx, r, s, site, driver); err != nil {
			return provision.CheckResult{}, err
		}
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
	driver, host, port, socket := eng.EnvConnection()
	// Pre-scan every site BEFORE touching apt/repos/SQL: an engine switch must
	// abort before the new server is even installed.
	for _, site := range s.Sites {
		if err := assertEnvEngineMatch(ctx, r, s, site, driver); err != nil {
			return err
		}
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

	// Accumulate per-site secrets and write the local cache once at the end so
	// sites do not clobber each other's cached passwords. A cache that cannot
	// be READ is a hard error, not an empty map — saving over it would clobber
	// every credential it held (LoadCache treats only never-written as empty).
	cache, err := secret.LoadCache(s.Host)
	if err != nil {
		return fmt.Errorf("load local secret cache: %w", err)
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
			// operator-added keys. The role's password must therefore come
			// from the file the app reads.
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
			// Persist FIRST (atomic), so a crash before EnsureUser still leaves a
			// recoverable secret on the host.
			if err := d.seedSharedEnv(ctx, r, s, site, dbName, dbUser, pw, appKey, driver, host, port, socket); err != nil {
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

// seedSharedEnv renders a site's shared/.env and writes it atomically, owned by
// that site's OS user (mode 0600) so other site users cannot read it.
func (d database) seedSharedEnv(ctx context.Context, r bssh.Runner, s *config.Server, site config.Site, dbName, dbUser, pw, appKey, driver, host, port, socket string) error {
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
	// When Valkey is provisioned, use it for cache, session and queue. Each
	// site talks to ITS OWN instance over a unix socket in a 0700 directory —
	// OS-level tenant isolation, no shared endpoint, no credentials. Cache
	// lives in logical DB 1 so this site's own `artisan cache:clear` (FLUSHDB)
	// cannot wipe its sessions/queue in DB 0; static indices are safe because
	// nothing is shared. phpredis treats a path-shaped host as a unix socket.
	if s.Valkey {
		kv["CACHE_DRIVER"] = "redis" // Laravel 10 spelling
		kv["CACHE_STORE"] = "redis"  // Laravel 11/12 spelling
		kv["SESSION_DRIVER"] = "redis"
		kv["QUEUE_CONNECTION"] = "redis"
		kv["REDIS_CLIENT"] = "phpredis"
		kv["REDIS_HOST"] = valkeySocketPath(site.Domain)
		kv["REDIS_PORT"] = "0"
		kv["REDIS_DB"] = "0"
		kv["REDIS_CACHE_DB"] = "1"
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

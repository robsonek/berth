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

// mariadbOrgSourceList is the apt source file the mariadb.org repo is written to;
// its presence is how Check knows the configured upstream source is in effect.
const mariadbOrgSourceList = "/etc/apt/sources.list.d/mariadb-org.list"

// dbPasswordKey is the .env / cache key under which the database password lives.
const dbPasswordKey = "DB_PASSWORD"

// dbPasswordLen is the length of a freshly generated database password.
const dbPasswordLen = 32

// reDBPassword is the alphanumeric charset secret.Generate uses. A password
// reused from the host's shared/.env (or the local cache) is re-validated against
// it before interpolation into SQL — defence-in-depth against a tampered env
// injecting quotes/metacharacters (design §7).
var reDBPassword = regexp.MustCompile(`^[A-Za-z0-9]+$`)

type database struct {
	redactor *secret.Redactor
}

// Database installs the database server, persists the credential, and ensures the
// application database and user. It takes the redactor so the generated password
// is masked in any logged output.
func Database(red *secret.Redactor) provision.Step { return database{redactor: red} }

func (database) Name() string       { return "database" }
func (database) Requires() []string { return []string{"base", "appdirs"} }

func (d database) Check(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	installed, err := pkgInstalled(ctx, r, "mariadb-server")
	if err != nil {
		return provision.CheckResult{}, err
	}
	// The shared/.env carrying the credential must exist for the database to be
	// considered provisioned; its content is sensitive so it is not hashed here.
	envExists, err := fileExists(ctx, r, sharedEnvPath(s))
	if err != nil {
		return provision.CheckResult{}, err
	}
	// When mariadb.org is the configured source, its repo must be registered; this
	// makes a source switch (debian -> mariadb) re-trigger Apply.
	sourceOK := true
	if s.Database.Source == "mariadb" {
		sourceOK, err = fileExists(ctx, r, mariadbOrgSourceList)
		if err != nil {
			return provision.CheckResult{}, err
		}
	}
	if installed && envExists && sourceOK {
		return provision.CheckResult{Satisfied: true, Reason: "mariadb-server installed (" + s.Database.Source + ") and credential persisted"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "database server, credential, or configured source not yet provisioned",
		Changes:   []string{"install mariadb-server (" + s.Database.Source + ")", "persist DB credential to shared/.env", "ensure database and user"},
		Sensitive: true,
	}, nil
}

func (d database) Apply(ctx context.Context, _ provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if s.Database.Source == "mariadb" {
		if err := apt.New(r).EnsureRepo(ctx, apt.MariaDBOrg()); err != nil {
			return fmt.Errorf("add mariadb.org repo: %w", err)
		}
	}
	if err := aptInstall(ctx, r, "mariadb-server"); err != nil {
		return fmt.Errorf("install mariadb-server: %w", err)
	}
	eng, err := dbpkg.Get(s.Database.Engine)
	if err != nil {
		return err
	}
	// Reuse an existing password from shared/.env or the local cache; otherwise
	// generate. Re-runs must not rotate the secret.
	pw, err := d.resolvePassword(ctx, s, r)
	if err != nil {
		return err
	}
	d.redactor.Add(pw) // mask in all output
	// Persist FIRST (atomic), so a crash before EnsureUser still leaves a
	// recoverable secret on the host and in the local cache.
	if err := d.seedSharedEnv(ctx, s, r, pw); err != nil {
		return err
	}
	if err := eng.EnsureDatabase(ctx, r, s.Database.Name); err != nil {
		return err
	}
	return eng.EnsureUser(ctx, r, s.Database.User, pw, s.Database.Name)
}

// sharedEnvPath is the server-side path of the application's shared .env.
func sharedEnvPath(s *config.Server) string {
	return s.Sites[0].DeployPath + "/shared/.env"
}

// resolvePassword returns the database password, preferring an existing one (host
// shared/.env, then the local cache) and only generating a new one when none
// exists. A reused password is re-validated against the allowed charset.
func (d database) resolvePassword(ctx context.Context, s *config.Server, r bssh.Runner) (string, error) {
	// 1) Existing value on the host.
	res, err := r.Run(ctx, "grep -m1 '^"+dbPasswordKey+"=' "+shQuote(sharedEnvPath(s)), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode == 0 {
		pw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(res.Stdout), dbPasswordKey+"="))
		if pw != "" {
			if !reDBPassword.MatchString(pw) {
				return "", fmt.Errorf("reused %s from %s is outside the allowed charset; refusing to use it", dbPasswordKey, sharedEnvPath(s))
			}
			return pw, nil
		}
	}
	// 2) Local cache (used to reuse, not rotate).
	if cache, err := secret.LoadCache(s.Host); err == nil {
		if pw := cache[dbPasswordKey]; pw != "" {
			if !reDBPassword.MatchString(pw) {
				return "", fmt.Errorf("cached %s is outside the allowed charset; refusing to use it", dbPasswordKey)
			}
			return pw, nil
		}
	}
	// 3) Generate a fresh one.
	pw, err := secret.Generate(dbPasswordLen)
	if err != nil {
		return "", fmt.Errorf("generate database password: %w", err)
	}
	return pw, nil
}

// seedSharedEnv renders shared/.env and writes it atomically (owner deploy, mode
// 0600), then caches the secret locally for reuse on re-run.
func (d database) seedSharedEnv(ctx context.Context, s *config.Server, r bssh.Runner, pw string) error {
	kv := map[string]string{
		"APP_ENV":       "production",
		"APP_DEBUG":     "false",
		"APP_URL":       appURL(s.Sites[0]),
		"DB_CONNECTION": "mysql",
		"DB_HOST":       "127.0.0.1",
		"DB_PORT":       "3306",
		"DB_DATABASE":   s.Database.Name,
		"DB_USERNAME":   s.Database.User,
		dbPasswordKey:   pw,
		"REDIS_HOST":    "127.0.0.1",
		"REDIS_PORT":    "6379",
	}
	body := secret.EnvFile(kv)
	if err := r.WriteFile(ctx, bssh.FileSpec{
		Path: sharedEnvPath(s), Content: body,
		Owner: "deploy", Group: "deploy", Mode: 0o600, Sudo: true,
	}); err != nil {
		return fmt.Errorf("write %s: %w", sharedEnvPath(s), err)
	}
	if err := secret.SaveCache(s.Host, map[string]string{dbPasswordKey: pw}); err != nil {
		return fmt.Errorf("cache database secret: %w", err)
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

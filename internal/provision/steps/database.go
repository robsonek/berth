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

// appKeyCacheKey is the local secret-cache key for a site's Laravel APP_KEY,
// stored beside the DB password (keyed by DB user) so a lost shared/.env can be
// re-seeded with the SAME key — otherwise encrypted-at-rest data (encrypted
// casts, Crypt::) is permanently undecryptable.
func appKeyCacheKey(dbUser string) string { return "appkey:" + dbUser }

// appKeyShape is the exact value shape of a berth-generated APP_KEY
// (secret.AppKey encodes exactly 32 bytes → "base64:" + 43 base64 chars + one
// "=" pad). It is shared verbatim by reAppKey and Check's remote grep -E probe
// (envHasBerthAppKey) so the two can never judge a key differently.
const appKeyShape = `base64:[A-Za-z0-9+/]{43}=`

// reAppKey validates an APP_KEY against appKeyShape. The strict shape rejects a
// truncated/corrupt key AND any newline a tampered source might use to inject a
// second shared/.env line.
var reAppKey = regexp.MustCompile(`^` + appKeyShape + `$`)

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

// clientAuthContainsScript builds the script that reports (exit 0) whether
// the client-auth file at path contains berth's OLD cached password. The
// password arrives via SSH stdin, `read` puts it in a shell variable, and
// printf pipes it to grep as the PATTERN (-f -) while the auth file is grep's
// named INPUT — pattern-from-pipe and data-from-file ride separate fds in
// this direction, and the secret never touches argv or stdout (-q). The
// caller shape-validates the password (alphanumeric), so single-pattern
// fixed-string semantics hold. Shared with the real-shell test in
// database_test.go so the tested bytes are the production bytes.
func clientAuthContainsScript(path string) string {
	return "IFS= read -r old; printf '%s\\n' \"$old\" | grep -qF -f - " + shQuote(path)
}

// cLocalePin is prepended to every whitespace-sensitive probe script so its
// grep/sed run under the C locale no matter what the host sets: Debian's
// default is LANG=C.UTF-8, where [[:space:]] also matches Unicode whitespace
// (e.g. U+2003) while the Go side (passwordFromEnv, appKeyFromEnv) trims
// ASCII only — left unpinned, that divergence can produce a false-green
// password agreement or endless APP_KEY drift. The leading assignment+export
// applies to every stage of the subsequent pipelines (an inline `LC_ALL=C
// cmd` prefix would cover only one stage) and survives berth's
// `sudo /bin/sh -c` wrapping. clientAuthContainsScript deliberately has no
// pin: fixed-string grep (-F) has no locale-sensitive operation. The test
// suite pins these prefix bytes independently of this constant.
const cLocalePin = "LC_ALL=C; export LC_ALL; "

// envCredentialPresentScript builds the exact shell script envCredentialPresent
// runs: grep -m1 selects the FIRST DB_PASSWORD line (a missing file or key
// yields empty input); the second grep validates it strictly and only its exit
// code answers (-q), so the secret never enters stdout. The C-locale pin keeps
// the trailing [[:space:]]* tolerance ASCII-only — exactly the set
// passwordFromEnv trims — so the probe never answers green over a value whose
// Unicode whitespace Apply's charset check refuses. Shared with the
// real-shell test in database_test.go so the tested bytes are the production
// bytes.
func envCredentialPresentScript(path string) string {
	return cLocalePin + "grep -m1 '^" + dbPasswordKey + "=' " + shQuote(path) + " | grep -Eq '^" + dbPasswordKey + "=[A-Za-z0-9]+[[:space:]]*$'"
}

// envCredentialPresent reports whether the FIRST DB_PASSWORD line of a site's
// shared/.env carries a charset-valid value — the same line passwordFromEnv
// reads, so Check and Apply always judge the same credential (a valid value on
// a later duplicate line must not satisfy Check when Apply would read the
// first).
func envCredentialPresent(ctx context.Context, r bssh.Runner, site config.Site) (bool, error) {
	res, err := r.Run(ctx, envCredentialPresentScript(sharedEnvPath(site)), nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// envValueMatchScript builds the exact shell script envValueMatches runs:
// `read` consumes the expected KEY=value line from stdin FIRST, the live env
// line is captured and trimmed separately (explicit grep exit mapping), and
// the comparison is plain quoted shell string equality — no grep pattern
// semantics, no pattern-file/input fd sharing. Shared with the real-shell
// test in database_test.go so the tested bytes are the production bytes.
// The C locale is enforced by cLocalePin, not assumed: under the pin,
// `sed 's/[[:space:]]*$//'` trims exactly the ASCII set passwordFromEnv
// trims, and the $(...) substitutions already strip trailing newlines — so a
// trailing-whitespace env line compares equal to the trimmed cached value
// (Check must never flag drift Apply cannot clear). Unpinned, the live-box
// C.UTF-8 default would also trim Unicode whitespace Go keeps in the value —
// a false-green match over a credential Apply refuses.
func envValueMatchScript(path, key string) string {
	return cLocalePin + "IFS= read -r want; " +
		"line=$(grep -m1 '^" + key + "=' " + shQuote(path) + "); s=$?; " +
		"if [ $s -eq 1 ]; then exit 3; elif [ $s -ne 0 ]; then exit 2; fi; " +
		`line=$(printf '%s' "$line" | sed 's/[[:space:]]*$//'); ` +
		`[ "$line" = "$want" ] && exit 0; exit 1`
}

// envValueMatches reports whether the FIRST <key>= line of a site's live
// shared/.env carries EXACTLY the expected value (modulo trailing ASCII
// whitespace, the same set passwordFromEnv trims). The expected value travels
// via STDIN (read into a shell variable — never argv, never stdout); the
// comparison is shell string equality, so no grep pattern semantics apply.
// The caller MUST have shape-validated expected (reDBPassword / reAppKey):
// a value with CR/LF could otherwise smuggle a second line past `read`, and
// a corrupt cache must fail loudly, not compare.
// Exit map: 0 = match; 1 = present but different; 3 = no <key>= line
// (treated as mismatch — the earlier presence probes make it unreachable,
// but a race must re-trigger Apply's loud handling, never error here);
// 2 = I/O error (hard Go error, never silent drift).
func envValueMatches(ctx context.Context, r bssh.Runner, site config.Site, key, expected string) (bool, error) {
	res, err := r.Run(ctx, envValueMatchScript(sharedEnvPath(site), key), []byte(key+"="+expected+"\n"))
	if err != nil {
		return false, err
	}
	switch res.ExitCode {
	case 0:
		return true, nil
	case 1, 3:
		return false, nil
	default:
		return false, fmt.Errorf("probe %s agreement in %s: %s", key, sharedEnvPath(site), res.Stderr)
	}
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
	// The recovery promise (re-seed a lost shared/.env with the SAME secrets)
	// holds only while the LOCAL cache carries them, so the cache is part of
	// this step's convergence, probed per site below. Read-only load — never
	// LockCache here (it creates files; Check must stay side-effect-free).
	cache, err := loadVerifiedSecrets(s)
	if err != nil {
		return provision.CheckResult{}, err
	}
	// The server is installed: every site needs its credential persisted AND
	// its database + user actually present. Probing real state (not just the
	// .env file) lets a re-run heal a provision that failed between the .env
	// write and EnsureUser. Convergence also covers the local recovery cache:
	// a green host with an empty ~/.berth (new workstation, crash before the
	// final save) must re-trigger Apply's backfill.
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
		// Local recovery cache: without the site's password a lost shared/.env
		// re-seeds with a NEW one (recoverable), and without the APP_KEY backup
		// it re-seeds with a NEW key — permanently breaking decryption of
		// encrypted-at-rest data. Apply backfills both from the live .env.
		if cache[s.SiteDBUser(site)] == "" {
			return d.unsatisfied(eng, "local secret cache missing the DB credential for "+site.Domain), nil
		}
		berthKey, err := envHasBerthAppKey(ctx, r, site)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if berthKey && cache[appKeyCacheKey(s.SiteDBUser(site))] == "" {
			return d.unsatisfied(eng, "local secret cache missing the APP_KEY backup for "+site.Domain), nil
		}
		// Value agreement between the live .env and the local cache: a restored
		// (older) .env would otherwise leave the role on the cache's password and
		// the cache holding a WRONG APP_KEY forever, with every run green —
		// Apply's passwordFromEnv branch reconciles the role and the cache toward
		// .env once triggered. Cached values are shape-validated BEFORE they ride
		// stdin: the strict charsets exclude CR/LF (nothing can smuggle a second
		// line past the script's `read`), and a corrupt cache must fail loudly,
		// never compare (mirroring newPassword/recoverOrNewAppKey's refusals).
		cachedPW := cache[s.SiteDBUser(site)]
		d.redactor.Add(cachedPW)
		if !reDBPassword.MatchString(cachedPW) {
			return provision.CheckResult{}, fmt.Errorf("cached password for %s is outside the allowed charset; refusing to use it", s.SiteDBUser(site))
		}
		match, err := envValueMatches(ctx, r, site, dbPasswordKey, cachedPW)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !match {
			return d.unsatisfied(eng, "DB credential for "+site.Domain+" disagrees between shared/.env and the local cache"), nil
		}
		// An operator-shaped APP_KEY berth does not back up must NOT be compared
		// (berthKey false): it would flag drift Apply never clears — the exact
		// brick envHasBerthAppKey's comment warns about.
		if berthKey && cache[appKeyCacheKey(s.SiteDBUser(site))] != "" {
			cachedKey := cache[appKeyCacheKey(s.SiteDBUser(site))]
			d.redactor.Add(cachedKey)
			if !reAppKey.MatchString(cachedKey) {
				return provision.CheckResult{}, fmt.Errorf("cached APP_KEY for %s is malformed; refusing to use it", s.SiteDBUser(site))
			}
			match, err = envValueMatches(ctx, r, site, appKeyKey, cachedKey)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if !match {
				return d.unsatisfied(eng, "APP_KEY for "+site.Domain+" disagrees between shared/.env and the local cache"), nil
			}
		}
	}
	return provision.CheckResult{Satisfied: true, Reason: eng.ServerPackage() + " installed (" + s.Database.Source + "); per-site databases, users and credentials present"}, nil
}

// envBerthAppKeyScript builds the exact shell script envHasBerthAppKey runs.
// Trailing ASCII whitespace is trimmed off the matched line BEFORE the shape
// grep — appKeyFromEnv trims the same set before caching, so without it a
// berth key with a trailing space would read as non-berth here and silently
// skip both the cache requirement and the agreement comparison for exactly
// the keys Apply DOES back up. The trim rides a pipeline stage (not the
// capture) so `s=$?` keeps grep's exit status. The C-locale pin keeps that
// trim ASCII-only, matching appKeyFromEnv: unpinned under the live-box
// C.UTF-8 default, sed would also strip Unicode whitespace, the probe would
// see a berth-shaped key appKeyFromEnv treats as absent, and Check would
// demand a cache entry Apply never writes — endless drift. Shared with the
// real-shell test in database_test.go so the tested bytes are the production
// bytes.
func envBerthAppKeyScript(path string) string {
	return cLocalePin + "line=$(grep -m1 '^" + appKeyKey + "=' " + shQuote(path) + "); s=$?; " +
		"if [ $s -eq 1 ]; then exit 1; elif [ $s -ne 0 ]; then exit 2; fi; " +
		`printf '%s' "$line" | sed 's/[[:space:]]*$//' | grep -Eq '^` + appKeyKey + `=` + appKeyShape + `$' && exit 0; exit 3`
}

// envHasBerthAppKey reports whether the FIRST APP_KEY line of a site's live
// shared/.env carries a value in EXACTLY the shape berth generates
// (appKeyShape — the same string reAppKey compiles; they MUST stay identical,
// modulo the trailing-whitespace trim appKeyFromEnv also applies), which is
// the only shape berth backs up. FIRST-line on purpose: it must match
// appKeyFromEnv's `grep -m1` read (phpdotenv's first-occurrence-wins) exactly,
// or a duplicate-key env — e.g. an empty first "APP_KEY=" and a berth-format
// key on a later line — would make Check demand a cache entry Apply never
// writes: endless drift. Deliberately exact-shape, not "any APP_KEY line": an
// operator-managed env can hold a Laravel-legal key berth does not back up
// (no "base64:" prefix, or an AES-128 22-char key), and appKeyFromEnv treats
// those as absent when Apply runs (never cached). If Check flagged them
// unsatisfied, it would demand a cache entry Apply never writes — the same
// endless drift (the key cannot be rotated without data loss). Probe-match ⟹
// Apply caches the key (converges); probe-miss ⟹ Apply treats it as absent
// exactly as today. Exit-code only (-q, and $line never printed) so the key
// never enters stdout. Exit map: 0 = first line is a berth-format key;
// 1 = no APP_KEY line; 3 = first line present but not berth-format;
// 2 (or anything else) = loud I/O error.
func envHasBerthAppKey(ctx context.Context, r bssh.Runner, site config.Site) (bool, error) {
	res, err := r.Run(ctx, envBerthAppKeyScript(sharedEnvPath(site)), nil)
	if err != nil {
		return false, err
	}
	switch res.ExitCode {
	case 0:
		return true, nil
	case 1, 3:
		return false, nil
	default:
		return false, fmt.Errorf("probe %s in %s: %s", appKeyKey, sharedEnvPath(site), res.Stderr)
	}
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
	release, err := secret.LockCache(s.CacheKey())
	if err != nil {
		return fmt.Errorf("lock local secret cache: %w", err)
	}
	defer release()
	cache, err := loadVerifiedSecrets(s)
	if err != nil {
		return fmt.Errorf("load local secret cache: %w", err)
	}
	for _, site := range s.Sites {
		dbName, dbUser := s.SiteDBName(site), s.SiteDBUser(site)
		// The client-auth reconciliation below must compare against what the
		// cache held BEFORE this run backfills it toward .env, so the pre-Apply
		// value is captured (and registered as a secret) up front.
		oldPW := cache[dbUser]
		d.redactor.Add(oldPW)
		envExists, err := fileExists(ctx, r, sharedEnvPath(site))
		if err != nil {
			return err
		}
		// Each secret is registered with the redactor the MOMENT it is
		// acquired — before the NEXT fallible operation, whose error text
		// could otherwise carry an unmasked value (e.g. the password must
		// already redact when appKeyFromEnv or the remote seed fails).
		var pw, appKey string
		if envExists {
			// An existing .env is never rewritten: the seed write is atomic,
			// so a present file is complete, and rewriting would clobber
			// operator-added keys. The role's password must therefore come
			// from the file the app reads.
			pw, err = d.passwordFromEnv(ctx, r, site)
			if err != nil {
				return err
			}
			d.redactor.Add(pw)
			appKey, err = d.appKeyFromEnv(ctx, r, site)
			if err != nil {
				return err
			}
			d.redactor.Add(appKey) // no-op when empty
		} else {
			pw, err = newPassword(dbUser, cache)
			if err != nil {
				return err
			}
			d.redactor.Add(pw)
			appKey, err = recoverOrNewAppKey(dbUser, cache)
			if err != nil {
				return err
			}
			d.redactor.Add(appKey)
			cache[dbUser] = pw
			cache[appKeyCacheKey(dbUser)] = appKey
			// Persist the recovery copy BEFORE the secret goes live remotely
			// (the accounts step does the same before chpasswd): a crash after
			// the remote seed can no longer strand a secret that exists only on
			// the host.
			if err := saveSecrets(s, cache); err != nil {
				return fmt.Errorf("cache database secrets before seeding: %w", err)
			}
			// The remote write itself is atomic, so a crash before EnsureUser
			// still leaves a complete, recoverable .env on the host.
			if err := d.seedSharedEnv(ctx, r, s, site, dbName, dbUser, pw, appKey, driver, host, port, socket); err != nil {
				return err
			}
		}
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
		user := s.SiteUser(site)
		if !authExists {
			// Seed-if-absent, like shared/.env: the password is reused (never
			// rotated) and the operator may customize the file, so a present
			// file is never rewritten. Written AFTER EnsureUser so the
			// credential it holds is live; a crash in between heals on the
			// next run via Check's existence probe.
			//
			// The client-auth file sits directly in /home/<user>, which the
			// account owns. A root write there is redirectable by a swapped LEAF
			// symlink: a destination that resolves to a directory makes mv move
			// the staged file INSIDE it, planting an account-owned file in a
			// directory of the tenant's choosing. Writing as the account removes
			// the privilege from that path.
			if err := writeFileAsUser(ctx, r, user, authPath, 0o600, eng.ClientAuthFile(dbName, dbUser, pw)); err != nil {
				return err
			}
		}
		// The containment probe's contract requires a shape-validated password
		// (a value whose FIRST line is empty would feed grep -F an EMPTY
		// pattern, which matches EVERY line and would rewrite an
		// operator-customized file). Check validates the same value, but its
		// earlier unsatisfied-returns can hand a corrupted cache straight to
		// Apply — so the tripwire fires here too, loudly, exactly as
		// newPassword refuses.
		if oldPW != "" && !reDBPassword.MatchString(oldPW) {
			return fmt.Errorf("cached password for %s is outside the allowed charset; refusing to use it", dbUser)
		}
		// A reconciled role password strands ~/.my.cnf|~/.pgpass on the old
		// credential (seed-if-absent). Rewrite ONLY a file that provably holds
		// berth's old cached password — an operator-customized file (no old
		// credential inside) is left alone, the same respect shared/.env gets.
		// The old password rides SSH stdin into the probe; a probe I/O failure
		// (grep exit >= 2) is loud, never read as "old credential absent".
		if oldPW != "" && oldPW != pw && authExists {
			res, err := r.Run(ctx, clientAuthContainsScript(authPath), []byte(oldPW+"\n"))
			if err != nil {
				return err
			}
			if res.ExitCode > 1 {
				return fmt.Errorf("probe old credential in %s: %s", authPath, res.Stderr)
			}
			if res.ExitCode == 0 {
				if err := writeFileAsUser(ctx, r, user, authPath, 0o600, eng.ClientAuthFile(dbName, dbUser, pw)); err != nil {
					return err
				}
			}
		}
		cache[dbUser] = pw
		if appKey != "" { // keep the cached key in sync with the live .env
			cache[appKeyCacheKey(dbUser)] = appKey
		}
	}
	if err := saveSecrets(s, cache); err != nil {
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

// appKeyFromEnv reads APP_KEY from a site's existing shared/.env, mirroring
// passwordFromEnv but LENIENT: a berth-seeded .env always has it, yet an
// operator-managed .env may not, so a missing key returns ("", nil) — it
// simply is not backed up. A present-but-EMPTY "APP_KEY=" line (stock Laravel's
// placeholder) counts as absent too, and so does a PRESENT key in a shape berth
// does not generate: distinguishing an operator-managed Laravel-legal key (no
// "base64:" prefix, an AES-128 22-char key) from a corrupt berth key is
// impossible from shape alone, and erroring bricked Apply on operator-keyed
// hosts for ANY trigger — a key berth cannot recognize is simply not berth's
// to back up (it is never cached either, so nothing corrupt is laundered into
// the cache, and envHasBerthAppKey renders the same verdict in Check). A grep
// failure (exit >= 2) stays a hard error — an I/O error must never read as
// "absent". Reading the key keeps the cached copy in sync with the live file,
// exactly as cache[dbUser]=pw does for the password.
func (d database) appKeyFromEnv(ctx context.Context, r bssh.Runner, site config.Site) (string, error) {
	env := sharedEnvPath(site)
	res, err := r.Run(ctx, "grep -m1 '^"+appKeyKey+"=' "+shQuote(env), nil)
	if err != nil {
		return "", err
	}
	switch res.ExitCode {
	case 0:
	case 1:
		return "", nil // no APP_KEY line
	default:
		return "", fmt.Errorf("grep %s in %s: %s", appKeyKey, env, res.Stderr)
	}
	line := strings.TrimRight(res.Stdout, " \t\n\v\f\r")
	k := strings.TrimPrefix(line, appKeyKey+"=")
	if k == "" || k == line || !reAppKey.MatchString(k) {
		return "", nil
	}
	return k, nil
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

// recoverOrNewAppKey reuses a well-formed cached APP_KEY, else generates one and
// stores it — mirroring newPassword's reuse-not-rotate rule.
func recoverOrNewAppKey(dbUser string, cache map[string]string) (string, error) {
	if k := cache[appKeyCacheKey(dbUser)]; k != "" {
		if !reAppKey.MatchString(k) {
			return "", fmt.Errorf("cached APP_KEY for %s is malformed; refusing to use it", dbUser)
		}
		return k, nil
	}
	k, err := secret.AppKey()
	if err != nil {
		return "", err
	}
	cache[appKeyCacheKey(dbUser)] = k
	return k, nil
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
	// shared/.env sits inside shared/, which the site user owns, so the root
	// write path could be redirected by a swapped symlink into creating a
	// tenant-owned file in a root-only directory (see writeFileAsUser). The
	// account writes its own .env; the content still rides on stdin, so the
	// generated password never reaches a command string.
	body, err := secret.EnvFile(kv)
	if err != nil {
		return fmt.Errorf("render shared/.env for %s: %w", site.Domain, err)
	}
	if err := writeFileAsUser(ctx, r, user, sharedEnvPath(site), 0o600, body); err != nil {
		return err
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

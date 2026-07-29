package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	// Explicit a-zA-Z on purpose (NOT `(?i)`): Go's case-insensitive matching
	// uses Unicode simple folding, which lets non-ASCII letters that fold into
	// a-z (e.g. U+017F LONG S -> s) pass — and the lowercase guard in
	// Site.validate cannot catch them either (ToLower(U+017F) == U+017F).
	// Uppercase ASCII still matches here so that guard can keep its friendly
	// "must be lowercase" message.
	reHostname = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	// reServerID keeps ids filename-safe (the secret cache is keyed by them)
	// and unambiguous: lowercase, no path separators, no leading/trailing
	// punctuation, 2-64 chars.
	reServerID     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$`)
	reSQLIdent     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	rePHPVer       = regexp.MustCompile(`^\d+\.\d+$`)
	reEmail        = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	reLinuxUser    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reFail2banTime = regexp.MustCompile(`^[0-9]+[smhdw]?$`)
	reDaemonName   = regexp.MustCompile(`^[a-z0-9-]+$`)
	// reQueueToken constrains queue.connection / queue.queue: rendered unquoted
	// into the Supervisor command= line, which supervisord word-splits, so a
	// space (or shell metachar) would inject extra worker argv tokens. Commas
	// stay legal (`--queue=high,default` is Laravel's priority-list form), as do
	// braces (`{default}` — Redis Cluster hash-tagged queue names); supervisord
	// does not run a shell, so neither expands.
	reQueueToken  = regexp.MustCompile(`^[A-Za-z0-9_.,{}-]*$`)
	reValkeyMem   = regexp.MustCompile(`^(?i)[0-9]+(b|kb|mb|gb|k|m|g)?$`)
	reMariaDBSize = regexp.MustCompile(`^(?i)[0-9]+[kmg]?$`)
	// rePHPSize guards PHP ini shorthand sizes: positive digits + optional
	// K/M/G, NO leading zeros (PHP's shorthand parser reads 010M as octal
	// while nginx reads decimal — the two sides would diverge) and no sign
	// (so -1/unlimited is unrepresentable). "0" is likewise rejected: PHP
	// treats post_max_size=0 and nginx client_max_body_size 0 as unlimited.
	rePHPSize  = regexp.MustCompile(`^[1-9][0-9]*[KMGkmg]?$`)
	reSwapSize = regexp.MustCompile(`^[1-9][0-9]*[MmGg]$`)
	// reTimezone guards IANA zone names (UTC, Europe/Warsaw, Etc/GMT+8,
	// America/Argentina/Buenos_Aires — at most three segments). The value
	// reaches `timedatectl set-timezone` verbatim (config-injection defence);
	// existence is deliberately NOT validated locally — Windows berth binaries
	// ship no tzdb, and timedatectl rejects unknown zones loudly on the host.
	reTimezone = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$`)
	// reCronSchedule matches exactly five space-separated cron fields over a strict
	// character class (digits and * , - /). It rejects extra fields, embedded
	// newlines and any other shell/cron metacharacter — the value is rendered
	// verbatim into /etc/cron.d as root, so a loose value is injection. This is an
	// injection/shape guard, NOT a semantic cron validator: it accepts out-of-range-
	// but-harmless values like "99 99 * * *" (cron itself rejects those at run time).
	// Full per-field range checking is intentionally out of scope.
	reCronSchedule = regexp.MustCompile(`^[0-9*,/-]+( [0-9*,/-]+){4}$`)
)

// GROW-ONLY after the first real deployment: removing a value from any of
// these allow-lists hard-fails Load() for an existing pinned config of a
// live host that cannot migrate (php.version is immutable on a provisioned
// host). Add new values freely; deletions need a deprecation path.
var allowedPHPVersions = map[string]bool{"8.2": true, "8.3": true, "8.4": true, "8.5": true}
var allowedPHPSources = map[string]bool{"auto": true, "sury": true, "debian": true}
var allowedNginxSources = map[string]bool{"debian": true, "nginx": true}

// allowedValkeyPolicies are the maxmemory-policy values Valkey accepts.
var allowedValkeyPolicies = map[string]bool{
	"noeviction": true, "allkeys-lru": true, "allkeys-lfu": true, "allkeys-random": true,
	"volatile-lru": true, "volatile-lfu": true, "volatile-random": true, "volatile-ttl": true,
}

// reservedOSUsers are names berth refuses for a site OS user: stock Debian
// system accounts (whose homes are not /home/<user> and which own privileged
// resources) plus berth's own provisioning account. Using one would collide
// with an existing account and break berth's per-user home layout.
var reservedOSUsers = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"uucp": true, "proxy": true, "www-data": true, "backup": true,
	"list": true, "irc": true, "gnats": true, "nobody": true, "_apt": true,
	"messagebus": true, "sshd": true,
	"systemd-network": true, "systemd-resolve": true, "systemd-timesync": true,
	"berth": true,
}

// IsValidSiteOSUser reports whether name could be configured as sites[].user:
// a valid Linux username that is not reserved by the system or berth. Steps
// use it to decide whether an error message may suggest pinning an
// encountered directory owner as the site user (stat's UNKNOWN placeholder,
// numeric uids and reserved accounts must never be suggested).
func IsValidSiteOSUser(name string) bool {
	return reLinuxUser.MatchString(name) && !reservedOSUsers[name]
}

// deniedDeployRoots are filesystem trees a deploy_path may never equal or
// enter. appdirs runs `install -d -o <user> -g www-data -m 00710 <deploy_path>`
// as root, and GNU install -d applies -o/-g/-m to an EXISTING directory (and
// follows a directory symlink to its target), so a deploy_path inside a
// system tree hands its ownership to the tenant (e.g. /etc -> replaceable
// /etc/pam.d -> root). /home is banned outright: a site user owns its own
// /home/<user> (0700), so a deploy_path under it (a) cannot be served — nginx
// as www-data cannot traverse the 0700 home — and (b) lets the tenant swap
// the directory for a symlink between runs. /var is handled separately (only
// /var/www is allowed) so the enumeration cannot silently miss a /var subtree.
var deniedDeployRoots = []string{
	"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64",
	"/libx32", "/media", "/mnt", "/proc", "/root", "/run", "/sbin", "/sys",
	"/tmp", "/usr",
}

// ValidateDeployPath guards a single site's deploy_path. Exported so the
// wizard's per-field validation applies exactly the same rules as config
// loading. The path must be absolute, free of shell metacharacters, in
// canonical (clean) form, at least two components deep, and outside every
// denied tree; under /var only a per-site subdirectory of /var/www is allowed.
// Cross-site rules (duplicates, nesting) live in Server.Validate, which sees
// all sites at once.
func ValidateDeployPath(p string) error {
	if !path.IsAbs(p) || strings.ContainsAny(p, " ;&|$`\n\t\"'\\*?[]{}~") {
		return fmt.Errorf("deploy_path %q must be an absolute path without shell metacharacters", p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("deploy_path %q is not in canonical form; write it clean (e.g. /var/www/app: no trailing slash, no . or .. segments)", p)
	}
	if strings.Count(p, "/") < 2 {
		return fmt.Errorf("deploy_path %q is a top-level directory; use a dedicated subdirectory (e.g. /var/www/app)", p)
	}
	// /var: only a per-site subdirectory of the web root is allowed. Denying
	// by allow-rule (not an enumeration of /var subtrees) means no future
	// /var/<x> tree can slip through.
	if p == "/var" || strings.HasPrefix(p, "/var/") {
		switch {
		case p == "/var/www":
			return fmt.Errorf("deploy_path %q is the shared web root itself; use a per-site subdirectory such as /var/www/<domain>", p)
		case p == "/var/www/berth-acme" || strings.HasPrefix(p, "/var/www/berth-acme/"):
			return fmt.Errorf("deploy_path %q is berth's ACME webroot (owned by www-data); use a dedicated directory such as /var/www/<domain>", p)
		case strings.HasPrefix(p, "/var/www/"):
			return nil
		default:
			return fmt.Errorf("deploy_path %q is under /var but outside /var/www; berth would chown it as root — use /var/www/<domain>", p)
		}
	}
	for _, root := range deniedDeployRoots {
		if p == root || strings.HasPrefix(p, root+"/") {
			return fmt.Errorf("deploy_path %q is inside the system tree %s; berth would chown it as root (install -d applies ownership to an existing directory, and a tenant-owned parent enables a symlink swap to root) — use a dedicated directory such as /var/www/<domain>", p, root)
		}
	}
	return nil
}

// dbEngineUpstreamSource maps each supported database engine to the non-"debian"
// value its database.source may take (its trusted producer repo).
var dbEngineUpstreamSource = map[string]string{"mariadb": "mariadb", "postgres": "pgdg"}

// DatabaseChoice is one selectable (engine, source) pair with a display label.
// It is the single source of truth the wizard's database picker builds from, so
// adding a 5th pair stays a one-line edit to dbEngineUpstreamSource (plus labels).
type DatabaseChoice struct {
	Engine string
	Source string
	Label  string
}

var dbEngineLabel = map[string]string{"mariadb": "MariaDB", "postgres": "PostgreSQL"}
var dbSourceLabel = map[string]string{"debian": "Debian", "mariadb": "mariadb.org", "pgdg": "pgdg"}

// DatabaseChoices returns every valid (engine, source) pair in deterministic
// order: engines sorted, each emitting its implicit "debian" source then its
// upstream source from dbEngineUpstreamSource.
func DatabaseChoices() []DatabaseChoice {
	engines := make([]string, 0, len(dbEngineUpstreamSource))
	for e := range dbEngineUpstreamSource {
		engines = append(engines, e)
	}
	sort.Strings(engines)
	out := make([]DatabaseChoice, 0, len(engines)*2)
	for _, e := range engines {
		el := dbEngineLabel[e]
		if el == "" {
			el = e
		}
		for _, src := range []string{"debian", dbEngineUpstreamSource[e]} {
			sl := dbSourceLabel[src]
			if sl == "" {
				sl = src
			}
			out = append(out, DatabaseChoice{
				Engine: e, Source: src,
				Label: el + " (" + sl + ")",
			})
		}
	}
	return out
}

// supportedEngines returns the sorted, comma-joined list of supported database
// engines, derived from dbEngineUpstreamSource so a new engine flows through to
// error messages automatically.
func supportedEngines() string {
	es := make([]string, 0, len(dbEngineUpstreamSource))
	for e := range dbEngineUpstreamSource {
		es = append(es, e)
	}
	sort.Strings(es)
	return strings.Join(es, ", ")
}

// ValidFingerprint reports whether fp is acceptable as ssh.fingerprint. Empty is
// allowed (host key trusted on first use). A non-empty value must mirror
// xssh.FingerprintSHA256 output: "SHA256:" + unpadded base64 decoding to exactly
// 32 bytes. The authoritative match against the live host key still happens in
// internal/ssh/hostkey.go; this only rejects impossible pins at config load.
func ValidFingerprint(fp string) error {
	if fp == "" {
		return nil
	}
	rest, ok := strings.CutPrefix(fp, "SHA256:")
	if !ok {
		return fmt.Errorf("ssh.fingerprint %q must be SHA256:<base64> (e.g. from ssh-keyscan)", fp)
	}
	raw, err := base64.RawStdEncoding.DecodeString(rest)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("ssh.fingerprint %q is not a valid SHA256 fingerprint", fp)
	}
	return nil
}

// ParseSwapBytes converts a swap size ("2G", "512M", case-insensitive) to
// bytes. Units are binary (M = MiB, G = GiB) to match `fallocate -l` and
// `stat -c %s`. Authoritative for the whole program: System.validate calls it
// at config load, the wizard's per-field validator delegates to it, and the
// system step keeps only a thin defensive wrapper. Sizes above 1 TiB are
// rejected — reSwapSize does not bound the digit count, so an absurd size
// would otherwise overflow the multiplication (or reach fallocate and fail
// remotely instead of at validation).
func ParseSwapBytes(size string) (int64, error) {
	if !reSwapSize.MatchString(size) {
		return 0, fmt.Errorf("swap %q must be a positive number suffixed M or G (e.g. 2G)", size)
	}
	s := strings.ToUpper(size)
	num, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
	if err != nil || num <= 0 {
		return 0, fmt.Errorf("invalid swap size %q", size)
	}
	const tib = int64(1) << 40
	var bytes int64
	switch s[len(s)-1] {
	case 'M':
		bytes = num * (1 << 20)
	case 'G':
		bytes = num * (1 << 30)
	}
	if num > (tib>>20) || bytes > tib || bytes <= 0 { // the num-cap alone suffices (no wrapping product is reachable below it); the byte checks are belt
		return 0, fmt.Errorf("swap %q exceeds the 1 TiB cap (and no realistic VPS wants more)", size)
	}
	return bytes, nil
}

// ValidateServerID guards the FORMAT of the top-level `id` (the secret-cache
// key: filename-safe, unambiguous). Exported so the wizard's per-field
// validation applies exactly the same rule as config loading. Empty passes
// HERE by design — the wizard validates the prompt before auto-generating an
// id, so blank means "generate one" at that layer; only Server.Validate
// requires a non-empty id.
func ValidateServerID(id string) error {
	if id != "" && !reServerID.MatchString(id) {
		return fmt.Errorf("id %q is not a valid server id (lowercase [a-z0-9._-], 2-64 chars, must start and end alphanumeric)", id)
	}
	return nil
}

// Validate checks every field that reaches a shell, SQL statement, or path.
func (s *Server) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("id is required: it is the stable identity of the machine's local secret cache (a host rename must never silently re-key it) — run `berth init` to generate one, or add e.g. `id: prod-<name>-<4 random hex>`")
	}
	if err := ValidateServerID(s.ID); err != nil {
		return err
	}
	if !reHostname.MatchString(s.Host) {
		return fmt.Errorf("host %q is not a valid hostname or IP", s.Host)
	}
	if s.SSH.Port < 1 || s.SSH.Port > 65535 {
		return fmt.Errorf("ssh.port %d out of range", s.SSH.Port)
	}
	if err := ValidFingerprint(s.SSH.Fingerprint); err != nil {
		return err
	}
	if !rePHPVer.MatchString(s.PHP.Version) || !allowedPHPVersions[s.PHP.Version] {
		return fmt.Errorf("php.version %q is not an allowed version", s.PHP.Version)
	}
	if !allowedPHPSources[s.PHP.Source] {
		return fmt.Errorf("php.source %q must be auto, sury, or debian", s.PHP.Source)
	}
	if !allowedNginxSources[s.Nginx.Source] {
		return fmt.Errorf("nginx.source %q must be debian or nginx", s.Nginx.Source)
	}
	if s.Fail2ban.Bantime != "" && !reFail2banTime.MatchString(s.Fail2ban.Bantime) {
		return fmt.Errorf("fail2ban.bantime %q must be a number optionally suffixed s/m/h/d/w", s.Fail2ban.Bantime)
	}
	if s.Fail2ban.Findtime != "" && !reFail2banTime.MatchString(s.Fail2ban.Findtime) {
		return fmt.Errorf("fail2ban.findtime %q must be a number optionally suffixed s/m/h/d/w", s.Fail2ban.Findtime)
	}
	if s.Fail2ban.Maxretry != 0 && (s.Fail2ban.Maxretry < 1 || s.Fail2ban.Maxretry > 100) {
		return fmt.Errorf("fail2ban.maxretry %d out of range (1-100)", s.Fail2ban.Maxretry)
	}
	if err := s.Tuning.validate(); err != nil {
		return err
	}
	if err := s.System.validate(); err != nil {
		return err
	}
	if err := s.Backups.validate(); err != nil {
		return err
	}
	if s.Backups.Offsite != nil && !s.AnyBackupsEnabled() {
		return fmt.Errorf("backups.offsite requires backups to be enabled (there would be nothing to ship)")
	}
	upstream, engineOK := dbEngineUpstreamSource[s.Database.Engine]
	if !engineOK {
		return fmt.Errorf("database.engine %q unsupported (supported: %s)", s.Database.Engine, supportedEngines())
	}
	if s.Database.Source != "debian" && s.Database.Source != upstream {
		return fmt.Errorf("database.source %q invalid for engine %q (use debian or %s)", s.Database.Source, s.Database.Engine, upstream)
	}
	if len(s.Sites) == 0 {
		return fmt.Errorf("at least one site is required")
	}
	seenDomain, seenUser, seenDBName, seenDBUser, seenPath := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	seenProgram := map[string]bool{}
	type sitePath struct{ domain, path string }
	var seenSitePaths []sitePath
	dup := func(seen map[string]bool, key, what string) error {
		if seen[key] {
			return fmt.Errorf("two sites share the same %s %q; each site must be distinct for isolation", what, key)
		}
		seen[key] = true
		return nil
	}
	for i := range s.Sites {
		site := s.Sites[i]
		// Checked before site.validate() so the default-letsencrypt case reports
		// the cloudflare_only pairing, not a missing ssl_email it would only
		// need after dropping cloudflare_only anyway.
		if site.SSL && s.CloudflareOnlyEnabled(site) && site.CertMode() == "letsencrypt" {
			return fmt.Errorf("site %s: cloudflare_only cannot issue a Let's Encrypt certificate (a proxied DNS record never points at the origin); use ssl_mode: selfsigned (Cloudflare SSL mode %q) or disable cloudflare_only for this site", site.Domain, "Full")
		}
		if err := site.validate(); err != nil {
			return fmt.Errorf("site %d: %w", i, err)
		}
		// Per-site database identity: every site carries its own block. Checked
		// before the SQL-identifier tests so the message names the real problem
		// instead of rejecting "" as an invalid identifier.
		if site.Database.Name == "" || site.Database.User == "" {
			return fmt.Errorf("site %d (%s): missing database block; every site needs database: {name, user}", i, site.Domain)
		}
		dbName, dbUser := s.SiteDBName(site), s.SiteDBUser(site)
		if !reSQLIdent.MatchString(dbName) {
			return fmt.Errorf("site %d (%s): database name %q is not a valid SQL identifier", i, site.Domain, dbName)
		}
		if !reSQLIdent.MatchString(dbUser) {
			return fmt.Errorf("site %d (%s): database user %q is not a valid SQL identifier", i, site.Domain, dbUser)
		}
		// The per-site OS user (explicit or derived) must be a valid Linux name.
		osUser := s.SiteUser(site)
		if !reLinuxUser.MatchString(osUser) {
			return fmt.Errorf("site %d (%s): os user %q is not a valid Linux username", i, site.Domain, osUser)
		}
		if reservedOSUsers[osUser] {
			return fmt.Errorf("site %d (%s): os user %q is reserved by the system; set sites[].user to a non-reserved name", i, site.Domain, osUser)
		}
		// HTTP/3 (QUIC) is always over TLS and needs an nginx built with the v3
		// module — berth only knows the nginx.org mainline package ships it.
		if site.HTTP3 {
			if !site.SSL {
				return fmt.Errorf("site %d (%s): http3 requires ssl: true (QUIC is always over TLS)", i, site.Domain)
			}
			if s.Nginx.Source != "nginx" {
				return fmt.Errorf("site %d (%s): http3 requires nginx.source: nginx (only that source ships the HTTP/3 module)", i, site.Domain)
			}
		}
		// Isolation requires a distinct domain, OS user, DB name, DB user and path.
		if err := dup(seenDomain, site.Domain, "domain"); err != nil {
			return err
		}
		if err := dup(seenUser, osUser, "os user"); err != nil {
			return err
		}
		if err := dup(seenDBName, dbName, "database name"); err != nil {
			return err
		}
		if err := dup(seenDBUser, dbUser, "database user"); err != nil {
			return err
		}
		if err := dup(seenPath, site.DeployPath, "deploy_path"); err != nil {
			return err
		}
		// Nested deploy_paths break tenant isolation: appdirs would chown one
		// site's ancestor (or subtree) to another site's user. Paths are clean
		// here (ValidateDeployPath ran in site.validate above), so the
		// "/"-suffixed prefix test is exact — siblings sharing a string prefix
		// (/var/www/app-one, /var/www/app-two) do NOT match.
		for _, prev := range seenSitePaths {
			if strings.HasPrefix(site.DeployPath, prev.path+"/") || strings.HasPrefix(prev.path, site.DeployPath+"/") {
				return fmt.Errorf("site %s deploy_path %s and site %s deploy_path %s are nested; every deploy_path must be a disjoint directory for isolation", prev.domain, prev.path, site.Domain, site.DeployPath)
			}
		}
		seenSitePaths = append(seenSitePaths, sitePath{domain: site.Domain, path: site.DeployPath})
		for _, prog := range s.SiteProgramNames(site) {
			if err := dup(seenProgram, prog, "supervisor program"); err != nil {
				return err
			}
		}
	}
	return nil
}

// phpMaxExecutionCeiling caps tuning.php_max_execution_time at 300 s — an
// opinionated sanity bound (long-running work belongs in queue workers), the
// same domain the wizard input enforces. Note it is NOT a wall-clock pact
// with nginx: fastcgi_read_timeout 300 is a between-reads timeout and PHP's
// limit excludes I/O wait.
const phpMaxExecutionCeiling = 300

// phpMaxInputVarsCeiling caps tuning.php_max_input_vars, matching the wizard
// input's domain so both public config paths accept the same values.
const phpMaxInputVarsCeiling = 1000000

// validatePHPSize guards a PHP ini shorthand size knob: grammar first, then a
// parse-and-bound check so accepted values can never overflow PHP's signed
// 64-bit ini parser into the -1 "unlimited" sentinel.
func validatePHPSize(field, v string) error {
	if !rePHPSize.MatchString(v) {
		return fmt.Errorf("%s %q must be a positive number optionally suffixed K/M/G, no leading zeros (e.g. 256M)", field, v)
	}
	b, err := phpSizeBytes(v)
	if err != nil {
		return fmt.Errorf("%s %q: %w", field, v, err)
	}
	if b > phpSizeMaxBytes {
		return fmt.Errorf("%s %q exceeds the 64G bound", field, v)
	}
	return nil
}

// validate checks the tuning knobs that reach a config / unit file. Empty values
// mean "use the default" and pass; non-empty values are format-/allow-list-guarded
// (config-injection defence — the values are rendered verbatim into config files).
func (t Tuning) validate() error {
	if t.ValkeyMaxmemory != "" && !reValkeyMem.MatchString(t.ValkeyMaxmemory) {
		return fmt.Errorf("tuning.valkey_maxmemory %q must be a number optionally suffixed b/kb/mb/gb (e.g. 256mb)", t.ValkeyMaxmemory)
	}
	if t.ValkeyMaxmemoryPolicy != "" && !allowedValkeyPolicies[t.ValkeyMaxmemoryPolicy] {
		return fmt.Errorf("tuning.valkey_maxmemory_policy %q is not a valid Valkey eviction policy", t.ValkeyMaxmemoryPolicy)
	}
	if t.MariaDBBufferPool != "" && !reMariaDBSize.MatchString(t.MariaDBBufferPool) {
		return fmt.Errorf("tuning.mariadb_innodb_buffer_pool %q must be a number optionally suffixed K/M/G (e.g. 256M)", t.MariaDBBufferPool)
	}
	if t.MariaDBLogFileSize != "" {
		if !reMariaDBSize.MatchString(t.MariaDBLogFileSize) {
			return fmt.Errorf("tuning.mariadb_log_file_size %q must be a number optionally suffixed K/M/G (e.g. 1G)", t.MariaDBLogFileSize)
		}
		b, err := phpSizeBytes(t.MariaDBLogFileSize)
		if err != nil {
			return fmt.Errorf("tuning.mariadb_log_file_size %q: %w", t.MariaDBLogFileSize, err)
		}
		if b < mariadbLogFileSizeMin {
			return fmt.Errorf("tuning.mariadb_log_file_size %q is below MariaDB's 4M minimum", t.MariaDBLogFileSize)
		}
		if b > mariadbLogFileSizeMax {
			return fmt.Errorf("tuning.mariadb_log_file_size %q exceeds MariaDB's 512G maximum", t.MariaDBLogFileSize)
		}
		if b%mariadbLogFileSizeBlock != 0 {
			return fmt.Errorf("tuning.mariadb_log_file_size %q must be a multiple of 4096 (the redo-log block size)", t.MariaDBLogFileSize)
		}
	}
	if t.MariaDBTmpTableSize != "" && !reMariaDBSize.MatchString(t.MariaDBTmpTableSize) {
		return fmt.Errorf("tuning.mariadb_tmp_table_size %q must be a number optionally suffixed K/M/G (e.g. 128M)", t.MariaDBTmpTableSize)
	}
	if t.MariaDBMaxAllowedPacket != "" {
		if !reMariaDBSize.MatchString(t.MariaDBMaxAllowedPacket) {
			return fmt.Errorf("tuning.mariadb_max_allowed_packet %q must be a number optionally suffixed K/M/G (e.g. 64M)", t.MariaDBMaxAllowedPacket)
		}
		b, err := phpSizeBytes(t.MariaDBMaxAllowedPacket)
		if err != nil {
			return fmt.Errorf("tuning.mariadb_max_allowed_packet %q: %w", t.MariaDBMaxAllowedPacket, err)
		}
		if b > mariadbMaxAllowedPacketCeiling {
			return fmt.Errorf("tuning.mariadb_max_allowed_packet %q exceeds MariaDB's 1G ceiling (the server silently truncates larger values)", t.MariaDBMaxAllowedPacket)
		}
		if b < mariadbMaxAllowedPacketFloor {
			return fmt.Errorf("tuning.mariadb_max_allowed_packet %q is below MariaDB's 1024-byte floor (the server silently clamps it up)", t.MariaDBMaxAllowedPacket)
		}
		if b%mariadbMaxAllowedPacketFloor != 0 {
			return fmt.Errorf("tuning.mariadb_max_allowed_packet %q must be a multiple of 1024 (MariaDB silently rounds down)", t.MariaDBMaxAllowedPacket)
		}
	}
	if t.MariaDBMaxConnections != 0 && (t.MariaDBMaxConnections < 10 || t.MariaDBMaxConnections > 100000) {
		return fmt.Errorf("tuning.mariadb_max_connections %d out of range (10-100000)", t.MariaDBMaxConnections)
	}
	if t.PHPMemoryLimit != "" {
		if err := validatePHPSize("tuning.php_memory_limit", t.PHPMemoryLimit); err != nil {
			return err
		}
	}
	if t.PHPUploadMax != "" {
		if err := validatePHPSize("tuning.php_upload_max", t.PHPUploadMax); err != nil {
			return err
		}
	}
	if t.PHPMaxExecutionTime < 0 || t.PHPMaxExecutionTime > phpMaxExecutionCeiling {
		return fmt.Errorf("tuning.php_max_execution_time %d out of range (0-%d s; 0 = default, long-running work belongs in queue workers)", t.PHPMaxExecutionTime, phpMaxExecutionCeiling)
	}
	if t.PHPMaxInputVars < 0 || t.PHPMaxInputVars > phpMaxInputVarsCeiling {
		return fmt.Errorf("tuning.php_max_input_vars %d out of range (0-%d; 0 = default)", t.PHPMaxInputVars, phpMaxInputVarsCeiling)
	}
	if t.PHPFPMMaxChildren != 0 && (t.PHPFPMMaxChildren < 4 || t.PHPFPMMaxChildren > 10000) {
		return fmt.Errorf("tuning.php_fpm_max_children %d out of range (4-10000; the static pm.max_spare_servers = 4 must not exceed it)", t.PHPFPMMaxChildren)
	}
	if t.MariaDBLongQueryTime != 0 && (t.MariaDBLongQueryTime < 1 || t.MariaDBLongQueryTime > 86400) {
		return fmt.Errorf("tuning.mariadb_long_query_time %d out of range (1-86400 s)", t.MariaDBLongQueryTime)
	}
	if t.MariaDBLongQueryTime != 0 && !t.MariaDBSlowQueryLog {
		return fmt.Errorf("tuning.mariadb_long_query_time is set but tuning.mariadb_slow_query_log is false; enable the slow log or remove the threshold")
	}
	return nil
}

// validate guards the system knobs. Empty Swap / false Sysctl mean "off" and pass.
// A non-empty Swap must be a positive integer suffixed M (MiB) or G (GiB); the value
// reaches `fallocate -l` verbatim, so reject anything else (config-injection defence).
// A non-empty Timezone must match reTimezone; the value reaches timedatectl
// set-timezone verbatim.
func (sy System) validate() error {
	if sy.Swap != "" {
		if _, err := ParseSwapBytes(sy.Swap); err != nil {
			return fmt.Errorf("system.swap: %w", err)
		}
	}
	if sy.Timezone != "" && !reTimezone.MatchString(sy.Timezone) {
		return fmt.Errorf("system.timezone %q must be an IANA zone name like Europe/Warsaw (letters, digits, _ + -, at most two /)", sy.Timezone)
	}
	if sy.Hostname != "" {
		if len(sy.Hostname) > 64 {
			return fmt.Errorf("system.hostname %q exceeds 64 characters (the kernel HOST_NAME_MAX)", sy.Hostname)
		}
		if !reHostname.MatchString(sy.Hostname) {
			return fmt.Errorf("system.hostname %q is not a valid hostname", sy.Hostname)
		}
	}
	return nil
}

// validate guards the backup knobs. Zero/empty values mean "use the default" and
// pass (the *Eff accessors supply them). A non-empty schedule must be exactly five
// strict cron fields with no control characters — it is written verbatim into a
// root /etc/cron.d file, so a loose value is command injection. Retention, when
// set, must be a sane positive number of days.
func (b Backups) validate() error {
	if b.Schedule != "" && (hasControlChars(b.Schedule) || !reCronSchedule.MatchString(b.Schedule)) {
		return fmt.Errorf("backups.schedule %q must be 5 cron fields over [0-9*,/-] (e.g. \"30 3 * * *\")", b.Schedule)
	}
	if b.Retention != 0 && (b.Retention < 1 || b.Retention > 3650) {
		return fmt.Errorf("backups.retention_days %d out of range (1-3650)", b.Retention)
	}
	if b.Offsite != nil {
		if err := b.Offsite.validate(); err != nil {
			return err
		}
	}
	return nil
}

var allowedOffsiteBackends = map[string]bool{"s3": true, "sftp": true}

// reOffsiteHost accepts a lowercase DNS hostname or IPv4 literal — the only
// shapes that may reach the root-executed ssh command line (IPv6 literals
// are deliberately out: they would need [] quoting in three syntaxes).
var reOffsiteHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// reOffsiteUser bounds the sftp login to a safe account name: it lands as the
// "<user>@<host>" token in a root-executed ssh command, so it must never start
// with '-' (OpenSSH would parse it as an option — a ProxyCommand injection).
// No leading/trailing punctuation guarantees that.
var reOffsiteUser = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$`)

// validate checks the offsite target fields. Every value lands single-quoted
// inside root-executed files (offsite.env, the offsite script), so quotes,
// whitespace and control characters are rejected as injection, and the
// composed repository string must stay one shell-safe word. Lenient zero
// handling follows the Fail2ban pattern: unset optional values fall back to
// the *Eff accessors.
func (o *Offsite) validate() error {
	if !allowedOffsiteBackends[o.Backend] {
		return fmt.Errorf("backups.offsite.backend %q unsupported (supported: s3, sftp)", o.Backend)
	}
	plain := func(name, v string) error {
		if v != "" && (hasControlChars(v) || strings.ContainsAny(v, "'\"\\ \t")) {
			return fmt.Errorf("backups.offsite.%s %q must not contain whitespace, quotes, backslashes or control characters", name, v)
		}
		return nil
	}
	for _, f := range []struct{ name, v string }{
		{"endpoint", o.Endpoint}, {"bucket", o.Bucket}, {"prefix", o.Prefix},
		{"user", o.User}, {"path", o.Path},
	} {
		if err := plain(f.name, f.v); err != nil {
			return err
		}
	}
	// Range-check the port BEFORE the per-backend switch: the sftp host_key
	// pin is compared against a canonical token derived from the port, and a
	// nonsense port must be reported as a port error, not a pin mismatch.
	if o.Port != 0 && (o.Port < 1 || o.Port > 65535) {
		return fmt.Errorf("backups.offsite.port %d out of range (1-65535)", o.Port)
	}
	switch o.Backend {
	case "s3":
		if o.Endpoint == "" || o.Bucket == "" {
			return fmt.Errorf("backups.offsite with backend s3 requires endpoint and bucket")
		}
		if o.Host != "" || o.User != "" || o.Path != "" || o.HostKey != "" || o.Port != 0 {
			return fmt.Errorf("backups.offsite: host/port/user/path/host_key are only valid for backend sftp")
		}
	case "sftp":
		if o.Host == "" || o.User == "" || o.Path == "" || o.HostKey == "" {
			return fmt.Errorf("backups.offsite with backend sftp requires host, user, path and host_key")
		}
		// The host reaches a root-executed ssh command line: only a strict
		// hostname/IPv4 literal is acceptable — never trust plain() alone
		// with a value that could carry sed/shell metacharacters.
		if !reOffsiteHost.MatchString(o.Host) {
			return fmt.Errorf("backups.offsite.host %q must be a lowercase hostname or IPv4 literal", o.Host)
		}
		// The user lands as the "<user>@<host>" token on the same root-executed
		// ssh command line — a leading '-' would be parsed as an ssh option.
		if !reOffsiteUser.MatchString(o.User) {
			return fmt.Errorf("backups.offsite.user %q must be a plain login name (letters, digits, dot, underscore, hyphen; no leading or trailing punctuation) — it lands in a root-executed ssh command", o.User)
		}
		if !strings.HasPrefix(o.Path, "/") {
			return fmt.Errorf("backups.offsite.path %q must be absolute", o.Path)
		}
		if o.Endpoint != "" || o.Bucket != "" || o.Prefix != "" {
			return fmt.Errorf("backups.offsite: endpoint/bucket/prefix are only valid for backend s3")
		}
		if hasControlChars(o.HostKey) || strings.ContainsAny(o.HostKey, "'\"") {
			return fmt.Errorf("backups.offsite.host_key must not contain quotes or control characters")
		}
		fields := strings.Fields(o.HostKey)
		if len(fields) < 3 {
			return fmt.Errorf("backups.offsite.host_key %q must be one ssh-keyscan line (host keytype key)", o.HostKey)
		}
		if fields[0] != o.KnownHostsToken() {
			return fmt.Errorf("backups.offsite.host_key must pin %q — the canonical token OpenSSH looks up (bare host on port 22, [host]:port otherwise); its first field is %q", o.KnownHostsToken(), fields[0])
		}
	}
	if o.Schedule != "" && (hasControlChars(o.Schedule) || !reCronSchedule.MatchString(o.Schedule)) {
		return fmt.Errorf("backups.offsite.schedule %q must be 5 cron fields over [0-9*,/-] (e.g. \"15 4 * * *\")", o.Schedule)
	}
	for _, k := range []struct {
		name string
		v    int
	}{{"last", o.Keep.Last}, {"hourly", o.Keep.Hourly}, {"daily", o.Keep.Daily}, {"weekly", o.Keep.Weekly}, {"monthly", o.Keep.Monthly}} {
		if k.v != 0 && (k.v < 1 || k.v > 3650) {
			return fmt.Errorf("backups.offsite.keep.%s %d out of range (1-3650)", k.name, k.v)
		}
	}
	return nil
}

// maxSiteDomainLen caps a site domain so every on-host artifact name berth
// derives from it fits the kernel limits. poolName only swaps dots for
// underscores, so len(pool) == len(domain). The binding budgets today:
//
//	unix sockets (sun_path, 107 usable bytes):
//	  /run/berth-valkey/<pool>/valkey.sock -> 30 + len -> len <= 77 (tightest)
//	  /run/php/berth-<pool>.sock           -> 20 + len -> len <= 87
//	filenames (NAME_MAX, 255 bytes):
//	  berth-valkey-<pool>.service          -> 21 + len -> len <= 234
//	  berth-backup-<pool> (cron + script)  -> 13 + len
//	  berth-site-<pool> (scheduler cron)   -> 11 + len
//
// The cap is the TRUE universal hard bound, 77 — every accepted domain works
// with every feature, and every longer one breaks something. The Valkey
// budget applies unconditionally (never gate this on valkey being enabled: a
// domain valid only while valkey is off would blow up the day the knob is
// switched on). TestDomainCapMatchesPrefixArithmetic recomputes this bound
// from the live prefix constants (ValkeyRunBase, FPMSocketPrefix), so growing
// a prefix fails the build's tests instead of silently shrinking the budget.
// There is deliberately no headroom, because headroom rejects working domains.
// Without the guard a longer (still RFC-valid, up to 253 chars) domain passed
// validation and then EVERY Apply failed creating the derived artifact,
// permanently, after services were already reloaded.
const maxSiteDomainLen = 77

func (st *Site) validate() error {
	if !reHostname.MatchString(st.Domain) {
		return fmt.Errorf("domain %q is not a valid hostname", st.Domain)
	}
	if st.Domain != strings.ToLower(st.Domain) {
		return fmt.Errorf("domain %q must be lowercase: certbot lowercases DNS names while nginx and certificate file paths are case-sensitive", st.Domain)
	}
	if len(st.Domain) > maxSiteDomainLen {
		return fmt.Errorf("domain %q is %d characters; berth derives per-site artifact names from it (unix sockets, systemd units, cron files) that must fit kernel path limits — use a domain of at most %d characters", st.Domain, len(st.Domain), maxSiteDomainLen)
	}
	if err := ValidateDeployPath(st.DeployPath); err != nil {
		return err
	}
	if st.Repository != "" && !validGitURL(st.Repository) {
		return fmt.Errorf("repository %q must be an SSH git URL (scp-like or ssh://); HTTPS is out of v1 scope", st.Repository)
	}
	if st.SSLMode != "" && st.SSLMode != "letsencrypt" && st.SSLMode != "selfsigned" {
		return fmt.Errorf("ssl_mode %q must be letsencrypt or selfsigned", st.SSLMode)
	}
	if st.SSL && st.CertMode() == "letsencrypt" {
		// Let's Encrypt needs a contact email; self-signed does not.
		if st.SSLEmail == "" {
			return fmt.Errorf("ssl_email is required when ssl is true with letsencrypt")
		}
		if !reEmail.MatchString(st.SSLEmail) {
			return fmt.Errorf("ssl_email %q is not a valid email address", st.SSLEmail)
		}
	}
	if err := st.validateQueueDaemons(); err != nil {
		return err
	}
	return nil
}

// validGitURL accepts only SSH git URLs in v1 (scp-like git@host:path or
// ssh://…), because berth generates an SSH deploy key for the repository.
// HTTPS repositories are out of v1 scope (no deploy key would be generated).
func validGitURL(s string) bool {
	if strings.HasPrefix(s, "ssh://") {
		u, err := url.Parse(s)
		return err == nil && u.Host != "" && strings.Trim(u.Path, "/") != ""
	}
	// scp-like: user@host:path
	return regexp.MustCompile(`^[\w.-]+@[\w.-]+:[\w./~-]+$`).MatchString(s)
}

// GitEndpoint returns the SSH host and optional port of a repository URL.
// port is "" for scp-style URLs (git@host:path) and for ssh:// URLs without
// an explicit port; an explicit :22 also normalizes to "" — OpenSSH stores
// default-port entries under the bare hostname (ssh-keygen -F "[host]:22"
// never matches them and ssh-keyscan -p 22 emits bare-host lines), so
// treating 22 as a "custom" port could never converge. known_hosts stores
// non-default-port entries under the "[host]:port" token and ssh-keyscan
// needs -p, so callers that manage known_hosts must use both values —
// GitHost alone silently loses the port.
func GitEndpoint(repo string) (host, port string, err error) {
	if strings.HasPrefix(repo, "http") || strings.HasPrefix(repo, "ssh://") {
		u, err := url.Parse(repo)
		if err != nil {
			return "", "", err
		}
		port := u.Port()
		if port == "22" {
			port = ""
		}
		return u.Hostname(), port, nil
	}
	at := strings.Index(repo, "@")
	colon := strings.Index(repo, ":")
	if at < 0 || colon < 0 || colon < at {
		return "", "", fmt.Errorf("cannot parse host from %q", repo)
	}
	return repo[at+1 : colon], "", nil
}

// GitHost is a thin host-only convenience over GitEndpoint. Callers that
// manage known_hosts must use GitEndpoint instead — this drops the port.
func GitHost(repo string) (string, error) {
	host, _, err := GitEndpoint(repo)
	return host, err
}

// hasControlChars reports whether s contains a newline, carriage return, NUL, or
// other ASCII control character — rejected for any value rendered onto a single
// Supervisor/command line (config injection guard).
func hasControlChars(s string) bool {
	for _, r := range s {
		if r == 0 || r == '\n' || r == '\r' || r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func (st *Site) validateQueueDaemons() error {
	if q := st.Queue; q != nil {
		switch q.Driver {
		case "", "work", "horizon", "none":
		default:
			return fmt.Errorf("queue.driver %q must be work, horizon or none", q.Driver)
		}
		if q.Driver == "none" {
			if q.Connection != "" || q.Queue != "" || q.Processes != 0 || q.Sleep != 0 || q.Tries != 0 || q.Timeout != 0 || q.MaxMemory != 0 {
				return fmt.Errorf("queue: none disables the worker; remove the other queue settings")
			}
		}
		for _, kv := range []struct {
			name string
			v    int
		}{{"processes", q.Processes}, {"sleep", q.Sleep}, {"tries", q.Tries}, {"timeout", q.Timeout}, {"max_memory", q.MaxMemory}} {
			if kv.v < 0 {
				return fmt.Errorf("queue.%s must not be negative", kv.name)
			}
		}
		if q.Processes > 64 {
			return fmt.Errorf("queue.processes %d exceeds the cap of 64", q.Processes)
		}
		if !reQueueToken.MatchString(q.Connection) || !reQueueToken.MatchString(q.Queue) {
			return fmt.Errorf("queue.connection/queue may contain only letters, digits and _ . , - (they are word-split on the supervisor command line)")
		}
		if q.Driver == "horizon" {
			if q.Connection != "" || q.Queue != "" || q.Sleep != 0 || q.Tries != 0 || q.Timeout != 0 || q.MaxMemory != 0 {
				return fmt.Errorf("queue: horizon manages its own workers; remove connection/queue/sleep/tries/timeout/max_memory")
			}
			if q.Processes > 1 {
				return fmt.Errorf("queue: horizon forces numprocs=1; remove processes > 1")
			}
		}
	}
	seen := map[string]bool{}
	for i := range st.Daemons {
		d := st.Daemons[i]
		if !reDaemonName.MatchString(d.Name) {
			return fmt.Errorf("daemon %d: name %q must match [a-z0-9-]+", i, d.Name)
		}
		if seen[d.Name] {
			return fmt.Errorf("daemon name %q is duplicated within the site", d.Name)
		}
		seen[d.Name] = true
		if strings.TrimSpace(d.Command) == "" {
			return fmt.Errorf("daemon %q: command is required", d.Name)
		}
		if hasControlChars(d.Command) {
			return fmt.Errorf("daemon %q: command must be single-line (no control characters)", d.Name)
		}
		if d.Processes < 0 || d.Processes > 64 {
			return fmt.Errorf("daemon %q: processes %d out of range (0-64)", d.Name, d.Processes)
		}
	}
	return nil
}

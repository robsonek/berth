package config

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var (
	reHostname     = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	reSQLIdent     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	rePHPVer       = regexp.MustCompile(`^\d+\.\d+$`)
	reEmail        = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	reLinuxUser    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reFail2banTime = regexp.MustCompile(`^[0-9]+[smhdw]?$`)
	reDaemonName   = regexp.MustCompile(`^[a-z0-9-]+$`)
	reValkeyMem    = regexp.MustCompile(`^(?i)[0-9]+(b|kb|mb|gb|k|m|g)?$`)
	reMariaDBSize  = regexp.MustCompile(`^(?i)[0-9]+[kmg]?$`)
)

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

// dbEngineUpstreamSource maps each supported database engine to the non-"debian"
// value its database.source may take (its trusted producer repo).
var dbEngineUpstreamSource = map[string]string{"mariadb": "mariadb", "postgres": "pgdg"}

// Validate checks every field that reaches a shell, SQL statement, or path.
func (s *Server) Validate() error {
	if !reHostname.MatchString(s.Host) {
		return fmt.Errorf("host %q is not a valid hostname or IP", s.Host)
	}
	if s.SSH.Port < 1 || s.SSH.Port > 65535 {
		return fmt.Errorf("ssh.port %d out of range", s.SSH.Port)
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
	upstream, engineOK := dbEngineUpstreamSource[s.Database.Engine]
	if !engineOK {
		return fmt.Errorf("database.engine %q unsupported (supported: mariadb, postgres)", s.Database.Engine)
	}
	if s.Database.Source != "debian" && s.Database.Source != upstream {
		return fmt.Errorf("database.source %q invalid for engine %q (use debian or %s)", s.Database.Source, s.Database.Engine, upstream)
	}
	if len(s.Sites) == 0 {
		return fmt.Errorf("at least one site is required")
	}
	seenDomain, seenUser, seenDBName, seenDBUser, seenPath := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	seenProgram := map[string]bool{}
	dup := func(seen map[string]bool, key, what string) error {
		if seen[key] {
			return fmt.Errorf("two sites share the same %s %q; each site must be distinct for isolation", what, key)
		}
		seen[key] = true
		return nil
	}
	inheritLegacyDB := 0
	for i := range s.Sites {
		site := s.Sites[i]
		if err := site.validate(); err != nil {
			return fmt.Errorf("site %d: %w", i, err)
		}
		// Per-site database identity (its own block, or the inherited legacy
		// top-level database.name/user for a lone site).
		if site.Database.Name == "" && site.Database.User == "" {
			inheritLegacyDB++
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
		for _, prog := range s.SiteProgramNames(site) {
			if err := dup(seenProgram, prog, "supervisor program"); err != nil {
				return err
			}
		}
	}
	// The legacy top-level database.name/user can back exactly one site; with
	// several inheriting sites it is ambiguous — each needs its own database block.
	if inheritLegacyDB > 1 {
		return fmt.Errorf("%d sites have no database block; give each site its own database: {name, user} (top-level database.name/user is single-site legacy)", inheritLegacyDB)
	}
	// With Valkey each site is isolated onto its own Redis logical DB (index 0..N);
	// Redis ships 16 logical DBs, so per-site isolation caps at 16 sites.
	if s.Valkey && len(s.Sites) > 16 {
		return fmt.Errorf("valkey: true supports at most 16 sites (one Redis logical DB each); got %d — reduce sites or set valkey: false", len(s.Sites))
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
	return nil
}

func (st *Site) validate() error {
	if !reHostname.MatchString(st.Domain) {
		return fmt.Errorf("domain %q is not a valid hostname", st.Domain)
	}
	if !path.IsAbs(st.DeployPath) || strings.ContainsAny(st.DeployPath, " ;&|$`\n\t") {
		return fmt.Errorf("deploy_path %q must be an absolute path without shell metacharacters", st.DeployPath)
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

// GitHost extracts the host from a repository URL for known_hosts (Plan 2 uses it).
func GitHost(repo string) (string, error) {
	if strings.HasPrefix(repo, "http") || strings.HasPrefix(repo, "ssh://") {
		u, err := url.Parse(repo)
		if err != nil {
			return "", err
		}
		return u.Hostname(), nil
	}
	at := strings.Index(repo, "@")
	colon := strings.Index(repo, ":")
	if at < 0 || colon < 0 || colon < at {
		return "", fmt.Errorf("cannot parse host from %q", repo)
	}
	return repo[at+1 : colon], nil
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
		case "", "work", "horizon":
		default:
			return fmt.Errorf("queue.driver %q must be work or horizon", q.Driver)
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
		if hasControlChars(q.Connection) || hasControlChars(q.Queue) {
			return fmt.Errorf("queue.connection/queue must be single-line (no control characters)")
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

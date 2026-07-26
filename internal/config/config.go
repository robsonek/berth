// Package config loads and validates per-server berth configuration.
package config

import (
	"fmt"
	"hash/fnv"
	"math"
	"reflect"
	"strconv"
	"strings"

	mapstructure "github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type SSH struct {
	User        string `mapstructure:"user" yaml:"user"`
	Port        int    `mapstructure:"port" yaml:"port"`
	Key         string `mapstructure:"key" yaml:"key"`
	Fingerprint string `mapstructure:"fingerprint" yaml:"fingerprint,omitempty"`
}

type PHP struct {
	Version string `mapstructure:"version" yaml:"version"`
	Source  string `mapstructure:"source" yaml:"source"` // auto | sury | debian
}

type Nginx struct {
	Source string `mapstructure:"source" yaml:"source"` // debian | nginx (nginx.org mainline)
}

// Fail2ban holds the tunable knobs for berth's managed jail.local. bantime and
// findtime are a number optionally suffixed s/m/h/d/w (e.g. "1h", "10m");
// compound forms like "1h30m" are not supported. Zero/empty values mean "use
// the default"; defaults live in the *Eff accessors (NOT in Load() via
// SetDefault) so wizard ToServer() and literal Server callers that bypass
// Load() still render valid, non-empty values into jail.local.
type Fail2ban struct {
	Bantime  string `mapstructure:"bantime" yaml:"bantime,omitempty"`
	Findtime string `mapstructure:"findtime" yaml:"findtime,omitempty"`
	Maxretry int    `mapstructure:"maxretry" yaml:"maxretry,omitempty"`
}

const (
	defaultFail2banBantime  = "1h"
	defaultFail2banFindtime = "10m"
	defaultFail2banMaxretry = 5
)

// BantimeEff returns the configured bantime or the default ("1h").
func (f Fail2ban) BantimeEff() string {
	if f.Bantime == "" {
		return defaultFail2banBantime
	}
	return f.Bantime
}

// FindtimeEff returns the configured findtime or the default ("10m").
func (f Fail2ban) FindtimeEff() string {
	if f.Findtime == "" {
		return defaultFail2banFindtime
	}
	return f.Findtime
}

// MaxretryEff returns the configured maxretry or the default (5).
func (f Fail2ban) MaxretryEff() int {
	if f.Maxretry <= 0 {
		return defaultFail2banMaxretry
	}
	return f.Maxretry
}

// Tuning holds optional, conservative performance-tuning overrides. The Valkey
// knobs render into the per-site instance units (`berth-valkey-<pool>.service`;
// the cap is per instance), the MariaDB ones into a managed mariadb.conf.d
// drop-in. Empty fields
// fall back to the defaults returned by the *Eff accessors. The defaults live in
// the accessors (NOT in Load() via SetDefault) so wizard ToServer() and literal
// Server callers that bypass Load() still render valid, non-empty values — an
// empty value would otherwise produce a broken directive (e.g. "maxmemory ").
// PHP fields render into the php step's FPM-only conf.d drop-in; PHPUploadMax
// is the max single-file size, from which post_max_size and nginx
// client_max_body_size are derived (PHPPostBodyMaxEff).
// The four MariaDB parity knobs (log file size, tmp table size, max
// connections, max allowed packet) are unset-by-default: an empty knob
// renders no directive at all and the engine's stock default stays in
// force, so they deliberately have no *Eff accessors. PHPFPMMaxChildren is
// the exception (default 10): the pool file renders pm.max_children
// unconditionally, so the default must reproduce today's bytes.
type Tuning struct {
	ValkeyMaxmemory         string `mapstructure:"valkey_maxmemory" yaml:"valkey_maxmemory,omitempty"`
	ValkeyMaxmemoryPolicy   string `mapstructure:"valkey_maxmemory_policy" yaml:"valkey_maxmemory_policy,omitempty"`
	MariaDBBufferPool       string `mapstructure:"mariadb_innodb_buffer_pool" yaml:"mariadb_innodb_buffer_pool,omitempty"`
	MariaDBSlowQueryLog     bool   `mapstructure:"mariadb_slow_query_log" yaml:"mariadb_slow_query_log,omitempty"`
	MariaDBLongQueryTime    int    `mapstructure:"mariadb_long_query_time" yaml:"mariadb_long_query_time,omitempty"`
	MariaDBLogFileSize      string `mapstructure:"mariadb_log_file_size" yaml:"mariadb_log_file_size,omitempty"`
	MariaDBTmpTableSize     string `mapstructure:"mariadb_tmp_table_size" yaml:"mariadb_tmp_table_size,omitempty"`
	MariaDBMaxConnections   int    `mapstructure:"mariadb_max_connections" yaml:"mariadb_max_connections,omitempty"`
	MariaDBMaxAllowedPacket string `mapstructure:"mariadb_max_allowed_packet" yaml:"mariadb_max_allowed_packet,omitempty"`
	PHPMemoryLimit          string `mapstructure:"php_memory_limit" yaml:"php_memory_limit,omitempty"`
	PHPUploadMax            string `mapstructure:"php_upload_max" yaml:"php_upload_max,omitempty"`
	PHPMaxExecutionTime     int    `mapstructure:"php_max_execution_time" yaml:"php_max_execution_time,omitempty"`
	PHPMaxInputVars         int    `mapstructure:"php_max_input_vars" yaml:"php_max_input_vars,omitempty"`
	PHPFPMMaxChildren       int    `mapstructure:"php_fpm_max_children" yaml:"php_fpm_max_children,omitempty"`
}

const (
	defaultValkeyMaxmemory       = "256mb"
	defaultValkeyMaxmemoryPolicy = "allkeys-lru"
	defaultMariaDBBufferPool     = "256M"
	defaultMariaDBLongQueryTime  = 2
	defaultPHPMemoryLimit        = "256M"
	defaultPHPUploadMax          = "32M"
	defaultPHPMaxExecutionTime   = 30
	defaultPHPMaxInputVars       = 1000
	defaultPHPFPMMaxChildren     = 10
)

// phpSizeMaxBytes bounds the PHP size knobs (64 GiB — far above any sane VPS
// value). It keeps every accepted value representable in PHP's signed 64-bit
// ini parser: past that, PHP's shorthand parse wraps to the -1 "unlimited"
// sentinel, silently removing the limit.
const phpSizeMaxBytes = 64 << 30

// mariadbMaxAllowedPacketCeiling is MariaDB's hard upper bound for
// max_allowed_packet (1 GiB). The server silently truncates larger configured
// values, so berth rejects them loudly instead.
const mariadbMaxAllowedPacketCeiling = 1 << 30

// mariadbMaxAllowedPacketFloor is MariaDB's lower bound and block size for
// max_allowed_packet (1024 bytes). The server silently clamps smaller values
// up to it and rounds non-multiples down to the nearest 1024-byte block, so
// the effective value would differ from the configured one; berth rejects
// both loudly instead.
const mariadbMaxAllowedPacketFloor = 1 << 10

// mariadbLogFileSize{Min,Max,Block} pin innodb_log_file_size to MariaDB's
// documented domain: 4 MiB to 512 GiB in 4096-byte redo-log blocks. An
// out-of-domain value risks a poison drop-in — mariadbd failing at startup
// poisons every subsequent run (the same failure mode the buffer-pool RAM
// guard exists for) — so berth rejects it before it reaches the host.
const (
	mariadbLogFileSizeMin   = 4 << 20
	mariadbLogFileSizeMax   = 512 << 30
	mariadbLogFileSizeBlock = 4096
)

// phpPostHeadroomMinBytes is the minimum multipart-envelope allowance added
// to php_upload_max when deriving post_max_size / client_max_body_size
// (boundaries, form fields and metadata all count toward the request body).
const phpPostHeadroomMinBytes = 2 << 20

// ValkeyMaxmemoryEff returns the configured maxmemory or the conservative default.
func (t Tuning) ValkeyMaxmemoryEff() string {
	if t.ValkeyMaxmemory == "" {
		return defaultValkeyMaxmemory
	}
	return t.ValkeyMaxmemory
}

// ValkeyMaxmemoryPolicyEff returns the configured eviction policy or the default.
func (t Tuning) ValkeyMaxmemoryPolicyEff() string {
	if t.ValkeyMaxmemoryPolicy == "" {
		return defaultValkeyMaxmemoryPolicy
	}
	return t.ValkeyMaxmemoryPolicy
}

// MariaDBBufferPoolEff returns the configured innodb_buffer_pool_size or the default.
func (t Tuning) MariaDBBufferPoolEff() string {
	if t.MariaDBBufferPool == "" {
		return defaultMariaDBBufferPool
	}
	return t.MariaDBBufferPool
}

// MariaDBLongQueryTimeEff returns the slow-query threshold in seconds or the
// default (2). Non-positive means "unset" (the MaxretryEff precedent). Only
// rendered when MariaDBSlowQueryLog is true.
func (t Tuning) MariaDBLongQueryTimeEff() int {
	if t.MariaDBLongQueryTime <= 0 {
		return defaultMariaDBLongQueryTime
	}
	return t.MariaDBLongQueryTime
}

// phpSizeBytes converts a PHP ini shorthand size — digits with an optional
// K/M/G suffix (1024-based, case-insensitive) — to bytes. Inputs are normally
// pre-guarded by rePHPSize; the error path covers literal-Server callers
// that bypass validation.
func phpSizeBytes(v string) (uint64, error) {
	num, mult := v, uint64(1)
	if len(v) > 0 {
		switch v[len(v)-1] {
		case 'K', 'k':
			num, mult = v[:len(v)-1], 1<<10
		case 'M', 'm':
			num, mult = v[:len(v)-1], 1<<20
		case 'G', 'g':
			num, mult = v[:len(v)-1], 1<<30
		}
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q is not a number with an optional K/M/G suffix", v)
	}
	if n > math.MaxUint64/mult {
		return 0, fmt.Errorf("size %q overflows", v)
	}
	return n * mult, nil
}

// PHPMemoryLimitEff returns the configured FPM memory_limit or the default.
func (t Tuning) PHPMemoryLimitEff() string {
	if t.PHPMemoryLimit == "" {
		return defaultPHPMemoryLimit
	}
	return t.PHPMemoryLimit
}

// PHPUploadMaxEff returns the configured max single-file upload size or the
// default. It renders verbatim as upload_max_filesize; the request-body caps
// (post_max_size, nginx client_max_body_size) derive from it via
// PHPPostBodyMaxEff so a file of exactly this size fits its multipart envelope.
func (t Tuning) PHPUploadMaxEff() string {
	if t.PHPUploadMax == "" {
		return defaultPHPUploadMax
	}
	return t.PHPUploadMax
}

// PHPPostBodyMaxEff returns the derived request-body cap (post_max_size and
// nginx client_max_body_size) as an exact byte count — valid size syntax for
// both PHP ini shorthand and nginx: bytes(upload) + max(2 MiB, 5%).
// Unparsable or out-of-bound values (possible only for literal-Server callers
// that bypass validation) fall back to the default derivation, keeping the
// accessor total and deterministic.
func (t Tuning) PHPPostBodyMaxEff() string {
	b, err := phpSizeBytes(t.PHPUploadMaxEff())
	if err != nil || b == 0 || b > phpSizeMaxBytes {
		b, _ = phpSizeBytes(defaultPHPUploadMax)
	}
	head := b / 20
	if head < phpPostHeadroomMinBytes {
		head = phpPostHeadroomMinBytes
	}
	return strconv.FormatUint(b+head, 10)
}

// PHPMaxExecutionTimeEff returns the configured max_execution_time (seconds)
// or the default. Non-positive means "unset" (the Fail2ban.MaxretryEff precedent).
func (t Tuning) PHPMaxExecutionTimeEff() int {
	if t.PHPMaxExecutionTime <= 0 {
		return defaultPHPMaxExecutionTime
	}
	return t.PHPMaxExecutionTime
}

// PHPMaxInputVarsEff returns the configured max_input_vars or the default.
func (t Tuning) PHPMaxInputVarsEff() int {
	if t.PHPMaxInputVars <= 0 {
		return defaultPHPMaxInputVars
	}
	return t.PHPMaxInputVars
}

// PHPFPMMaxChildrenEff returns the configured per-pool pm.max_children or the
// default (10). Non-positive means unset.
func (t Tuning) PHPFPMMaxChildrenEff() int {
	if t.PHPFPMMaxChildren <= 0 {
		return defaultPHPFPMMaxChildren
	}
	return t.PHPFPMMaxChildren
}

// System holds optional, opt-in host-level OS provisioning knobs. All default
// off: an empty Swap, a false Sysctl and empty Timezone/Hostname mean berth
// never touches swap, kernel sysctl, the system timezone or the hostname.
// Values are constants in the step (no SetDefault), so wizard ToServer() and
// literal-Server callers that bypass Load() need nothing seeded. Unlike Swap,
// clearing Timezone or Hostname drift-removes nothing — both are plain system
// state, so empty means "stop managing", never "revert". BreakGlass, by
// contrast, reconciles BOTH ways (the berth account's posture is fully
// berth-owned): on gives the account a generated console password (cached in
// ~/.berth/<host>.secrets.json — sshd keeps PasswordAuthentication off, so it
// works only at the provider's console/VNC), off locks the password again.
type System struct {
	Swap       string `mapstructure:"swap"        yaml:"swap,omitempty"`        // e.g. "2G"; empty = no swap
	Sysctl     bool   `mapstructure:"sysctl"      yaml:"sysctl,omitempty"`      // default false = no sysctl drop-in
	Timezone   string `mapstructure:"timezone"    yaml:"timezone,omitempty"`    // IANA zone (e.g. Europe/Warsaw); empty = leave untouched
	Hostname   string `mapstructure:"hostname"    yaml:"hostname,omitempty"`    // static hostname; empty = leave untouched
	BreakGlass bool   `mapstructure:"break_glass" yaml:"break_glass,omitempty"` // console password for the berth account; default off = locked
}

// Backups holds the opt-in scheduled-backup knobs. Enabled is off by default
// (a server-wide switch; a per-site sites[].backups *bool overrides it). When
// on, the backups step installs one managed cron + script per site that dumps
// the site database and tars its shared/ dir locally, pruning by age. Retention
// and Schedule fall back to the *Eff accessors' defaults (NOT SetDefault) so
// wizard ToServer() / literal-Server callers that bypass Load() still render
// valid values — an empty schedule would otherwise produce a broken cron line.
type Backups struct {
	Enabled   bool   `mapstructure:"enabled"        yaml:"enabled,omitempty"`
	Retention int    `mapstructure:"retention_days" yaml:"retention_days,omitempty"` // age cutoff for pruning; default 7
	Schedule  string `mapstructure:"schedule"       yaml:"schedule,omitempty"`       // 5-field cron; default "30 3 * * *"
}

const (
	defaultBackupRetentionDays = 7
	defaultBackupSchedule      = "30 3 * * *"
)

// RetentionDaysEff returns the configured retention in days or the default (7).
func (b Backups) RetentionDaysEff() int {
	if b.Retention <= 0 {
		return defaultBackupRetentionDays
	}
	return b.Retention
}

// ScheduleEff returns the configured cron schedule or the default (03:30 daily).
func (b Backups) ScheduleEff() string {
	if b.Schedule == "" {
		return defaultBackupSchedule
	}
	return b.Schedule
}

type Database struct {
	Engine string `mapstructure:"engine" yaml:"engine"` // mariadb | postgres (server-wide)
	Source string `mapstructure:"source" yaml:"source"` // debian | mariadb | pgdg
	// Name/User are legacy single-site fields; multi-site sites carry their own
	// database block. A lone site without a site.database inherits these.
	Name string `mapstructure:"name" yaml:"name,omitempty"`
	User string `mapstructure:"user" yaml:"user,omitempty"`
}

// SiteDatabase is a per-site database name + user (each domain its own DB).
type SiteDatabase struct {
	Name string `mapstructure:"name" yaml:"name"`
	User string `mapstructure:"user" yaml:"user"`
}

// QueueConfig tunes a site's queue worker. nil => the server-default worker
// (when Server.Queue) or none. Driver "" / "work" => queue:work; "horizon" =>
// `artisan horizon` (Horizon manages its own workers; queue:work-only knobs are
// rejected by validation and numprocs is forced to 1).
type QueueConfig struct {
	Driver     string `mapstructure:"driver" yaml:"driver,omitempty"`
	Processes  int    `mapstructure:"processes" yaml:"processes,omitempty"`
	Connection string `mapstructure:"connection" yaml:"connection,omitempty"`
	Queue      string `mapstructure:"queue" yaml:"queue,omitempty"`
	Sleep      int    `mapstructure:"sleep" yaml:"sleep,omitempty"`
	Tries      int    `mapstructure:"tries" yaml:"tries,omitempty"`
	Timeout    int    `mapstructure:"timeout" yaml:"timeout,omitempty"`
	MaxMemory  int    `mapstructure:"max_memory" yaml:"max_memory,omitempty"`
}

// Daemon is an arbitrary long-running Supervisor program (Horizon/Reverb/custom).
// Command is the FULL command, run from <deploy_path>/current.
type Daemon struct {
	Name      string `mapstructure:"name" yaml:"name"`
	Command   string `mapstructure:"command" yaml:"command"`
	Processes int    `mapstructure:"processes" yaml:"processes,omitempty"`
}

type Site struct {
	Domain         string       `mapstructure:"domain" yaml:"domain"`
	DeployPath     string       `mapstructure:"deploy_path" yaml:"deploy_path"`
	User           string       `mapstructure:"user" yaml:"user,omitempty"` // OS user that owns/runs the site; derived from the domain when empty
	Repository     string       `mapstructure:"repository" yaml:"repository,omitempty"`
	SSL            bool         `mapstructure:"ssl" yaml:"ssl"`
	SSLMode        string       `mapstructure:"ssl_mode" yaml:"ssl_mode,omitempty"` // letsencrypt (default) | selfsigned
	SSLEmail       string       `mapstructure:"ssl_email" yaml:"ssl_email,omitempty"`
	HTTP3          bool         `mapstructure:"http3" yaml:"http3"` // HTTP/3 (QUIC); requires ssl + nginx.source: nginx
	Database       SiteDatabase `mapstructure:"database" yaml:"database"`
	Scheduler      *bool        `mapstructure:"scheduler" yaml:"scheduler,omitempty"`             // per-site override; nil = inherit server default
	CloudflareOnly *bool        `mapstructure:"cloudflare_only" yaml:"cloudflare_only,omitempty"` // per-site override; nil = inherit server default
	Backups        *bool        `mapstructure:"backups" yaml:"backups,omitempty"`                 // per-site override; nil = inherit server default
	Queue          *QueueConfig `mapstructure:"queue" yaml:"queue,omitempty"`
	Daemons        []Daemon     `mapstructure:"daemons" yaml:"daemons,omitempty"`
}

// CertMode returns the certificate mode for a site, defaulting to "letsencrypt".
func (st Site) CertMode() string {
	if st.SSLMode == "" {
		return "letsencrypt"
	}
	return st.SSLMode
}

// SiteUser returns the OS user that owns and runs a site. An explicit
// sites[].user wins; otherwise the name is derived from the domain, so every
// site is isolated under its own account regardless of how many sites the
// config lists. (Before v0.18 a lone site implicitly kept a shared "deploy"
// account; pin sites[].user: deploy to keep that identity.)
func (s *Server) SiteUser(site Site) string {
	if site.User != "" {
		return site.User
	}
	return DerivedSiteUser(site.Domain)
}

// SchedulerEnabled reports whether the Laravel scheduler cron should be installed
// for a site: an explicit per-site sites[].scheduler wins; otherwise the
// server-level scheduler default (true by default) applies.
func (s *Server) SchedulerEnabled(site Site) bool {
	if site.Scheduler != nil {
		return *site.Scheduler
	}
	return s.Scheduler
}

// CloudflareOnlyEnabled reports whether origin lockdown applies to a site: an
// explicit per-site sites[].cloudflare_only wins; otherwise the server-level
// default applies. Twin of SchedulerEnabled.
func (s *Server) CloudflareOnlyEnabled(site Site) bool {
	if site.CloudflareOnly != nil {
		return *site.CloudflareOnly
	}
	return s.CloudflareOnly
}

// AnyCloudflareOnly reports whether at least one site resolves to enabled, which
// drives whether the global nginx http-context snippet is written or removed.
func (s *Server) AnyCloudflareOnly() bool {
	for _, site := range s.Sites {
		if s.CloudflareOnlyEnabled(site) {
			return true
		}
	}
	return false
}

// BackupsEnabled reports whether scheduled backups are installed for a site: an
// explicit per-site sites[].backups wins; otherwise the server-level
// backups.enabled default applies. Twin of SchedulerEnabled.
func (s *Server) BackupsEnabled(site Site) bool {
	if site.Backups != nil {
		return *site.Backups
	}
	return s.Backups.Enabled
}

// AnyBackupsEnabled reports whether at least one site resolves to enabled, which
// drives whether the backups step installs prerequisites and the global
// logrotate fragment (vs drift-removing them).
func (s *Server) AnyBackupsEnabled() bool {
	for _, site := range s.Sites {
		if s.BackupsEnabled(site) {
			return true
		}
	}
	return false
}

// PoolName derives the FPM pool / supervisor program slug from a domain
// (filesystem-safe: dots -> underscores). Single source of truth shared by the
// steps package and validation so program names never diverge.
func PoolName(domain string) string { return strings.ReplaceAll(domain, ".", "_") }

// QueueEnabled reports whether a site gets a queue worker: an explicit per-site
// queue block, OR the server-wide Server.Queue default. site.Queue works
// independently of Server.Queue.
func (s *Server) QueueEnabled(site Site) bool { return site.Queue != nil || s.Queue }

// NeedsSupervisor reports whether the supervisor step must run: any site has a
// queue worker or any daemons.
func (s *Server) NeedsSupervisor() bool {
	for _, site := range s.Sites {
		if s.QueueEnabled(site) || len(site.Daemons) > 0 {
			return true
		}
	}
	return false
}

// SiteProgramNames returns the Supervisor program names a site owns, worker
// first: "berth-<pool>" iff QueueEnabled, then "berth-<pool>-<name>" per daemon.
// THE single source of truth for program naming.
func (s *Server) SiteProgramNames(site Site) []string {
	pool := PoolName(site.Domain)
	var names []string
	if s.QueueEnabled(site) {
		names = append(names, "berth-"+pool)
	}
	for _, d := range site.Daemons {
		names = append(names, "berth-"+pool+"-"+d.Name)
	}
	return names
}

// SiteDBName / SiteDBUser return the per-site database name and user, inheriting
// the legacy top-level database.name/user when a lone site omits its own block.
func (s *Server) SiteDBName(site Site) string {
	if site.Database.Name != "" {
		return site.Database.Name
	}
	return s.Database.Name
}

func (s *Server) SiteDBUser(site Site) string {
	if site.Database.User != "" {
		return site.Database.User
	}
	return s.Database.User
}

// DerivedSiteUser builds a Linux-valid, collision-resistant username from a
// domain: "b_" + a sanitized domain prefix + "_" + an 8-hex fnv hash, lowercased
// and capped at 32 characters. Stable across runs (deterministic hash).
func DerivedSiteUser(domain string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(domain))
	suffix := fmt.Sprintf("%08x", h.Sum32())
	var b strings.Builder
	for _, c := range strings.ToLower(domain) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	slug := b.String()
	if max := 32 - len("b_") - len("_") - len(suffix); len(slug) > max {
		slug = slug[:max]
	}
	return "b_" + slug + "_" + suffix
}

type Server struct {
	Host           string   `mapstructure:"host" yaml:"host"`
	SSH            SSH      `mapstructure:"ssh" yaml:"ssh"`
	PHP            PHP      `mapstructure:"php" yaml:"php"`
	Nginx          Nginx    `mapstructure:"nginx" yaml:"nginx"`
	Database       Database `mapstructure:"database" yaml:"database"`
	Valkey         bool     `mapstructure:"valkey" yaml:"valkey"`
	Queue          bool     `mapstructure:"queue" yaml:"queue"`
	Scheduler      bool     `mapstructure:"scheduler" yaml:"scheduler"`
	CloudflareOnly bool     `mapstructure:"cloudflare_only" yaml:"cloudflare_only"`
	Fail2ban       Fail2ban `mapstructure:"fail2ban" yaml:"fail2ban,omitempty"`
	Tuning         Tuning   `mapstructure:"tuning" yaml:"tuning,omitempty"`
	System         System   `mapstructure:"system" yaml:"system,omitempty"`
	Backups        Backups  `mapstructure:"backups" yaml:"backups,omitempty"`
	Sites          []Site   `mapstructure:"sites" yaml:"sites"`
}

// Load reads a YAML config file, applies defaults, and validates it.
func Load(path string) (*Server, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetDefault("ssh.port", 22)
	v.SetDefault("ssh.user", "root")
	v.SetDefault("php.source", "auto")
	v.SetDefault("nginx.source", "debian")
	v.SetDefault("database.source", "debian")
	v.SetDefault("scheduler", true)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var s Server
	if err := v.Unmarshal(&s, viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
		stringToQueueConfigHook,
	))); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &s, nil
}

// stringToQueueConfigHook lets a bare string (e.g. `queue: horizon`) decode into
// a QueueConfig{Driver: <string>}. It fires only for string sources whose target
// is QueueConfig or *QueueConfig; map sources (`queue: {…}`) fall through.
func stringToQueueConfigHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	if f.Kind() != reflect.String {
		return data, nil
	}
	if t == reflect.TypeOf(QueueConfig{}) || t == reflect.TypeOf(&QueueConfig{}) {
		return map[string]interface{}{"driver": data}, nil
	}
	return data, nil
}

// Package config loads and validates per-server berth configuration.
package config

import (
	"fmt"
	"hash/fnv"
	"math"
	"reflect"
	"strconv"
	"strings"

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

// Fail2ban holds the tunable knobs for berth's managed jail.d drop-in.
// bantime and findtime are a number optionally suffixed s/m/h/d/w (e.g. "1h",
// "10m"); compound forms like "1h30m" are not supported. Zero/empty values
// mean "use the default"; defaults live in the *Eff accessors (NOT in Load()
// via SetDefault) so wizard ToServer() and literal Server callers that bypass
// Load() still render valid, non-empty values into the jail drop-in.
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
	Enabled   bool     `mapstructure:"enabled"        yaml:"enabled,omitempty"`
	Retention int      `mapstructure:"retention_days" yaml:"retention_days,omitempty"` // age cutoff for pruning; default 7
	Schedule  string   `mapstructure:"schedule"       yaml:"schedule,omitempty"`       // 5-field cron; default "30 3 * * *"
	Offsite   *Offsite `mapstructure:"offsite"        yaml:"offsite,omitempty"`        // nil = no offsite target
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

// Offsite holds the opt-in offsite-backup target (restic). Nil = offsite off.
// The typed per-backend fields keep the YAML secret-free: cloud credentials
// live in the local secret cache (`berth secret set`) and, on the host, in
// root-owned /etc/berth/offsite.env — never in this struct.
type Offsite struct {
	Backend  string      `mapstructure:"backend"  yaml:"backend"`            // s3 | sftp
	Endpoint string      `mapstructure:"endpoint" yaml:"endpoint,omitempty"` // s3: endpoint host
	Bucket   string      `mapstructure:"bucket"   yaml:"bucket,omitempty"`   // s3
	Prefix   string      `mapstructure:"prefix"   yaml:"prefix,omitempty"`   // s3: default "berth/<id>"
	Host     string      `mapstructure:"host"     yaml:"host,omitempty"`     // sftp
	Port     int         `mapstructure:"port"     yaml:"port,omitempty"`     // sftp: default 22
	User     string      `mapstructure:"user"     yaml:"user,omitempty"`     // sftp
	Path     string      `mapstructure:"path"     yaml:"path,omitempty"`     // sftp: absolute repo dir
	HostKey  string      `mapstructure:"host_key" yaml:"host_key,omitempty"` // sftp: one ssh-keyscan line
	Schedule string      `mapstructure:"schedule" yaml:"schedule,omitempty"` // default "15 4 * * *" — after the local 03:30 backups
	Keep     OffsiteKeep `mapstructure:"keep"     yaml:"keep,omitempty"`
}

// OffsiteKeep is the remote retention policy (restic forget --keep-*).
type OffsiteKeep struct {
	Last    int `mapstructure:"last"    yaml:"last,omitempty"`   // keep the N most recent snapshots (0 = off)
	Hourly  int `mapstructure:"hourly"  yaml:"hourly,omitempty"` // keep one per hour for the last N hours (0 = off)
	Daily   int `mapstructure:"daily"   yaml:"daily,omitempty"`
	Weekly  int `mapstructure:"weekly"  yaml:"weekly,omitempty"`
	Monthly int `mapstructure:"monthly" yaml:"monthly,omitempty"`
}

const (
	defaultOffsiteSchedule    = "15 4 * * *"
	defaultOffsitePort        = 22
	defaultOffsiteKeepDaily   = 7
	defaultOffsiteKeepWeekly  = 4
	defaultOffsiteKeepMonthly = 6
)

// OffsiteEnabled reports whether an offsite target is configured. Validation
// guarantees an enabled offsite always rides on enabled backups.
func (s *Server) OffsiteEnabled() bool { return s.Backups.Offsite != nil }

// PrefixEff returns the configured repo prefix or the id-derived default.
func (o *Offsite) PrefixEff(id string) string {
	if o.Prefix != "" {
		return o.Prefix
	}
	return "berth/" + id
}

// Repository composes the restic repository string from the typed fields.
func (o *Offsite) Repository(id string) string {
	if o.Backend == "sftp" {
		return "sftp:" + o.User + "@" + o.Host + ":" + o.Path
	}
	return "s3:https://" + o.Endpoint + "/" + o.Bucket + "/" + o.PrefixEff(id)
}

// PortEff returns the configured sftp port or 22.
func (o *Offsite) PortEff() int {
	if o.Port == 0 {
		return defaultOffsitePort
	}
	return o.Port
}

// KnownHostsToken is the canonical first field OpenSSH looks up in a
// known_hosts file for this target: the bare host on port 22,
// "[host]:port" otherwise. host_key must pin exactly this token, or the
// pin would not match the actual connection.
func (o *Offsite) KnownHostsToken() string {
	if o.PortEff() == defaultOffsitePort {
		return o.Host
	}
	return fmt.Sprintf("[%s]:%d", o.Host, o.PortEff())
}

// ScheduleEff returns the configured cron schedule or the default (04:15
// daily — deliberately after the local backups' 03:30 default).
func (o *Offsite) ScheduleEff() string {
	if o.Schedule == "" {
		return defaultOffsiteSchedule
	}
	return o.Schedule
}

// DailyEff / WeeklyEff / MonthlyEff return the keep policy or its defaults.
func (k OffsiteKeep) DailyEff() int {
	if k.Daily <= 0 {
		return defaultOffsiteKeepDaily
	}
	return k.Daily
}

func (k OffsiteKeep) WeeklyEff() int {
	if k.Weekly <= 0 {
		return defaultOffsiteKeepWeekly
	}
	return k.Weekly
}

func (k OffsiteKeep) MonthlyEff() int {
	if k.Monthly <= 0 {
		return defaultOffsiteKeepMonthly
	}
	return k.Monthly
}

type Database struct {
	Engine string `mapstructure:"engine" yaml:"engine"` // mariadb | postgres (server-wide)
	Source string `mapstructure:"source" yaml:"source"` // debian | mariadb | pgdg
}

// SiteDatabase is a per-site database name + user (each domain its own DB).
type SiteDatabase struct {
	Name string `mapstructure:"name" yaml:"name"`
	User string `mapstructure:"user" yaml:"user"`
}

// QueueConfig tunes a site's queue worker. nil => the server-default worker
// (when Server.Queue) or none. Driver "" / "work" => queue:work; "horizon" =>
// `artisan horizon` (Horizon manages its own workers; queue:work-only knobs are
// rejected by validation and numprocs is forced to 1); "none" => no worker for
// this site even under a server-wide queue: true (every other knob rejected).
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
// CacheKey is the local secret-cache key: the declared server ID when set,
// else the host. The host branch is unreachable for Load-validated configs
// (Validate requires id) and survives for step-level tests and as defense in
// depth against a literal Server that bypassed validation. Every LockCache/
// LoadEnvelope/SaveEnvelope call must go through this — never s.Host directly.
func (s *Server) CacheKey() string {
	if s.ID != "" {
		return s.ID
	}
	return s.Host
}

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

// FROZEN FOREVER (see TestDerivationsAreFrozen): this slug names FPM pools,
// sockets, supervisor programs and systemd units on every live host.
// PoolName derives the FPM pool / supervisor program slug from a domain
// (filesystem-safe: dots -> underscores). Single source of truth shared by the
// steps package and validation so program names never diverge.
func PoolName(domain string) string { return strings.ReplaceAll(domain, ".", "_") }

// FROZEN FOREVER: the on-host name prefixes below root every per-site socket
// and directory berth derives. They live here — not in the steps that write
// them — because validation's domain-length cap is computed from their byte
// lengths (TestDomainCapMatchesPrefixArithmetic) and steps->config is the only
// legal import direction.

// FPMSocketPrefix roots the per-site PHP-FPM unix sockets. Deliberately PHP
// version-independent: the sockets survive a php.version migration, which is
// also why assertPHPVersionExclusive must keep two masters from fighting over
// them.
const FPMSocketPrefix = "/run/php/berth-"

// FPMSocketPath is the per-site PHP-FPM unix socket for a pool slug (one per
// site, each pool running as its own user).
func FPMSocketPath(pool string) string { return FPMSocketPrefix + pool + ".sock" }

// ValkeyRunBase / ValkeyStateBase root every per-site Valkey instance's
// runtime (socket) and state (data) directories. The systemd unit template
// embeds both as literals (RuntimeDirectory=/StateDirectory= plus the
// --unixsocket/--dir arguments) — render-pin tests hold it to these constants.
const (
	ValkeyRunBase   = "/run/berth-valkey"
	ValkeyStateBase = "/var/lib/berth-valkey"
)

// ValkeySocketPath is the per-site Valkey unix socket for a pool slug. Its
// byte length under sun_path is the TIGHTEST budget behind maxSiteDomainLen.
func ValkeySocketPath(pool string) string { return ValkeyRunBase + "/" + pool + "/valkey.sock" }

// DeployKeyPath is the site user's git deploy private key, generated by the
// accounts step; `berth site key` prints the .pub beside it.
func DeployKeyPath(user string) string { return "/home/" + user + "/.ssh/id_ed25519" }

// QueueEnabled reports whether a site gets a queue worker: an explicit
// per-site queue block (driver "none" opts OUT — the only per-site off
// switch against a server-wide queue: true), else the server-wide default.
func (s *Server) QueueEnabled(site Site) bool {
	if site.Queue != nil {
		return site.Queue.Driver != "none"
	}
	return s.Queue
}

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

// SiteWorkerProgram / SiteDaemonProgram derive one program's Supervisor name:
// "berth-<pool>" for the queue worker, "berth-<pool>-<daemon>" per daemon.
// The per-name halves of SiteProgramNames, exported so the steps that render
// and path a SINGLE program (site.go) share the exact derivation the
// list-consuming surfaces (sweep, Check, sudoers) get from the list.
func SiteWorkerProgram(domain string) string { return "berth-" + PoolName(domain) }

func SiteDaemonProgram(domain, daemon string) string {
	return SiteWorkerProgram(domain) + "-" + daemon
}

// SiteProgramNames returns the Supervisor program names a site owns, worker
// first: SiteWorkerProgram iff QueueEnabled, then SiteDaemonProgram per daemon.
// THE single source of truth for program naming.
func (s *Server) SiteProgramNames(site Site) []string {
	var names []string
	if s.QueueEnabled(site) {
		names = append(names, SiteWorkerProgram(site.Domain))
	}
	for _, d := range site.Daemons {
		names = append(names, SiteDaemonProgram(site.Domain, d.Name))
	}
	return names
}

// SiteDBName / SiteDBUser return the per-site database name and user. Every
// site carries its own database block; the pre-release top-level
// database.name/user fallback was removed before the first real deployment.
func (s *Server) SiteDBName(site Site) string { return site.Database.Name }

func (s *Server) SiteDBUser(site Site) string { return site.Database.User }

// FROZEN FOREVER (see TestDerivationsAreFrozen): this name is the OS user
// owning every implicitly-named tenant's files, DB role and dump contents.
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
	if maxSlugLen := 32 - len("b_") - len("_") - len(suffix); len(slug) > maxSlugLen {
		slug = slug[:maxSlugLen]
	}
	return "b_" + slug + "_" + suffix
}

type Server struct {
	// ID is the operator-declared stable identity of the MACHINE (not a
	// display name): the local secret cache is keyed by it, so different
	// machines behind one hostname get separate credential caches and one
	// machine addressed by several configs shares a single cache (give every
	// config of that machine the same id — and, in v1, the same current
	// host:port). Required by Server.Validate (`berth init` generates one);
	// CacheKey's host fallback survives only for pre-id tombstone handling.
	// Immutable once set — the identity step refuses a renamed id (the host
	// tombstone records the owning id) instead of orphaning the cache.
	ID             string   `mapstructure:"id" yaml:"id,omitempty"`
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
	// UnmarshalExact, not Unmarshal: an unknown key must be an error, never a
	// silent default. A typo in a safety-relevant key — cloudflare_only, a
	// backup setting, a per-site policy — would otherwise leave the operator
	// convinced they configured something berth never read. The strictness is
	// cheap while only test configs exist and becomes a breaking change once
	// real ones do, which is why it lands before the first deployment.
	// Exactly one custom hook: the queue string shorthand. No schema field is
	// a time.Duration or []string, and keeping the stock hooks for those
	// types would silently grant any FUTURE such field an alias spelling from
	// day one (comma-split strings for []string, "5s"-style strings for
	// time.Duration).
	if err := v.UnmarshalExact(&s, viper.DecodeHook(stringToQueueConfigHook)); err != nil {
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

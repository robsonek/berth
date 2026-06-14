// Package config loads and validates per-server berth configuration.
package config

import (
	"fmt"
	"hash/fnv"
	"reflect"
	"strings"

	mapstructure "github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type SSH struct {
	User        string `mapstructure:"user" yaml:"user"`
	Port        int    `mapstructure:"port" yaml:"port"`
	Key         string `mapstructure:"key" yaml:"key"`
	Fingerprint string `mapstructure:"fingerprint" yaml:"fingerprint"`
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
// compound forms like "1h30m" are not supported. Zero/empty values mean
// "use the default"; defaults are set in Load().
type Fail2ban struct {
	Bantime  string `mapstructure:"bantime" yaml:"bantime,omitempty"`
	Findtime string `mapstructure:"findtime" yaml:"findtime,omitempty"`
	Maxretry int    `mapstructure:"maxretry" yaml:"maxretry,omitempty"`
}

type Database struct {
	Engine string `mapstructure:"engine" yaml:"engine"` // mariadb | postgres (server-wide)
	Source string `mapstructure:"source" yaml:"source"` // debian | mariadb | pgdg
	// Name/User are legacy single-site fields; multi-site sites carry their own
	// database block. A lone site without a site.database inherits these.
	Name string `mapstructure:"name" yaml:"name"`
	User string `mapstructure:"user" yaml:"user"`
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
	Domain     string       `mapstructure:"domain" yaml:"domain"`
	DeployPath string       `mapstructure:"deploy_path" yaml:"deploy_path"`
	User       string       `mapstructure:"user" yaml:"user"` // OS user that owns/runs the site; derived when empty
	Repository string       `mapstructure:"repository" yaml:"repository"`
	SSL        bool         `mapstructure:"ssl" yaml:"ssl"`
	SSLMode    string       `mapstructure:"ssl_mode" yaml:"ssl_mode"` // letsencrypt (default) | selfsigned
	SSLEmail   string       `mapstructure:"ssl_email" yaml:"ssl_email"`
	HTTP3      bool         `mapstructure:"http3" yaml:"http3"` // HTTP/3 (QUIC); requires ssl + nginx.source: nginx
	Database   SiteDatabase `mapstructure:"database" yaml:"database"`
	Scheduler  *bool        `mapstructure:"scheduler" yaml:"scheduler,omitempty"` // per-site override; nil = inherit server default
	Queue      *QueueConfig `mapstructure:"queue" yaml:"queue,omitempty"`
	Daemons    []Daemon     `mapstructure:"daemons" yaml:"daemons,omitempty"`
}

// CertMode returns the certificate mode for a site, defaulting to "letsencrypt".
func (st Site) CertMode() string {
	if st.SSLMode == "" {
		return "letsencrypt"
	}
	return st.SSLMode
}

// SiteUser returns the OS user that owns and runs a site. An explicit
// sites[].user wins; a single site (legacy single-site config) keeps the shared
// "deploy" account for backward compatibility; otherwise the name is derived
// from the domain so each site of a multi-site server is isolated.
func (s *Server) SiteUser(site Site) string {
	if site.User != "" {
		return site.User
	}
	if len(s.Sites) == 1 {
		return "deploy"
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
	Host      string   `mapstructure:"host" yaml:"host"`
	SSH       SSH      `mapstructure:"ssh" yaml:"ssh"`
	PHP       PHP      `mapstructure:"php" yaml:"php"`
	Nginx     Nginx    `mapstructure:"nginx" yaml:"nginx"`
	Database  Database `mapstructure:"database" yaml:"database"`
	Valkey    bool     `mapstructure:"valkey" yaml:"valkey"`
	Queue     bool     `mapstructure:"queue" yaml:"queue"`
	Scheduler bool     `mapstructure:"scheduler" yaml:"scheduler"`
	Fail2ban  Fail2ban `mapstructure:"fail2ban" yaml:"fail2ban,omitempty"`
	Sites     []Site   `mapstructure:"sites" yaml:"sites"`
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
	v.SetDefault("fail2ban.bantime", "1h")
	v.SetDefault("fail2ban.findtime", "10m")
	v.SetDefault("fail2ban.maxretry", 5)
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

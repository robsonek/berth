// Package config loads and validates per-server berth configuration.
package config

import (
	"fmt"
	"hash/fnv"
	"strings"

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

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var s Server
	if err := v.Unmarshal(&s); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &s, nil
}

// Package config loads and validates per-server berth configuration.
package config

import (
	"fmt"

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

type Database struct {
	Engine string `mapstructure:"engine" yaml:"engine"` // mariadb
	Name   string `mapstructure:"name" yaml:"name"`
	User   string `mapstructure:"user" yaml:"user"`
}

type Site struct {
	Domain     string `mapstructure:"domain" yaml:"domain"`
	DeployPath string `mapstructure:"deploy_path" yaml:"deploy_path"`
	Repository string `mapstructure:"repository" yaml:"repository"`
	SSL        bool   `mapstructure:"ssl" yaml:"ssl"`
	SSLEmail   string `mapstructure:"ssl_email" yaml:"ssl_email"`
}

type Server struct {
	Host      string   `mapstructure:"host" yaml:"host"`
	SSH       SSH      `mapstructure:"ssh" yaml:"ssh"`
	PHP       PHP      `mapstructure:"php" yaml:"php"`
	Database  Database `mapstructure:"database" yaml:"database"`
	Valkey    bool     `mapstructure:"valkey" yaml:"valkey"`
	Queue     bool     `mapstructure:"queue" yaml:"queue"`
	Scheduler bool     `mapstructure:"scheduler" yaml:"scheduler"`
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

// Package config loads and validates per-server berth configuration.
package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type SSH struct {
	User        string `mapstructure:"user"`
	Port        int    `mapstructure:"port"`
	Key         string `mapstructure:"key"`
	Fingerprint string `mapstructure:"fingerprint"`
}

type PHP struct {
	Version string `mapstructure:"version"`
	Source  string `mapstructure:"source"` // auto | sury | debian
}

type Database struct {
	Engine string `mapstructure:"engine"` // mariadb
	Name   string `mapstructure:"name"`
	User   string `mapstructure:"user"`
}

type Site struct {
	Domain     string `mapstructure:"domain"`
	DeployPath string `mapstructure:"deploy_path"`
	Repository string `mapstructure:"repository"`
	SSL        bool   `mapstructure:"ssl"`
	SSLEmail   string `mapstructure:"ssl_email"`
}

type Server struct {
	Host      string   `mapstructure:"host"`
	SSH       SSH      `mapstructure:"ssh"`
	PHP       PHP      `mapstructure:"php"`
	Database  Database `mapstructure:"database"`
	Valkey    bool     `mapstructure:"valkey"`
	Queue     bool     `mapstructure:"queue"`
	Scheduler bool     `mapstructure:"scheduler"`
	Sites     []Site   `mapstructure:"sites"`
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

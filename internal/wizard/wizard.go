// Package wizard builds a server config interactively and serializes it.
package wizard

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/robsonek/berth/internal/config"
	"gopkg.in/yaml.v3"
)

// Answers is the flat set of values the huh form collects.
type Answers struct {
	Name       string
	Host       string
	Port       int
	Key        string
	PHPVersion string
	PHPSource  string
	DBName     string
	DBUser     string
	Valkey     bool
	Queue      bool
	Scheduler  bool
	Domain     string
	DeployPath string
	Repository string
	SSL        bool
	SSLEmail   string
}

// ToServer maps validated answers into a config.Server.
func (a Answers) ToServer() *config.Server {
	return &config.Server{
		Host:     a.Host,
		SSH:      config.SSH{User: "root", Port: a.Port, Key: a.Key},
		PHP:      config.PHP{Version: a.PHPVersion, Source: a.PHPSource},
		Database: config.Database{Engine: "mariadb", Name: a.DBName, User: a.DBUser},
		Valkey:   a.Valkey, Queue: a.Queue, Scheduler: a.Scheduler,
		Sites: []config.Site{{
			Domain: a.Domain, DeployPath: a.DeployPath, Repository: a.Repository,
			SSL: a.SSL, SSLEmail: a.SSLEmail,
		}},
	}
}

// Write validates the server and writes servers/<name>.yml (refusing to clobber).
func (a Answers) Write() (string, error) {
	srv := a.ToServer()
	if err := srv.Validate(); err != nil {
		return "", err
	}
	if err := os.MkdirAll("servers", 0o755); err != nil {
		return "", err
	}
	path := filepath.Join("servers", a.Name+".yml")
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("%s already exists; refusing to overwrite", path)
	}
	b, err := yaml.Marshal(srv)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

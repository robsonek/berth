// Package wizard builds a server config interactively and serializes it.
package wizard

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"charm.land/huh/v2"
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

// Run presents the interactive form and returns the collected answers.
func Run() (Answers, error) {
	a := Answers{Port: 22, PHPVersion: "8.5", PHPSource: "auto", Key: "~/.ssh/id_ed25519"}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Config name").Value(&a.Name).Validate(required("config name")),
			huh.NewInput().Title("Host (IP)").Value(&a.Host).Validate(validHostname("host")),
			huh.NewInput().Title("SSH key path").Value(&a.Key).Validate(required("SSH key path")),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("PHP version").
				Options(huh.NewOptions("8.5", "8.4", "8.3", "8.2")...).Value(&a.PHPVersion),
			huh.NewSelect[string]().Title("PHP source").
				Options(huh.NewOptions("auto", "sury", "debian")...).Value(&a.PHPSource),
		),
		huh.NewGroup(
			huh.NewInput().Title("Database name").Value(&a.DBName).Validate(validSQLIdent("database name")),
			huh.NewInput().Title("Database user").Value(&a.DBUser).Validate(validSQLIdent("database user")),
			huh.NewConfirm().Title("Install Valkey?").Value(&a.Valkey),
			huh.NewConfirm().Title("Queue worker (Supervisor)?").Value(&a.Queue),
			huh.NewConfirm().Title("Scheduler (cron)?").Value(&a.Scheduler),
		),
		huh.NewGroup(
			huh.NewInput().Title("Domain").Value(&a.Domain).Validate(validHostname("domain")),
			huh.NewInput().Title("Deploy path").Value(&a.DeployPath).Validate(validDeployPath),
			huh.NewInput().Title("Repository (optional)").Value(&a.Repository),
			huh.NewConfirm().Title("Enable TLS (Let's Encrypt)?").Value(&a.SSL),
			huh.NewInput().Title("TLS email").Value(&a.SSLEmail).Validate(validTLSEmail(&a.SSL)),
		),
	)
	if err := form.Run(); err != nil {
		return Answers{}, err
	}
	return a, nil
}

// The validators below mirror config.Server.Validate for inline feedback as the
// user types; config.Server.Validate remains the authoritative gate in Write.
var (
	reHostname = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	reSQLIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	reEmail    = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
)

func required(field string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
}

func validHostname(field string) func(string) error {
	return func(s string) error {
		if !reHostname.MatchString(s) {
			return fmt.Errorf("%s %q is not a valid hostname or IP", field, s)
		}
		return nil
	}
}

func validSQLIdent(field string) func(string) error {
	return func(s string) error {
		if !reSQLIdent.MatchString(s) {
			return fmt.Errorf("%s %q is not a valid SQL identifier", field, s)
		}
		return nil
	}
}

func validDeployPath(s string) error {
	// Deploy paths target the remote Debian server, so use POSIX path
	// semantics (path.IsAbs) to match config.Site.validate.
	if !path.IsAbs(s) || strings.ContainsAny(s, " ;&|$`\n\t") {
		return fmt.Errorf("deploy path %q must be absolute without shell metacharacters", s)
	}
	return nil
}

// validTLSEmail requires a valid address only when TLS is enabled.
func validTLSEmail(ssl *bool) func(string) error {
	return func(s string) error {
		if !*ssl {
			return nil
		}
		if !reEmail.MatchString(s) {
			return fmt.Errorf("TLS email %q is not a valid email address", s)
		}
		return nil
	}
}

// ToServer maps validated answers into a config.Server.
func (a Answers) ToServer() *config.Server {
	return &config.Server{
		Host:     a.Host,
		SSH:      config.SSH{User: "root", Port: a.Port, Key: a.Key},
		PHP:      config.PHP{Version: a.PHPVersion, Source: a.PHPSource},
		Nginx:    config.Nginx{Source: "debian"},
		Database: config.Database{Engine: "mariadb", Name: a.DBName, User: a.DBUser, Source: "debian"},
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

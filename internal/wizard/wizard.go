// Package wizard builds a server config interactively and serializes it.
//
// The wizard collects every supported feature combination (multi-site,
// postgres+pgdg, nginx.org upstream, self-signed/HTTP3 TLS, per-site
// queue/daemons/scheduler, fail2ban + tuning, optional ssh.fingerprint pinning)
// with progressive disclosure and incremental validation.
//
// All TTY I/O (huh forms) lives behind the prompter interface (prompter.go) so
// the orchestration in run.go is exercised with a scripted fake. Normalization
// is a pure Answers.ToServer() mapping (toserver.go) proven by round-trip
// Write -> config.Load tests; config.Server.Validate() stays authoritative.
package wizard

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Answers is the data the wizard collects: server-level fields plus one or more sites.
type Answers struct {
	Name string // -> servers/<Name>.yml

	// connection
	Host        string
	SSHUser     string
	Port        int
	Key         string
	Fingerprint string // "" => omitted (TOFU)

	// server runtime
	PHPVersion  string
	PHPSource   string
	DBEngine    string // mariadb | postgres
	DBSource    string // debian | mariadb | pgdg (paired with engine)
	NginxSource string // debian | nginx
	Valkey      bool
	Queue       bool // server-wide default worker
	Scheduler   bool // server-wide default

	// server advanced (zero unless the gate is taken)
	Fail2ban Fail2banAnswers
	Tuning   TuningAnswers

	Sites []SiteAnswers
}

type Fail2banAnswers struct {
	Bantime  string
	Findtime string
	Maxretry int
}

type TuningAnswers struct {
	ValkeyMaxmemory       string
	ValkeyMaxmemoryPolicy string
	MariaDBBufferPool     string
}

type SiteAnswers struct {
	Domain     string
	DeployPath string
	User       string // "" => derived (or "deploy" for a single site)
	DBName     string
	DBUser     string
	Repository string
	SSL        bool
	SSLMode    string // letsencrypt | selfsigned (only meaningful when SSL)
	SSLEmail   string
	HTTP3      bool

	// site advanced
	SchedulerOverride string        // "inherit" | "on" | "off"
	Queue             *QueueAnswers // nil => inherit server-wide
	Daemons           []DaemonAnswers
}

type QueueAnswers struct {
	Driver     string // "" | "work" | "horizon"
	Processes  int
	Connection string
	Queue      string
	Sleep      int
	Tries      int
	Timeout    int
	MaxMemory  int
}

type DaemonAnswers struct {
	Name      string
	Command   string
	Processes int
}

// defaults returns an Answers pre-seeded with berth's conventional defaults so the
// huh forms (and the fake prompter) start from a valid, idiomatic baseline.
func defaults() Answers {
	return Answers{
		SSHUser: "root", Port: 22, Key: "~/.ssh/id_ed25519",
		PHPVersion: "8.5", PHPSource: "auto",
		DBEngine: "mariadb", DBSource: "debian",
		NginxSource: "debian",
		Scheduler:   true,
	}
}

// Run presents the interactive wizard and returns the collected answers.
func Run() (Answers, error) { return run(newHuhPrompter()) }

// Write validates the answers and writes servers/<name>.yml, refusing to clobber.
func (a Answers) Write() (string, error) {
	if err := required("config name")(a.Name); err != nil {
		return "", err
	}
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

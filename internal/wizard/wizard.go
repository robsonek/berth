// Package wizard builds a server config interactively and serializes it.
//
// The wizard collects every supported feature combination (multi-site,
// postgres+pgdg, nginx.org upstream, self-signed/HTTP3 TLS, per-site
// queue/daemons/scheduler, fail2ban + tuning, extra apt repos + packages,
// optional ssh.fingerprint pinning) with progressive disclosure and
// incremental validation.
//
// All TTY I/O (huh forms) lives behind the prompter interface (prompter.go) so
// the orchestration in run.go is exercised with a scripted fake. Normalization
// is a pure Answers.ToServer() mapping (toserver.go) proven by round-trip
// Write -> config.Load tests; config.Server.Validate() stays authoritative.
package wizard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/robsonek/berth/internal/secret"
	"gopkg.in/yaml.v3"
)

// Answers is the data the wizard collects: server-level fields plus one or more sites.
type Answers struct {
	// ID is the stable machine identity written as the config's top-level
	// `id` (secret-cache key). Blank at the prompt = auto-generated after
	// the core form from the config name + crypto/rand suffix.
	ID   string
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

	System         SystemAnswers
	Backups        BackupsAnswers
	CloudflareOnly bool // server-wide origin-lockdown default

	// server-level extras
	AptRepos    []AptRepoAnswers
	AptPackages string // space-separated; "" = none

	Sites []SiteAnswers
}

// AptRepoAnswers collects one user-declared apt repository (config apt.repos
// entry). Components is a space-separated string ("" = main) because huh
// inputs are strings; ToServer splits it.
type AptRepoAnswers struct {
	Name        string
	URI         string
	Suite       string
	Components  string
	KeyURL      string
	Fingerprint string
}

type Fail2banAnswers struct {
	Bantime  string
	Findtime string
	Maxretry int
}

type TuningAnswers struct {
	ValkeyMaxmemory         string
	ValkeyMaxmemoryPolicy   string
	MariaDBBufferPool       string
	MariaDBSlowQueryLog     bool
	MariaDBLongQueryTime    int
	MariaDBLogFileSize      string
	MariaDBTmpTableSize     string
	MariaDBMaxConnections   int
	MariaDBMaxAllowedPacket string
	PHPMemoryLimit          string
	PHPUploadMax            string
	PHPMaxExecutionTime     int
	PHPMaxInputVars         int
	PHPFPMMaxChildren       int
}

type SystemAnswers struct {
	Swap       string // e.g. "2G"; blank = no swap
	Sysctl     bool
	Timezone   string // IANA zone; blank = leave untouched
	Hostname   string // static hostname; blank = leave untouched
	BreakGlass bool   // console password for the berth account; default off
}

type BackupsAnswers struct {
	Enabled       bool
	RetentionDays int    // 0 = default (7)
	Schedule      string // blank = default ("30 3 * * *")
	Offsite       OffsiteAnswers
}

// OffsiteAnswers mirrors config.Offsite for the wizard: WHERE the restic
// repository lives. Credentials are deliberately NOT asked here — the wizard
// prints the `berth secret set` recipe instead (secret-free YAML contract).
type OffsiteAnswers struct {
	Enabled  bool
	Backend  string // s3 | sftp
	Endpoint string // s3
	Bucket   string // s3
	Prefix   string // s3; blank = default <id>
	Host     string // sftp
	Port     int    // sftp; 0 = 22
	User     string // sftp
	Path     string // sftp
	HostKey  string // sftp: one ssh-keyscan line
	Schedule string // blank = default "15 4 * * *"

	KeepLast, KeepHourly               int // 0 = off (sub-daily retention; opt-in)
	KeepDaily, KeepWeekly, KeepMonthly int // 0 = defaults 7/4/6
}

type SiteAnswers struct {
	Domain     string
	DeployPath string
	User       string // "" => ToServer fills in the domain-derived name (YAML stays explicit)
	DBName     string
	DBUser     string
	Repository string
	SSL        bool
	SSLMode    string // letsencrypt | selfsigned (only meaningful when SSL)
	SSLEmail   string
	HTTP3      bool

	// site advanced
	SchedulerOverride  string        // "inherit" | "on" | "off"
	CloudflareOverride string        // "inherit" | "on" | "off"
	BackupsOverride    string        // "inherit" | "on" | "off"
	Queue              *QueueAnswers // nil => inherit server-wide
	Daemons            []DaemonAnswers
}

type QueueAnswers struct {
	Driver     string // "" | "work" | "horizon" | "none"
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

// SecretRecipe returns the operator instructions `berth init` prints after
// writing the config — the secrets that must be seeded into the local cache
// before the first provision run — or "" when none are needed. Only the s3
// backend needs pre-seeded credentials; sftp needs none (the provision run
// itself prints the generated public key to authorize on the target).
func (a Answers) SecretRecipe() string {
	o := a.Backups.Offsite
	if !o.Enabled || o.Backend != "s3" {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nOffsite credentials are never stored in the YAML. Before the first provision run:\n")
	fmt.Fprintf(&b, "  berth secret set servers/%s.yml %s\n", a.Name, secret.OffsiteS3AccessKey)
	fmt.Fprintf(&b, "  berth secret set servers/%s.yml %s\n", a.Name, secret.OffsiteS3SecretKey)
	return b.String()
}

// validConfigName guards the RAW config name shared by the prompt validator
// and the authoritative Write below: the name becomes servers/<name>.yml, so
// path separators, dot-prefixes and a leading dash must never reach
// filepath.Join (which would CLEAN "../x" and hide the escape from any
// post-join check).
func validConfigName(name string) error {
	if !reConfigName.MatchString(name) {
		return fmt.Errorf("config name %q must match [A-Za-z0-9][A-Za-z0-9._-]* (no path separators, no leading dot or dash)", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("config name %q must not contain \"..\"", name)
	}
	return nil
}

var reConfigName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Write validates the answers and writes servers/<name>.yml, refusing to clobber.
func (a Answers) Write() (string, error) {
	if err := validConfigName(a.Name); err != nil {
		return "", err
	}
	srv := a.ToServer()
	if err := srv.Validate(); err != nil {
		return "", err
	}
	// Marshal before touching the filesystem: a render error must not leave
	// an empty file behind.
	b, err := yaml.Marshal(srv)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll("servers", 0o755); err != nil {
		return "", err
	}
	path := filepath.Join("servers", a.Name+".yml")
	// O_EXCL closes the stat->write race two concurrent wizards would hit.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("%s already exists; refusing to overwrite", path)
	}
	if err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(path) // never leave a truncated config behind
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close %s: %w", path, err)
	}
	return path, nil
}

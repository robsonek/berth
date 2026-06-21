package wizard

import (
	"fmt"
	"io"
	"os"
	"strconv"

	huh "charm.land/huh/v2"
	"github.com/robsonek/berth/internal/config"
)

// prompter is the seam between orchestration (run) and I/O. The production
// implementation drives huh forms; tests use a scripted fake. Each method fills
// the pointed-to answers in place so a re-prompt (passing the same struct) shows
// the user's prior entries.
type prompter interface {
	ServerCore(a *Answers) error     // host, ssh, php, db (combined), nginx, valkey, queue, scheduler
	ServerAdvanced(a *Answers) error // fail2ban + tuning
	ServerOps(a *Answers) error      // swap/sysctl, cloudflare-only, backups
	SiteCore(index int, sa *SiteAnswers) error
	SiteOverrides(sa *SiteAnswers) error // scheduler + cloudflare + backups overrides (inherit/on/off)
	Queue(q *QueueAnswers) error
	Daemon(d *DaemonAnswers) error
	Confirm(prompt string) (bool, error)
	ShowError(err error)
}

type huhPrompter struct{ out io.Writer }

func newHuhPrompter() prompter { return &huhPrompter{out: os.Stderr} }

func (h *huhPrompter) ShowError(err error) { fmt.Fprintf(h.out, "  ✗ %v — please fix it\n", err) }

func (h *huhPrompter) Confirm(prompt string) (bool, error) {
	v := false
	err := huh.NewForm(huh.NewGroup(huh.NewConfirm().Title(prompt).Value(&v))).Run()
	return v, err
}

func (h *huhPrompter) ServerCore(a *Answers) error {
	portStr := strconv.Itoa(a.Port)
	choice := config.DatabaseChoice{Engine: a.DBEngine, Source: a.DBSource}
	dbOpts := make([]huh.Option[config.DatabaseChoice], 0)
	for _, c := range config.DatabaseChoices() {
		dbOpts = append(dbOpts, huh.NewOption(c.Label, c))
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Config name").Value(&a.Name).Validate(required("config name")),
			huh.NewInput().Title("Host (IP or DNS)").Value(&a.Host).Validate(validHostname("host")),
			huh.NewInput().Title("SSH user").Value(&a.SSHUser).Validate(required("ssh user")),
			huh.NewInput().Title("SSH port").Value(&portStr).Validate(validIntField("ssh.port", 1, 65535)),
			huh.NewInput().Title("SSH key path").Value(&a.Key).Validate(required("ssh key")),
			huh.NewInput().Title("Host key fingerprint (optional, SHA256:… ; blank = trust on first use)").
				Value(&a.Fingerprint).Validate(func(s string) error { return config.ValidFingerprint(s) }),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("PHP version").Options(huh.NewOptions("8.5", "8.4", "8.3", "8.2")...).Value(&a.PHPVersion),
			huh.NewSelect[string]().Title("PHP source").Options(huh.NewOptions("auto", "sury", "debian")...).Value(&a.PHPSource),
			huh.NewSelect[config.DatabaseChoice]().Title("Database engine + source").Options(dbOpts...).Value(&choice),
			huh.NewSelect[string]().Title("nginx source").Options(huh.NewOptions("debian", "nginx")...).Value(&a.NginxSource),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("Install Valkey (Redis)?").Value(&a.Valkey),
			huh.NewConfirm().Title("Default queue worker (Supervisor) for all sites?").Value(&a.Queue),
			huh.NewConfirm().Title("Scheduler (cron) on by default?").Value(&a.Scheduler),
		),
	)
	if err := form.Run(); err != nil {
		return err
	}
	// parseIntInRange trims like the validator did, so a padded but accepted port
	// (e.g. " 2222 ") is kept rather than silently dropped to 0 by a raw Atoi.
	a.Port, _ = parseIntInRange("ssh.port", portStr, 1, 65535)
	a.DBEngine, a.DBSource = choice.Engine, choice.Source
	return nil
}

func (h *huhPrompter) ServerAdvanced(a *Answers) error {
	maxretry := strconv.Itoa(a.Fail2ban.Maxretry)
	policies := []string{"", "noeviction", "allkeys-lru", "allkeys-lfu", "allkeys-random", "volatile-lru", "volatile-lfu", "volatile-random", "volatile-ttl"}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("fail2ban bantime (e.g. 1h, blank=default)").Value(&a.Fail2ban.Bantime).Validate(optionalFail2banTime),
			huh.NewInput().Title("fail2ban findtime (e.g. 10m, blank=default)").Value(&a.Fail2ban.Findtime).Validate(optionalFail2banTime),
			huh.NewInput().Title("fail2ban maxretry (1-100, blank/0=default)").Value(&maxretry).Validate(optionalInt("fail2ban.maxretry", 0, 100)),
		),
		huh.NewGroup(
			huh.NewInput().Title("Valkey maxmemory (e.g. 256mb, blank=default)").Value(&a.Tuning.ValkeyMaxmemory).Validate(optionalValkeyMem),
			huh.NewSelect[string]().Title("Valkey eviction policy (blank=default)").Options(huh.NewOptions(policies...)...).Value(&a.Tuning.ValkeyMaxmemoryPolicy),
			huh.NewInput().Title("MariaDB innodb_buffer_pool (e.g. 256M, blank=default)").Value(&a.Tuning.MariaDBBufferPool).Validate(optionalMariaDBSize),
		),
	)
	if err := form.Run(); err != nil {
		return err
	}
	// Trim-safe like the validator (optionalInt); blank/"0" -> 0 = default, an
	// accepted " 5 " -> 5 (a raw Atoi would have dropped it to the default).
	a.Fail2ban.Maxretry, _ = parseIntInRange("fail2ban.maxretry", maxretry, 0, 100)
	return nil
}

func (h *huhPrompter) ServerOps(a *Answers) error {
	retention := strconv.Itoa(a.Backups.RetentionDays)
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Swap file size (e.g. 2G, blank=none)").Value(&a.System.Swap).Validate(optionalSwapSize),
			huh.NewConfirm().Title("Apply conservative kernel sysctl tuning?").Value(&a.System.Sysctl),
			huh.NewConfirm().Title("Cloudflare-only origin lockdown (server default)?").Value(&a.CloudflareOnly),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("Enable nightly local backups (server default)?").Value(&a.Backups.Enabled),
			huh.NewInput().Title("Backup retention days (1-3650, blank/0=default 7)").Value(&retention).Validate(optionalInt("backups.retention_days", 1, 3650)),
			huh.NewInput().Title("Backup schedule (5-field cron, blank=default 30 3 * * *)").Value(&a.Backups.Schedule).Validate(optionalCronSchedule),
		),
	)
	if err := form.Run(); err != nil {
		return err
	}
	// parseIntInRange trims like the validator did, so an accepted " 14 " is kept (not
	// silently dropped by a raw Atoi); blank/"0"/out-of-range return (0, err) => 0 = default.
	a.Backups.RetentionDays, _ = parseIntInRange("backups.retention_days", retention, 1, 3650)
	return nil
}

func (h *huhPrompter) SiteCore(index int, sa *SiteAnswers) error {
	core := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title(fmt.Sprintf("Site #%d", index+1)),
			huh.NewInput().Title("Domain").Value(&sa.Domain).Validate(validHostname("domain")),
			huh.NewInput().Title("Deploy path").Value(&sa.DeployPath).Validate(validDeployPath),
			huh.NewInput().Title("OS user (blank = derived / 'deploy' for single site)").Value(&sa.User).Validate(validOSUser),
			huh.NewInput().Title("Database name").Value(&sa.DBName).Validate(validSQLIdent("database name")),
			huh.NewInput().Title("Database user").Value(&sa.DBUser).Validate(validSQLIdent("database user")),
			huh.NewInput().Title("Git repository (optional, SSH URL)").Value(&sa.Repository),
			huh.NewConfirm().Title("Enable TLS?").Value(&sa.SSL),
		),
	)
	if err := core.Run(); err != nil {
		return err
	}
	if !sa.SSL {
		sa.SSLMode, sa.SSLEmail, sa.HTTP3 = "", "", false
		return nil
	}
	if sa.SSLMode == "" {
		sa.SSLMode = "letsencrypt"
	}
	tls := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Title("Certificate mode").Options(huh.NewOptions("letsencrypt", "selfsigned")...).Value(&sa.SSLMode),
			huh.NewInput().Title("Let's Encrypt email (required for letsencrypt)").Value(&sa.SSLEmail).Validate(validTLSEmail(&sa.SSL, &sa.SSLMode)),
			huh.NewConfirm().Title("Enable HTTP/3 (QUIC)? (needs nginx.org)").Value(&sa.HTTP3),
		),
	)
	return tls.Run()
}

func (h *huhPrompter) SiteOverrides(sa *SiteAnswers) error {
	return huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().Title("Scheduler for this site").
			Options(huh.NewOptions("inherit", "on", "off")...).Value(&sa.SchedulerOverride),
		huh.NewSelect[string]().Title("Cloudflare-only for this site").
			Options(huh.NewOptions("inherit", "on", "off")...).Value(&sa.CloudflareOverride),
		huh.NewSelect[string]().Title("Backups for this site").
			Options(huh.NewOptions("inherit", "on", "off")...).Value(&sa.BackupsOverride),
	)).Run()
}

func (h *huhPrompter) Queue(q *QueueAnswers) error {
	if q.Driver == "" {
		q.Driver = "work"
	}
	procs := "1"
	driverForm := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().Title("Queue driver").Options(huh.NewOptions("work", "horizon")...).Value(&q.Driver),
	))
	if err := driverForm.Run(); err != nil {
		return err
	}
	if q.Driver == "horizon" {
		// Horizon manages its own workers; leave the work-only knobs zero.
		return nil
	}
	tries, timeout := "3", "60"
	sleep, maxmem := "3", "0"
	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Processes (1-64)").Value(&procs).Validate(validIntField("processes", 1, 64)),
		huh.NewInput().Title("Connection (blank=default)").Value(&q.Connection),
		huh.NewInput().Title("Queue name (blank=default)").Value(&q.Queue),
		huh.NewInput().Title("Tries").Value(&tries).Validate(validIntField("tries", 0, 1000)),
		huh.NewInput().Title("Timeout (s)").Value(&timeout).Validate(validIntField("timeout", 0, 86400)),
		huh.NewInput().Title("Sleep (s when no job)").Value(&sleep).Validate(validIntField("sleep", 0, 86400)),
		huh.NewInput().Title("Max memory (MB, 0 = unlimited)").Value(&maxmem).Validate(validIntField("max_memory", 0, 4096)),
	))
	if err := form.Run(); err != nil {
		return err
	}
	q.Processes, _ = strconv.Atoi(procs)
	q.Tries, _ = strconv.Atoi(tries)
	q.Timeout, _ = strconv.Atoi(timeout)
	q.Sleep, _ = strconv.Atoi(sleep)
	q.MaxMemory, _ = strconv.Atoi(maxmem)
	return nil
}

func (h *huhPrompter) Daemon(d *DaemonAnswers) error {
	procs := "1"
	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Daemon name (a-z0-9-)").Value(&d.Name).Validate(validDaemonName),
		huh.NewInput().Title("Command (run from <deploy>/current)").Value(&d.Command).Validate(required("command")),
		huh.NewInput().Title("Processes (1-64)").Value(&procs).Validate(validIntField("processes", 1, 64)),
	))
	if err := form.Run(); err != nil {
		return err
	}
	d.Processes, _ = strconv.Atoi(procs)
	return nil
}

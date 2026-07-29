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
	ServerOps(a *Answers) error      // swap/sysctl, cloudflare-only, apt packages, backups
	SiteCore(index int, sa *SiteAnswers) error
	SiteOverrides(sa *SiteAnswers) error // scheduler + cloudflare + backups overrides (inherit/on/off)
	Queue(q *QueueAnswers) error
	Daemon(d *DaemonAnswers) error
	AptRepo(ar *AptRepoAnswers) error
	Confirm(prompt string) (bool, error)
	ShowError(err error)
}

type huhPrompter struct{ out io.Writer }

func newHuhPrompter() prompter { return &huhPrompter{out: os.Stderr} }

func (h *huhPrompter) ShowError(err error) {
	_, _ = fmt.Fprintf(h.out, "  ✗ %v — please fix it\n", err)
}

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
			huh.NewInput().Title("Config name").Value(&a.Name).Validate(validConfigName),
			huh.NewInput().Title("Server id (stable machine identity; blank = auto-generate)").
				Value(&a.ID).Validate(config.ValidateServerID),
			huh.NewInput().Title("Host (IP or DNS)").Value(&a.Host).Validate(validHostname("host")),
			huh.NewInput().Title("SSH user").Value(&a.SSHUser).Validate(required("ssh user")),
			huh.NewInput().Title("SSH port").Value(&portStr).Validate(validIntField("ssh.port", 1, 65535)),
			huh.NewInput().Title("SSH key path").Value(&a.Key).Validate(required("ssh key")),
			huh.NewInput().Title("Host key fingerprint (optional, SHA256:… ; blank = trust on first use)").
				Value(&a.Fingerprint).Validate(config.ValidFingerprint),
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
	execTime := strconv.Itoa(a.Tuning.PHPMaxExecutionTime)
	inputVars := strconv.Itoa(a.Tuning.PHPMaxInputVars)
	longQuery := strconv.Itoa(a.Tuning.MariaDBLongQueryTime)
	maxConns := strconv.Itoa(a.Tuning.MariaDBMaxConnections)
	maxChildren := strconv.Itoa(a.Tuning.PHPFPMMaxChildren)
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
			huh.NewConfirm().Title("MariaDB slow query log?").Value(&a.Tuning.MariaDBSlowQueryLog),
			huh.NewInput().Title("MariaDB long_query_time (1-86400 s, blank/0=default 2; needs the slow log on)").Value(&longQuery).Validate(optionalInt("tuning.mariadb_long_query_time", 1, 86400)),
			huh.NewInput().Title("MariaDB innodb_log_file_size (4M-512G, e.g. 1G, blank=engine default 96M)").Value(&a.Tuning.MariaDBLogFileSize).Validate(optionalMariaDBLogSize),
			huh.NewInput().Title("MariaDB tmp_table_size + max_heap_table_size (e.g. 128M, blank=engine default 16M)").Value(&a.Tuning.MariaDBTmpTableSize).Validate(optionalMariaDBSize),
			huh.NewInput().Title("MariaDB max_connections (10-100000, blank/0=engine default 151)").Value(&maxConns).Validate(optionalInt("tuning.mariadb_max_connections", 10, 100000)),
			huh.NewInput().Title("MariaDB max_allowed_packet (e.g. 64M, max 1G, blank=engine default 16M)").Value(&a.Tuning.MariaDBMaxAllowedPacket).Validate(optionalMariaDBPacket),
		),
		huh.NewGroup(
			huh.NewInput().Title("PHP memory_limit (e.g. 256M, blank=default)").Value(&a.Tuning.PHPMemoryLimit).Validate(optionalPHPSize),
			huh.NewInput().Title("PHP max upload file size, body caps derived (e.g. 32M, blank=default)").Value(&a.Tuning.PHPUploadMax).Validate(optionalPHPSize),
			huh.NewInput().Title("PHP max_execution_time (1-300 s, blank/0=default)").Value(&execTime).Validate(optionalInt("tuning.php_max_execution_time", 1, 300)),
			huh.NewInput().Title("PHP max_input_vars (1-1000000, blank/0=default)").Value(&inputVars).Validate(optionalInt("tuning.php_max_input_vars", 1, 1000000)),
			huh.NewInput().Title("PHP-FPM pm.max_children per site pool (4-10000, blank/0=default 10)").Value(&maxChildren).Validate(optionalInt("tuning.php_fpm_max_children", 4, 10000)),
		),
	)
	if err := form.Run(); err != nil {
		return err
	}
	// Trim-safe like the validator (optionalInt); blank/"0" -> 0 = default, an
	// accepted " 5 " -> 5 (a raw Atoi would have dropped it to the default).
	a.Fail2ban.Maxretry, _ = parseIntInRange("fail2ban.maxretry", maxretry, 0, 100)
	a.Tuning.PHPMaxExecutionTime, _ = parseIntInRange("tuning.php_max_execution_time", execTime, 1, 300)
	a.Tuning.PHPMaxInputVars, _ = parseIntInRange("tuning.php_max_input_vars", inputVars, 1, 1000000)
	a.Tuning.MariaDBLongQueryTime, _ = parseIntInRange("tuning.mariadb_long_query_time", longQuery, 1, 86400)
	a.Tuning.MariaDBMaxConnections, _ = parseIntInRange("tuning.mariadb_max_connections", maxConns, 10, 100000)
	a.Tuning.PHPFPMMaxChildren, _ = parseIntInRange("tuning.php_fpm_max_children", maxChildren, 4, 10000)
	return nil
}

func (h *huhPrompter) ServerOps(a *Answers) error {
	retention := strconv.Itoa(a.Backups.RetentionDays)
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Swap file size (e.g. 2G, blank=none)").Value(&a.System.Swap).Validate(optionalSwapSize),
			huh.NewInput().Title("System timezone (e.g. Europe/Warsaw, blank=leave untouched)").Value(&a.System.Timezone).Validate(optionalTimezone),
			huh.NewInput().Title("System hostname (blank=leave untouched)").Value(&a.System.Hostname).Validate(optionalSystemHostname),
			huh.NewConfirm().Title("Break-glass console password for the berth account? (saved to ~/.berth/<name>.secrets.json)").Value(&a.System.BreakGlass),
			huh.NewConfirm().Title("Apply conservative kernel sysctl tuning?").Value(&a.System.Sysctl),
			huh.NewConfirm().Title("Cloudflare-only origin lockdown (server default)?").Value(&a.CloudflareOnly),
			huh.NewInput().Title("Extra apt packages (space-separated; blank = none)").Value(&a.AptPackages).Validate(validAptPackages),
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
	// Offsite rides on enabled backups (config rejects it otherwise), so the
	// gate is only reachable here. Credentials are deliberately not prompted:
	// the YAML stays secret-free and `berth init` prints the `berth secret set`
	// recipe instead (Answers.SecretRecipe).
	if !a.Backups.Enabled {
		return nil
	}
	o := &a.Backups.Offsite
	gate := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().Title("Ship backups offsite (restic)?").Value(&o.Enabled),
	))
	if err := gate.Run(); err != nil {
		return err
	}
	if !o.Enabled {
		return nil
	}
	if o.Backend == "" {
		o.Backend = "s3"
	}
	backend := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().Title("Offsite backend").Options(huh.NewOptions("s3", "sftp")...).Value(&o.Backend),
	))
	if err := backend.Run(); err != nil {
		return err
	}
	// ServerOps has no re-prompt loop (run.go's site loop re-prompts only the
	// site), so every input below must be inline-valid on its own — the
	// validators mirror config's offsite rules field for field.
	switch o.Backend {
	case "s3":
		s3 := huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("S3 endpoint host (e.g. s3.eu-central-1.amazonaws.com)").Value(&o.Endpoint).Validate(offsiteWord("backups.offsite.endpoint", true)),
			huh.NewInput().Title("S3 bucket").Value(&o.Bucket).Validate(offsiteWord("backups.offsite.bucket", true)),
			huh.NewInput().Title("Repository prefix (blank = default <id>)").Value(&o.Prefix).Validate(offsiteWord("backups.offsite.prefix", false)),
		))
		if err := s3.Run(); err != nil {
			return err
		}
	case "sftp":
		port := strconv.Itoa(o.Port)
		target := huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("SFTP host").Value(&o.Host).Validate(validOffsiteHost),
			huh.NewInput().Title("SFTP port (blank/0 = 22)").Value(&port).Validate(optionalInt("backups.offsite.port", 1, 65535)),
			huh.NewInput().Title("SFTP user").Value(&o.User).Validate(validOffsiteUser),
			huh.NewInput().Title("Repository path (absolute directory for the restic repo)").Value(&o.Path).Validate(validOffsitePath),
		))
		if err := target.Run(); err != nil {
			return err
		}
		o.Port, _ = parseIntInRange("backups.offsite.port", port, 1, 65535)
		// The host-key form runs AFTER host/port are final so its validator
		// pins the exact known_hosts token config.Validate will demand.
		token := (&config.Offsite{Host: o.Host, Port: o.Port}).KnownHostsToken()
		hostKey := huh.NewForm(huh.NewGroup(
			huh.NewInput().Title(fmt.Sprintf("SFTP host key (one ssh-keyscan line starting with %q)", token)).
				Value(&o.HostKey).Validate(validOffsiteHostKey(token)),
		))
		if err := hostKey.Run(); err != nil {
			return err
		}
	}
	last := strconv.Itoa(o.KeepLast)
	hourly := strconv.Itoa(o.KeepHourly)
	daily := strconv.Itoa(o.KeepDaily)
	weekly := strconv.Itoa(o.KeepWeekly)
	monthly := strconv.Itoa(o.KeepMonthly)
	shared := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Offsite schedule (5-field cron, blank=default 15 4 * * *)").Value(&o.Schedule).Validate(optionalCronSchedule),
		huh.NewInput().Title("Keep last N snapshots (1-3650, blank/0=off)").Value(&last).Validate(optionalInt("backups.offsite.keep.last", 1, 3650)),
		huh.NewInput().Title("Keep one per hour for the last N hours with snapshots (1-3650, blank/0=off)").Value(&hourly).Validate(optionalInt("backups.offsite.keep.hourly", 1, 3650)),
		huh.NewInput().Title("Keep daily snapshots (1-3650, blank/0=default 7)").Value(&daily).Validate(optionalInt("backups.offsite.keep.daily", 1, 3650)),
		huh.NewInput().Title("Keep weekly snapshots (1-3650, blank/0=default 4)").Value(&weekly).Validate(optionalInt("backups.offsite.keep.weekly", 1, 3650)),
		huh.NewInput().Title("Keep monthly snapshots (1-3650, blank/0=default 6)").Value(&monthly).Validate(optionalInt("backups.offsite.keep.monthly", 1, 3650)),
	))
	if err := shared.Run(); err != nil {
		return err
	}
	o.KeepLast, _ = parseIntInRange("backups.offsite.keep.last", last, 1, 3650)
	o.KeepHourly, _ = parseIntInRange("backups.offsite.keep.hourly", hourly, 1, 3650)
	o.KeepDaily, _ = parseIntInRange("backups.offsite.keep.daily", daily, 1, 3650)
	o.KeepWeekly, _ = parseIntInRange("backups.offsite.keep.weekly", weekly, 1, 3650)
	o.KeepMonthly, _ = parseIntInRange("backups.offsite.keep.monthly", monthly, 1, 3650)
	return nil
}

func (h *huhPrompter) SiteCore(index int, sa *SiteAnswers) error {
	core := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title(fmt.Sprintf("Site #%d", index+1)),
			huh.NewInput().Title("Domain").Value(&sa.Domain).Validate(validHostname("domain")),
			huh.NewInput().Title("Deploy path").Value(&sa.DeployPath).Validate(validDeployPath),
			huh.NewInput().Title("OS user (blank = derived from the domain)").Value(&sa.User).Validate(validOSUser),
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
		huh.NewSelect[string]().Title("Queue driver").Options(huh.NewOptions("work", "horizon", "none")...).Value(&q.Driver),
	))
	if err := driverForm.Run(); err != nil {
		return err
	}
	if q.Driver == "none" {
		// none opts the site out of the server-wide worker; validation rejects
		// every other knob, so clear them all instead of prompting.
		q.Processes, q.Sleep, q.Tries, q.Timeout, q.MaxMemory = 0, 0, 0, 0, 0
		q.Connection, q.Queue = "", ""
		return nil
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

func (h *huhPrompter) AptRepo(ar *AptRepoAnswers) error {
	return huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Repo name (short slug, e.g. signal-cli)").Value(&ar.Name).Validate(config.ValidateAptRepoName),
		huh.NewInput().Title("Repository URL (https://…)").Value(&ar.URI).Validate(validAptURL("uri")),
		huh.NewInput().Title("Suite (e.g. trixie, signalcli)").Value(&ar.Suite).Validate(config.ValidateAptSuite),
		huh.NewInput().Title("Components (space-separated; blank = main)").Value(&ar.Components).Validate(validAptComponents),
		huh.NewInput().Title("Signing key URL (https://…)").Value(&ar.KeyURL).Validate(validAptURL("key_url")),
		huh.NewInput().Title("Signing key fingerprint (40 hex chars — berth pins every repo key)").Value(&ar.Fingerprint).Validate(config.ValidateAptFingerprint),
	)).Run()
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

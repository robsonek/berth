package wizard

import "github.com/robsonek/berth/internal/config"

// ToServer maps collected answers into a *config.Server. It is a pure, total
// mapping — no I/O, no mutation of server-level choices (HTTP/3↔nginx is resolved
// during orchestration, not here). config.Server.Validate() remains authoritative.
// A site left without an OS user gets the domain-derived name filled in, so the
// marshaled YAML always carries an explicit user:.
func (a Answers) ToServer() *config.Server {
	srv := &config.Server{
		ID:       a.ID,
		Host:     a.Host,
		SSH:      config.SSH{User: a.SSHUser, Port: a.Port, Key: a.Key, Fingerprint: a.Fingerprint},
		PHP:      config.PHP{Version: a.PHPVersion, Source: a.PHPSource},
		Nginx:    config.Nginx{Source: a.NginxSource},
		Database: config.Database{Engine: a.DBEngine, Source: a.DBSource}, // no top-level name/user
		Valkey:   a.Valkey, Queue: a.Queue, Scheduler: a.Scheduler,
		Fail2ban: config.Fail2ban{Bantime: a.Fail2ban.Bantime, Findtime: a.Fail2ban.Findtime, Maxretry: a.Fail2ban.Maxretry},
		Tuning: config.Tuning{
			ValkeyMaxmemory:         a.Tuning.ValkeyMaxmemory,
			ValkeyMaxmemoryPolicy:   a.Tuning.ValkeyMaxmemoryPolicy,
			MariaDBBufferPool:       a.Tuning.MariaDBBufferPool,
			MariaDBSlowQueryLog:     a.Tuning.MariaDBSlowQueryLog,
			MariaDBLongQueryTime:    a.Tuning.MariaDBLongQueryTime,
			MariaDBLogFileSize:      a.Tuning.MariaDBLogFileSize,
			MariaDBTmpTableSize:     a.Tuning.MariaDBTmpTableSize,
			MariaDBMaxConnections:   a.Tuning.MariaDBMaxConnections,
			MariaDBMaxAllowedPacket: a.Tuning.MariaDBMaxAllowedPacket,
			PHPMemoryLimit:          a.Tuning.PHPMemoryLimit,
			PHPUploadMax:            a.Tuning.PHPUploadMax,
			PHPMaxExecutionTime:     a.Tuning.PHPMaxExecutionTime,
			PHPMaxInputVars:         a.Tuning.PHPMaxInputVars,
			PHPFPMMaxChildren:       a.Tuning.PHPFPMMaxChildren,
		},
		System:         config.System{Swap: a.System.Swap, Sysctl: a.System.Sysctl, Timezone: a.System.Timezone, Hostname: a.System.Hostname, BreakGlass: a.System.BreakGlass},
		CloudflareOnly: a.CloudflareOnly,
		Backups:        config.Backups{Enabled: a.Backups.Enabled, Retention: a.Backups.RetentionDays, Schedule: a.Backups.Schedule},
	}
	for _, sa := range a.Sites {
		user := sa.User
		if user == "" {
			// Emit the derived name explicitly so the generated YAML pins the
			// site identity: the operator needs the account name for their
			// deployer config, and a later domain edit must not silently
			// re-derive it.
			user = config.DerivedSiteUser(sa.Domain)
		}
		site := config.Site{
			Domain:     sa.Domain,
			DeployPath: sa.DeployPath,
			User:       user,
			Repository: sa.Repository,
			Database:   config.SiteDatabase{Name: sa.DBName, User: sa.DBUser},
			SSL:        sa.SSL,
			SSLMode:    sa.SSLMode,
			SSLEmail:   sa.SSLEmail,
			HTTP3:      sa.HTTP3,
		}
		switch sa.SchedulerOverride {
		case "on":
			v := true
			site.Scheduler = &v
		case "off":
			v := false
			site.Scheduler = &v
		} // "inherit"/"" => nil
		switch sa.CloudflareOverride {
		case "on":
			v := true
			site.CloudflareOnly = &v
		case "off":
			v := false
			site.CloudflareOnly = &v
		} // "inherit"/"" => nil
		switch sa.BackupsOverride {
		case "on":
			v := true
			site.Backups = &v
		case "off":
			v := false
			site.Backups = &v
		} // "inherit"/"" => nil
		if sa.Queue != nil {
			site.Queue = &config.QueueConfig{
				Driver: sa.Queue.Driver, Processes: sa.Queue.Processes,
				Connection: sa.Queue.Connection, Queue: sa.Queue.Queue,
				Sleep: sa.Queue.Sleep, Tries: sa.Queue.Tries,
				Timeout: sa.Queue.Timeout, MaxMemory: sa.Queue.MaxMemory,
			}
		}
		for _, d := range sa.Daemons {
			site.Daemons = append(site.Daemons, config.Daemon{Name: d.Name, Command: d.Command, Processes: d.Processes})
		}
		srv.Sites = append(srv.Sites, site)
	}
	return srv
}

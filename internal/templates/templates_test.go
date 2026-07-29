package templates

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

// checkGolden renders the named template and compares it against the golden
// file under testdata/, refreshing the golden when -update is passed.
func checkGolden(t *testing.T, name, golden string, data any) {
	t.Helper()
	checkGoldenRender(t, Render, name, golden, data)
}

// checkGoldenINI compares a template rendered with the INI (semicolon) marker.
func checkGoldenINI(t *testing.T, name, golden string, data any) {
	t.Helper()
	checkGoldenRender(t, RenderINI, name, golden, data)
}

func checkGoldenRender(t *testing.T, render func(string, any) ([]byte, error), name, golden string, data any) {
	t.Helper()
	got, err := render(name, data)
	if err != nil {
		t.Fatalf("render(%q) error = %v", name, err)
	}
	path := filepath.Join("testdata", golden)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %q: %v", path, err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %q (run with -update to create): %v", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("render mismatch; run with -update to refresh\n got:\n%s", got)
	}
}

// The marker text is FROZEN FOREVER as of the first real deployment: it is
// the first line of every managed file on every host, and the drift
// machinery classifies files by comparing it exactly. Changing either
// constant would make every already-provisioned host read as foreign
// (abort-unless--force on every write) and blind every marker-guarded sweep.
// If this test fails, you are about to break every live host — stop.
func TestManagedMarkerIsFrozen(t *testing.T) {
	if ManagedMarker != "# managed by berth" {
		t.Fatalf("ManagedMarker changed: %q", ManagedMarker)
	}
	if ManagedMarkerINI != "; managed by berth" {
		t.Fatalf("ManagedMarkerINI changed: %q", ManagedMarkerINI)
	}
}

type nginxData struct {
	Domain, DeployPath, ACMEWebroot, Socket, CertPath, KeyPath, BodyMax string
	HTTP3, QUICReuseport, HSTS, CloudflareOnly                          bool
}

const testSocket = "/run/php/berth-app_example_com.sock"

func nginxGoldenData() nginxData {
	return nginxData{
		Domain: "app.example.com", DeployPath: "/home/deploy/myapp",
		ACMEWebroot: "/var/www/berth-acme/app.example.com", Socket: testSocket,
		CertPath: "/etc/letsencrypt/live/app.example.com/fullchain.pem",
		KeyPath:  "/etc/letsencrypt/live/app.example.com/privkey.pem",
		BodyMax:  "35651584",
		HSTS:     true,
	}
}

func TestRenderNginxHTTPGolden(t *testing.T) {
	checkGolden(t, "nginx_http.conf.tmpl", "nginx_http.golden", nginxGoldenData())
}

func TestRenderNginxHTTPSGolden(t *testing.T) {
	checkGolden(t, "nginx_https.conf.tmpl", "nginx_https.golden", nginxGoldenData())
}

func TestRenderNginxHTTPSHTTP3Golden(t *testing.T) {
	d := nginxGoldenData()
	d.HTTP3 = true
	d.QUICReuseport = true
	checkGolden(t, "nginx_https.conf.tmpl", "nginx_https_http3.golden", d)
}

func TestRenderNginxHTTPSNoHSTSGolden(t *testing.T) {
	// HSTS:false is a direct template-field override (template isolation), not a
	// selfsigned scenario — the test-local nginxData has no cert-mode concept.
	d := nginxGoldenData()
	d.HSTS = false
	checkGolden(t, "nginx_https.conf.tmpl", "nginx_https_nohsts.golden", d)
}

func TestRenderNginxHTTPCloudflareGolden(t *testing.T) {
	d := nginxGoldenData()
	d.CloudflareOnly = true
	checkGolden(t, "nginx_http.conf.tmpl", "nginx_http_cloudflare.golden", d)
}

func TestRenderNginxHTTPSCloudflareGolden(t *testing.T) {
	d := nginxGoldenData()
	d.CloudflareOnly = true
	checkGolden(t, "nginx_https.conf.tmpl", "nginx_https_cloudflare.golden", d)
}

func TestRenderPHPOpcacheGolden(t *testing.T) {
	checkGoldenINI(t, "php_opcache.ini.tmpl", "php_opcache.golden", nil)
}

func TestRenderPHPTuningGolden(t *testing.T) {
	checkGoldenINI(t, "php_tuning.ini.tmpl", "php_tuning.golden", struct {
		MemoryLimit, UploadMax, PostMax string
		MaxExecutionTime, MaxInputVars  int
	}{MemoryLimit: "256M", UploadMax: "32M", PostMax: "35651584", MaxExecutionTime: 30, MaxInputVars: 1000})
}

func TestRenderFPMPoolGolden(t *testing.T) {
	checkGoldenINI(t, "fpm_pool.conf.tmpl", "fpm_pool.golden", struct {
		PoolName, User, Socket, DeployPath string
		MaxChildren                        int
	}{
		PoolName: "app_example_com", User: "webuser", Socket: testSocket, DeployPath: "/home/deploy/myapp",
		MaxChildren: 10,
	})
}

func TestRenderFPMPoolMaxChildrenGolden(t *testing.T) {
	checkGoldenINI(t, "fpm_pool.conf.tmpl", "fpm_pool_maxchildren.golden", struct {
		PoolName, User, Socket, DeployPath string
		MaxChildren                        int
	}{
		PoolName: "app_example_com", User: "webuser", Socket: testSocket, DeployPath: "/home/deploy/myapp",
		MaxChildren: 16,
	})
}

func TestRenderSupervisorGolden(t *testing.T) {
	checkGolden(t, "supervisor.conf.tmpl", "supervisor.golden", struct {
		ProgramName, Command, DeployPath, User string
		Numprocs                               int
	}{
		ProgramName: "berth-app_example_com",
		Command:     "php /home/deploy/myapp/current/artisan queue:work --sleep=3 --tries=3 --max-time=3600",
		DeployPath:  "/home/deploy/myapp", User: "webuser", Numprocs: 1,
	})
}

func TestRenderSupervisorHorizonGolden(t *testing.T) {
	checkGolden(t, "supervisor.conf.tmpl", "supervisor_horizon.golden", struct {
		ProgramName, Command, DeployPath, User string
		Numprocs                               int
	}{
		ProgramName: "berth-app_example_com",
		Command:     "php /home/deploy/myapp/current/artisan horizon",
		DeployPath:  "/home/deploy/myapp", User: "webuser", Numprocs: 1,
	})
}

func TestRenderSupervisorDaemonGolden(t *testing.T) {
	checkGolden(t, "supervisor.conf.tmpl", "supervisor_daemon.golden", struct {
		ProgramName, Command, DeployPath, User string
		Numprocs                               int
	}{
		ProgramName: "berth-app_example_com-reverb",
		Command:     "php /home/deploy/myapp/current/artisan reverb:start",
		DeployPath:  "/home/deploy/myapp", User: "webuser", Numprocs: 2,
	})
}

func TestRenderSudoersDeployGolden(t *testing.T) {
	checkGolden(t, "sudoers_deploy.tmpl", "sudoers_deploy.golden", struct {
		User     string
		Programs []string
	}{User: "webuser", Programs: []string{"berth-app_example_com"}})
}

func TestRenderSudoersDeployDaemonsGolden(t *testing.T) {
	checkGolden(t, "sudoers_deploy.tmpl", "sudoers_deploy_daemons.golden", struct {
		User     string
		Programs []string
	}{User: "webuser", Programs: []string{"berth-app_example_com", "berth-app_example_com-reverb"}})
}

func TestRenderReloadFPMGolden(t *testing.T) {
	// The deployer-facing sudoers grant is version-stable (/bin/sh + this
	// wrapper's path); the PHP version lives only INSIDE the wrapper body, so a
	// php.version migration rewrites one root-owned file instead of every
	// deploy pipeline. systemctl is invoked by ABSOLUTE path — the wrapper must
	// never depend on PATH.
	checkGolden(t, "reload_fpm.sh.tmpl", "reload_fpm.golden", struct{ PHPVersion string }{"8.5"})
}

func TestRenderSchedulerCronGolden(t *testing.T) {
	checkGolden(t, "scheduler.cron.tmpl", "scheduler.cron.golden", struct{ DeployPath, User string }{
		DeployPath: "/home/deploy/myapp", User: "webuser",
	})
}

func TestRenderAptAutoUpgradesGolden(t *testing.T) {
	checkGolden(t, "apt_auto_upgrades.conf.tmpl", "apt_auto_upgrades.golden", nil)
}

func TestAptSourceTemplate(t *testing.T) {
	checkGolden(t, "apt_source.list.tmpl", "apt_source.golden", map[string]string{
		"Keyring":    "/usr/share/keyrings/nginx-org.gpg",
		"URI":        "https://nginx.org/packages/mainline/debian/",
		"Suite":      "trixie",
		"Components": "nginx",
	})
}

func TestRenderFail2banJailGolden(t *testing.T) {
	checkGolden(t, "fail2ban_jail.tmpl", "fail2ban_jail.golden", struct {
		Bantime, Findtime string
		Maxretry, SSHPort int
	}{Bantime: "1h", Findtime: "10m", Maxretry: 5, SSHPort: 22})
}

func TestRenderLogrotateGolden(t *testing.T) {
	checkGolden(t, "logrotate.conf.tmpl", "logrotate.golden", nil)
}

func TestRenderBerthValkeyServiceGolden(t *testing.T) {
	checkGolden(t, "berth_valkey.service.tmpl", "berth_valkey.service.golden", struct {
		Domain, User, Pool, Maxmemory, Policy string
	}{
		Domain: "app.example.com", User: "webuser", Pool: "app_example_com",
		Maxmemory: "256mb", Policy: "allkeys-lru",
	})
}

// mariadbTuningGoldenData mirrors the render struct in steps.renderMariaDBTuning
// (test-local copy — keep the fields in sync).
type mariadbTuningGoldenData struct {
	BufferPool       string
	LogFileSize      string
	TmpTableSize     string
	MaxConnections   int
	MaxAllowedPacket string
	SlowQueryLog     bool
	LongQueryTime    int
}

func TestRenderMariaDBTuningGolden(t *testing.T) {
	checkGolden(t, "mariadb_tuning.cnf.tmpl", "mariadb_tuning.golden", mariadbTuningGoldenData{BufferPool: "256M"})
}

func TestRenderMariaDBTuningSlowLogGolden(t *testing.T) {
	checkGolden(t, "mariadb_tuning.cnf.tmpl", "mariadb_tuning_slowlog.golden", mariadbTuningGoldenData{
		BufferPool: "256M", SlowQueryLog: true, LongQueryTime: 2,
	})
}

func TestRenderMariaDBTuningParityGolden(t *testing.T) {
	checkGolden(t, "mariadb_tuning.cnf.tmpl", "mariadb_tuning_parity.golden", mariadbTuningGoldenData{
		BufferPool: "256M", LogFileSize: "1G", TmpTableSize: "128M",
		MaxConnections: 256, MaxAllowedPacket: "64M", SlowQueryLog: true, LongQueryTime: 2,
	})
}

func TestRenderCloudflareGolden(t *testing.T) {
	checkGolden(t, "cloudflare.conf.tmpl", "cloudflare.golden", struct{ Ranges []string }{
		[]string{"203.0.113.0/24", "2001:db8::/32"},
	})
}

func TestRenderSysctlSwapGolden(t *testing.T) {
	checkGolden(t, "sysctl_swap.conf.tmpl", "sysctl_swap.golden", nil)
}

func TestRenderSysctlBerthGolden(t *testing.T) {
	checkGolden(t, "sysctl_berth.conf.tmpl", "sysctl_berth.golden", nil)
}

func TestRenderBackupScriptGolden(t *testing.T) {
	checkGolden(t, "backup.sh.tmpl", "backup_sh.golden", struct {
		Pool, DumpCommand, DBName, DeployPath, BackupDir, LogFile, LockFile string
		ArtifactsLock                                                       string
		BerthVersion, Domain, Engine, DBUser, SiteUser                      string
		RetentionDays                                                       int
	}{
		Pool:          "app_example_com",
		DumpCommand:   "mysqldump --protocol=socket --single-transaction --no-tablespaces --routines --events 'myapp'",
		DBName:        "myapp",
		DeployPath:    "/home/deploy/myapp",
		BackupDir:     "/var/backups/berth/app_example_com",
		LogFile:       "/var/log/berth/backup-app_example_com.log",
		LockFile:      "/var/backups/berth/app_example_com/.lock",
		ArtifactsLock: "/var/backups/berth/.artifacts.lock",
		BerthVersion:  "v9.9.9",
		Domain:        "app.example.com",
		Engine:        "mariadb",
		DBUser:        "myapp",
		SiteUser:      "b_appexamplecom_dd46c94b",
		RetentionDays: 7,
	})
}

// offsiteScriptGoldenData mirrors the offsite step's render struct for
// offsite.sh.tmpl (test-local copy — keep the fields in sync).
type offsiteScriptGoldenData struct {
	LogFile, LockFile, ArtifactsLock, EnvFile, ResticOpts, BackupBaseDir, HostID string
	KeepLast, KeepHourly, KeepDaily, KeepWeekly, KeepMonthly                     int
}

func offsiteScriptGoldenBase() offsiteScriptGoldenData {
	return offsiteScriptGoldenData{
		LogFile:       "/var/log/berth/backup-offsite.log",
		LockFile:      "/var/backups/berth/.offsite.lock",
		ArtifactsLock: "/var/backups/berth/.artifacts.lock",
		EnvFile:       "/etc/berth/offsite.env",
		BackupBaseDir: "/var/backups/berth",
		HostID:        "box-1",
		KeepDaily:     7, KeepWeekly: 4, KeepMonthly: 6,
	}
}

func TestRenderOffsiteScriptGolden(t *testing.T) {
	// S3 flavor: no extra restic options — ResticOpts stays empty so the
	// invocation composes as a bare "restic".
	checkGolden(t, "offsite.sh.tmpl", "offsite_sh.golden", offsiteScriptGoldenBase())
}

func TestRenderOffsiteScriptSFTPGolden(t *testing.T) {
	// SFTP flavor: ResticOpts is non-empty and MUST begin with a space —
	// "restic{{ .ResticOpts }}" composes without a separator of its own.
	// The sample string is the real offsiteResticOpts shape (keep in sync).
	d := offsiteScriptGoldenBase()
	d.ResticOpts = " -o sftp.command='ssh -F /dev/null -o BatchMode=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=/root/.ssh/berth_offsite_known_hosts -i /root/.ssh/berth_offsite -p 22 backup@sftp.example.com -s sftp'"
	checkGolden(t, "offsite.sh.tmpl", "offsite_sh_sftp.golden", d)
}

func TestRenderOffsiteScriptSubdailyGolden(t *testing.T) {
	// Sub-daily retention: keep.last / keep.hourly are opt-in (0 = off), so
	// only this fixture sets them — the s3/sftp cases above leave both at 0
	// and their goldens must stay byte-identical.
	d := offsiteScriptGoldenBase()
	d.KeepLast = 12
	d.KeepHourly = 24
	checkGolden(t, "offsite.sh.tmpl", "offsite_sh_subdaily.golden", d)
}

func TestRenderOffsiteEnvGolden(t *testing.T) {
	checkGolden(t, "offsite_env.tmpl", "offsite_env.golden", struct {
		Repository, Password string
		S3                   bool
		AccessKey, SecretKey string
	}{
		Repository: "s3:https://s3.example.com/bkt/berth/box-1",
		Password:   "fake-password-123",
		S3:         true,
		AccessKey:  "AKIAEXAMPLE",
		SecretKey:  "fake/secret+KEY",
	})
}

func TestRenderOffsiteEnvSFTPGolden(t *testing.T) {
	// S3=false must render a password-only file: no AWS block and no stray
	// blank line where the trimmed conditional was.
	checkGolden(t, "offsite_env.tmpl", "offsite_env_sftp.golden", struct {
		Repository, Password string
		S3                   bool
		AccessKey, SecretKey string
	}{
		Repository: "sftp:off@backup.example.net:/srv/berth/box-1",
		Password:   "fake-password-123",
		S3:         false,
	})
}

func TestRenderBackupCronGolden(t *testing.T) {
	checkGolden(t, "backup.cron.tmpl", "backup_cron.golden", struct{ Schedule, ScriptPath string }{
		Schedule: "30 3 * * *", ScriptPath: "/usr/local/sbin/berth-backup-app_example_com",
	})
}

func TestRenderBackupLogrotateGolden(t *testing.T) {
	checkGolden(t, "backup_logrotate.conf.tmpl", "backup_logrotate.golden", nil)
}

func TestRenderBackupManifestGolden(t *testing.T) {
	checkGolden(t, "backup_manifest.tmpl", "backup_manifest.golden", struct {
		BerthVersion, Domain, Pool, Engine, DBName, DBUser, SiteUser, DeployPath string
	}{
		BerthVersion: "v9.9.9",
		Domain:       "app.example.com",
		Pool:         "app_example_com",
		Engine:       "mariadb",
		DBName:       "myapp",
		DBUser:       "myapp",
		SiteUser:     "b_appexamplecom_dd46c94b",
		DeployPath:   "/home/deploy/myapp",
	})
}

func TestRenderManifestGolden(t *testing.T) {
	checkGolden(t, "manifest.tmpl", "manifest.golden", struct{ Version, ProvisionedAt string }{
		Version: "v9.9.9", ProvisionedAt: "2026-01-02T03:04:05Z",
	})
}

func TestRenderCertbotDeployHookGolden(t *testing.T) {
	// Static POSIX-sh certbot deploy hook: certbot executes directory hooks via
	// `sh -c <path>` (ENOEXEC fallback), so no shebang — the managed marker must
	// stay the first byte — and no bashisms (no pipefail).
	checkGolden(t, "certbot_deploy_hook.sh.tmpl", "certbot_deploy_hook.golden", nil)
}

func TestFPMPoolIsolatesTempDirs(t *testing.T) {
	out, err := RenderINI("fpm_pool.conf.tmpl", struct {
		PoolName, User, Socket, DeployPath string
		MaxChildren                        int
	}{
		PoolName: "app_example_com", User: "webuser", Socket: testSocket, DeployPath: "/home/deploy/myapp",
		MaxChildren: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// The shared /tmp is world-readable across tenants; open_basedir must be
	// exactly current:shared and PHP's temp/upload staging must live inside
	// shared/tmp (which appdirs creates 0700 <user>:<user>).
	if !strings.Contains(s, "php_admin_value[open_basedir] = /home/deploy/myapp/current:/home/deploy/myapp/shared\n") {
		t.Errorf("open_basedir must be exactly current:shared (no shared /tmp):\n%s", s)
	}
	for _, want := range []string{
		"php_admin_value[sys_temp_dir] = /home/deploy/myapp/shared/tmp",
		"php_admin_value[upload_tmp_dir] = /home/deploy/myapp/shared/tmp",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in pool config:\n%s", want, s)
		}
	}
}

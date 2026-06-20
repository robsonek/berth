package templates

import (
	"flag"
	"os"
	"path/filepath"
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

type nginxData struct {
	Domain, DeployPath, ACMEWebroot, Socket, CertPath, KeyPath string
	HTTP3, QUICReuseport, HSTS, CloudflareOnly                 bool
}

const testSocket = "/run/php/berth-app_example_com.sock"

func nginxGoldenData() nginxData {
	return nginxData{
		Domain: "app.example.com", DeployPath: "/home/deploy/myapp",
		ACMEWebroot: "/var/www/berth-acme/app.example.com", Socket: testSocket,
		CertPath: "/etc/letsencrypt/live/app.example.com/fullchain.pem",
		KeyPath:  "/etc/letsencrypt/live/app.example.com/privkey.pem",
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

func TestRenderFPMPoolGolden(t *testing.T) {
	checkGoldenINI(t, "fpm_pool.conf.tmpl", "fpm_pool.golden", struct{ PoolName, User, Socket, DeployPath string }{
		PoolName: "app_example_com", User: "webuser", Socket: testSocket, DeployPath: "/home/deploy/myapp",
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

func TestRenderEnvGolden(t *testing.T) {
	checkGolden(t, "env.tmpl", "env.golden", struct{ AppURL, DBName, DBUser, DBPassword string }{
		AppURL: "https://app.example.com", DBName: "myapp", DBUser: "myapp", DBPassword: "s3cr3tpassword",
	})
}

func TestRenderSudoersDeployGolden(t *testing.T) {
	checkGolden(t, "sudoers_deploy.tmpl", "sudoers_deploy.golden", struct {
		User, PHPVersion string
		Programs         []string
	}{User: "webuser", PHPVersion: "8.5", Programs: []string{"berth-app_example_com"}})
}

func TestRenderSudoersDeployDaemonsGolden(t *testing.T) {
	checkGolden(t, "sudoers_deploy.tmpl", "sudoers_deploy_daemons.golden", struct {
		User, PHPVersion string
		Programs         []string
	}{User: "webuser", PHPVersion: "8.5", Programs: []string{"berth-app_example_com", "berth-app_example_com-reverb"}})
}

func TestRenderSchedulerCronGolden(t *testing.T) {
	checkGolden(t, "scheduler.cron.tmpl", "scheduler.cron.golden", struct{ DeployPath, User string }{
		DeployPath: "/home/deploy/myapp", User: "webuser",
	})
}

func TestRenderAptAutoUpgradesGolden(t *testing.T) {
	checkGolden(t, "apt_auto_upgrades.conf.tmpl", "apt_auto_upgrades.golden", nil)
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

func TestRenderValkeyDropInGolden(t *testing.T) {
	checkGolden(t, "valkey_dropin.conf.tmpl", "valkey_dropin.golden", struct{ Maxmemory, Policy string }{
		Maxmemory: "256mb", Policy: "allkeys-lru",
	})
}

func TestRenderMariaDBTuningGolden(t *testing.T) {
	checkGolden(t, "mariadb_tuning.cnf.tmpl", "mariadb_tuning.golden", struct{ BufferPool string }{
		BufferPool: "256M",
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

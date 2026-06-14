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
	HTTP3, QUICReuseport                                       bool
}

const testSocket = "/run/php/berth-app_example_com.sock"

func nginxGoldenData() nginxData {
	return nginxData{
		Domain: "app.example.com", DeployPath: "/home/deploy/myapp",
		ACMEWebroot: "/var/www/berth-acme/app.example.com", Socket: testSocket,
		CertPath: "/etc/letsencrypt/live/app.example.com/fullchain.pem",
		KeyPath:  "/etc/letsencrypt/live/app.example.com/privkey.pem",
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

func TestRenderFPMPoolGolden(t *testing.T) {
	checkGoldenINI(t, "fpm_pool.conf.tmpl", "fpm_pool.golden", struct{ PoolName, User, Socket, DeployPath string }{
		PoolName: "app_example_com", User: "webuser", Socket: testSocket, DeployPath: "/home/deploy/myapp",
	})
}

func TestRenderSupervisorGolden(t *testing.T) {
	checkGolden(t, "supervisor.conf.tmpl", "supervisor.golden", struct{ ProgramName, DeployPath, User string }{
		ProgramName: "berth-app_example_com", DeployPath: "/home/deploy/myapp", User: "webuser",
	})
}

func TestRenderEnvGolden(t *testing.T) {
	checkGolden(t, "env.tmpl", "env.golden", struct{ AppURL, DBName, DBUser, DBPassword string }{
		AppURL: "https://app.example.com", DBName: "myapp", DBUser: "myapp", DBPassword: "s3cr3tpassword",
	})
}

func TestRenderSudoersDeployGolden(t *testing.T) {
	checkGolden(t, "sudoers_deploy.tmpl", "sudoers_deploy.golden", struct{ User, PHPVersion, ProgramName string }{
		User: "webuser", PHPVersion: "8.5", ProgramName: "berth-app_example_com",
	})
}

func TestRenderSchedulerCronGolden(t *testing.T) {
	checkGolden(t, "scheduler.cron.tmpl", "scheduler.cron.golden", struct{ DeployPath, User string }{
		DeployPath: "/home/deploy/myapp", User: "webuser",
	})
}

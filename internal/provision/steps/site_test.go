package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func siteServer() *config.Server {
	return &config.Server{
		Host: "app.example.com",
		PHP:  config.PHP{Version: "8.4", Source: "auto"},
		Sites: []config.Site{{
			Domain:     "app.example.com",
			DeployPath: "/home/deploy/myapp",
		}},
	}
}

func TestSiteRequires(t *testing.T) {
	got := Site().Requires()
	want := []string{"php", "nginx", "appdirs", "database"}
	if len(got) != len(want) {
		t.Fatalf("Requires() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Requires() = %v, want %v", got, want)
		}
	}
}

func TestSiteApplyValidatesNginxBeforeReload(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// nginx -t must run before systemctl reload nginx.
	var idxTest, idxReload = -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "nginx -t":
			idxTest = i
		case "systemctl reload nginx":
			idxReload = i
		}
	}
	if idxTest < 0 || idxReload < 0 {
		t.Fatalf("expected both nginx -t and reload; calls=%v", f.Calls())
	}
	if idxTest > idxReload {
		t.Error("nginx -t must run before systemctl reload nginx")
	}
}

func TestSiteApplyAbortsOnNginxTestFailure(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 1, Stderr: "invalid config"})
	// systemctl reload is intentionally NOT stubbed: it must never be called.

	err := Site().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil {
		t.Fatal("expected Apply to abort when nginx -t fails")
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl reload nginx" {
			t.Error("reload must not run after a failed nginx -t")
		}
	}
}

func TestSiteApplyWritesManagedFiles(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	wantPaths := map[string]bool{
		"/etc/nginx/sites-available/app.example.com": false,
	}
	var supervisorBody string
	for _, w := range f.Writes() {
		if _, ok := wantPaths[w.Path]; ok {
			wantPaths[w.Path] = true
		}
		if strings.Contains(w.Path, "/etc/supervisor/conf.d/") {
			supervisorBody = string(w.Content)
		}
		if strings.HasPrefix(w.Path, "/etc/cron.d/berth-") {
			wantPaths["cron"] = true
		}
		if strings.Contains(w.Path, "fpm/pool.d/") {
			wantPaths["fpm"] = true
		}
	}
	for path, seen := range wantPaths {
		if !seen {
			t.Errorf("expected a write for %q", path)
		}
	}
	if !strings.Contains(supervisorBody, "autostart=false") {
		t.Error("supervisor program must be installed dormant (autostart=false)")
	}
}

func TestSiteCheckSatisfiedWhenFilesManagedAndNginxValid(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 0})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when managed files match and nginx -t passes; got %+v", cr)
	}
}

func TestSiteCheckUnsatisfiedWhenNginxInvalid(t *testing.T) {
	s := siteServer()
	f := bssh.NewFakeRunner()
	stubManagedSiteFiles(t, s, f)
	f.On("nginx -t", bssh.Result{ExitCode: 1})

	cr, err := Site().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when nginx -t fails")
	}
}

// stubManagedSiteFiles makes every managed site file read back as up-to-date so
// the Check's content-hash comparison is satisfied.
func stubManagedSiteFiles(t *testing.T, s *config.Server, f *bssh.FakeRunner) {
	t.Helper()
	for _, mf := range managedSiteFiles(s) {
		f.On("cat "+shQuote(mf.path), bssh.Result{Stdout: string(mf.content)})
	}
}

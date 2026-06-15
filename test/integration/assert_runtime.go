//go:build integration

package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertRuntime verifies the deployer-handoff runtime, each invariant on its OWN gate:
// every site has an FPM socket; queue-enabled sites have a DORMANT worker (supervisor
// active + all processes STOPPED, never FATAL/BACKOFF); scheduler-enabled sites have a
// valid managed scheduler cron.
func assertRuntime(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	anyQueue := false
	for _, site := range srv.Sites {
		if srv.QueueEnabled(site) {
			anyQueue = true
		}
	}
	if anyQueue {
		assertExitZero(ctx, t, c, "supervisor active", "systemctl is-active supervisor")
	}
	for _, site := range srv.Sites {
		pool := config.PoolName(site.Domain)
		// Every site has its own FPM pool socket.
		assertExitZero(ctx, t, c, "fpm socket "+site.Domain, "test -S /run/php/berth-"+pool+".sock")

		if srv.QueueEnabled(site) {
			prog := "berth-" + pool
			st, err := c.Run(ctx, "sudo supervisorctl status '"+prog+":*'", nil)
			if err != nil {
				t.Fatalf("%s: supervisorctl status: %v", site.Domain, err)
			}
			if !supervisorAllStopped(st.Stdout) {
				t.Errorf("%s: worker %s not fully dormant (want every process STOPPED):\n%s", site.Domain, prog, st.Stdout)
			}
		}

		if srv.SchedulerEnabled(site) {
			cron := "/etc/cron.d/berth-" + pool
			if perm, err := c.Run(ctx, "stat -c '%U:%G %a' "+cron, nil); err != nil {
				t.Fatalf("%s: stat cron: %v", site.Domain, err)
			} else if got := strings.TrimSpace(perm.Stdout); got != "root:root 644" {
				t.Errorf("%s: cron %s perms = %q, want root:root 644", site.Domain, cron, got)
			}
			body, err := c.Run(ctx, "cat "+cron, nil)
			if err != nil {
				t.Fatalf("%s: cat cron: %v", site.Domain, err)
			}
			wantLine := "* * * * * " + srv.SiteUser(site)
			if !strings.Contains(body.Stdout, "managed by berth") ||
				!strings.Contains(body.Stdout, wantLine) ||
				!strings.Contains(body.Stdout, "artisan schedule:run") {
				t.Errorf("%s: cron %s is not the managed scheduler cron (want %q + artisan schedule:run):\n%s", site.Domain, cron, wantLine, body.Stdout)
			}
		}
	}
}

// assertOpcacheEffective verifies OPcache validate_timestamps=0 is effective for the FPM
// SAPI. php-fpm has no -i and the CLI default SAPI shows the un-overridden value, so the
// FPM conf.d is loaded explicitly via PHP_INI_SCAN_DIR (verified live).
func assertOpcacheEffective(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	ver := srv.PHP.Version
	dropin := "/etc/php/" + ver + "/fpm/conf.d/99-berth-opcache.ini"
	if body, err := c.Run(ctx, "cat "+dropin, nil); err != nil {
		t.Fatalf("read opcache drop-in: %v", err)
	} else if body.ExitCode != 0 || !strings.Contains(body.Stdout, "managed by berth") {
		t.Errorf("opcache drop-in %s missing or unmanaged (exit %d)", dropin, body.ExitCode)
	}
	info, err := c.Run(ctx, "PHP_INI_SCAN_DIR=/etc/php/"+ver+"/fpm/conf.d php"+ver+" -i", nil)
	if err != nil {
		t.Fatalf("php -i (fpm scan dir): %v", err)
	}
	if !strings.Contains(info.Stdout, "opcache.validate_timestamps => Off") {
		t.Errorf("FPM opcache.validate_timestamps not effective Off:\n%s", grepLines(info.Stdout, "opcache"))
	}
	if !strings.Contains(info.Stdout, "opcache.enable => On") {
		t.Errorf("FPM opcache.enable not On:\n%s", grepLines(info.Stdout, "opcache"))
	}
}

// assertDeployReload validates the deploy-reload contract: each site user is authorized to
// reload php<ver>-fpm via its narrow sudoers grant; running that graceful reload keeps
// EVERY site's FPM socket up and a .php request answering (404 fine, never a persistent
// 5xx gateway error). useHTTPS picks the scheme the box actually serves.
func assertDeployReload(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server, useHTTPS bool) {
	t.Helper()
	ver := srv.PHP.Version
	seen := map[string]bool{}
	for _, site := range srv.Sites {
		user := srv.SiteUser(site)
		if seen[user] {
			continue
		}
		seen[user] = true
		assertExitZero(ctx, t, c, user+" authorized to reload fpm",
			fmt.Sprintf("sudo -u %s sudo -n -l /usr/bin/systemctl reload php%s-fpm", user, ver))
		if res, err := c.Run(ctx, fmt.Sprintf("sudo -u %s sudo -n /usr/bin/systemctl reload php%s-fpm", user, ver), nil); err != nil {
			t.Fatalf("%s: deploy reload: %v", user, err)
		} else if res.ExitCode != 0 {
			t.Errorf("%s: deploy reload exit %d: %s", user, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
	}
	// After the reload the FPM stack must settle: active, EVERY site socket present, and a
	// .php request (through FastCGI) returns a non-gateway-error. Retry — reload returns early.
	ok := eventually(20*time.Second, func() bool {
		a, _ := c.Run(ctx, "systemctl is-active php"+ver+"-fpm", nil)
		if strings.TrimSpace(a.Stdout) != "active" {
			return false
		}
		for _, site := range srv.Sites {
			s, _ := c.Run(ctx, "test -S /run/php/berth-"+config.PoolName(site.Domain)+".sock", nil)
			if s.ExitCode != 0 {
				return false
			}
		}
		return phpPathServes(srv.Host, useHTTPS)
	})
	if !ok {
		t.Errorf("FPM did not settle after the deploy reload (active / all sockets / .php request)")
	}
}

// phpPathServes GETs a .php URI (forcing nginx -> FastCGI -> FPM) and reports whether the
// FPM chain answered: a 404 for the missing script is fine; 502/503/504 means FPM is down.
func phpPathServes(host string, useHTTPS bool) bool {
	scheme := "http"
	tr := &http.Transport{}
	if useHTTPS {
		scheme = "https"
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	cl := &http.Client{Timeout: 10 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Get(scheme + "://" + host + "/berth-probe.php")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode != http.StatusBadGateway &&
		resp.StatusCode != http.StatusServiceUnavailable &&
		resp.StatusCode != http.StatusGatewayTimeout
}

// eventually polls check until it returns true or the deadline passes.
func eventually(d time.Duration, check func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if check() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return check()
}

// grepLines returns the lines of s containing substr (for readable assertion failures).
func grepLines(s, substr string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, substr) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

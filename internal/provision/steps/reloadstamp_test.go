package steps

import (
	"context"
	"testing"

	bssh "github.com/robsonek/berth/internal/ssh"
)

func markReloadedCmd(unit string) string {
	stamp := shQuote("/var/lib/berth/" + unit + ".reloaded")
	return "install -d -o root -g root -m 0755 /var/lib/berth && rm -f " + stamp + " && install -o root -g root -m 0644 /dev/null " + stamp
}

func TestMarkReloadedInstallsFreshRootStamp(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(markReloadedCmd("nginx"), bssh.Result{})
	if err := markReloaded(context.Background(), f, "nginx"); err != nil {
		t.Fatalf("markReloaded() error = %v", err)
	}
}

func TestMarkReloadedFailsLoud(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(markReloadedCmd("nginx"), bssh.Result{ExitCode: 1, Stderr: "read-only fs"})
	if err := markReloaded(context.Background(), f, "nginx"); err == nil {
		t.Fatal("a failed stamp write must be an error (Check depends on the stamp)")
	}
}

func TestInvalidateReloadedRemovesStamp(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("rm -f "+shQuote("/var/lib/berth/nginx.reloaded"), bssh.Result{})
	if err := invalidateReloaded(context.Background(), f, "nginx"); err != nil {
		t.Fatalf("invalidateReloaded() error = %v", err)
	}
}

func reloadedSinceCmd(unit string, paths ...string) string {
	stamp := shQuote("/var/lib/berth/" + unit + ".reloaded")
	cmd := "[ -e " + stamp + " ]"
	for _, p := range paths {
		cmd += " && [ ! " + shQuote(p) + " -nt " + stamp + " ]"
	}
	return cmd
}

func TestReloadedSinceTrueWhenNoFileNewer(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(reloadedSinceCmd("nginx", "/etc/nginx/sites-available/a", "/etc/nginx/conf.d/b"), bssh.Result{})
	ok, err := reloadedSince(context.Background(), f, "nginx", "/etc/nginx/sites-available/a", "/etc/nginx/conf.d/b")
	if err != nil || !ok {
		t.Fatalf("reloadedSince() = %v, %v; want true, nil", ok, err)
	}
}

// restartedSinceCmd mirrors reloadedSince's fallback probe (reloadstamp.go) —
// a copy on purpose, so a change to the issued text fails here first.
func restartedSinceCmd(unit string, paths ...string) string {
	stamp := shQuote("/var/lib/berth/" + unit + ".reloaded")
	cmd := `s="$(systemctl show -p ActiveEnterTimestamp --value --timestamp=unix ` + unit + ` 2>/dev/null | tr -d @)"; [ -n "$s" ] && [ -e ` + stamp + ` ] && systemctl is-active --quiet ` + unit
	for _, p := range paths {
		cmd += ` && [ "$(stat -c %Y ` + shQuote(p) + ` 2>/dev/null)" -le "$s" ]`
	}
	return cmd
}

// stubNotReloaded makes both reload probes fail for unit: the stamp is
// missing or older than a path, and the unit was not restarted since.
func stubNotReloaded(f *bssh.FakeRunner, unit string, paths ...string) {
	f.On(reloadedSinceCmd(unit, paths...), bssh.Result{ExitCode: 1})
	f.On(restartedSinceCmd(unit, paths...), bssh.Result{ExitCode: 1})
}

func TestReloadedSinceFalseWhenStampMissingOrStale(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubNotReloaded(f, "fail2ban", "/etc/fail2ban/jail.d/99-berth.conf")
	ok, err := reloadedSince(context.Background(), f, "fail2ban", "/etc/fail2ban/jail.d/99-berth.conf")
	if err != nil || ok {
		t.Fatalf("reloadedSince() = %v, %v; want false, nil", ok, err)
	}
}

// A package upgrade bumps the mtime of a config directory and restarts the
// unit itself: the stamp is older than the path, yet the running unit
// started after it and so has loaded everything on disk. That is not a
// pending reload.
func TestReloadedSinceTrueWhenUnitRestartedAfterEveryPath(t *testing.T) {
	paths := []string{"/etc/php/8.5/fpm/pool.d/app.conf", "/etc/php/8.5/fpm/pool.d"}
	f := bssh.NewFakeRunner()
	f.On(reloadedSinceCmd("php8.5-fpm", paths...), bssh.Result{ExitCode: 1})
	f.On(restartedSinceCmd("php8.5-fpm", paths...), bssh.Result{})
	ok, err := reloadedSince(context.Background(), f, "php8.5-fpm", paths...)
	if err != nil || !ok {
		t.Fatalf("reloadedSince() = %v, %v; want true, nil", ok, err)
	}
}

// The restart fallback is only consulted when the stamp test fails: a
// converged host pays for one probe, not two.
func TestReloadedSinceSkipsTheFallbackWhenTheStampIsCurrent(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(reloadedSinceCmd("nginx", "/etc/nginx/nginx.conf"), bssh.Result{})
	if ok, err := reloadedSince(context.Background(), f, "nginx", "/etc/nginx/nginx.conf"); err != nil || !ok {
		t.Fatalf("reloadedSince() = %v, %v; want true, nil", ok, err)
	}
	if n := len(f.Calls()); n != 1 {
		t.Errorf("want exactly one probe on a current stamp, got %d", n)
	}
}

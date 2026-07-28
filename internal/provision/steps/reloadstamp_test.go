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

func TestReloadedSinceFalseWhenStampMissingOrStale(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(reloadedSinceCmd("fail2ban", "/etc/fail2ban/jail.d/99-berth.conf"), bssh.Result{ExitCode: 1})
	ok, err := reloadedSince(context.Background(), f, "fail2ban", "/etc/fail2ban/jail.d/99-berth.conf")
	if err != nil || ok {
		t.Fatalf("reloadedSince() = %v, %v; want false, nil", ok, err)
	}
}

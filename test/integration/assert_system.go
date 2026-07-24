//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertSwapSysctl verifies the live end state of the system step: when swap is
// configured, /swapfile is an active swap area and vm.swappiness is 10; when sysctl
// is enabled, each managed key's running value matches; when a timezone is set,
// the live system zone matches; when a hostname is set, the static hostname
// matches and /etc/hosts holds exactly one 127.0.1.1 alias — berth's marked
// line. A no-op when all four are off.
func assertSwapSysctl(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()

	if srv.System.Swap != "" {
		on, err := c.Run(ctx, "swapon --show=NAME --noheadings", nil)
		if err != nil {
			t.Fatalf("swapon --show: %v", err)
		}
		// Require an EXACT /swapfile line (so e.g. /swapfile-old never passes a substring).
		active := false
		for _, line := range strings.Split(on.Stdout, "\n") {
			if strings.TrimSpace(line) == "/swapfile" {
				active = true
				break
			}
		}
		if !active {
			t.Errorf("/swapfile not an active swap area:\n%s", on.Stdout)
		}
		// -F fixed-string, -x whole-line match, -q quiet: the fstab line must match exactly.
		fstab, err := c.Run(ctx, "grep -Fxq '/swapfile none swap sw 0 0 # managed by berth' /etc/fstab", nil)
		if err != nil {
			t.Fatalf("grep fstab: %v", err)
		}
		if fstab.ExitCode != 0 {
			t.Error("berth swap line missing from /etc/fstab")
		}
		sw, err := c.Run(ctx, "cat /proc/sys/vm/swappiness", nil)
		if err != nil {
			t.Fatalf("read swappiness: %v", err)
		}
		if strings.TrimSpace(sw.Stdout) != "10" {
			t.Errorf("vm.swappiness = %q, want 10", strings.TrimSpace(sw.Stdout))
		}
	}

	if srv.System.Sysctl {
		for _, kv := range []struct{ key, val string }{
			{"net.core.somaxconn", "4096"},
			{"net.ipv4.tcp_tw_reuse", "1"},
			{"fs.file-max", "1048576"},
			{"fs.inotify.max_user_watches", "524288"},
		} {
			res, err := c.Run(ctx, "sysctl -n "+kv.key, nil)
			if err != nil {
				t.Fatalf("sysctl -n %s: %v", kv.key, err)
			}
			if strings.TrimSpace(res.Stdout) != kv.val {
				t.Errorf("sysctl %s = %q, want %q", kv.key, strings.TrimSpace(res.Stdout), kv.val)
			}
		}
	}

	if srv.System.Timezone != "" {
		tz, err := c.Run(ctx, "timedatectl show -p Timezone --value", nil)
		if err != nil {
			t.Fatalf("timedatectl show: %v", err)
		}
		if tz.ExitCode != 0 {
			t.Fatalf("timedatectl show exit %d: %s", tz.ExitCode, strings.TrimSpace(tz.Stderr))
		}
		if got := strings.TrimSpace(tz.Stdout); got != srv.System.Timezone {
			t.Errorf("system timezone = %q, want %q", got, srv.System.Timezone)
		}
	}

	if srv.System.Hostname != "" {
		hn, err := c.Run(ctx, "hostnamectl --static", nil)
		if err != nil {
			t.Fatalf("hostnamectl --static: %v", err)
		}
		if hn.ExitCode != 0 {
			t.Fatalf("hostnamectl --static exit %d: %s", hn.ExitCode, strings.TrimSpace(hn.Stderr))
		}
		if got := strings.TrimSpace(hn.Stdout); got != srv.System.Hostname {
			t.Errorf("static hostname = %q, want %q", got, srv.System.Hostname)
		}
		// berth's exact marked alias line is present (-F fixed, -x whole line)...
		assertExitZero(ctx, t, c, "marked 127.0.1.1 alias present",
			"grep -Fxq '"+hostsAliasLine(srv.System.Hostname)+"' /etc/hosts")
		// ...and it is the ONLY 127.0.1.1 line — a foreign alias beside it would
		// keep resolving the image's old name (the takeover contract).
		cnt, err := c.Run(ctx, `grep -c '^127\.0\.1\.1[[:space:]]' /etc/hosts`, nil)
		if err != nil {
			t.Fatalf("count 127.0.1.1 lines: %v", err)
		}
		if got := strings.TrimSpace(cnt.Stdout); got != "1" {
			t.Errorf("127.0.1.1 alias lines in /etc/hosts = %s, want exactly 1", got)
		}
	}
}

// hostsAliasLine mirrors steps.hostsHostnameLine (unexported): the exact marked
// /etc/hosts alias line berth manages for the configured static hostname.
func hostsAliasLine(hostname string) string {
	names := hostname
	if short, _, ok := strings.Cut(hostname, "."); ok && short != "" {
		names = hostname + " " + short
	}
	return "127.0.1.1 " + names + " # managed by berth"
}

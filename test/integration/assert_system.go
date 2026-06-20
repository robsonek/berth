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
// is enabled, each managed key's running value matches. A no-op when both are off.
func assertSwapSysctl(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()

	if srv.System.Swap != "" {
		on, err := c.Run(ctx, "swapon --show=NAME --noheadings", nil)
		if err != nil {
			t.Fatalf("swapon --show: %v", err)
		}
		if !strings.Contains(on.Stdout, "/swapfile") {
			t.Errorf("/swapfile not an active swap area:\n%s", on.Stdout)
		}
		fstab, err := c.Run(ctx, "grep -F '/swapfile none swap sw 0 0 # managed by berth' /etc/fstab", nil)
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
}

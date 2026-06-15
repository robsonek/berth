//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertExitZero fails unless cmd exits 0 on the target. It lives in a non-test
// file (not provision_test.go) so the assert_*.go files — themselves non-test
// files — can reference it under `go build -tags integration`.
func assertExitZero(ctx context.Context, t *testing.T, c *bssh.Client, label, cmd string) {
	t.Helper()
	res, err := c.Run(ctx, cmd, nil)
	if err != nil {
		t.Fatalf("%s: run: %v", label, err)
	}
	if res.ExitCode != 0 {
		t.Errorf("%s: exit %d, stderr %q", label, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
}

// knownHostsPath returns ~/.ssh/known_hosts, or "" if the home dir is unknown.
func knownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.ssh/known_hosts"
}

//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

const (
	composerBinPath        = "/usr/local/bin/composer"
	composerUpdateCronPath = "/etc/cron.d/berth-composer-update"
)

// assertComposerAutoUpdate proves the composer.auto_update knob on the host.
// With the knob on (the default) Composer is installed where the cron expects
// it and the managed daily self-update cron exists, naming that binary. With
// the knob off only the absence of a berth-managed cron is asserted: a
// foreign file at the path is legitimately left alone (even with --force).
// The self-update itself needs the network and a wall-clock schedule, so it
// is exercised by the live gate, not here.
func assertComposerAutoUpdate(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	assertExitZero(ctx, t, c, "composer installed by berth", "test -x "+shQuote(composerBinPath))
	if !srv.Composer.AutoUpdateEnabled() {
		assertExitZero(ctx, t, c, "no berth-managed composer cron (composer.auto_update: false)",
			"! { test -e "+shQuote(composerUpdateCronPath)+" && head -n 1 "+shQuote(composerUpdateCronPath)+" | grep -qx '# managed by berth'; }")
		return
	}
	assertExitZero(ctx, t, c, "composer self-update cron managed", "head -n 1 "+shQuote(composerUpdateCronPath)+" | grep -qx '# managed by berth'")
	assertExitZero(ctx, t, c, "composer self-update cron targets berth's binary",
		"grep -qF "+shQuote(composerBinPath+" self-update --stable")+" "+shQuote(composerUpdateCronPath))
}

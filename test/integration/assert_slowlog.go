//go:build integration

package integration

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertSlowQueryLog verifies the opt-in MariaDB slow query log end-to-end. The
// file-existence check is load-bearing: Debian 13 ships no /var/log/mysql, and
// when mariadbd cannot open the log at startup it disables slow logging for the
// whole process lifetime while @@slow_query_log still reads ON — so the running
// variables alone would pass on a broken host (the exact bug the tuning step's
// file probe fixes). When the threshold is small enough to wait out, a marker
// query slower than it must actually land in the log. A no-op unless the engine
// is mariadb with the slow log enabled.
func assertSlowQueryLog(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	if srv.Database.Engine != "mariadb" || !srv.Tuning.MariaDBSlowQueryLog {
		return
	}
	const logPath = "/var/log/mysql/mariadb-slow.log" // mirrors steps.mariadbSlowLogPath

	on, err := c.Run(ctx, `sudo mysql --protocol=socket -N -e 'SELECT @@slow_query_log'`, nil)
	if err != nil {
		t.Fatalf("read @@slow_query_log: %v", err)
	}
	if got := strings.TrimSpace(on.Stdout); got != "1" {
		t.Errorf("@@slow_query_log = %q, want 1", got)
	}
	eff := srv.Tuning.MariaDBLongQueryTimeEff()
	lqt, err := c.Run(ctx, `sudo mysql --protocol=socket -N -e 'SELECT CAST(@@long_query_time AS UNSIGNED)'`, nil)
	if err != nil {
		t.Fatalf("read @@long_query_time: %v", err)
	}
	if got := strings.TrimSpace(lqt.Stdout); got != strconv.Itoa(eff) {
		t.Errorf("@@long_query_time = %q, want %d", got, eff)
	}
	assertExitZero(ctx, t, c, "slow log file exists (logging really initialized)",
		"test -f "+logPath)

	// Behavioral proof, bounded: only when the threshold is short enough to wait
	// out in a test. The marker rides in a string literal (a comment could be
	// stripped client-side before it reaches the server or the log).
	if eff > 5 {
		t.Logf("long_query_time %d s > 5 s — skipping the live slow-query capture", eff)
		return
	}
	marker := fmt.Sprintf("berth-slowlog-probe-%d", time.Now().UnixNano())
	assertExitZero(ctx, t, c, "slow query captured in the log",
		fmt.Sprintf(`sudo mysql --protocol=socket -N -e "SELECT SLEEP(%d), '%s'" && sleep 1 && sudo grep -Fq '%s' %s`,
			eff+1, marker, marker, logPath))
}

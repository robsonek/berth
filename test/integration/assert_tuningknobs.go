//go:build integration

package integration

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// mariadbSizeBytes converts a MariaDB K/M/G shorthand (1024-based,
// case-insensitive) to bytes — test-local copy of steps.parseMariaDBSize
// (unexported there). Values come from an already-validated config.
func mariadbSizeBytes(t *testing.T, v string) uint64 {
	t.Helper()
	num, mult := v, uint64(1)
	switch v[len(v)-1] {
	case 'K', 'k':
		num, mult = v[:len(v)-1], 1<<10
	case 'M', 'm':
		num, mult = v[:len(v)-1], 1<<20
	case 'G', 'g':
		num, mult = v[:len(v)-1], 1<<30
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		t.Fatalf("size %q: %v", v, err)
	}
	return n * mult
}

// assertTuningKnobs verifies the tuning pack 2 knobs took effect in the
// RUNNING services (@@variables / the parsed FPM config, not the files berth
// wrote). Every probe is gated on its knob being set in the test config, so
// this is a no-op for configs that do not exercise the knobs.
func assertTuningKnobs(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	if srv.Database.Engine == "mariadb" {
		sizes := []struct{ knob, variable string }{
			{srv.Tuning.MariaDBLogFileSize, "innodb_log_file_size"},
			{srv.Tuning.MariaDBTmpTableSize, "tmp_table_size"},
			{srv.Tuning.MariaDBTmpTableSize, "max_heap_table_size"},
			{srv.Tuning.MariaDBMaxAllowedPacket, "max_allowed_packet"},
		}
		for _, p := range sizes {
			if p.knob == "" {
				continue
			}
			want := mariadbSizeBytes(t, p.knob)
			res, err := c.Run(ctx, `sudo mysql --protocol=socket -N -e 'SELECT @@`+p.variable+`'`, nil)
			if err != nil {
				t.Fatalf("read @@%s: %v", p.variable, err)
			}
			if got := strings.TrimSpace(res.Stdout); got != strconv.FormatUint(want, 10) {
				t.Errorf("@@%s = %q, want %d (%s)", p.variable, got, want, p.knob)
			}
		}
		if v := srv.Tuning.MariaDBMaxConnections; v != 0 {
			res, err := c.Run(ctx, `sudo mysql --protocol=socket -N -e 'SELECT @@max_connections'`, nil)
			if err != nil {
				t.Fatalf("read @@max_connections: %v", err)
			}
			if got := strings.TrimSpace(res.Stdout); got != strconv.Itoa(v) {
				t.Errorf("@@max_connections = %q, want %d", got, v)
			}
		}
	}
	if v := srv.Tuning.PHPFPMMaxChildren; v != 0 {
		res, err := c.Run(ctx, "php-fpm"+srv.PHP.Version+" -tt 2>&1", nil)
		if err != nil {
			t.Fatalf("php-fpm -tt: %v", err)
		}
		// Anchored to end-of-line so knob=5 cannot false-pass on a host
		// serving 50 (decimal-prefix collision).
		re := regexp.MustCompile(fmt.Sprintf(`(?m)^\s*pm\.max_children = %d\s*$`, v))
		if !re.MatchString(res.Stdout + res.Stderr) {
			t.Errorf("php-fpm -tt output lacks pm.max_children = %d", v)
		}
	}
}

//go:build integration

package integration

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// assertPHPTuning verifies the tuning.php_* drop-in is managed and its values
// are EFFECTIVE for the FPM SAPI, and that every vhost's client_max_body_size
// carries the same derived request-body cap, so the whole upload path honors
// one source of truth. The probe is `php-fpm<ver> -i` — the FPM binary prints
// phpinfo for its own SAPI and, unlike the CLI SAPI, does not hardcode
// max_execution_time to 0 (verified in docker debian:trixie: a conf.d value of
// 30 reports `max_execution_time => 30 => 30`, exit 0). Expected values come
// from the same Tuning *Eff accessors production rendering uses — the
// assertions can never drift from the derivation. phpinfo rows are matched as
// `key => local => ` so a longer actual value (300 vs 30) can never false-pass
// a substring check.
func assertPHPTuning(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	ver := srv.PHP.Version
	tn := srv.Tuning
	dropin := "/etc/php/" + ver + "/fpm/conf.d/99-berth-tuning.ini"
	body, err := c.Run(ctx, "cat "+dropin, nil)
	if err != nil {
		t.Fatalf("read tuning drop-in: %v", err)
	}
	if body.ExitCode != 0 || !strings.Contains(body.Stdout, "managed by berth") {
		t.Errorf("tuning drop-in %s missing or unmanaged (exit %d)", dropin, body.ExitCode)
	}

	info, err := c.Run(ctx, "php-fpm"+ver+" -i", nil)
	if err != nil {
		t.Fatalf("php-fpm%s -i: %v", ver, err)
	}
	if info.ExitCode != 0 {
		t.Fatalf("php-fpm%s -i exit %d: %s", ver, info.ExitCode, strings.TrimSpace(info.Stderr))
	}
	for _, want := range []string{
		"memory_limit => " + tn.PHPMemoryLimitEff() + " => ",
		"upload_max_filesize => " + tn.PHPUploadMaxEff() + " => ",
		"post_max_size => " + tn.PHPPostBodyMaxEff() + " => ",
		"max_execution_time => " + strconv.Itoa(tn.PHPMaxExecutionTimeEff()) + " => ",
		"max_input_vars => " + strconv.Itoa(tn.PHPMaxInputVarsEff()) + " => ",
		"expose_php => Off => ",
	} {
		key := want[:strings.Index(want, " =>")]
		if !strings.Contains(info.Stdout, want) {
			t.Errorf("FPM %s not effective (want %q):\n%s", key, want, grepLines(info.Stdout, key))
		}
	}

	// nginx carries the SAME derived cap in every vhost (the upload path's
	// other half — without it uploads die at nginx with 413 before PHP). The
	// trailing ';' anchors the grep against longer values.
	bodyMax := "client_max_body_size " + tn.PHPPostBodyMaxEff() + ";"
	for _, site := range srv.Sites {
		vhost := "/etc/nginx/sites-available/" + site.Domain
		assertExitZero(ctx, t, c, "nginx body cap "+site.Domain,
			"grep -qF '"+bodyMax+"' "+vhost)
	}
}

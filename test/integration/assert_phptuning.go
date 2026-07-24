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

// assertPHPTuning verifies the tuning.php_* drop-in is effective for the FPM
// SAPI and that every vhost's client_max_body_size carries the same derived
// request-body cap, so the whole upload path honors one source of truth.
// Expected values come from the same Tuning *Eff accessors production
// rendering uses — the assertions can never drift from the derivation.
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
	// max_execution_time can only be asserted at the file level: the CLI SAPI
	// (which `php -i` below runs under) hardcodes it to 0 regardless of ini
	// files, so the effective-value probe would always read 0.
	if want := "max_execution_time = " + strconv.Itoa(tn.PHPMaxExecutionTimeEff()); !strings.Contains(body.Stdout, want) {
		t.Errorf("tuning drop-in missing %q:\n%s", want, body.Stdout)
	}

	// Effective values for the FPM SAPI — same PHP_INI_SCAN_DIR technique as
	// assertOpcacheEffective (php-fpm has no -i; the CLI SAPI's own php.ini
	// loads first, then the FPM conf.d overrides it, mirroring FPM's chain).
	info, err := c.Run(ctx, "PHP_INI_SCAN_DIR=/etc/php/"+ver+"/fpm/conf.d php"+ver+" -i", nil)
	if err != nil {
		t.Fatalf("php -i (fpm scan dir): %v", err)
	}
	for _, want := range []string{
		"memory_limit => " + tn.PHPMemoryLimitEff(),
		"upload_max_filesize => " + tn.PHPUploadMaxEff(),
		"post_max_size => " + tn.PHPPostBodyMaxEff(),
		"max_input_vars => " + strconv.Itoa(tn.PHPMaxInputVarsEff()),
		"expose_php => Off",
	} {
		key := want[:strings.Index(want, " =>")]
		if !strings.Contains(info.Stdout, want) {
			t.Errorf("FPM %s not effective (want %q):\n%s", key, want, grepLines(info.Stdout, key))
		}
	}

	// nginx carries the SAME derived cap in every vhost (the upload path's
	// other half — without it uploads die at nginx with 413 before PHP).
	bodyMax := "client_max_body_size " + tn.PHPPostBodyMaxEff() + ";"
	for _, site := range srv.Sites {
		vhost := "/etc/nginx/sites-available/" + site.Domain
		assertExitZero(ctx, t, c, "nginx body cap "+site.Domain,
			"grep -qF '"+bodyMax+"' "+vhost)
	}
}

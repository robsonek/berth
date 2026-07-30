package status

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func certSrv() *config.Server {
	return &config.Server{
		ID: "t", Host: "h",
		PHP:      config.PHP{Version: "8.4"},
		Database: config.Database{Engine: "mariadb"},
		Sites: []config.Site{
			{Domain: "app.example.com", SSL: true},
			{Domain: "stage.example.com", SSL: true, SSLMode: "selfsigned"},
			{Domain: "plain.example.com"},
		},
	}
}

func TestProbeCertsReadsExpiryAndDaysLeft(t *testing.T) {
	s := certSrv()
	cmd := certsCmd([]string{
		"/etc/letsencrypt/live/app.example.com/fullchain.pem",
		"/etc/ssl/berth/stage.example.com/fullchain.pem",
	})
	f := bssh.NewFakeRunner().On(cmd, bssh.Result{Stdout: "" +
		"/etc/letsencrypt/live/app.example.com/fullchain.pem\tnotAfter=Sep 28 07:31:00 2026 GMT\n" +
		"/etc/ssl/berth/stage.example.com/fullchain.pem\t\n"})

	hostTime := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	got, err := probeCerts(context.Background(), f, s, hostTime)
	if err != nil {
		t.Fatalf("probeCerts: %v", err)
	}

	app := got["app.example.com"]
	if !app.Present || app.Mode != "letsencrypt" {
		t.Fatalf("app cert = %+v, want present letsencrypt", app)
	}
	if app.DaysLeft == nil || *app.DaysLeft != 61 {
		t.Errorf("DaysLeft = %v, want 61", app.DaysLeft)
	}

	// A declared-but-not-yet-issued certificate is present:false with no dates
	// — never a zero time that renders as 1970 or as "expired".
	stage := got["stage.example.com"]
	if stage.Present || stage.NotAfter != nil || stage.DaysLeft != nil {
		t.Errorf("stage cert = %+v, want absent with nil dates", stage)
	}
	if stage.Mode != "selfsigned" {
		t.Errorf("stage mode = %q, want selfsigned", stage.Mode)
	}

	// A site without ssl is not probed at all.
	if _, ok := got["plain.example.com"]; ok {
		t.Error("a non-SSL site must not appear in the cert map")
	}
}

// Days left is computed against the HOST clock, not the collector's: a skewed
// laptop must not shift every expiry in the fleet.
func TestProbeCertsUsesHostClock(t *testing.T) {
	s := &config.Server{
		ID: "t", Host: "h",
		PHP: config.PHP{Version: "8.4"}, Database: config.Database{Engine: "mariadb"},
		Sites: []config.Site{{Domain: "app.example.com", SSL: true}},
	}
	cmd := certsCmd([]string{"/etc/letsencrypt/live/app.example.com/fullchain.pem"})
	f := bssh.NewFakeRunner().On(cmd, bssh.Result{
		Stdout: "/etc/letsencrypt/live/app.example.com/fullchain.pem\tnotAfter=Sep 28 07:31:00 2026 GMT\n"})

	got, err := probeCerts(context.Background(), f, s, time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if d := got["app.example.com"].DaysLeft; d == nil || *d != 1 {
		t.Errorf("DaysLeft = %v, want 1", d)
	}
}

func TestProbeCertsNoSSLSitesIssuesNoCommand(t *testing.T) {
	s := &config.Server{
		ID: "t", Host: "h",
		PHP: config.PHP{Version: "8.4"}, Database: config.Database{Engine: "mariadb"},
		Sites: []config.Site{{Domain: "plain.example.com"}},
	}
	f := bssh.NewFakeRunner() // every command is unstubbed → any call errors
	got, err := probeCerts(context.Background(), f, s, time.Now())
	if err != nil {
		t.Fatalf("probeCerts must not run a command with no SSL sites: %v", err)
	}
	if len(got) != 0 || len(f.Calls()) != 0 {
		t.Errorf("got %d certs and %d calls, want 0 and 0", len(got), len(f.Calls()))
	}
}

// The probe's for-loop exits with the last printf's status (0) even when an
// individual openssl call fails, so a non-zero exit means the loop itself
// never ran cleanly (e.g. sudo -n denied) — that must be a loud error, not
// an empty map at exit 0. Mirrors TestProbeServicesFailsOnNonZeroExit.
func TestProbeCertsFailsOnNonZeroExit(t *testing.T) {
	s := &config.Server{
		ID: "t", Host: "h",
		PHP: config.PHP{Version: "8.4"}, Database: config.Database{Engine: "mariadb"},
		Sites: []config.Site{{Domain: "app.example.com", SSL: true}},
	}
	cmd := certsCmd([]string{"/etc/letsencrypt/live/app.example.com/fullchain.pem"})
	f := bssh.NewFakeRunner().On(cmd,
		bssh.Result{ExitCode: 1, Stderr: "sudo: a password is required\n"})

	got, err := probeCerts(context.Background(), f, s, time.Now())
	if err == nil {
		t.Fatalf("probeCerts = %v, want error on exit 1", got)
	}
	if !strings.Contains(err.Error(), "sudo: a password is required") {
		t.Errorf("error %q does not surface the host's stderr", err)
	}
}

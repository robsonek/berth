package status

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func srvFixture() *config.Server {
	return &config.Server{
		ID: "t", Host: "h",
		PHP:      config.PHP{Version: "8.4"},
		Database: config.Database{Engine: "mariadb"},
		Valkey:   true,
		Sites:    []config.Site{{Domain: "app.example.com"}},
	}
}

func TestUnitListCoversTheDeclaredStack(t *testing.T) {
	got := unitList(srvFixture())
	want := []string{"nginx", "php8.4-fpm", "mariadb", "fail2ban", "cron", "ssh", "berth-valkey-app_example_com.service"}
	if len(got) != len(want) {
		t.Fatalf("units = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("unit[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestUnitListPostgresAndNoValkey(t *testing.T) {
	s := srvFixture()
	s.Database.Engine = "postgres"
	s.Valkey = false
	got := unitList(s)
	for _, u := range got {
		if u == "mariadb" || u == "berth-valkey-app_example_com.service" {
			t.Errorf("unexpected unit %q for a postgres, valkey-less server", u)
		}
	}
	var hasPG bool
	for _, u := range got {
		if u == "postgresql" {
			hasPG = true
		}
	}
	if !hasPG {
		t.Error("postgresql unit missing")
	}
}

// A server whose TLS sites are all self-signed has no certbot, so its renewal
// timer is correctly absent — listing it would report a healthy server as DOWN.
func TestUnitListOmitsCertbotTimerForSelfSignedOnly(t *testing.T) {
	s := srvFixture()
	s.Sites = []config.Site{{Domain: "app.example.com", SSL: true, SSLMode: "selfsigned"}}
	for _, u := range unitList(s) {
		if u == "certbot.timer" {
			t.Error("certbot.timer must not be expected on a selfsigned-only server")
		}
	}

	s.Sites = append(s.Sites, config.Site{Domain: "real.example.com", SSL: true})
	var found bool
	for _, u := range unitList(s) {
		if u == "certbot.timer" {
			found = true
		}
	}
	if !found {
		t.Error("certbot.timer must be expected once a Let's Encrypt site exists")
	}
}

func TestProbeServicesParsesActiveAndEnabled(t *testing.T) {
	s := srvFixture()
	cmd := servicesCmd(unitList(s))
	f := bssh.NewFakeRunner().On(cmd, bssh.Result{Stdout: "" +
		"nginx\tactive\tenabled\n" +
		"php8.4-fpm\tactive\tenabled\n" +
		"mariadb\tinactive\tenabled\n" +
		"fail2ban\tactive\tdisabled\n" +
		"cron\tactive\tenabled\n" +
		"ssh\tactive\tenabled\n" +
		"berth-valkey-app_example_com.service\t\t\n"})

	got, warn, err := probeServices(context.Background(), f, s)
	if err != nil {
		t.Fatalf("probeServices: %v", err)
	}
	if warn != nil {
		t.Fatalf("warn = %v, want none for a complete answer", warn)
	}
	byName := map[string]Service{}
	for _, sv := range got {
		byName[sv.Name] = sv
	}
	if sv := byName["mariadb"]; sv.Active || !sv.Enabled {
		t.Errorf("mariadb = %+v, want inactive+enabled", sv)
	}
	if sv := byName["fail2ban"]; !sv.Active || sv.Enabled {
		t.Errorf("fail2ban = %+v, want active+disabled", sv)
	}
	// An absent unit produces empty fields; it must read as down, never as up.
	if sv := byName["berth-valkey-app_example_com.service"]; sv.Active || sv.Enabled {
		t.Errorf("absent unit = %+v, want inactive+disabled", sv)
	}
}

// Output carrying only SOME of the requested units (exit 0) is an incomplete
// answer, not a smaller server: every requested unit must still appear, in the
// request order, with the unanswered ones reading as down — and the truncation
// must be reported so it reaches the exit code.
func TestProbeServicesReportsMissingUnits(t *testing.T) {
	s := srvFixture()
	units := unitList(s)
	f := bssh.NewFakeRunner().On(servicesCmd(units), bssh.Result{Stdout: "" +
		"nginx\tactive\tenabled\n" +
		"cron\tactive\tenabled\n"})

	got, warn, err := probeServices(context.Background(), f, s)
	if err != nil {
		t.Fatalf("a truncated answer is degraded, not fatal: %v", err)
	}
	if len(got) != len(units) {
		t.Fatalf("got %d entries, want all %d requested units", len(got), len(units))
	}
	// The order is the REQUEST order, so the rendered table never shuffles.
	for i, u := range units {
		if got[i].Name != u {
			t.Errorf("unit[%d] = %q, want %q", i, got[i].Name, u)
		}
	}
	for _, sv := range got {
		if sv.Name != "nginx" && sv.Name != "cron" && (sv.Active || sv.Enabled) {
			t.Errorf("unanswered unit %q = %+v, must read as down", sv.Name, sv)
		}
	}
	if warn == nil || !strings.Contains(warn.Error(), "ssh") {
		t.Errorf("warn = %v, want the missing units named", warn)
	}
}

// A duplicate row could carry conflicting states and an unexpected row is not
// something this probe asked about: both are anomalies to report, never to
// silently fold into the result.
func TestProbeServicesRejectsDuplicateAndUnexpectedRows(t *testing.T) {
	s := srvFixture()
	units := unitList(s)
	var rows strings.Builder
	for _, u := range units {
		rows.WriteString(u + "\tactive\tenabled\n")
	}
	rows.WriteString("nginx\tinactive\tdisabled\n") // duplicate, conflicting
	rows.WriteString("rogue\tactive\tenabled\n")    // never requested
	f := bssh.NewFakeRunner().On(servicesCmd(units), bssh.Result{Stdout: rows.String()})

	got, warn, err := probeServices(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(units) {
		t.Fatalf("got %d entries, want %d", len(got), len(units))
	}
	if !got[0].Active || !got[0].Enabled {
		t.Errorf("nginx = %+v, want the FIRST row kept, not the duplicate", got[0])
	}
	for _, sv := range got {
		if sv.Name == "rogue" {
			t.Error("an unexpected row must not enter the result")
		}
	}
	if warn == nil || !strings.Contains(warn.Error(), "duplicate") || !strings.Contains(warn.Error(), "rogue") {
		t.Errorf("warn = %v, want both anomalies named", warn)
	}
}

// A non-zero exit is data, not a Go error (Runner contract). If the command
// itself fails — sudo denied on a half-broken host — the probe must return an
// error, not an empty slice that renders as a clean-looking blank at exit 0.
func TestProbeServicesFailsOnNonZeroExit(t *testing.T) {
	s := srvFixture()
	f := bssh.NewFakeRunner().On(servicesCmd(unitList(s)),
		bssh.Result{ExitCode: 1, Stderr: "sudo: a password is required\n"})

	got, _, err := probeServices(context.Background(), f, s)
	if err == nil {
		t.Fatalf("probeServices = %v, want error on exit 1", got)
	}
	if !strings.Contains(err.Error(), "sudo: a password is required") {
		t.Errorf("error %q does not surface the host's stderr", err)
	}
}

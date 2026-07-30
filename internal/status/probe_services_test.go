package status

import (
	"context"
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
		"berth-valkey-app_example_com.service\t\t\n"})

	got, err := probeServices(context.Background(), f, s)
	if err != nil {
		t.Fatalf("probeServices: %v", err)
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

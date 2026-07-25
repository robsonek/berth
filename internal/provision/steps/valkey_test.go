package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestValkeyRequiresBase(t *testing.T) {
	if got := Valkey().Requires(); len(got) != 1 || got[0] != "base" {
		t.Fatalf("Requires() = %v, want [base]", got)
	}
}

func TestValkeyCheckSatisfiedWhenInstalledAndUp(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s valkey-server", bssh.Result{ExitCode: 0})
	f.On("systemctl is-active valkey-server.service", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled valkey-server.service", bssh.Result{ExitCode: 0})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when valkey-server installed and running; got %+v", cr)
	}
}

func TestValkeyCheckUnsatisfiedWhenNotInstalled(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("dpkg -s valkey-server", bssh.Result{ExitCode: 1})
	f.On("systemctl is-active valkey-server.service", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled valkey-server.service", bssh.Result{ExitCode: 0})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, &config.Server{}, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when valkey-server is not installed")
	}
}

func TestValkeyPathHelpers(t *testing.T) {
	if got := valkeyInstanceUnit("app.example.com"); got != "berth-valkey-app_example_com.service" {
		t.Errorf("valkeyInstanceUnit = %q", got)
	}
	if got := valkeyUnitPath("app.example.com"); got != "/etc/systemd/system/berth-valkey-app_example_com.service" {
		t.Errorf("valkeyUnitPath = %q", got)
	}
	if got := valkeySocketPath("app.example.com"); got != "/run/berth-valkey/app_example_com/valkey.sock" {
		t.Errorf("valkeySocketPath = %q", got)
	}
	if got := valkeyDataDir("app.example.com"); got != "/var/lib/berth-valkey/app_example_com" {
		t.Errorf("valkeyDataDir = %q", got)
	}
}

func TestRenderValkeyUnit(t *testing.T) {
	s := &config.Server{Sites: []config.Site{{Domain: "app.example.com", User: "tenant1"}}}
	got, err := renderValkeyUnit(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if !strings.HasPrefix(body, "# managed by berth\n") {
		t.Errorf("unit must start with the managed marker:\n%s", body)
	}
	for _, want := range []string{
		"User=tenant1",
		"Group=tenant1",
		"RuntimeDirectory=berth-valkey/app_example_com",
		"RuntimeDirectoryMode=0700",
		"StateDirectory=berth-valkey/app_example_com",
		"StateDirectoryMode=0700",
		"--port 0",
		"--unixsocket /run/berth-valkey/app_example_com/valkey.sock",
		"--unixsocketperm 600",
		"--dir /var/lib/berth-valkey/app_example_com",
		"--maxmemory 256mb",              // default from ValkeyMaxmemoryEff
		"--maxmemory-policy allkeys-lru", // default from PolicyEff
		"Type=notify",
		"--supervised systemd",
		"Restart=always",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("unit missing %q:\n%s", want, body)
		}
	}
}

func TestValkeyApplyInstallsAndEnables(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl enable --now valkey-server.service", bssh.Result{})
	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, &config.Server{}, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"apt-get install -y valkey-server", "systemctl enable --now valkey-server.service"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Apply did not run %q; calls:\n%s", want, joined)
		}
	}
}

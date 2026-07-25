package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func valkeyServer() *config.Server {
	return &config.Server{Sites: []config.Site{{Domain: "app.example.com", User: "tenant1"}}}
}

// valkeyLoadedCmd mirrors serviceConfigLoaded's exact command construction
// (tuning.go:180) for an instance unit — FakeRunner needs the exact string.
// Keep it byte-identical to the production helper's fmt (copy, don't retype).
func valkeyLoadedCmd(domain string) string {
	return `[ "$(stat -c %Y ` + shQuote(valkeyUnitPath(domain)) + ` 2>/dev/null)" -le "$(date -d "$(systemctl show -p ActiveEnterTimestamp --value ` + valkeyInstanceUnit(domain) + `)" +%s 2>/dev/null)" ]`
}

func valkeyCacheFreshCmd(domain string) string {
	return "systemctl show -p NeedDaemonReload --value " + valkeyInstanceUnit(domain)
}

// stubValkeyCheckGreen stubs every probe of a fully converged single-site host.
func stubValkeyCheckGreen(f *bssh.FakeRunner, s *config.Server) {
	f.On("dpkg -s valkey-server", bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled valkey-server.service", bssh.Result{ExitCode: 1, Stdout: "disabled\n"})
	f.On("systemctl is-active valkey-server.service", bssh.Result{ExitCode: 3, Stdout: "inactive\n"})
	f.On("cat "+shQuote(valkeyDropInPath), bssh.Result{ExitCode: 1}) // legacy tuning drop-in absent
	site := s.Sites[0]
	want, _ := renderValkeyUnit(s, site)
	f.On("cat "+shQuote(valkeyUnitPath(site.Domain)), bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On("systemctl is-active "+valkeyInstanceUnit(site.Domain), bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled "+valkeyInstanceUnit(site.Domain), bssh.Result{ExitCode: 0})
	f.On(valkeyLoadedCmd(site.Domain), bssh.Result{ExitCode: 0})
	f.On(valkeyCacheFreshCmd(site.Domain), bssh.Result{ExitCode: 0, Stdout: "no\n"})
	f.On(valkeyPingCmd("tenant1", site.Domain), bssh.Result{ExitCode: 0, Stdout: "PONG\n"})
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0, Stdout: valkeyUnitPath(site.Domain) + "\n"})
}

func TestValkeyRequiresBaseAndAccounts(t *testing.T) {
	got := Valkey().Requires()
	if len(got) != 2 || got[0] != "base" || got[1] != "accounts" {
		t.Fatalf("Requires() = %v, want [base accounts]", got)
	}
}

func TestValkeyCheckSatisfiedFleet(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestValkeyCheckUnsatisfiedWhenStockEnabled(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	// Stock service re-enabled by hand: the unauthenticated 6379 listener is back.
	f.On("systemctl is-enabled valkey-server.service", bssh.Result{ExitCode: 0, Stdout: "enabled\n"})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while the stock shared service is enabled")
	}
}

func TestValkeyCheckUnsatisfiedWhenPingFails(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	f.On(valkeyPingCmd("tenant1", "app.example.com"), bssh.Result{ExitCode: 1, Stderr: "Connection refused"})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the instance does not answer PONG as the site user")
	}
}

func TestValkeyCheckUnsatisfiedOnManagedOrphanUnit(t *testing.T) {
	s := valkeyServer()
	orphan := "/etc/systemd/system/berth-valkey-gone_example_com.service"
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0,
		Stdout: valkeyUnitPath("app.example.com") + "\n" + orphan + "\n"})
	f.On("cat "+shQuote(orphan), bssh.Result{ExitCode: 0, Stdout: managedMarker + "\n[Service]\n"})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while a berth-managed orphan unit remains")
	}
}

func TestValkeyCheckIgnoresForeignGlobMatch(t *testing.T) {
	// A hand-written unit matching the glob is NOT berth's to remove: Apply
	// skips it (managedFilePresent guard), so Check counting it as an orphan
	// would make the step permanently unsatisfiable. It must not block.
	s := valkeyServer()
	foreign := "/etc/systemd/system/berth-valkey-foreign_example_com.service"
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0,
		Stdout: valkeyUnitPath("app.example.com") + "\n" + foreign + "\n"})
	f.On("cat "+shQuote(foreign), bssh.Result{ExitCode: 0, Stdout: "[Unit]\nDescription=hand-written\n"})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied despite a foreign glob match; got %+v", cr)
	}
}

func TestValkeyCheckUnsatisfiedWhenUnitNotLoaded(t *testing.T) {
	// Crash window: unit written (+ maybe daemon-reload) but the instance was
	// never restarted — bytes match, service active, PONG answers from the OLD
	// process. The mtime-vs-ActiveEnterTimestamp probe must flag it.
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	f.On(valkeyLoadedCmd("app.example.com"), bssh.Result{ExitCode: 1})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the running instance predates its unit file")
	}
}

func TestValkeyCheckUnsatisfiedWhenManagerCacheStale(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	f.On(valkeyCacheFreshCmd("app.example.com"), bssh.Result{ExitCode: 0, Stdout: "yes\n"})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when systemd needs a daemon-reload for the unit")
	}
}

func TestValkeyCheckAbortsOnUnmanagedUnit(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{ExitCode: 0, Stdout: "[Unit]\nDescription=hand-written\n"})
	if _, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f); err == nil {
		t.Fatal("expected abort on an unmanaged file at the instance unit path without --force")
	}
}

func TestValkeyCheckUnsatisfiedWhenLegacyTuningDropInPresent(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	f.On("cat "+shQuote(valkeyDropInPath), bssh.Result{ExitCode: 0, Stdout: managedMarker + "\n[Service]\nExecStart=\n"})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while the legacy berth-managed tuning drop-in remains")
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

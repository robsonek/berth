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
// (tuning.go) for an instance unit — FakeRunner needs the exact string.
// Keep it byte-identical to the production helper's fmt (copy, don't retype).
func valkeyLoadedCmd(domain string) string {
	return `[ "$(stat -c %Y ` + shQuote(valkeyUnitPath(domain)) + ` 2>/dev/null)" -le "$(systemctl show -p ActiveEnterTimestamp --value --timestamp=unix ` + valkeyInstanceUnit(domain) + ` 2>/dev/null | tr -d @)" ]`
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
	f.On(valkeyExecCmd(valkeyInstanceUnit(site.Domain)), bssh.Result{ExitCode: 0})
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
	_, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
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

// TestValkeyExecCmdFollowsSymlinkBothSides guards the idempotency bug found on
// a fresh box: /usr/bin/valkey-server is a symlink to the multi-call binary,
// so the exec-freshness probe MUST `stat -L` (follow) BOTH the process's exe
// and the binary path — otherwise it compares the process's real inode to the
// symlink's inode, never matches, and every healthy instance re-applies
// forever. Unit tests cannot model symlink resolution (FakeRunner stubs the
// string), so pin the command shape.
func TestValkeyExecCmdFollowsSymlinkBothSides(t *testing.T) {
	cmd := valkeyExecCmd("berth-valkey-app_example_com.service")
	if !strings.Contains(cmd, "stat -Lc %i /proc/$p/exe") {
		t.Errorf("exec probe must stat -L the process exe:\n%s", cmd)
	}
	if !strings.Contains(cmd, "stat -Lc %i "+valkeyBinary) {
		t.Errorf("exec probe must stat -L the binary (it is a symlink to the multi-call binary):\n%s", cmd)
	}
	if strings.Contains(cmd, "stat -c %i "+valkeyBinary) {
		t.Errorf("exec probe must NOT bare-stat the symlink (compares symlink inode, never matches):\n%s", cmd)
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
		"TimeoutStopSec=infinity",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("unit missing %q:\n%s", want, body)
		}
	}
}

func TestValkeyApplyConvergesFreshFleet(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl disable --now valkey-server.service", bssh.Result{})
	f.On("cat "+shQuote(valkeyDropInPath), bssh.Result{ExitCode: 1})                  // legacy: absent
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0})                                // no instances yet
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl enable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	// Fresh unit -> no restart; the post-enable liveness/heal probes run:
	f.On(valkeyLoadedCmd("app.example.com"), bssh.Result{ExitCode: 0})
	f.On(valkeyCacheFreshCmd("app.example.com"), bssh.Result{ExitCode: 0, Stdout: "no\n"})
	f.On(valkeyExecCmd(valkeyInstanceUnit("app.example.com")), bssh.Result{ExitCode: 0})
	f.On(valkeyPingCmd("tenant1", "app.example.com"), bssh.Result{ExitCode: 0, Stdout: "PONG\n"})

	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	idx := func(want string) int {
		for i, c := range f.Calls() {
			if c.Cmd == want {
				return i
			}
		}
		return -1
	}
	// lastIdx: the unit path is cat'ed twice (checkManagedFile, then
	// writeManagedFile's guard). The SECOND cat immediately precedes the
	// actual write — the closest observable proxy for write-before-reload,
	// since FakeRunner records WriteFile outside the Run timeline.
	lastIdx := func(want string) int {
		last := -1
		for i, c := range f.Calls() {
			if c.Cmd == want {
				last = i
			}
		}
		return last
	}
	install := idx("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server")
	stockOff := idx("systemctl disable --now valkey-server.service")
	guard := lastIdx("cat " + shQuote(valkeyUnitPath("app.example.com")))
	reload := idx("systemctl daemon-reload")
	enable := idx("systemctl enable --now " + valkeyInstanceUnit("app.example.com"))
	if install < 0 || stockOff < 0 || guard < 0 || reload < 0 || enable < 0 {
		t.Fatalf("missing commands; install=%d stockOff=%d guard=%d reload=%d enable=%d", install, stockOff, guard, reload, enable)
	}
	if !(install < stockOff && stockOff < guard && guard < reload && reload < enable) {
		t.Errorf("want install < stock-disable < write-guard < daemon-reload < enable; got %d %d %d %d %d", install, stockOff, guard, reload, enable)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl restart "+valkeyInstanceUnit("app.example.com") {
			t.Error("a FRESH unit must not be restarted after enable --now")
		}
	}
	var wrote bool
	for _, w := range f.Writes() {
		if w.Path == valkeyUnitPath("app.example.com") {
			wrote = true
			if w.Owner != "root" || w.Group != "root" || w.Mode != 0o644 {
				t.Errorf("unit FileSpec = %s:%s %o, want root:root 644", w.Owner, w.Group, w.Mode)
			}
		}
	}
	if !wrote {
		t.Error("instance unit was not written")
	}
}

func TestValkeyApplyRestartsDriftedUnit(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl disable --now valkey-server.service", bssh.Result{})
	f.On("cat "+shQuote(valkeyDropInPath), bssh.Result{ExitCode: 1})
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0, Stdout: valkeyUnitPath("app.example.com") + "\n"})
	// Managed unit with stale content -> drift -> rewrite + restart.
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")),
		bssh.Result{ExitCode: 0, Stdout: managedMarker + "\n[Service]\nExecStart=/usr/bin/valkey-server --old\n"})
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl enable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On("systemctl restart "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On(valkeyPingCmd("tenant1", "app.example.com"), bssh.Result{ExitCode: 0, Stdout: "PONG\n"})

	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var restarted bool
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl restart "+valkeyInstanceUnit("app.example.com") {
			restarted = true
		}
	}
	if !restarted {
		t.Error("a drifted unit must be restarted to load the new config")
	}
}

func TestValkeyApplyHealsWedgedInstance(t *testing.T) {
	// Everything on disk is converged, but the daemon does not answer (wedged
	// process, vanished socket). Without the heal path Check stays unsatisfied
	// and Apply is a no-op — an infinite loop. Apply must restart once and
	// re-probe.
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl disable --now valkey-server.service", bssh.Result{})
	f.On("cat "+shQuote(valkeyDropInPath), bssh.Result{ExitCode: 1})
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0, Stdout: valkeyUnitPath("app.example.com") + "\n"})
	want, _ := renderValkeyUnit(s, s.Sites[0])
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{ExitCode: 0, Stdout: string(want)}) // up to date
	f.On("systemctl enable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On(valkeyLoadedCmd("app.example.com"), bssh.Result{ExitCode: 0})
	f.On(valkeyCacheFreshCmd("app.example.com"), bssh.Result{ExitCode: 0, Stdout: "no\n"})
	f.On(valkeyExecCmd(valkeyInstanceUnit("app.example.com")), bssh.Result{ExitCode: 0})
	f.OnSeq(valkeyPingCmd("tenant1", "app.example.com"),
		bssh.Result{ExitCode: 1, Stderr: "Connection refused"},
		bssh.Result{ExitCode: 0, Stdout: "PONG\n"})
	f.On("systemctl restart "+valkeyInstanceUnit("app.example.com"), bssh.Result{})

	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var restarts int
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl restart "+valkeyInstanceUnit("app.example.com") {
			restarts++
		}
	}
	if restarts != 1 {
		t.Errorf("expected exactly one healing restart, got %d", restarts)
	}
	// No daemon-reload: nothing on disk changed.
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl daemon-reload" {
			t.Error("no daemon-reload expected when no unit changed")
		}
	}
}

func TestValkeyApplyReloadsStaleManagerCache(t *testing.T) {
	// Crash window: a previous run wrote the unit but died before its
	// daemon-reload. On this run nothing on disk changes, yet NeedDaemonReload
	// is "yes" — restart alone re-runs the manager's CACHED definition, so
	// Apply must daemon-reload first or the step never converges.
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl disable --now valkey-server.service", bssh.Result{})
	f.On("cat "+shQuote(valkeyDropInPath), bssh.Result{ExitCode: 1})
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0, Stdout: valkeyUnitPath("app.example.com") + "\n"})
	want, _ := renderValkeyUnit(s, s.Sites[0])
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{ExitCode: 0, Stdout: string(want)}) // up to date
	f.On("systemctl enable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On(valkeyLoadedCmd("app.example.com"), bssh.Result{ExitCode: 0})
	f.On(valkeyCacheFreshCmd("app.example.com"), bssh.Result{ExitCode: 0, Stdout: "yes\n"}) // stale cache
	f.On(valkeyExecCmd(valkeyInstanceUnit("app.example.com")), bssh.Result{ExitCode: 0})
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl restart "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On(valkeyPingCmd("tenant1", "app.example.com"), bssh.Result{ExitCode: 0, Stdout: "PONG\n"})

	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	reloads, restarts, reloadIdx, restartIdx := 0, 0, -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "systemctl daemon-reload":
			reloads++
			reloadIdx = i
		case "systemctl restart " + valkeyInstanceUnit("app.example.com"):
			restarts++
			restartIdx = i
		}
	}
	if reloads != 1 || restarts != 1 {
		t.Fatalf("expected exactly one daemon-reload and one restart, got %d and %d", reloads, restarts)
	}
	if reloadIdx > restartIdx {
		t.Errorf("daemon-reload (idx %d) must precede the restart (idx %d)", reloadIdx, restartIdx)
	}
}

func TestValkeyApplyFailsLoudWhenInstanceStaysDead(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl disable --now valkey-server.service", bssh.Result{})
	f.On("cat "+shQuote(valkeyDropInPath), bssh.Result{ExitCode: 1})
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0, Stdout: valkeyUnitPath("app.example.com") + "\n"})
	want, _ := renderValkeyUnit(s, s.Sites[0])
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On("systemctl enable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On(valkeyLoadedCmd("app.example.com"), bssh.Result{ExitCode: 0})
	f.On(valkeyCacheFreshCmd("app.example.com"), bssh.Result{ExitCode: 0, Stdout: "no\n"})
	f.On(valkeyExecCmd(valkeyInstanceUnit("app.example.com")), bssh.Result{ExitCode: 0})
	f.On(valkeyPingCmd("tenant1", "app.example.com"), bssh.Result{ExitCode: 1, Stderr: "Connection refused"})
	f.On("systemctl restart "+valkeyInstanceUnit("app.example.com"), bssh.Result{})

	err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "PONG") {
		t.Fatalf("err = %v, want a loud does-not-answer-PONG failure", err)
	}
	var restarts int
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl restart "+valkeyInstanceUnit("app.example.com") {
			restarts++
		}
	}
	if restarts != 1 {
		t.Errorf("expected exactly one healing restart before failing, got %d", restarts)
	}
}

func TestValkeyApplySweepsOrphanAndLegacyDropIn(t *testing.T) {
	s := valkeyServer()
	orphan := "/etc/systemd/system/berth-valkey-gone_example_com.service"
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl disable --now valkey-server.service", bssh.Result{})
	// Legacy berth-managed tuning drop-in present -> removed (+ rmdir attempt).
	f.On("cat "+shQuote(valkeyDropInPath), bssh.Result{ExitCode: 0, Stdout: managedMarker + "\n[Service]\n"})
	f.On("rm -f "+shQuote(valkeyDropInPath), bssh.Result{})
	f.On("rmdir --ignore-fail-on-non-empty "+shQuote(valkeyDropInDir), bssh.Result{})
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0, Stdout: orphan + "\n"})
	f.On("cat "+shQuote(orphan), bssh.Result{ExitCode: 0, Stdout: managedMarker + "\n[Service]\n"})
	f.On("systemctl disable --now berth-valkey-gone_example_com.service", bssh.Result{})
	f.On("rm -f "+shQuote(orphan), bssh.Result{})
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl enable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On(valkeyLoadedCmd("app.example.com"), bssh.Result{ExitCode: 0})
	f.On(valkeyCacheFreshCmd("app.example.com"), bssh.Result{ExitCode: 0, Stdout: "no\n"})
	f.On(valkeyExecCmd(valkeyInstanceUnit("app.example.com")), bssh.Result{ExitCode: 0})
	f.On(valkeyPingCmd("tenant1", "app.example.com"), bssh.Result{ExitCode: 0, Stdout: "PONG\n"})

	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var sawOrphanRm, sawLegacyRm bool
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "rm -f " + shQuote(orphan):
			sawOrphanRm = true
		case "rm -f " + shQuote(valkeyDropInPath):
			sawLegacyRm = true
		}
	}
	if !sawOrphanRm || !sawLegacyRm {
		t.Errorf("expected orphan and legacy drop-in removal; orphan=%v legacy=%v", sawOrphanRm, sawLegacyRm)
	}
}

func TestValkeyApplyLeavesForeignOrphanUnit(t *testing.T) {
	s := valkeyServer()
	orphan := "/etc/systemd/system/berth-valkey-foreign_example_com.service"
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl disable --now valkey-server.service", bssh.Result{})
	f.On("cat "+shQuote(valkeyDropInPath), bssh.Result{ExitCode: 1})
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0, Stdout: orphan + "\n"})
	f.On("cat "+shQuote(orphan), bssh.Result{ExitCode: 0, Stdout: "[Unit]\nDescription=hand-written\n"}) // no marker
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{ExitCode: 1})
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl enable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On(valkeyLoadedCmd("app.example.com"), bssh.Result{ExitCode: 0})
	f.On(valkeyCacheFreshCmd("app.example.com"), bssh.Result{ExitCode: 0, Stdout: "no\n"})
	f.On(valkeyExecCmd(valkeyInstanceUnit("app.example.com")), bssh.Result{ExitCode: 0})
	f.On(valkeyPingCmd("tenant1", "app.example.com"), bssh.Result{ExitCode: 0, Stdout: "PONG\n"})

	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote(orphan) || c.Cmd == "systemctl disable --now berth-valkey-foreign_example_com.service" {
			t.Error("a foreign file matching the glob must never be disabled or removed")
		}
	}
}

func TestValkeyCheckUnsatisfiedWhenBinaryUpgraded(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	// Binary replaced under the running process (unattended-upgrades).
	f.On(valkeyExecCmd(valkeyInstanceUnit("app.example.com")), bssh.Result{ExitCode: 1})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the running instance executes a replaced (deleted) binary")
	}
}

func TestValkeyApplyRestartsStaleBinary(t *testing.T) {
	s := valkeyServer()
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl disable --now valkey-server.service", bssh.Result{})
	f.On("cat "+shQuote(valkeyDropInPath), bssh.Result{ExitCode: 1})
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0, Stdout: valkeyUnitPath("app.example.com") + "\n"})
	want, _ := renderValkeyUnit(s, s.Sites[0])
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{ExitCode: 0, Stdout: string(want)}) // up to date
	f.On("systemctl enable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On(valkeyLoadedCmd("app.example.com"), bssh.Result{ExitCode: 0}) // cache/loaded green
	f.On(valkeyCacheFreshCmd("app.example.com"), bssh.Result{ExitCode: 0, Stdout: "no\n"})
	f.On(valkeyExecCmd(valkeyInstanceUnit("app.example.com")), bssh.Result{ExitCode: 1}) // binary stale
	f.On("systemctl restart "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On(valkeyPingCmd("tenant1", "app.example.com"), bssh.Result{ExitCode: 0, Stdout: "PONG\n"})

	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var restarts, reloads int
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "systemctl restart " + valkeyInstanceUnit("app.example.com"):
			restarts++
		case "systemctl daemon-reload":
			reloads++
		}
	}
	if restarts != 1 {
		t.Errorf("expected one restart for the stale binary, got %d", restarts)
	}
	if reloads != 0 {
		t.Errorf("a stale binary needs no daemon-reload (unit file unchanged), got %d", reloads)
	}
}

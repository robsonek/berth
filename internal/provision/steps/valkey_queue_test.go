package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// valkeyQueueServer is a one-site server with BOTH instances on and distinct,
// non-default limits for each, so a renderer reading the wrong knob shows.
func valkeyQueueServer() *config.Server {
	return &config.Server{
		Valkey: true, ValkeyQueue: true,
		Tuning: config.Tuning{ValkeyMaxmemory: "768mb", ValkeyMaxmemoryPolicy: "volatile-lru", ValkeyQueueMaxmemory: "96mb"},
		Sites:  []config.Site{{Domain: "app.example.com", User: "tenant1"}},
	}
}

// stubValkeyDataDirsAbsent answers the data-owner guard's stat probe
// "absent" for every instance data dir of s — a fresh host, the guard's
// pass-through case.
func stubValkeyDataDirsAbsent(f *bssh.FakeRunner, s *config.Server) {
	for _, in := range valkeyInstances(s) {
		f.On(valkeyDataOwnerCmd(in.dataDir), bssh.Result{ExitCode: 1, Stderr: "No such file or directory"})
	}
}

// valkeyQueueLoadedCmd mirrors serviceConfigLoaded's exact command for the
// queue instance (copy of valkeyLoadedCmd with the queue unit/path).
func valkeyQueueLoadedCmd(domain string) string {
	return `[ "$(stat -c %Y ` + shQuote(valkeyQueueUnitPath(domain)) + ` 2>/dev/null)" -le "$(systemctl show -p ActiveEnterTimestamp --value --timestamp=unix ` + valkeyQueueInstanceUnit(domain) + ` 2>/dev/null | tr -d @)" ]`
}

func valkeyQueueCacheFreshCmd(domain string) string {
	return "systemctl show -p NeedDaemonReload --value " + valkeyQueueInstanceUnit(domain)
}

// stubValkeyQueueCheckGreen stubs every probe of a converged host with both
// instances: the cache stubs (stubValkeyCheckGreen) plus the queue's.
func stubValkeyQueueCheckGreen(f *bssh.FakeRunner, s *config.Server) {
	stubValkeyCheckGreen(f, s)
	site := s.Sites[0]
	want, _ := renderValkeyQueueUnit(s, site)
	f.On("cat "+shQuote(valkeyQueueUnitPath(site.Domain)), bssh.Result{ExitCode: 0, Stdout: string(want)})
	f.On("systemctl is-active "+valkeyQueueInstanceUnit(site.Domain), bssh.Result{ExitCode: 0})
	f.On("systemctl is-enabled "+valkeyQueueInstanceUnit(site.Domain), bssh.Result{ExitCode: 0})
	f.On(valkeyQueueLoadedCmd(site.Domain), bssh.Result{ExitCode: 0})
	f.On(valkeyQueueCacheFreshCmd(site.Domain), bssh.Result{ExitCode: 0, Stdout: "no\n"})
	f.On(valkeyExecCmd(valkeyQueueInstanceUnit(site.Domain)), bssh.Result{ExitCode: 0})
	f.On(valkeyPingOver("tenant1", valkeyQueueSocketPath(site.Domain)), bssh.Result{ExitCode: 0, Stdout: "PONG\n"})
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0, Stdout: valkeyUnitPath(site.Domain) + "\n" + valkeyQueueUnitPath(site.Domain) + "\n"})
}

// stubValkeyQueueApplyBase stubs the Apply preamble shared by every queue
// Apply test: package install, stock service off, both data dirs absent, the
// listing with both desired units, daemon-reload and enable --now for both.
func stubValkeyQueueApplyBase(f *bssh.FakeRunner, s *config.Server) {
	site := s.Sites[0]
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f.On("systemctl disable --now valkey-server.service", bssh.Result{})
	stubValkeyDataDirsAbsent(f, s)
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0, Stdout: valkeyUnitPath(site.Domain) + "\n" + valkeyQueueUnitPath(site.Domain) + "\n"})
	f.On("systemctl daemon-reload", bssh.Result{})
	f.On("systemctl enable --now "+valkeyInstanceUnit(site.Domain), bssh.Result{})
	f.On("systemctl enable --now "+valkeyQueueInstanceUnit(site.Domain), bssh.Result{})
}

// stubValkeyQueueLiveness stubs the post-enable liveness probes green for
// both instances (loaded, manager cache fresh, binary current, PONG).
func stubValkeyQueueLiveness(f *bssh.FakeRunner, s *config.Server) {
	site := s.Sites[0]
	f.On(valkeyLoadedCmd(site.Domain), bssh.Result{ExitCode: 0})
	f.On(valkeyCacheFreshCmd(site.Domain), bssh.Result{ExitCode: 0, Stdout: "no\n"})
	f.On(valkeyExecCmd(valkeyInstanceUnit(site.Domain)), bssh.Result{ExitCode: 0})
	f.On(valkeyPingOver("tenant1", valkeySocketPath(site.Domain)), bssh.Result{ExitCode: 0, Stdout: "PONG\n"})
	f.On(valkeyQueueLoadedCmd(site.Domain), bssh.Result{ExitCode: 0})
	f.On(valkeyQueueCacheFreshCmd(site.Domain), bssh.Result{ExitCode: 0, Stdout: "no\n"})
	f.On(valkeyExecCmd(valkeyQueueInstanceUnit(site.Domain)), bssh.Result{ExitCode: 0})
	f.On(valkeyPingOver("tenant1", valkeyQueueSocketPath(site.Domain)), bssh.Result{ExitCode: 0, Stdout: "PONG\n"})
}

func countCmd(f *bssh.FakeRunner, cmd string) int {
	n := 0
	for _, c := range f.Calls() {
		if c.Cmd == cmd {
			n++
		}
	}
	return n
}

func firstIdx(f *bssh.FakeRunner, cmd string) int {
	for i, c := range f.Calls() {
		if c.Cmd == cmd {
			return i
		}
	}
	return -1
}

func lastCmdIdx(f *bssh.FakeRunner, cmd string) int {
	last := -1
	for i, c := range f.Calls() {
		if c.Cmd == cmd {
			last = i
		}
	}
	return last
}

func TestValkeyQueuePathHelpers(t *testing.T) {
	if got := valkeyQueueInstanceUnit("app.example.com"); got != "berth-valkey-app_example_com-queue.service" {
		t.Errorf("valkeyQueueInstanceUnit = %q", got)
	}
	if got := valkeyQueueUnitPath("app.example.com"); got != "/etc/systemd/system/berth-valkey-app_example_com-queue.service" {
		t.Errorf("valkeyQueueUnitPath = %q", got)
	}
	if got := valkeyQueueSocketPath("app.example.com"); got != "/run/berth-valkey/app_example_com/queue.sock" {
		t.Errorf("valkeyQueueSocketPath = %q", got)
	}
	if got := valkeyQueueDataDir("app.example.com"); got != "/var/lib/berth-valkey/app_example_com-queue" {
		t.Errorf("valkeyQueueDataDir = %q", got)
	}
	// The queue ping is the cache ping's exact shape over the queue socket —
	// the read-only classifier pins both leaves.
	want := "setpriv --reuid 'tenant1' --regid 'tenant1' --init-groups -- valkey-cli -s '/run/berth-valkey/app_example_com/queue.sock' ping"
	if got := valkeyPingOver("tenant1", valkeyQueueSocketPath("app.example.com")); got != want {
		t.Errorf("valkeyPingOver = %q, want %q", got, want)
	}
}

// valkeyInstances is the step's unit of work: the cache instance of every
// site, then — with the knob on — its queue instance, in site order.
func TestValkeyInstances(t *testing.T) {
	s := valkeyQueueServer()
	s.Sites = append(s.Sites, config.Site{Domain: "www.example.com", User: "tenant2"})
	var got []string
	for _, in := range valkeyInstances(s) {
		got = append(got, in.unit+" "+in.path+" "+in.socket+" "+in.dataDir)
	}
	want := []string{
		"berth-valkey-app_example_com.service /etc/systemd/system/berth-valkey-app_example_com.service /run/berth-valkey/app_example_com/valkey.sock /var/lib/berth-valkey/app_example_com",
		"berth-valkey-app_example_com-queue.service /etc/systemd/system/berth-valkey-app_example_com-queue.service /run/berth-valkey/app_example_com/queue.sock /var/lib/berth-valkey/app_example_com-queue",
		"berth-valkey-www_example_com.service /etc/systemd/system/berth-valkey-www_example_com.service /run/berth-valkey/www_example_com/valkey.sock /var/lib/berth-valkey/www_example_com",
		"berth-valkey-www_example_com-queue.service /etc/systemd/system/berth-valkey-www_example_com-queue.service /run/berth-valkey/www_example_com/queue.sock /var/lib/berth-valkey/www_example_com-queue",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("valkeyInstances:\n got %v\nwant %v", got, want)
	}
	s.ValkeyQueue = false
	if n := len(valkeyInstances(s)); n != 2 {
		t.Errorf("without the knob only the cache instances remain, got %d", n)
	}
}

func TestRenderValkeyQueueUnit(t *testing.T) {
	s := valkeyQueueServer()
	got, err := renderValkeyQueueUnit(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if !strings.HasPrefix(body, "# managed by berth\n") {
		t.Errorf("unit must start with the managed marker:\n%s", body)
	}
	for _, want := range []string{
		"Description=Valkey queue for app.example.com (berth)",
		"User=tenant1",
		"Group=tenant1",
		"RuntimeDirectory=berth-valkey/app_example_com\n", // the SAME runtime dir as the cache socket
		"RuntimeDirectoryMode=0700",
		"RuntimeDirectoryPreserve=yes",
		"StateDirectory=berth-valkey/app_example_com-queue\n",
		"StateDirectoryMode=0700",
		"--port 0",
		"--unixsocket /run/berth-valkey/app_example_com/queue.sock",
		"--unixsocketperm 600",
		"--dir /var/lib/berth-valkey/app_example_com-queue ",
		"--maxmemory 96mb",                        // the QUEUE knob, not the cache one
		"--maxmemory-policy noeviction",           // fixed: a queue never evicts jobs
		"--appendonly yes --appendfsync everysec", // fixed durability
		"--supervised systemd",
		"Type=notify",
		"Restart=always",
		"TimeoutStopSec=infinity",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("queue unit missing %q:\n%s", want, body)
		}
	}
	for _, reject := range []string{"768mb", "volatile-lru", "valkey.sock", "--dir /var/lib/berth-valkey/app_example_com ", "StateDirectory=berth-valkey/app_example_com\n"} {
		if strings.Contains(body, reject) {
			t.Errorf("queue unit must not carry the cache instance's %q:\n%s", reject, body)
		}
	}
}

// TestRenderValkeyUnitZeroChangeWithoutQueue: with valkey_queue off the cache
// unit renders exactly as before this feature — no Preserve line, no AOF —
// so provisioned hosts see no drift from the upgrade alone.
func TestRenderValkeyUnitZeroChangeWithoutQueue(t *testing.T) {
	s := valkeyQueueServer()
	s.ValkeyQueue = false
	got, err := renderValkeyUnit(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	for _, reject := range []string{"RuntimeDirectoryPreserve", "appendonly", "appendfsync", "queue", "96mb"} {
		if strings.Contains(body, reject) {
			t.Errorf("cache unit without valkey_queue must not contain %q:\n%s", reject, body)
		}
	}
	for _, want := range []string{
		"Description=Valkey for app.example.com (berth)",
		"--unixsocket /run/berth-valkey/app_example_com/valkey.sock",
		"--dir /var/lib/berth-valkey/app_example_com ",
		"--maxmemory 768mb --maxmemory-policy volatile-lru --supervised systemd",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("cache unit missing %q:\n%s", want, body)
		}
	}
}

// TestRenderValkeyCacheUnitPreservesRuntimeDirWithQueue: with valkey_queue
// on, the cache unit gains RuntimeDirectoryPreserve=yes (the dir now also
// holds the queue socket) and nothing else changes.
func TestRenderValkeyCacheUnitPreservesRuntimeDirWithQueue(t *testing.T) {
	s := valkeyQueueServer()
	got, err := renderValkeyUnit(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	for _, want := range []string{
		"RuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\nStateDirectory=berth-valkey/app_example_com\n",
		"--unixsocket /run/berth-valkey/app_example_com/valkey.sock",
		"--maxmemory 768mb --maxmemory-policy volatile-lru --supervised systemd",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("cache unit with valkey_queue missing %q:\n%s", want, body)
		}
	}
	for _, reject := range []string{"appendonly", "96mb", "queue"} {
		if strings.Contains(body, reject) {
			t.Errorf("cache unit must not contain the queue instance's %q:\n%s", reject, body)
		}
	}
}

// TestRenderValkeyQueueUnitPathsMatchConsts pins the queue unit's path
// literals to the config helpers, like TestRenderValkeyUnitPathsMatchConsts
// does for the cache instance.
func TestRenderValkeyQueueUnitPathsMatchConsts(t *testing.T) {
	s := valkeyQueueServer()
	pool := poolName(s.Sites[0].Domain)
	got, err := renderValkeyQueueUnit(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	for _, want := range []string{
		"RuntimeDirectory=" + strings.TrimPrefix(config.ValkeyRunBase, "/run/") + "/" + pool + "\n",
		"StateDirectory=" + strings.TrimPrefix(config.ValkeyQueueDataDir(pool), "/var/lib/") + "\n",
		"--unixsocket " + config.ValkeyQueueSocketPath(pool) + " ",
		"--dir " + config.ValkeyQueueDataDir(pool) + " ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("queue unit diverged from the config helpers, missing %q:\n%s", want, body)
		}
	}
}

// ---- Check ----

func TestValkeyQueueCheckSatisfiedFleet(t *testing.T) {
	s := valkeyQueueServer()
	f := bssh.NewFakeRunner()
	stubValkeyQueueCheckGreen(f, s)
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied with both instances green; got %+v", cr)
	}
}

// With only the cache probes stubbed, Check must still reach for the queue
// instance — the first unstubbed queue command surfaces as the error, which
// proves the probes are issued at all (a loop over sites instead of
// instances would report Satisfied here).
func TestValkeyQueueCheckIssuesQueueProbes(t *testing.T) {
	s := valkeyQueueServer()
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	f.On(valkeyListUnitsCmd, bssh.Result{Stdout: valkeyUnitPath("app.example.com") + "\n" + valkeyQueueUnitPath("app.example.com") + "\n"})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "-queue.service") {
		t.Fatalf("Check must probe the queue instance (unstubbed here); got cr=%+v err=%v", cr, err)
	}
}

func TestValkeyQueueCheckUnsatisfiedOnQueueOnlyFault(t *testing.T) {
	const domain = "app.example.com"
	queueUnit := valkeyQueueInstanceUnit(domain)
	for _, tc := range []struct {
		name string
		cmd  string
		res  bssh.Result
	}{
		{"ping fails", valkeyPingOver("tenant1", valkeyQueueSocketPath(domain)), bssh.Result{ExitCode: 1, Stderr: "Connection refused"}},
		{"unit absent", "cat " + shQuote(valkeyQueueUnitPath(domain)), bssh.Result{ExitCode: 1}},
		{"inactive", "systemctl is-active " + queueUnit, bssh.Result{ExitCode: 3, Stdout: "inactive\n"}},
		{"disabled", "systemctl is-enabled " + queueUnit, bssh.Result{ExitCode: 1, Stdout: "disabled\n"}},
		{"manager cache stale", valkeyQueueCacheFreshCmd(domain), bssh.Result{ExitCode: 0, Stdout: "yes\n"}},
		{"unit not loaded", valkeyQueueLoadedCmd(domain), bssh.Result{ExitCode: 1}},
		{"binary stale", valkeyExecCmd(queueUnit), bssh.Result{ExitCode: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := valkeyQueueServer()
			f := bssh.NewFakeRunner()
			stubValkeyQueueCheckGreen(f, s) // cache stays green throughout
			f.On(tc.cmd, tc.res)
			cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
			if err != nil {
				t.Fatal(err)
			}
			if cr.Satisfied {
				t.Errorf("a queue-only fault (%s) must leave the step unsatisfied", tc.name)
			}
		})
	}
}

// ---- Apply ----

func TestValkeyQueueApplyConvergesFreshFleet(t *testing.T) {
	s := valkeyQueueServer()
	f := bssh.NewFakeRunner()
	stubValkeyQueueApplyBase(f, s)
	f.On(valkeyListUnitsCmd, bssh.Result{ExitCode: 0}) // nothing yet
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(valkeyQueueUnitPath("app.example.com")), bssh.Result{ExitCode: 1})
	stubValkeyQueueLiveness(f, s)

	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if n := len(f.Writes()); n != 2 {
		t.Fatalf("expected exactly two unit writes (cache, queue); got %d", n)
	}
	byPath := map[string]bssh.FileSpec{}
	for _, w := range f.Writes() {
		byPath[w.Path] = w
		if w.Owner != "root" || w.Group != "root" || w.Mode != 0o644 {
			t.Errorf("%s FileSpec = %s:%s %o, want root:root 644", w.Path, w.Owner, w.Group, w.Mode)
		}
	}
	cache, ok := byPath[valkeyUnitPath("app.example.com")]
	if !ok {
		t.Fatal("cache unit was not written")
	}
	if c := string(cache.Content); !strings.Contains(c, "valkey.sock") || !strings.Contains(c, "RuntimeDirectoryPreserve=yes") || strings.Contains(c, "appendonly") {
		t.Errorf("cache unit content wrong for its path:\n%s", c)
	}
	queue, ok := byPath[valkeyQueueUnitPath("app.example.com")]
	if !ok {
		t.Fatal("queue unit was not written")
	}
	if c := string(queue.Content); !strings.Contains(c, "queue.sock") || !strings.Contains(c, "--appendonly yes") || strings.Contains(c, "valkey.sock") {
		t.Errorf("queue unit content wrong for its path:\n%s", c)
	}
	// Ordering: both write-guards (the last cat of each path precedes its
	// write) < the single daemon-reload < enable cache < enable queue.
	guardCache := lastCmdIdx(f, "cat "+shQuote(valkeyUnitPath("app.example.com")))
	guardQueue := lastCmdIdx(f, "cat "+shQuote(valkeyQueueUnitPath("app.example.com")))
	reload := firstIdx(f, "systemctl daemon-reload")
	enableCache := firstIdx(f, "systemctl enable --now "+valkeyInstanceUnit("app.example.com"))
	enableQueue := firstIdx(f, "systemctl enable --now "+valkeyQueueInstanceUnit("app.example.com"))
	if guardCache < 0 || guardQueue < 0 || reload < 0 || enableCache < 0 || enableQueue < 0 {
		t.Fatalf("missing commands: guards=%d/%d reload=%d enable=%d/%d", guardCache, guardQueue, reload, enableCache, enableQueue)
	}
	if !(guardCache < reload && guardQueue < reload && reload < enableCache && enableCache < enableQueue) {
		t.Errorf("want guards < daemon-reload < enable cache < enable queue; got %d %d %d %d %d", guardCache, guardQueue, reload, enableCache, enableQueue)
	}
	if n := countCmd(f, "systemctl daemon-reload"); n != 1 {
		t.Errorf("expected exactly one daemon-reload, got %d", n)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "systemctl restart ") {
			t.Errorf("a FRESH unit must not be restarted: %q", c.Cmd)
		}
	}
}

func TestValkeyQueueApplyRestartsDriftedQueueUnitOnly(t *testing.T) {
	s := valkeyQueueServer()
	f := bssh.NewFakeRunner()
	stubValkeyQueueApplyBase(f, s)
	cacheWant, _ := renderValkeyUnit(s, s.Sites[0])
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{Stdout: string(cacheWant)}) // up to date
	f.On("cat "+shQuote(valkeyQueueUnitPath("app.example.com")),
		bssh.Result{Stdout: managedMarker + "\n[Service]\nExecStart=/usr/bin/valkey-server --old\n"}) // drifted
	stubValkeyQueueLiveness(f, s)
	f.On("systemctl restart "+valkeyQueueInstanceUnit("app.example.com"), bssh.Result{})

	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if n := countCmd(f, "systemctl restart "+valkeyQueueInstanceUnit("app.example.com")); n != 1 {
		t.Errorf("expected exactly one restart of the drifted queue unit, got %d", n)
	}
	if n := countCmd(f, "systemctl restart "+valkeyInstanceUnit("app.example.com")); n != 0 {
		t.Errorf("the untouched cache unit must not be restarted, got %d", n)
	}
	if n := countCmd(f, "systemctl daemon-reload"); n != 1 {
		t.Errorf("expected exactly one daemon-reload, got %d", n)
	}
	if n := len(f.Writes()); n != 1 || f.Writes()[0].Path != valkeyQueueUnitPath("app.example.com") {
		t.Errorf("expected exactly the queue unit to be rewritten, got %d writes", n)
	}
}

func TestValkeyQueueApplyHealsWedgedQueueOnly(t *testing.T) {
	s := valkeyQueueServer()
	f := bssh.NewFakeRunner()
	stubValkeyQueueApplyBase(f, s)
	cacheWant, _ := renderValkeyUnit(s, s.Sites[0])
	queueWant, _ := renderValkeyQueueUnit(s, s.Sites[0])
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{Stdout: string(cacheWant)})
	f.On("cat "+shQuote(valkeyQueueUnitPath("app.example.com")), bssh.Result{Stdout: string(queueWant)})
	stubValkeyQueueLiveness(f, s)
	f.OnSeq(valkeyPingOver("tenant1", valkeyQueueSocketPath("app.example.com")),
		bssh.Result{ExitCode: 1, Stderr: "Connection refused"},
		bssh.Result{ExitCode: 0, Stdout: "PONG\n"})
	f.On("systemctl restart "+valkeyQueueInstanceUnit("app.example.com"), bssh.Result{})

	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if n := countCmd(f, "systemctl restart "+valkeyQueueInstanceUnit("app.example.com")); n != 1 {
		t.Errorf("expected exactly one healing restart of the queue unit, got %d", n)
	}
	if n := countCmd(f, "systemctl restart "+valkeyInstanceUnit("app.example.com")); n != 0 {
		t.Errorf("a wedged queue must not restart the cache, got %d", n)
	}
	if n := countCmd(f, "systemctl daemon-reload"); n != 0 {
		t.Errorf("no daemon-reload when nothing on disk changed, got %d", n)
	}
}

func TestValkeyQueueApplyFailsLoudWhenQueueStaysDead(t *testing.T) {
	s := valkeyQueueServer()
	f := bssh.NewFakeRunner()
	stubValkeyQueueApplyBase(f, s)
	cacheWant, _ := renderValkeyUnit(s, s.Sites[0])
	queueWant, _ := renderValkeyQueueUnit(s, s.Sites[0])
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{Stdout: string(cacheWant)})
	f.On("cat "+shQuote(valkeyQueueUnitPath("app.example.com")), bssh.Result{Stdout: string(queueWant)})
	stubValkeyQueueLiveness(f, s)
	f.On(valkeyPingOver("tenant1", valkeyQueueSocketPath("app.example.com")), bssh.Result{ExitCode: 1, Stderr: "Connection refused"})
	f.On("systemctl restart "+valkeyQueueInstanceUnit("app.example.com"), bssh.Result{})

	err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "-queue.service") || !strings.Contains(err.Error(), "queue.sock") {
		t.Fatalf("err = %v, want a loud failure naming the queue unit and socket", err)
	}
	if n := countCmd(f, "systemctl restart "+valkeyQueueInstanceUnit("app.example.com")); n != 1 {
		t.Errorf("expected exactly one healing restart before failing, got %d", n)
	}
}

// ---- Sweep ----

// With the knob off, a berth-managed queue unit is an orphan: stop+disable+
// remove it, leave the cache instance alone.
func TestValkeyQueueDisabledSweepsQueueOrphan(t *testing.T) {
	s := valkeyServer() // valkey on, valkey_queue off
	queueOrphan := valkeyQueueUnitPath("app.example.com")
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	f.On(valkeyListUnitsCmd, bssh.Result{Stdout: valkeyUnitPath("app.example.com") + "\n" + queueOrphan + "\n"})
	f.On("cat "+shQuote(queueOrphan), bssh.Result{Stdout: managedMarker + "\n[Service]\n"})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("Check = %+v err=%v, want unsatisfied while a managed queue orphan remains", cr, err)
	}

	f2 := bssh.NewFakeRunner()
	f2.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f2.On("systemctl disable --now valkey-server.service", bssh.Result{})
	stubValkeyDataDirsAbsent(f2, s)
	f2.On(valkeyListUnitsCmd, bssh.Result{Stdout: valkeyUnitPath("app.example.com") + "\n" + queueOrphan + "\n"})
	f2.On("cat "+shQuote(queueOrphan), bssh.Result{Stdout: managedMarker + "\n[Service]\n"})
	f2.On("systemctl disable --now "+valkeyQueueInstanceUnit("app.example.com"), bssh.Result{})
	f2.On("rm -f "+shQuote(queueOrphan), bssh.Result{})
	cacheWant, _ := renderValkeyUnit(s, s.Sites[0])
	f2.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{Stdout: string(cacheWant)})
	f2.On("systemctl daemon-reload", bssh.Result{})
	f2.On("systemctl enable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f2.On(valkeyLoadedCmd("app.example.com"), bssh.Result{})
	f2.On(valkeyCacheFreshCmd("app.example.com"), bssh.Result{Stdout: "no\n"})
	f2.On(valkeyExecCmd(valkeyInstanceUnit("app.example.com")), bssh.Result{})
	f2.On(valkeyPingOver("tenant1", valkeySocketPath("app.example.com")), bssh.Result{Stdout: "PONG\n"})
	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f2); err != nil {
		t.Fatal(err)
	}
	if countCmd(f2, "systemctl disable --now "+valkeyQueueInstanceUnit("app.example.com")) != 1 || countCmd(f2, "rm -f "+shQuote(queueOrphan)) != 1 {
		t.Error("the managed queue orphan must be disabled and removed")
	}
	if countCmd(f2, "systemctl disable --now "+valkeyInstanceUnit("app.example.com")) != 0 || countCmd(f2, "rm -f "+shQuote(valkeyUnitPath("app.example.com"))) != 0 {
		t.Error("the desired cache unit must not be touched by the sweep")
	}
	if countCmd(f2, "systemctl daemon-reload") != 1 {
		t.Error("daemon-reload must follow the removal")
	}
}

// valkey: false sweeps BOTH kinds of berth-managed instances.
func TestValkeyFalseSweepsBothInstances(t *testing.T) {
	s := &config.Server{Valkey: false, Sites: []config.Site{{Domain: "app.example.com"}}}
	cache, queue := valkeyUnitPath("app.example.com"), valkeyQueueUnitPath("app.example.com")
	f := bssh.NewFakeRunner()
	f.On(valkeyListUnitsCmd, bssh.Result{Stdout: cache + "\n" + queue + "\n"})
	f.On("cat "+shQuote(cache), bssh.Result{Stdout: managedMarker + "\n[Unit]\n"})
	f.On("cat "+shQuote(queue), bssh.Result{Stdout: managedMarker + "\n[Unit]\n"})
	f.On("systemctl disable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f.On("systemctl disable --now "+valkeyQueueInstanceUnit("app.example.com"), bssh.Result{})
	f.On("rm -f "+shQuote(cache), bssh.Result{})
	f.On("rm -f "+shQuote(queue), bssh.Result{})
	f.On("systemctl daemon-reload", bssh.Result{})
	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"systemctl disable --now " + valkeyInstanceUnit("app.example.com"),
		"systemctl disable --now " + valkeyQueueInstanceUnit("app.example.com"),
		"rm -f " + shQuote(cache),
		"rm -f " + shQuote(queue),
	} {
		if countCmd(f, want) != 1 {
			t.Errorf("valkey: false must sweep both instances; missing %q", want)
		}
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "LC_ALL=C stat") {
			t.Errorf("disabled mode must not probe data-dir owners: %q", c.Cmd)
		}
	}
}

// A hand-written queue-looking unit without the marker is never berth's to
// disable or remove, and must not keep the step unsatisfied forever.
func TestValkeyQueueLeavesForeignQueueUnit(t *testing.T) {
	s := valkeyServer() // valkey_queue off
	foreign := valkeyQueueUnitPath("app.example.com")
	f := bssh.NewFakeRunner()
	stubValkeyCheckGreen(f, s)
	f.On(valkeyListUnitsCmd, bssh.Result{Stdout: valkeyUnitPath("app.example.com") + "\n" + foreign + "\n"})
	f.On("cat "+shQuote(foreign), bssh.Result{Stdout: "[Unit]\nDescription=hand-written\n"})
	cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("a foreign queue-named unit must not block convergence; got %+v", cr)
	}
	f2 := bssh.NewFakeRunner()
	f2.On("DEBIAN_FRONTEND=noninteractive apt-get install -y valkey-server", bssh.Result{})
	f2.On("systemctl disable --now valkey-server.service", bssh.Result{})
	stubValkeyDataDirsAbsent(f2, s)
	f2.On(valkeyListUnitsCmd, bssh.Result{Stdout: valkeyUnitPath("app.example.com") + "\n" + foreign + "\n"})
	f2.On("cat "+shQuote(foreign), bssh.Result{Stdout: "[Unit]\nDescription=hand-written\n"})
	cacheWant, _ := renderValkeyUnit(s, s.Sites[0])
	f2.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{Stdout: string(cacheWant)})
	f2.On("systemctl enable --now "+valkeyInstanceUnit("app.example.com"), bssh.Result{})
	f2.On(valkeyLoadedCmd("app.example.com"), bssh.Result{})
	f2.On(valkeyCacheFreshCmd("app.example.com"), bssh.Result{Stdout: "no\n"})
	f2.On(valkeyExecCmd(valkeyInstanceUnit("app.example.com")), bssh.Result{})
	f2.On(valkeyPingOver("tenant1", valkeySocketPath("app.example.com")), bssh.Result{Stdout: "PONG\n"})
	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f2); err != nil {
		t.Fatal(err)
	}
	for _, c := range f2.Calls() {
		if c.Cmd == "rm -f "+shQuote(foreign) || c.Cmd == "systemctl disable --now "+valkeyQueueInstanceUnit("app.example.com") {
			t.Errorf("a foreign file must never be disabled or removed: %q", c.Cmd)
		}
	}
}

// With both instances desired, an orphan whose name is a PREFIX of the cache
// unit (a removed site app.example.co) is swept, and neither desired unit is.
func TestValkeyQueueSweepKeepsBothDesiredBesidePrefixOrphan(t *testing.T) {
	s := valkeyQueueServer()
	orphan := "/etc/systemd/system/berth-valkey-app_example_co.service"
	f := bssh.NewFakeRunner()
	stubValkeyQueueApplyBase(f, s)
	f.On(valkeyListUnitsCmd, bssh.Result{Stdout: orphan + "\n" + valkeyUnitPath("app.example.com") + "\n" + valkeyQueueUnitPath("app.example.com") + "\n"})
	f.On("cat "+shQuote(orphan), bssh.Result{Stdout: managedMarker + "\n[Service]\n"})
	f.On("systemctl disable --now berth-valkey-app_example_co.service", bssh.Result{})
	f.On("rm -f "+shQuote(orphan), bssh.Result{})
	cacheWant, _ := renderValkeyUnit(s, s.Sites[0])
	queueWant, _ := renderValkeyQueueUnit(s, s.Sites[0])
	f.On("cat "+shQuote(valkeyUnitPath("app.example.com")), bssh.Result{Stdout: string(cacheWant)})
	f.On("cat "+shQuote(valkeyQueueUnitPath("app.example.com")), bssh.Result{Stdout: string(queueWant)})
	stubValkeyQueueLiveness(f, s)
	if err := Valkey().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	if countCmd(f, "rm -f "+shQuote(orphan)) != 1 {
		t.Error("the prefix-named orphan must be removed")
	}
	for _, desired := range []string{valkeyUnitPath("app.example.com"), valkeyQueueUnitPath("app.example.com")} {
		if countCmd(f, "rm -f "+shQuote(desired)) != 0 {
			t.Errorf("desired unit %s must survive the sweep", desired)
		}
	}
	if countCmd(f, "systemctl disable --now "+valkeyInstanceUnit("app.example.com")) != 0 ||
		countCmd(f, "systemctl disable --now "+valkeyQueueInstanceUnit("app.example.com")) != 0 {
		t.Error("desired units must not be disabled")
	}
}

// ---- Data-owner guard ----

// An EXISTING instance data dir owned by someone else is a previous tenant's
// dataset (a removed site keeps its data on purpose); systemd's
// StateDirectory= would chown it recursively to the configured user. Refuse
// in Check and Apply, before anything is installed, swept or written; never
// bypassed by --force; cache and queue alike; nothing probed when valkey is
// off.
func TestValkeyRefusesForeignOwnedDataDir(t *testing.T) {
	const cacheDir = "/var/lib/berth-valkey/app_example_com"
	const queueDir = "/var/lib/berth-valkey/app_example_com-queue"
	refuse := func(t *testing.T, s *config.Server, dir, stdout, wantSub string) {
		t.Helper()
		f := bssh.NewFakeRunner()
		stubValkeyQueueCheckGreen(f, s)
		f.On(valkeyDataOwnerCmd(dir), bssh.Result{Stdout: stdout})
		_, err := Valkey().Check(context.Background(), provision.RunCtx{Force: true}, s, f)
		if err == nil || !strings.Contains(err.Error(), wantSub) || !strings.Contains(err.Error(), "--force does not override") {
			t.Fatalf("Check err = %v, want a refusal containing %q (and the --force note)", err, wantSub)
		}
		f2 := bssh.NewFakeRunner()
		stubValkeyQueueApplyBase(f2, s)
		f2.On(valkeyDataOwnerCmd(dir), bssh.Result{Stdout: stdout})
		err = Valkey().Apply(context.Background(), provision.RunCtx{Force: true}, s, f2)
		if err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Fatalf("Apply err = %v, want a refusal containing %q", err, wantSub)
		}
		for _, c := range f2.Calls() {
			if strings.Contains(c.Cmd, "apt-get") || strings.Contains(c.Cmd, "disable") || strings.HasPrefix(c.Cmd, "rm ") {
				t.Errorf("the guard must refuse before any mutation; saw %q", c.Cmd)
			}
		}
		if len(f2.Writes()) != 0 {
			t.Errorf("the guard must refuse before any write; got %d", len(f2.Writes()))
		}
	}
	t.Run("queue dir owned by another user", func(t *testing.T) {
		refuse(t, valkeyQueueServer(), queueDir, "olduser 1005 directory\n", "owned by olduser")
	})
	t.Run("cache dir owned by another user, queue on", func(t *testing.T) {
		refuse(t, valkeyQueueServer(), cacheDir, "olduser 1005 directory\n", "owned by olduser")
	})
	t.Run("cache dir owned by another user, queue off", func(t *testing.T) {
		s := valkeyServer()
		f := bssh.NewFakeRunner()
		stubValkeyCheckGreen(f, s)
		f.On(valkeyDataOwnerCmd(cacheDir), bssh.Result{Stdout: "olduser 1005 directory\n"})
		_, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
		if err == nil || !strings.Contains(err.Error(), "owned by olduser") {
			t.Fatalf("Check err = %v, want the owner refusal for the cache dir with the knob off", err)
		}
	})
	t.Run("own directory passes", func(t *testing.T) {
		s := valkeyQueueServer()
		f := bssh.NewFakeRunner()
		stubValkeyQueueCheckGreen(f, s)
		f.On(valkeyDataOwnerCmd(cacheDir), bssh.Result{Stdout: "tenant1 1001 directory\n"})
		f.On(valkeyDataOwnerCmd(queueDir), bssh.Result{Stdout: "tenant1 1001 directory\n"})
		cr, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f)
		if err != nil || !cr.Satisfied {
			t.Fatalf("Check = %+v err=%v, want satisfied when the dirs belong to the site user", cr, err)
		}
	})
	t.Run("not a directory", func(t *testing.T) {
		refuse(t, valkeyQueueServer(), queueDir, "tenant1 1001 regular file\n", "not a directory")
	})
	t.Run("valkey off probes nothing", func(t *testing.T) {
		s := &config.Server{Valkey: false, Sites: []config.Site{{Domain: "app.example.com"}}}
		f := bssh.NewFakeRunner()
		f.On(valkeyListUnitsCmd, bssh.Result{})
		if _, err := Valkey().Check(context.Background(), provision.RunCtx{}, s, f); err != nil {
			t.Fatal(err)
		}
		for _, c := range f.Calls() {
			if strings.HasPrefix(c.Cmd, "LC_ALL=C stat") {
				t.Errorf("disabled mode must not probe data-dir owners: %q", c.Cmd)
			}
		}
	})
}

package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestTuningRequiresDatabaseOnly(t *testing.T) {
	if got := Tuning().Requires(); len(got) != 1 || got[0] != "database" {
		t.Fatalf("Requires() = %v, want [database]", got)
	}
}

// stubServiceActive stubs the single command serviceActive issues so the unit
// reads as active (running). Check requires the service to be active before
// consulting liveness; enablement is the service's own step's responsibility, so
// tuning never consults systemctl is-enabled.
func stubServiceActive(f *bssh.FakeRunner, unit string) {
	f.On("systemctl is-active "+unit, bssh.Result{ExitCode: 0})
}

// cmdIndex returns the index of the first call whose Cmd equals want, or -1.
func cmdIndex(f *bssh.FakeRunner, want string) int {
	for i, c := range f.Calls() {
		if c.Cmd == want {
			return i
		}
	}
	return -1
}

const mariadbLiveness = `[ "$(stat -c %Y '/etc/mysql/mariadb.conf.d/99-berth.cnf' 2>/dev/null)" -le "$(systemctl show -p ActiveEnterTimestamp --value --timestamp=unix mariadb.service 2>/dev/null | tr -d @)" ]`

func mariadbOnlyServer() *config.Server {
	return &config.Server{Database: config.Database{Engine: "mariadb"}}
}

func TestTuningCheckMariaDBSatisfiedWhenLoaded(t *testing.T) {
	srv := mariadbOnlyServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestTuningApplyMariaDBWritesDropInRestarts(t *testing.T) {
	srv := mariadbOnlyServer()
	f := bssh.NewFakeRunner()
	// Pre-check: cnf absent ⇒ block unsatisfied ⇒ Apply acts on it.
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 1})
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("systemctl restart mariadb.service", bssh.Result{})
	if err := Tuning().Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var found bool
	want, _ := renderMariaDBTuning(srv)
	for _, w := range f.Writes() {
		if w.Path == "/etc/mysql/mariadb.conf.d/99-berth.cnf" {
			found = true
			if string(w.Content) != string(want) {
				t.Errorf("cnf content mismatch:\n got: %q\nwant: %q", w.Content, want)
			}
		}
	}
	if !found {
		t.Fatal("mariadb tuning cnf not written")
	}
	var cmds []string
	for _, c := range f.Calls() {
		cmds = append(cmds, c.Cmd)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "systemctl restart mariadb.service") {
		t.Errorf("Apply did not restart mariadb; calls: %v", cmds)
	}
}

func TestTuningApplyMariaDBRestartErrorPropagates(t *testing.T) {
	srv := mariadbOnlyServer()
	f := bssh.NewFakeRunner()
	// Pre-check: cnf absent ⇒ block unsatisfied ⇒ Apply acts and reaches restart.
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 1})
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("systemctl restart mariadb.service", bssh.Result{ExitCode: 1, Stderr: "boom"})
	if err := Tuning().Apply(context.Background(), provision.RunCtx{}, srv, f); err == nil {
		t.Fatal("expected error when systemctl restart fails")
	}
}

func TestTuningGatingSkipsAbsentServices(t *testing.T) {
	// Postgres engine: Apply must touch nothing (no writes, no calls). Valkey
	// true on purpose — tuning ignores it now; the per-site instance units own
	// maxmemory.
	srv := &config.Server{Valkey: true, Database: config.Database{Engine: "postgres"}}
	f := bssh.NewFakeRunner()
	if err := Tuning().Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(f.Writes()) != 0 || len(f.Calls()) != 0 {
		t.Errorf("expected no-op; got writes=%v calls=%v", f.Writes(), f.Calls())
	}
	// And Check is trivially satisfied.
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied no-op; got %+v", cr)
	}
}

func TestTuningCheckMariaDBUnmanagedAbortsWithoutForce(t *testing.T) {
	srv := mariadbOnlyServer()
	// A pre-existing, foreign cnf lacking the "# managed by berth" marker.
	unmanaged := "[mysqld]\ninnodb_buffer_pool_size = 512M\n"
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: unmanaged})

	// Without --force: unmanaged file must abort (unsatisfied + non-nil error).
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
	if err == nil {
		t.Error("expected error aborting on unmanaged cnf without --force")
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied on unmanaged cnf")
	}

	// With --force: unsatisfied (will be overwritten), but no error.
	cr, err = Tuning().Check(context.Background(), provision.RunCtx{Force: true}, srv, f)
	if err != nil {
		t.Errorf("unexpected error with --force: %v", err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied (overwrite pending) on unmanaged cnf with --force")
	}
}

func TestTuningCheckMariaDBDriftedUnsatisfied(t *testing.T) {
	srv := mariadbOnlyServer()
	want, err := renderMariaDBTuning(srv)
	if err != nil {
		t.Fatal(err)
	}
	// Managed (keeps the marker) but content differs from desired.
	drifted := strings.Replace(string(want), "256M", "128M", 1)
	if drifted == string(want) {
		t.Fatal("test setup: expected drifted content to differ from desired")
	}
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: drifted})
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when managed cnf content has drifted")
	}
}

func TestTuningCheckMariaDBUnsatisfiedWhenNotLoaded(t *testing.T) {
	srv := mariadbOnlyServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 1}) // file newer than last restart
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when mariadb cnf present but not yet loaded")
	}
}

func TestTuningCheckMariaDBUnsatisfiedWhenAbsent(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 1})
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, mariadbOnlyServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when mariadb cnf absent")
	}
}

func calledCmd(f *bssh.FakeRunner, want string) bool { return cmdIndex(f, want) >= 0 }

func wrotePath(f *bssh.FakeRunner, path string) bool {
	for _, w := range f.Writes() {
		if w.Path == path {
			return true
		}
	}
	return false
}

func TestParseMariaDBSize(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"268435456", 268435456, true}, // bare bytes
		{"64K", 64 << 10, true},
		{"256M", 256 << 20, true},
		{"2G", 2 << 30, true},
		// MariaDB accepts lowercase suffixes; literal-Server callers bypass
		// reMariaDBSize validation entirely, so the parser must not false-reject.
		{"1k", 1 << 10, true},
		{"256m", 256 << 20, true},
		{"1g", 1 << 30, true},
		{"99999999999G", 0, false}, // overflows uint64
		{"", 0, false},
		{"G", 0, false},   // suffix without digits
		{"12Q", 0, false}, // unknown suffix
		{"12.5M", 0, false},
	} {
		got, err := parseMariaDBSize(tc.in)
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("parseMariaDBSize(%q) = %d, %v; want %d, nil", tc.in, got, err, tc.want)
		}
		if !tc.ok && err == nil {
			t.Errorf("parseMariaDBSize(%q) = %d, nil; want error", tc.in, got)
		}
	}
}

func TestTuningMariaDBBufferPoolGuardBoundaries(t *testing.T) {
	// MemTotal 1000000 kB = 1024000000 bytes; limit = 1024000000/100*80 =
	// 819200000. Exactly the limit passes; one byte over errors.
	for _, tc := range []struct {
		pool string
		ok   bool
	}{
		{"819200000", true},
		{"819200001", false},
	} {
		srv := mariadbOnlyServer()
		srv.Tuning.MariaDBBufferPool = tc.pool
		f := bssh.NewFakeRunner()
		f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1000000\n"})
		if tc.ok {
			// Fitting value: Check proceeds to the normal file probe.
			f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 1})
		}
		cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
		if tc.ok {
			if err != nil {
				t.Fatalf("pool %s: unexpected error: %v", tc.pool, err)
			}
			if cr.Satisfied {
				t.Errorf("pool %s: expected unsatisfied (file absent)", tc.pool)
			}
		} else if err == nil {
			t.Errorf("pool %s: expected guard error", tc.pool)
		} else if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("pool %s: expected the buffer-pool guard error, got: %v", tc.pool, err)
		}
	}
}

func TestTuningMariaDBGuardBadMemTotal(t *testing.T) {
	for _, out := range []string{"", "banana"} {
		srv := mariadbOnlyServer()
		f := bssh.NewFakeRunner()
		f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: out})
		if _, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f); err == nil {
			t.Errorf("MemTotal output %q: expected error, got nil", out)
		}
	}
}

func TestTuningCheckMariaDBOverLimitErrorsEvenWhenDeployed(t *testing.T) {
	// Accepted behavior change pinned: a host already running with an
	// over-limit drop-in fails Check on every run until the value is lowered.
	// The guard fires before the file is even consulted.
	srv := mariadbOnlyServer()
	srv.Tuning.MariaDBBufferPool = "2G"
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"}) // 1 GiB
	if _, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f); err == nil {
		t.Fatal("expected guard error for 2G pool on a 1 GiB host")
	}
	if calledCmd(f, "cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'") {
		t.Error("guard must fire before the managed-file probe")
	}
}

func TestTuningApplyMariaDBOverLimitNoWriteNoRestart(t *testing.T) {
	// Config raised above the limit while an old, fitting managed drop-in is
	// on disk: Apply must error BEFORE any write or restart.
	srv := mariadbOnlyServer()
	srv.Tuning.MariaDBBufferPool = "2G"
	old, err := renderMariaDBTuning(mariadbOnlyServer()) // default 256M content
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(old)})
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"}) // 1 GiB
	if err := Tuning().Apply(context.Background(), provision.RunCtx{}, srv, f); err == nil {
		t.Fatal("expected guard error from Apply")
	}
	if len(f.Writes()) != 0 {
		t.Errorf("Apply must not write anything past a failing guard: %+v", f.Writes())
	}
	if calledCmd(f, "systemctl restart mariadb.service") {
		t.Error("Apply must not restart mariadb past a failing guard")
	}
}

func TestRenderMariaDBTuningSlowLog(t *testing.T) {
	s := &config.Server{Tuning: config.Tuning{MariaDBSlowQueryLog: true, MariaDBLongQueryTime: 5}}
	b, err := renderMariaDBTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"slow_query_log = 1",
		"slow_query_log_file = /var/log/mysql/mariadb-slow.log",
		"long_query_time = 5",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("enabled slow log render missing %q:\n%s", want, b)
		}
	}
	off, err := renderMariaDBTuning(&config.Server{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(off), "slow_query_log") {
		t.Errorf("disabled slow log must render nothing slow-log related:\n%s", off)
	}
}

func TestRenderMariaDBTuningSlowLogDefaultThreshold(t *testing.T) {
	s := &config.Server{Tuning: config.Tuning{MariaDBSlowQueryLog: true}}
	b, err := renderMariaDBTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "long_query_time = 2") {
		t.Errorf("default threshold must render as 2 s:\n%s", b)
	}
}

func mariadbSlowLogServer() *config.Server {
	return &config.Server{Database: config.Database{Engine: "mariadb"}, Tuning: config.Tuning{MariaDBSlowQueryLog: true}}
}

func TestRenderMariaDBTuningSlowLogPathConst(t *testing.T) {
	// mariadbSlowLogPath must mirror slow_query_log_file in the template — the
	// convergence probe and the rendered config have to point at the same file.
	b, err := renderMariaDBTuning(mariadbSlowLogServer())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "slow_query_log_file = "+mariadbSlowLogPath+"\n") {
		t.Errorf("template slow_query_log_file diverged from mariadbSlowLogPath (%s):\n%s", mariadbSlowLogPath, b)
	}
}

func TestTuningCheckSlowLogFileMissingUnsatisfied(t *testing.T) {
	// When mariadbd cannot open the slow log at startup (Trixie ships no
	// /var/log/mysql; a root-owned dir behaves the same) it disables slow
	// logging for its whole lifetime while the drop-in reads loaded — the
	// missing log file is the only durable evidence. Check must not read
	// Satisfied on it.
	srv := mariadbSlowLogServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	f.On("test -f /var/log/mysql/mariadb-slow.log", bssh.Result{ExitCode: 1}) // logging silently off
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while the slow log file is missing with the slow log enabled")
	}
}

func TestTuningCheckSlowLogFilePresentSatisfied(t *testing.T) {
	srv := mariadbSlowLogServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	f.On("test -f /var/log/mysql/mariadb-slow.log", bssh.Result{ExitCode: 0})
	cr, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestTuningApplySlowLogEnsuresDirBeforeRestart(t *testing.T) {
	// The drop-in itself is loaded (checkTuned satisfied) but the log file is
	// missing: Apply must ensure the directory and THEN restart — mariadbd
	// disabled slow logging for the process duration, so the dir alone changes
	// nothing, and a restart before the dir would just fail to open it again.
	srv := mariadbSlowLogServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	f.On("test -f /var/log/mysql/mariadb-slow.log", bssh.Result{ExitCode: 1})
	f.On("install -d -m 02750 -o mysql -g adm /var/log/mysql", bssh.Result{})
	f.On("systemctl restart mariadb.service", bssh.Result{})
	if err := Tuning().Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	installIdx, restartIdx := -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "install -d -m 02750 -o mysql -g adm /var/log/mysql":
			installIdx = i
		case "systemctl restart mariadb.service":
			restartIdx = i
		}
	}
	if installIdx == -1 || restartIdx == -1 || installIdx > restartIdx {
		t.Errorf("want install (idx %d) strictly before restart (idx %d)", installIdx, restartIdx)
	}
	for _, w := range f.Writes() {
		if w.Path == mariadbTuningPath {
			t.Error("an up-to-date drop-in must not be rewritten")
		}
	}
}

func TestTuningApplySlowLogNoopWhenConverged(t *testing.T) {
	// Second-Apply convergence: drop-in loaded AND log file present -> no
	// install, no restart, no write.
	srv := mariadbSlowLogServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	f.On("test -f /var/log/mysql/mariadb-slow.log", bssh.Result{ExitCode: 0})
	if err := Tuning().Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "install -d") || strings.Contains(c.Cmd, "restart") {
			t.Errorf("converged slow log must not mutate; ran %q", c.Cmd)
		}
	}
	if len(f.Writes()) != 0 {
		t.Errorf("converged slow log must not write; wrote %v", f.Writes())
	}
}

func TestTuningSlowLogOffNeverProbesFile(t *testing.T) {
	srv := mariadbOnlyServer()
	want, _ := renderMariaDBTuning(srv)
	f := bssh.NewFakeRunner()
	f.On(memTotalCmd, bssh.Result{ExitCode: 0, Stdout: "1048576\n"})
	f.On("cat '/etc/mysql/mariadb.conf.d/99-berth.cnf'", bssh.Result{ExitCode: 0, Stdout: string(want)})
	stubServiceActive(f, mariadbUnit)
	f.On(mariadbLiveness, bssh.Result{ExitCode: 0})
	if _, err := Tuning().Check(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatal(err)
	}
	if err := Tuning().Apply(context.Background(), provision.RunCtx{}, srv, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "/var/log/mysql") {
			t.Errorf("slow log off must not probe the log path; ran %q", c.Cmd)
		}
	}
}

func TestRenderMariaDBTuningParityKnobs(t *testing.T) {
	s := &config.Server{Tuning: config.Tuning{
		MariaDBLogFileSize: "1G", MariaDBTmpTableSize: "128M",
		MariaDBMaxConnections: 256, MariaDBMaxAllowedPacket: "64M",
	}}
	b, err := renderMariaDBTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{
		"innodb_log_file_size = 1G\n",
		"tmp_table_size = 128M\n",
		"max_heap_table_size = 128M\n", // one knob drives BOTH directives
		"max_connections = 256\n",
		"max_allowed_packet = 64M\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Unset knobs must render NO directive (engine stock default stays in
	// force) — this is the byte-identity contract for existing hosts.
	off, err := renderMariaDBTuning(&config.Server{})
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"innodb_log_file_size", "tmp_table_size", "max_heap_table_size", "max_connections", "max_allowed_packet"} {
		if strings.Contains(string(off), banned) {
			t.Errorf("default render must omit %q, got:\n%s", banned, off)
		}
	}
}

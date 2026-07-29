package steps

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestUseSury(t *testing.T) {
	cases := []struct {
		src, ver string
		want     bool
		wantErr  bool
	}{
		{"auto", "8.5", true, false},
		{"auto", "8.4", false, false},
		{"sury", "8.4", true, false},
		{"debian", "8.5", false, true},
		{"debian", "8.4", false, false},
		{"ppa", "8.5", false, true},
	}
	for _, c := range cases {
		got, err := useSury(config.PHP{Version: c.ver, Source: c.src})
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("useSury(%s,%s) = %v,%v; want %v,err=%v", c.src, c.ver, got, err, c.want, c.wantErr)
		}
	}
}

// phpExtPkgs is the extension package set for PHP 8.4 — the version every
// php test pins (mirrors Apply's install list for a mysql-engine server).
func phpExtPkgs() []string {
	var pkgs []string
	for _, ext := range []string{"fpm", "cli", "mbstring", "xml", "bcmath", "curl", "intl", "zip", "gd", "redis", "mysql"} {
		pkgs = append(pkgs, "php8.4-"+ext)
	}
	return pkgs
}

// stubSuryRepoAbsent makes the sury source-list probe read back as absent:
// stock-source paths (ownRepoLingers) see nothing to sweep, and sury-source
// paths proceed to the full EnsureRepo chain (mirrors stubNginxRepoAbsent).
func stubSuryRepoAbsent(f *bssh.FakeRunner) {
	f.On("cat "+shQuote(apt.Sury().SourceListPath()), bssh.Result{ExitCode: 1})
}

func TestPHPCheckSuryDriftedListUnsatisfied(t *testing.T) {
	// A pre-E1 marker-less sury list with EXACT legacy bytes is adoptable
	// drift: Check reports unsatisfied (no error, no --force needed) so Apply
	// reconciles it via EnsureRepo.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "sury"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On("cat "+shQuote(apt.Sury().SourceListPath()), bssh.Result{ExitCode: 0, Stdout: apt.Sury().LegacySourceContents()[0]})
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the sury list is pre-E1 legacy bytes")
	}
	if !strings.Contains(cr.Reason, "sury") {
		t.Errorf("Reason = %q, want it to mention the sury repo", cr.Reason)
	}
}

func TestPHPCheckStockSourceFlagsLingeringSuryRepo(t *testing.T) {
	// php.source resolves to stock (8.4 via auto), yet a berth-owned sury list
	// still sits on disk: with everything else converged, the lingering repo
	// alone must flag drift so Apply removes it.
	s := &config.Server{PHP: config.PHP{Version: "8.4"}}
	want, err := renderOpcache()
	if err != nil {
		t.Fatal(err)
	}
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On("cat "+shQuote(apt.Sury().SourceListPath()), bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, apt.Sury()))})
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{})
	f.On(reloadedSinceCmd("php8.4-fpm", opcacheDropInPath("8.4"), phpTuningDropInPath("8.4")), bssh.Result{})
	f.On("test -d "+shQuote(phpLogDir), bssh.Result{ExitCode: 0})
	f.On("dpkg -s php8.4-mysql", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while a berth-owned sury list lingers")
	}
	if !strings.Contains(cr.Reason, "lingering") {
		t.Errorf("Reason = %q, want it to mention the lingering repo", cr.Reason)
	}
}

func TestPHPApplyStockSourceRemovesLingeringSuryRepo(t *testing.T) {
	// The config returned to Debian stock while a berth-owned sury list (and
	// keyring) linger from an earlier upstream provision: Apply sweeps them,
	// refreshes the indexes and warns that installed packages keep their
	// upstream versions (apt never auto-downgrades).
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	repo := apt.Sury()
	rmCmd := "rm -f " + repo.SourceListPath() + " " + repo.KeyringPath()
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On("cat "+shQuote(repo.SourceListPath()), bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, repo))})
	f.On(rmCmd, bssh.Result{})
	f.On("apt-get update", bssh.Result{})
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("php-fpm8.4 -t", bssh.Result{})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{}) // alive
	f.On("systemctl reload php8.4-fpm", bssh.Result{})
	f.On(markReloadedCmd("php8.4-fpm"), bssh.Result{})

	var warned []string
	rc := provision.RunCtx{Warn: func(msg string) { warned = append(warned, msg) }}
	if err := PHP().Apply(context.Background(), rc, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if callIdx(f, rmCmd, 0) < 0 {
		t.Error("Apply must remove the lingering sury list and keyring")
	}
	if callIdx(f, "apt-get update", 0) < 0 {
		t.Error("Apply must refresh the apt indexes after removing the sury repo")
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "upstream versions") {
		t.Fatalf("want one upstream-versions warning, got %q", warned)
	}
}

func TestPHPCheckForeignSuryListAbortsEvenWhenFPMMissing(t *testing.T) {
	// Codex #3 regression guard: on a FRESH host (php-fpm not installed) the
	// sury classification must run BEFORE the installed early-return —
	// otherwise Check would report plain unsatisfied and Apply would overwrite
	// the operator's foreign list without --force.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "sury"}}
	foreign := bssh.Result{ExitCode: 0, Stdout: "deb https://operator.example/ x main\n"}

	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On("cat "+shQuote(apt.Sury().SourceListPath()), foreign)
	_, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err = %v, want the abort-unless---force refusal", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "dpkg -s") {
			t.Errorf("the foreign-list refusal must precede any dpkg probe; ran %q", c.Cmd)
		}
	}

	// With --force the foreign file becomes an overwrite candidate: plain
	// unsatisfied (no error), reconciled by Apply.
	ff := bssh.NewFakeRunner()
	ff.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	ff.On("cat "+shQuote(apt.Sury().SourceListPath()), foreign)
	cr, err := PHP().Check(context.Background(), provision.RunCtx{Force: true}, s, ff)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a foreign sury list under --force must read unsatisfied, not satisfied")
	}
}

func TestPHPApplyRefusesForeignOpcacheDropIn(t *testing.T) {
	// An operator's own OPcache drop-in (no berth marker) must not be clobbered
	// by Apply without --force.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{})                            // stamp invalidation up front
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 0, Stdout: "opcache.enable=0\n"}) // foreign

	err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	for _, w := range f.Writes() {
		if w.Path == opcacheDropInPath("8.4") {
			t.Error("a foreign OPcache drop-in must not be overwritten without --force")
		}
	}
}

func TestPHPApplyWritesOpcacheDropIn(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}} // stock -> no Surý repo
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{}) // stamp invalidation up front
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})    // write-guard: absent
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})  // write-guard: absent
	f.On("php-fpm8.4 -t", bssh.Result{})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{}) // alive
	f.On("systemctl reload php8.4-fpm", bssh.Result{})
	f.On(markReloadedCmd("php8.4-fpm"), bssh.Result{})

	if err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var drop, tun *bssh.FileSpec
	for i := range f.Writes() {
		switch f.Writes()[i].Path {
		case opcacheDropInPath("8.4"):
			drop = &f.Writes()[i]
		case phpTuningDropInPath("8.4"):
			tun = &f.Writes()[i]
		}
	}
	if drop == nil {
		t.Fatal("OPcache drop-in was not written")
	}
	if tun == nil {
		t.Fatal("tuning drop-in was not written")
	}
	body := string(drop.Content)
	if !strings.Contains(body, "managed by berth") {
		t.Error("OPcache drop-in must carry the managed marker")
	}
	for _, want := range []string{"opcache.validate_timestamps = 0", "opcache.memory_consumption = 256", "opcache.max_accelerated_files = 20000"} {
		if !strings.Contains(body, want) {
			t.Errorf("OPcache drop-in missing %q; got:\n%s", want, body)
		}
	}
	tbody := string(tun.Content)
	if !strings.Contains(tbody, "managed by berth") {
		t.Error("tuning drop-in must carry the managed marker")
	}
	if !strings.Contains(tbody, "memory_limit = 256M") {
		t.Errorf("tuning drop-in missing default memory_limit; got:\n%s", tbody)
	}
	// FPM-only: never write a CLI drop-in (workers keep stock CLI limits).
	for _, w := range f.Writes() {
		if strings.Contains(w.Path, "/cli/conf.d/") {
			t.Errorf("must not write a CLI drop-in: %s", w.Path)
		}
	}
	// Both drop-ins share ONE validate + ONE graceful reload.
	var tests, reloads, createdLogDir int
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "php-fpm8.4 -t":
			tests++
		case "systemctl reload php8.4-fpm":
			reloads++
		case "install -d -o root -g root -m 0755 " + shQuote(phpLogDir):
			createdLogDir++
		}
	}
	if tests != 1 || reloads != 1 {
		t.Errorf("want exactly one -t and one reload; got %d and %d", tests, reloads)
	}
	if createdLogDir == 0 {
		t.Error("Apply must create " + phpLogDir)
	}
}

func TestPHPCheckUnsatisfiedWhenOpcacheDropInMissing(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"}) // installed
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})                       // drop-in absent
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the OPcache drop-in is missing")
	}
}

func TestPHPCheckSatisfiedWhenInstalledAndOpcacheManaged(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}}
	want, err := renderOpcache()
	if err != nil {
		t.Fatal(err)
	}
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{}) // alive
	f.On(reloadedSinceCmd("php8.4-fpm", opcacheDropInPath("8.4"), phpTuningDropInPath("8.4")), bssh.Result{})
	f.On("test -d "+shQuote(phpLogDir), bssh.Result{ExitCode: 0})
	f.On("dpkg -s php8.4-mysql", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"}) // engine "" -> pdo_mysql, installed
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when installed and both drop-ins up to date; got %+v", cr)
	}
}

func TestPHPPackagesEngineAware(t *testing.T) {
	mar := phpPackages("8.5", "mariadb")
	if !slices.Contains(mar, "php8.5-mysql") || slices.Contains(mar, "php8.5-pgsql") {
		t.Errorf("mariadb packages = %v; want php8.5-mysql, not php8.5-pgsql", mar)
	}
	if !slices.Contains(mar, "php8.5-fpm") || !slices.Contains(mar, "php8.5-redis") {
		t.Errorf("mariadb packages missing base extensions: %v", mar)
	}
	pg := phpPackages("8.5", "postgres")
	if !slices.Contains(pg, "php8.5-pgsql") || slices.Contains(pg, "php8.5-mysql") {
		t.Errorf("postgres packages = %v; want php8.5-pgsql, not php8.5-mysql", pg)
	}
}

func TestPHPCheckUnsatisfiedWhenPDODriverMissing(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}, Database: config.Database{Engine: "postgres"}}
	want, err := renderOpcache()
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{}) // alive
	f.On(reloadedSinceCmd("php8.4-fpm", opcacheDropInPath("8.4"), phpTuningDropInPath("8.4")), bssh.Result{})
	f.On("test -d "+shQuote(phpLogDir), bssh.Result{ExitCode: 0})
	f.On("dpkg -s php8.4-pgsql", bssh.Result{ExitCode: 1}) // PDO driver missing
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the engine PDO driver (php8.4-pgsql) is missing")
	}
}

func TestPHPCheckUnsatisfiedWhenLogDirMissing(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}}
	want, err := renderOpcache()
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{}) // alive
	f.On(reloadedSinceCmd("php8.4-fpm", opcacheDropInPath("8.4"), phpTuningDropInPath("8.4")), bssh.Result{})
	f.On("test -d "+shQuote(phpLogDir), bssh.Result{ExitCode: 1}) // /var/log/php missing
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when /var/log/php is missing")
	}
}

func TestPHPTuningRenderDefaultsFromLiteralServer(t *testing.T) {
	// A literal Server (bypassing config.Load) must still render every directive
	// with a valid value — guards against an accidental raw-field read.
	b, err := renderPHPTuning(&config.Server{})
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{
		"; managed by berth",
		"memory_limit = 256M",
		"upload_max_filesize = 32M",
		"post_max_size = 35651584", // 32M + 2 MiB multipart headroom, exact bytes
		"max_execution_time = 30",
		"max_input_vars = 1000",
		"expose_php = Off",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("tuning drop-in missing %q; got:\n%s", want, body)
		}
	}
}

func TestPHPTuningRenderHonorsOverrides(t *testing.T) {
	s := &config.Server{Tuning: config.Tuning{
		PHPMemoryLimit: "768M", PHPUploadMax: "64M", PHPMaxExecutionTime: 120, PHPMaxInputVars: 5000,
	}}
	b, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{
		"memory_limit = 768M",
		"upload_max_filesize = 64M",
		"post_max_size = 70464307", // 64M + 5% headroom
		"max_execution_time = 120",
		"max_input_vars = 5000",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("tuning drop-in missing %q; got:\n%s", want, body)
		}
	}
}

func TestPHPCheckUnsatisfiedWhenTuningDropInMissing(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}}
	wantOp, err := renderOpcache()
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(wantOp), ExitCode: 0})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1}) // absent
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the tuning drop-in is missing")
	}
}

func TestPHPApplyRefusesForeignTuningDropIn(t *testing.T) {
	// An operator's own file at the tuning drop-in path (no berth marker) must
	// not be clobbered by Apply without --force.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{})                                 // stamp invalidation up front
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})                                    // absent -> written
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 0, Stdout: "memory_limit = 512M\n"}) // foreign

	err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	for _, w := range f.Writes() {
		if w.Path == phpTuningDropInPath("8.4") {
			t.Error("a foreign tuning drop-in must not be overwritten without --force")
		}
	}
}

// phpDifferentialRunner stubs the common Apply prefix up to the first
// php-fpm -t for the fault-isolation differential tests (version 8.4,
// source debian, drop-ins absent).
func phpDifferentialRunner() *bssh.FakeRunner {
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{}) // stamp invalidation up front
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	return f
}

// strictRMCmd is the checked drop-in removal the differential performs.
const strictRMCmd8_4 = "rm -f '/etc/php/8.4/fpm/conf.d/99-berth-opcache.ini' '/etc/php/8.4/fpm/conf.d/99-berth-tuning.ini'"

func callIdx(f *bssh.FakeRunner, want string, nth int) int {
	seen := 0
	for i, c := range f.Calls() {
		if c.Cmd == want {
			if seen == nth {
				return i
			}
			seen++
		}
	}
	return -1
}

func TestPHPApplyRemovesDropInsOnOwnFault(t *testing.T) {
	// -t fails with the drop-ins present and passes without them: the fault is
	// berth's own rendered files. Keep them removed (leaving them would make
	// the next run's Check falsely Satisfied while the master never loaded
	// them) and fail loudly with today's message.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := phpDifferentialRunner()
	f.OnSeq("php-fpm8.4 -t",
		bssh.Result{ExitCode: 1, Stderr: "syntax error"},
		bssh.Result{}) // passes once berth's drop-ins are gone
	f.On(strictRMCmd8_4, bssh.Result{})

	err := PHP().Apply(context.Background(), provision.RunCtx{FullRun: true}, s, f)
	if err == nil || !strings.Contains(err.Error(), "-t failed") {
		t.Fatalf("err = %v, want the -t failure", err)
	}
	// The differential PROVED the fault is berth's own rendering — the error
	// must say so, and must not point at pool.d (wrong on this path).
	if !strings.Contains(err.Error(), "berth's own drop-ins are at fault") {
		t.Errorf("err = %v, want the proven own-fault verdict", err)
	}
	if strings.Contains(err.Error(), "pool.d") {
		t.Errorf("err = %v, must not hint at pool.d when the fault is proven to be berth's", err)
	}
	if callIdx(f, strictRMCmd8_4, 0) < 0 {
		t.Error("Apply must remove both drop-ins after a failed php-fpm -t")
	}
	if got := len(f.Writes()); got != 2 {
		t.Errorf("own fault must not restore the drop-ins; writes = %d, want 2 (initial only)", got)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "systemctl reload php8.4-fpm" || c.Cmd == "systemctl start php8.4-fpm" || c.Cmd == markReloadedCmd("php8.4-fpm") {
			t.Errorf("%q must not run after a failed php-fpm -t", c.Cmd)
		}
	}
}

func TestPHPApplyDefersOutsideFaultToSite(t *testing.T) {
	// -t fails both with AND without berth's drop-ins: the fault lives in a
	// file a later step owns (a pool under pool.d/). Restore the drop-ins,
	// skip start/reload/stamp and warn — the site step re-renders its pools,
	// validates and reloads, and its shared unit stamp blesses the restored
	// drop-ins in the same run.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := phpDifferentialRunner()
	f.OnSeq("php-fpm8.4 -t",
		bssh.Result{ExitCode: 1, Stderr: "bad with drop-ins"},
		bssh.Result{ExitCode: 1, Stderr: "bad without drop-ins"})
	f.On(strictRMCmd8_4, bssh.Result{})

	var warned []string
	rc := provision.RunCtx{FullRun: true, Warn: func(msg string) { warned = append(warned, msg) }}
	if err := PHP().Apply(context.Background(), rc, s, f); err != nil {
		t.Fatalf("outside fault must defer, not fail: %v", err)
	}
	if len(warned) != 1 {
		t.Fatalf("want exactly one warning, got %q", warned)
	}
	// The warning must carry the SECOND validator run's stderr — the verdict
	// obtained without berth's files — and point at the site step.
	if !strings.Contains(warned[0], "bad without drop-ins") || strings.Contains(warned[0], "bad with drop-ins") {
		t.Errorf("warning must quote the second -t stderr; got %q", warned[0])
	}
	if !strings.Contains(warned[0], "site step") {
		t.Errorf("warning must defer to the site step; got %q", warned[0])
	}
	// Restore: both drop-ins written again with identical managed content.
	w := f.Writes()
	if len(w) != 4 {
		t.Fatalf("want 4 writes (2 initial + 2 restore), got %d", len(w))
	}
	if w[2].Path != w[0].Path || string(w[2].Content) != string(w[0].Content) ||
		w[3].Path != w[1].Path || string(w[3].Content) != string(w[1].Content) {
		t.Error("restore must rewrite the same drop-ins with the same managed bytes")
	}
	// Ordering: first -t → strict rm → second -t → restore (the restore's
	// write-guard cat is its first remote call, so its index pins the phase).
	if !(callIdx(f, "php-fpm8.4 -t", 0) < callIdx(f, strictRMCmd8_4, 0) &&
		callIdx(f, strictRMCmd8_4, 0) < callIdx(f, "php-fpm8.4 -t", 1)) {
		t.Errorf("differential order wrong: %+v", f.Calls())
	}
	if !(callIdx(f, "php-fpm8.4 -t", 1) < callIdx(f, "cat "+shQuote(opcacheDropInPath("8.4")), 1)) {
		t.Errorf("restore must start only after the second -t; calls: %+v", f.Calls())
	}
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "systemctl reload php8.4-fpm", "systemctl start php8.4-fpm",
			"systemctl is-active php8.4-fpm", markReloadedCmd("php8.4-fpm"):
			t.Errorf("%q must not run when the reload is deferred to site", c.Cmd)
		}
	}
}

func TestPHPApplyFailsWhenStrictRemovalFails(t *testing.T) {
	// If the drop-ins cannot be removed, the differential cannot establish
	// the "without berth's files" condition — no verdict may be issued.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := phpDifferentialRunner()
	f.On("php-fpm8.4 -t", bssh.Result{ExitCode: 1, Stderr: "syntax error"})
	f.On(strictRMCmd8_4, bssh.Result{ExitCode: 1, Stderr: "rm: cannot remove"})

	var warned []string
	rc := provision.RunCtx{FullRun: true, Warn: func(msg string) { warned = append(warned, msg) }}
	err := PHP().Apply(context.Background(), rc, s, f)
	if err == nil || !strings.Contains(err.Error(), "syntax error") || !strings.Contains(err.Error(), "rm: cannot remove") {
		t.Fatalf("err = %v, want both the -t failure and the removal failure", err)
	}
	if n := callIdx(f, "php-fpm8.4 -t", 1); n >= 0 {
		t.Error("no second -t may run when the removal failed")
	}
	if len(f.Writes()) != 2 || len(warned) != 0 {
		t.Errorf("no restore and no warning on an unestablished differential; writes=%d warned=%q", len(f.Writes()), warned)
	}
}

func TestPHPApplyPropagatesRemovalTransportError(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := phpDifferentialRunner()
	f.On("php-fpm8.4 -t", bssh.Result{ExitCode: 1, Stderr: "syntax error"})
	f.OnError(strictRMCmd8_4, errors.New("connection lost"))

	err := PHP().Apply(context.Background(), provision.RunCtx{FullRun: true}, s, f)
	if err == nil || !strings.Contains(err.Error(), "connection lost") {
		t.Fatalf("err = %v, want the transport error propagated", err)
	}
}

// errOnNthRunner delegates to a FakeRunner but injects a transport error on
// the nth occurrence of one command — FakeRunner's OnError applies to every
// occurrence, which cannot model "the second -t dies mid-differential".
type errOnNthRunner struct {
	*bssh.FakeRunner
	cmd  string
	nth  int
	err  error
	seen int
}

func (r *errOnNthRunner) Run(ctx context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	if cmd == r.cmd {
		r.seen++
		if r.seen == r.nth {
			return bssh.Result{}, r.err
		}
	}
	return r.FakeRunner.Run(ctx, cmd, stdin)
}

func TestPHPApplyPropagatesSecondValidatorTransportError(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := phpDifferentialRunner()
	f.On("php-fpm8.4 -t", bssh.Result{ExitCode: 1, Stderr: "syntax error"})
	f.On(strictRMCmd8_4, bssh.Result{})
	r := &errOnNthRunner{FakeRunner: f, cmd: "php-fpm8.4 -t", nth: 2, err: errors.New("connection lost")}

	var warned []string
	rc := provision.RunCtx{FullRun: true, Warn: func(m string) { warned = append(warned, m) }}
	err := PHP().Apply(context.Background(), rc, s, r)
	if err == nil || !strings.Contains(err.Error(), "connection lost") {
		t.Fatalf("err = %v, want the transport error from the second -t propagated", err)
	}
	if len(f.Writes()) != 2 || len(warned) != 0 {
		t.Errorf("no restore and no warning after a dead second -t; writes=%d warned=%q", len(f.Writes()), warned)
	}
}

func TestPHPApplyPropagatesRestoreFailure(t *testing.T) {
	// A foreign file materializing at the drop-in path between the strict
	// removal and the restore must hit the managed-write guard: propagate,
	// emit no warning (the step did not reach a deferred state).
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{})
	f.OnSeq("cat "+shQuote(opcacheDropInPath("8.4")),
		bssh.Result{ExitCode: 1},                             // initial write guard: absent
		bssh.Result{ExitCode: 0, Stdout: "intruder content"}) // restore guard: foreign file
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.OnSeq("php-fpm8.4 -t",
		bssh.Result{ExitCode: 1, Stderr: "bad A"},
		bssh.Result{ExitCode: 1, Stderr: "bad B"})
	f.On(strictRMCmd8_4, bssh.Result{})

	var warned []string
	rc := provision.RunCtx{FullRun: true, Warn: func(msg string) { warned = append(warned, msg) }}
	err := PHP().Apply(context.Background(), rc, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the managed-write refusal from the restore", err)
	}
	if len(warned) != 0 {
		t.Errorf("no warning may be emitted when the restore failed: %q", warned)
	}
}

func TestPHPApplyOutsideFaultUnderOnlyFailsHard(t *testing.T) {
	// Deferring to site is honest only when site is guaranteed to run later
	// (a full pipeline). Under --only (FullRun=false) returning nil would
	// report Applied and exit 0 with no reload ever happening — fail instead,
	// with the drop-ins restored so on-disk state stays the desired one.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := phpDifferentialRunner()
	f.OnSeq("php-fpm8.4 -t",
		bssh.Result{ExitCode: 1, Stderr: "bad A"},
		bssh.Result{ExitCode: 1, Stderr: "bad B"})
	f.On(strictRMCmd8_4, bssh.Result{})

	var warned []string
	rc := provision.RunCtx{FullRun: false, Warn: func(msg string) { warned = append(warned, msg) }}
	err := PHP().Apply(context.Background(), rc, s, f)
	if err == nil || !strings.Contains(err.Error(), "full provision") {
		t.Fatalf("err = %v, want a hard error telling the operator to run a full provision", err)
	}
	if !strings.Contains(err.Error(), "/etc/php/8.4/fpm/pool.d/") {
		t.Errorf("err = %v, want the pool directory named", err)
	}
	if len(warned) != 0 {
		t.Errorf("no warning under --only, got %q", warned)
	}
	if len(f.Writes()) != 4 {
		t.Errorf("drop-ins must still be restored before failing; writes = %d, want 4", len(f.Writes()))
	}
}

func TestPHPApplyInvalidatesBeforePackageInstall(t *testing.T) {
	// apt itself can mutate the unit's config (conffiles, conf.d links,
	// maintainer scripts), so the stamp must be invalidated BEFORE the package
	// transaction — a crash between apt and the reload must not leave the old
	// stamp blessing a running master that never loaded apt's changes.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("php-fpm8.4 -t", bssh.Result{})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{})
	f.On("systemctl reload php8.4-fpm", bssh.Result{})
	f.On(markReloadedCmd("php8.4-fpm"), bssh.Result{})

	if err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	invalidate, install := -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "rm -f " + shQuote("/var/lib/berth/php8.4-fpm.reloaded"):
			invalidate = i
		case "DEBIAN_FRONTEND=noninteractive apt-get install -y " + strings.Join(phpExtPkgs(), " "):
			install = i
		}
	}
	if invalidate < 0 || install < 0 || invalidate > install {
		t.Errorf("the FPM stamp must be invalidated BEFORE the apt install; rm=%d install=%d", invalidate, install)
	}
}

func TestPHPCheckUnsatisfiedWhenFPMDead(t *testing.T) {
	// php-fpm -t validates syntax even when the daemon is dead; without a
	// liveness probe every step reports green while the host serves 502s.
	s := &config.Server{PHP: config.PHP{Version: "8.4"}}
	want, err := renderOpcache()
	if err != nil {
		t.Fatal(err)
	}
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})
	f.On("test -d "+shQuote(phpLogDir), bssh.Result{ExitCode: 0})
	f.On("dpkg -s php8.4-mysql", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{ExitCode: 3}) // dead
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the FPM daemon is not running")
	}
	if !strings.Contains(cr.Reason, "php8.4-fpm") {
		t.Errorf("Reason = %q, want it to mention the daemon", cr.Reason)
	}
}

func TestPHPCheckUnsatisfiedWhenDropInsNewerThanStamp(t *testing.T) {
	// A crash between Apply's drop-in writes and its reload leaves the running
	// master on the old config while every byte-level probe reads converged.
	s := &config.Server{PHP: config.PHP{Version: "8.4"}}
	want, err := renderOpcache()
	if err != nil {
		t.Fatal(err)
	}
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})
	f.On("test -d "+shQuote(phpLogDir), bssh.Result{ExitCode: 0})
	f.On("dpkg -s php8.4-mysql", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{})
	f.On(reloadedSinceCmd("php8.4-fpm", opcacheDropInPath("8.4"), phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when the drop-ins are newer than the reload stamp")
	}
}

func TestPHPApplyStartsDeadFPMAndStamps(t *testing.T) {
	// A dead FPM cannot be `reload`ed: Apply must start it (start, not
	// enable --now — the boot policy is not this step's call) and stamp.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{}) // stamp invalidation up front
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})    // write-guard: absent
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})  // write-guard: absent
	f.On("php-fpm8.4 -t", bssh.Result{})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{ExitCode: 3}) // dead
	f.On("systemctl start php8.4-fpm", bssh.Result{})
	f.On(markReloadedCmd("php8.4-fpm"), bssh.Result{})

	if err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var started, stamped bool
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "systemctl start php8.4-fpm":
			started = true
		case "systemctl reload php8.4-fpm":
			t.Error("a dead FPM must be started, never reloaded")
		case markReloadedCmd("php8.4-fpm"):
			stamped = true
		}
	}
	if !started {
		t.Error("Apply must start a dead FPM so the drop-ins load")
	}
	if !stamped {
		t.Error("Apply must record the reload stamp after a successful start")
	}
}

func TestPHPApplyReloadsLiveFPMAndStamps(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{}) // stamp invalidation up front
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})    // write-guard: absent
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})  // write-guard: absent
	f.On("php-fpm8.4 -t", bssh.Result{})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{}) // alive
	f.On("systemctl reload php8.4-fpm", bssh.Result{})
	f.On(markReloadedCmd("php8.4-fpm"), bssh.Result{})

	if err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var reloaded, stamped bool
	for _, c := range f.Calls() {
		switch c.Cmd {
		case "systemctl reload php8.4-fpm":
			reloaded = true
		case "systemctl start php8.4-fpm":
			t.Error("a live FPM must be reloaded (graceful), never started")
		case markReloadedCmd("php8.4-fpm"):
			stamped = true
		}
	}
	if !reloaded {
		t.Error("Apply must gracefully reload a live FPM")
	}
	if !stamped {
		t.Error("Apply must record the reload stamp after a successful reload")
	}
}

func TestPHPApplyNoStampWhenValidationFails(t *testing.T) {
	// A failed php-fpm -t must never install the reload stamp: the invalidation
	// up front already removed it, so the next run reconciles with one reload.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	rm := "rm -f " + shQuote(opcacheDropInPath("8.4")) + " " + shQuote(phpTuningDropInPath("8.4"))
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{}) // stamp invalidation up front
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("php-fpm8.4 -t", bssh.Result{ExitCode: 1, Stderr: "bad ini"})
	f.On(rm, bssh.Result{})

	// RunCtx{} means FullRun=false: both -t runs fail (same stub), so this
	// exercises the hard-error path of the differential — still no stamp.
	err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "-t fail") {
		t.Fatalf("err = %v, want the -t failure", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == markReloadedCmd("php8.4-fpm") {
			t.Error("the reload stamp must not be installed after a failed php-fpm -t")
		}
	}
}

func TestPHPApplyRemovesDropInsOnReloadFailure(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	rm := "rm -f " + shQuote(opcacheDropInPath("8.4")) + " " + shQuote(phpTuningDropInPath("8.4"))
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{}) // stamp invalidation up front
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("php-fpm8.4 -t", bssh.Result{})
	f.On("systemctl is-active php8.4-fpm", bssh.Result{}) // alive
	f.On("systemctl reload php8.4-fpm", bssh.Result{ExitCode: 1, Stderr: "job failed"})
	f.On(rm, bssh.Result{})

	err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "reload php8.4-fpm failed") {
		t.Fatalf("err = %v, want the reload failure", err)
	}
	var removed bool
	for _, c := range f.Calls() {
		if c.Cmd == rm {
			removed = true
		}
	}
	if !removed {
		t.Error("Apply must remove both drop-ins after a failed reload")
	}
}

func TestPHPDeferralConvergesViaSiteSharedStamp(t *testing.T) {
	// The central P13 invariant, composed across steps: php.Apply defers
	// (drop-ins restored, NO stamp), site.Apply heals its pool and marks the
	// SAME per-unit stamp, and php.Check — probing that same stamp — reports
	// Satisfied. FakeRunner cannot emulate mtime ordering, so the stamp probe
	// result is stubbed; what this test pins is the unit-name identity across
	// steps (php would never converge if its probe and site's mark used
	// different stamp paths) and the no-mark/mark division of labor. The
	// mtime semantics are proven live (design §7).
	s := siteServer() // PHP 8.4 (stock), one site, scheduler on
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSuryRepoAbsent(f)

	// --- Act 1: php.Apply — a pool file is broken, fault outside the drop-ins.
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs(), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("rm -f "+shQuote("/var/lib/berth/php8.4-fpm.reloaded"), bssh.Result{})
	f.OnSeq("php-fpm8.4 -t",
		bssh.Result{ExitCode: 1, Stderr: "pool broken"},
		bssh.Result{ExitCode: 1, Stderr: "pool broken"},
		bssh.Result{}) // third call: site's validation after healing the pool
	f.On(strictRMCmd8_4, bssh.Result{})

	var warned []string
	rc := provision.RunCtx{FullRun: true, Warn: func(m string) { warned = append(warned, m) }}
	if err := PHP().Apply(context.Background(), rc, s, f); err != nil {
		t.Fatalf("php.Apply must defer, not fail: %v", err)
	}
	if len(warned) != 1 {
		t.Fatalf("want one php warning, got %q", warned)
	}
	if callIdx(f, markReloadedCmd(fpmService(s)), 0) >= 0 {
		t.Fatal("php.Apply must NOT mark the FPM stamp on the deferral path")
	}

	// --- Act 2: site.Apply — re-renders the pool, validates, reloads, marks.
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	if err := Site().Apply(context.Background(), rc, s, f); err != nil {
		t.Fatalf("site.Apply must heal: %v", err)
	}
	if callIdx(f, markReloadedCmd(fpmService(s)), 0) < 0 {
		t.Fatal("site.Apply must mark the shared FPM unit stamp after its reload")
	}

	// --- Act 3: php.Check against the post-site state: the restored drop-in
	// bytes read back verbatim and the shared stamp is fresh → Satisfied.
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	replayWritesAsReads(f, f.Writes())
	f.On("systemctl is-active php8.4-fpm", bssh.Result{})
	f.On(reloadedSinceCmd(fpmService(s), opcacheDropInPath("8.4"), phpTuningDropInPath("8.4")), bssh.Result{})
	f.On("test -d "+shQuote(phpLogDir), bssh.Result{ExitCode: 0})
	f.On("dpkg -s php8.4-mysql", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	cr, err := PHP().Check(context.Background(), rc, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("php.Check must be satisfied once site reloaded and stamped the shared unit; got %+v", cr)
	}
}

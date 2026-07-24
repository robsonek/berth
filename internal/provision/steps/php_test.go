package steps

import (
	"context"
	"slices"
	"strings"
	"testing"

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

func phpExtPkgs(v string) []string {
	var pkgs []string
	for _, ext := range []string{"fpm", "cli", "mbstring", "xml", "bcmath", "curl", "intl", "zip", "gd", "redis", "mysql"} {
		pkgs = append(pkgs, "php"+v+"-"+ext)
	}
	return pkgs
}

func TestPHPApplyRefusesForeignOpcacheDropIn(t *testing.T) {
	// An operator's own OPcache drop-in (no berth marker) must not be clobbered
	// by Apply without --force.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs("8.4"), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
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
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs("8.4"), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})   // write-guard: absent
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1}) // write-guard: absent
	f.On("php-fpm8.4 -t", bssh.Result{})
	f.On("systemctl reload php8.4-fpm", bssh.Result{})

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
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0})                     // installed
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1}) // drop-in absent
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
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})
	f.On("test -d "+shQuote(phpLogDir), bssh.Result{ExitCode: 0})
	f.On("dpkg -s php8.4-mysql", bssh.Result{ExitCode: 0}) // engine "" -> pdo_mysql, installed
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
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})
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
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	wantTuning, err := renderPHPTuning(s)
	if err != nil {
		t.Fatal(err)
	}
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{Stdout: string(wantTuning), ExitCode: 0})
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
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0})
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
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs("8.4"), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
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

func TestPHPApplyRemovesDropInsOnTestFailure(t *testing.T) {
	// A failed php-fpm -t after the writes must remove BOTH drop-ins: leaving
	// them would make the next run's Check falsely Satisfied (bytes match)
	// while the running master never loaded the new content.
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	rm := "rm -f " + shQuote(opcacheDropInPath("8.4")) + " " + shQuote(phpTuningDropInPath("8.4"))
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs("8.4"), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("php-fpm8.4 -t", bssh.Result{ExitCode: 1, Stderr: "syntax error"})
	f.On(rm, bssh.Result{})

	err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "-t failed") {
		t.Fatalf("err = %v, want the -t failure", err)
	}
	var removed bool
	for _, c := range f.Calls() {
		if c.Cmd == rm {
			removed = true
		}
	}
	if !removed {
		t.Error("Apply must remove both drop-ins after a failed php-fpm -t")
	}
}

func TestPHPApplyRemovesDropInsOnReloadFailure(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}}
	rm := "rm -f " + shQuote(opcacheDropInPath("8.4")) + " " + shQuote(phpTuningDropInPath("8.4"))
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs("8.4"), " "), bssh.Result{})
	f.On("install -d -o root -g root -m 0755 "+shQuote(phpLogDir), bssh.Result{})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(phpTuningDropInPath("8.4")), bssh.Result{ExitCode: 1})
	f.On("php-fpm8.4 -t", bssh.Result{})
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

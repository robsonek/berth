package steps

import (
	"context"
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

func TestPHPApplyWritesOpcacheDropIn(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4", Source: "debian"}} // stock -> no Surý repo
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y "+strings.Join(phpExtPkgs("8.4"), " "), bssh.Result{})
	f.On("php-fpm8.4 -t", bssh.Result{})
	f.On("systemctl reload php8.4-fpm", bssh.Result{})

	if err := PHP().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var drop *bssh.FileSpec
	for i := range f.Writes() {
		if f.Writes()[i].Path == opcacheDropInPath("8.4") {
			drop = &f.Writes()[i]
		}
	}
	if drop == nil {
		t.Fatal("OPcache drop-in was not written")
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
	// FPM-only: never write a CLI OPcache drop-in (workers keep stock enable_cli=0).
	for _, w := range f.Writes() {
		if strings.Contains(w.Path, "/cli/conf.d/") {
			t.Errorf("must not write a CLI OPcache drop-in: %s", w.Path)
		}
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
	f := bssh.NewFakeRunner()
	f.On("dpkg -s php8.4-fpm", bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(opcacheDropInPath("8.4")), bssh.Result{Stdout: string(want), ExitCode: 0})
	cr, err := PHP().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied when installed and OPcache drop-in up to date; got %+v", cr)
	}
}

package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func manifestServer() *config.Server {
	return &config.Server{Host: "app.example.com", SSH: config.SSH{Port: 22}}
}

// --only runs never touch the manifest: Satisfied without a single remote call.
func TestManifestCheckOnlyRunIsSatisfiedWithoutProbes(t *testing.T) {
	f := bssh.NewFakeRunner()
	res, err := Manifest().Check(context.Background(), provision.RunCtx{FullRun: false}, manifestServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("partial runs must not demand a manifest: %+v", res)
	}
	if len(f.Calls()) != 0 {
		t.Fatalf("no remote probe expected on --only, got %v", f.Calls())
	}
}

func TestManifestCheckMissingFileUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat /var/lib/berth/manifest", bssh.Result{ExitCode: 1})
	res, err := Manifest().Check(context.Background(), provision.RunCtx{FullRun: true}, manifestServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("missing manifest must be unsatisfied on a full run")
	}
}

func TestManifestCheckVersionMatchSatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat /var/lib/berth/manifest", bssh.Result{ExitCode: 0,
		Stdout: "# managed by berth\nVERSION=dev\nPROVISIONED_AT=2026-01-02T03:04:05Z\n"})
	res, err := Manifest().Check(context.Background(), provision.RunCtx{FullRun: true}, manifestServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("VERSION=dev must satisfy a dev binary: %+v", res)
	}
}

func TestManifestCheckVersionMismatchUnsatisfied(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat /var/lib/berth/manifest", bssh.Result{ExitCode: 0,
		Stdout: "# managed by berth\nVERSION=v0.9.0\nPROVISIONED_AT=2026-01-02T03:04:05Z\n"})
	res, err := Manifest().Check(context.Background(), provision.RunCtx{FullRun: true}, manifestServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("a manifest from another version must be unsatisfied")
	}
	if !strings.Contains(res.Reason, "v0.9.0") {
		t.Fatalf("reason should name the recorded version, got %q", res.Reason)
	}
}

func TestManifestApplyWritesVersionAndTimestamp(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("date -u +%Y-%m-%dT%H:%M:%SZ", bssh.Result{ExitCode: 0, Stdout: "2026-07-28T00:00:00Z\n"})
	f.On("install -d -o root -g root -m 0755 /var/lib/berth", bssh.Result{})
	if err := Manifest().Apply(context.Background(), provision.RunCtx{FullRun: true}, manifestServer(), f); err != nil {
		t.Fatal(err)
	}
	ws := f.Writes()
	if len(ws) != 1 || ws[0].Path != "/var/lib/berth/manifest" {
		t.Fatalf("expected exactly the manifest write, got %+v", ws)
	}
	body := string(ws[0].Content)
	if !strings.Contains(body, "# managed by berth") ||
		!strings.Contains(body, "VERSION=dev\n") ||
		!strings.Contains(body, "PROVISIONED_AT=2026-07-28T00:00:00Z\n") {
		t.Fatalf("manifest body wrong:\n%s", body)
	}
	if ws[0].Owner != "root" || ws[0].Mode != 0o644 || !ws[0].Sudo {
		t.Fatalf("manifest must be root:root 0644 sudo, got %+v", ws[0])
	}
}

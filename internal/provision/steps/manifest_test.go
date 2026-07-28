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
	// The manifest attests pipeline completion, not host state — the Reason
	// must not overclaim "fully provisioned".
	if !strings.Contains(res.Reason, "full pipeline completed by dev") {
		t.Fatalf("Reason = %q, want it to say the full pipeline completed", res.Reason)
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

// A SAME-VERSION manifest must not satisfy Check when the run marked itself
// unconverged: Satisfied would skip Apply and make the withhold warning
// unreachable on exactly the run that matters — a same-version re-run that
// newly skipped TLS issuance. Check must report unsatisfied (routing into
// Apply's warn-and-skip) even though the recorded VERSION matches.
func TestManifestCheckUnsatisfiedWhenRunUnconverged(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("cat /var/lib/berth/manifest", bssh.Result{ExitCode: 0,
		Stdout: "# managed by berth\nVERSION=dev\nPROVISIONED_AT=2026-01-02T03:04:05Z\n"})
	rc := provision.RunCtx{
		FullRun:            true,
		UnconvergedReasons: func() []string { return []string{"tls skipped issuance for app.example.com"} },
	}
	res, err := Manifest().Check(context.Background(), rc, manifestServer(), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("a same-version manifest must not satisfy Check on an unconverged run — Apply's withhold guard would be unreachable")
	}
	if !strings.Contains(res.Reason, "withheld") {
		t.Fatalf("Reason = %q, want it to say the manifest write is withheld", res.Reason)
	}
}

// A run that knowingly left work undone (tls skipped issuance on a DNS
// mismatch) must not attest full convergence: Apply withholds the write with
// a warning and touches NOTHING on the host — a previous manifest, which
// attested a PRIOR converged run, stays intact.
func TestManifestApplyWithheldWhenRunUnconverged(t *testing.T) {
	f := bssh.NewFakeRunner() // no stubs: any remote call fails the test
	var warned []string
	rc := provision.RunCtx{
		FullRun: true,
		Warn:    func(msg string) { warned = append(warned, msg) },
		UnconvergedReasons: func() []string {
			return []string{"tls skipped issuance for app.example.com: it does not resolve to 203.0.113.10"}
		},
	}
	if err := Manifest().Apply(context.Background(), rc, manifestServer(), f); err != nil {
		t.Fatalf("withholding the manifest must not fail the run: %v", err)
	}
	if len(f.Writes()) != 0 {
		t.Fatalf("withheld manifest must write nothing, got %+v", f.Writes())
	}
	if len(f.Calls()) != 0 {
		t.Fatalf("withheld manifest must not run remote commands, got %v", f.Calls())
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "manifest withheld") ||
		!strings.Contains(warned[0], "app.example.com") {
		t.Fatalf("want one 'manifest withheld' warning carrying the reason, got %q", warned)
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

package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
	"github.com/robsonek/berth/internal/version"
)

// manifestPath records which berth version last FULLY provisioned this host.
// It lives beside the reload stamps in berth-exclusive /var/lib/berth (no
// marker-guard/--force semantics, same as the stamps: tenants can never write
// here and no operator file is expected), but the content still carries the
// managed marker so its origin is evident to an operator reading it.
const manifestPath = berthStateDir + "/manifest"

// Manifest is the LAST pipeline step: it stamps /var/lib/berth/manifest with
// the running berth version after every step before it converged. Check
// compares ONLY the VERSION field — deliberately not a content hash, so the
// PROVISIONED_AT timestamp never reads as drift. Partial runs (--only,
// FullRun=false) neither read nor write it: a partial run proves nothing
// about the whole pipeline, and a manifest claiming otherwise would mislead
// future migrations that branch on "last fully provisioned by <= vX".
type manifest struct{}

func Manifest() provision.Step { return manifest{} }

func (manifest) Name() string       { return "manifest" }
func (manifest) Requires() []string { return nil }

func (manifest) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	if !rc.FullRun {
		return provision.CheckResult{Satisfied: true, Reason: "manifest is written only by full runs"}, nil
	}
	res, err := r.Run(ctx, "cat "+manifestPath, nil)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if res.ExitCode != 0 {
		return provision.CheckResult{Satisfied: false, Reason: "no provisioning manifest recorded on the host", Changes: manifestChanges()}, nil
	}
	recorded := ""
	for _, line := range strings.Split(res.Stdout, "\n") {
		if v, ok := strings.CutPrefix(line, "VERSION="); ok {
			recorded = strings.TrimRight(v, " \t\r")
			break
		}
	}
	if recorded == version.Version {
		return provision.CheckResult{Satisfied: true, Reason: "host fully provisioned by " + recorded}, nil
	}
	return provision.CheckResult{Satisfied: false, Reason: fmt.Sprintf("manifest records %q, this binary is %s", recorded, version.Version), Changes: manifestChanges()}, nil
}

func manifestChanges() []string {
	return []string{"record VERSION=" + version.Version + " in " + manifestPath}
}

func (manifest) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	ts, err := r.Run(ctx, "date -u +%Y-%m-%dT%H:%M:%SZ", nil)
	if err != nil {
		return err
	}
	if ts.ExitCode != 0 {
		return fmt.Errorf("read remote UTC time: %s", ts.Stderr)
	}
	body, err := templates.Render("manifest.tmpl", struct{ Version, ProvisionedAt string }{
		Version:       version.Version,
		ProvisionedAt: strings.TrimSpace(ts.Stdout),
	})
	if err != nil {
		return err
	}
	if err := runOK(ctx, r, "install -d -o root -g root -m 0755 "+berthStateDir); err != nil {
		return err
	}
	return r.WriteFile(ctx, bssh.FileSpec{Path: manifestPath, Content: body, Owner: "root", Group: "root", Mode: 0o644, Sudo: true})
}

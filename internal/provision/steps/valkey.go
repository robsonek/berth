package steps

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

// valkeyUnit is the systemd unit shipped by the Debian valkey-server package.
const valkeyUnit = "valkey-server.service"

const (
	valkeyUnitDir   = "/etc/systemd/system"
	valkeyRunBase   = "/run/berth-valkey"
	valkeyStateBase = "/var/lib/berth-valkey"
)

// Per-site instance identity. One Valkey per site, reachable only via a unix
// socket in a 0700 runtime dir owned by the site user — OS-level tenant
// isolation, no TCP listener, no credentials (same philosophy as the per-site
// FPM pool). systemd creates Runtime/StateDirectory owned by User=, so the
// step needs no mkdir/chown and does not depend on appdirs.
func valkeyInstanceUnit(domain string) string { return "berth-valkey-" + poolName(domain) + ".service" }
func valkeyUnitPath(domain string) string     { return valkeyUnitDir + "/" + valkeyInstanceUnit(domain) }
func valkeySocketPath(domain string) string {
	return valkeyRunBase + "/" + poolName(domain) + "/valkey.sock"
}
func valkeyDataDir(domain string) string { return valkeyStateBase + "/" + poolName(domain) }

// renderValkeyUnit renders one site's managed instance unit. All configuration
// travels as ExecStart args on purpose: nothing here is secret, and it keeps
// the unit the single managed artifact per site. The maxmemory knobs are the
// existing tuning.* config values — the cap is per instance.
func renderValkeyUnit(s *config.Server, site config.Site) ([]byte, error) {
	return templates.Render("berth_valkey.service.tmpl", struct {
		Domain, User, Pool, Maxmemory, Policy string
	}{
		Domain:    site.Domain,
		User:      s.SiteUser(site),
		Pool:      poolName(site.Domain),
		Maxmemory: s.Tuning.ValkeyMaxmemoryEff(),
		Policy:    s.Tuning.ValkeyMaxmemoryPolicyEff(),
	})
}

type valkey struct{}

func Valkey() provision.Step { return valkey{} }

func (valkey) Name() string       { return "valkey" }
func (valkey) Requires() []string { return []string{"base"} }

func (valkey) Check(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	installed, err := pkgInstalled(ctx, r, "valkey-server")
	if err != nil {
		return provision.CheckResult{}, err
	}
	up, err := serviceUp(ctx, r, valkeyUnit)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if installed && up {
		return provision.CheckResult{Satisfied: true, Reason: "valkey-server installed and running"}, nil
	}
	return provision.CheckResult{
		Satisfied: false,
		Reason:    "valkey-server not installed or not running",
		Changes:   []string{"install valkey-server", "systemctl enable --now " + valkeyUnit},
	}, nil
}

func (valkey) Apply(ctx context.Context, _ provision.RunCtx, _ *config.Server, r bssh.Runner) error {
	if err := apt.New(r).EnsurePackages(ctx, nil, "valkey-server"); err != nil {
		return fmt.Errorf("install valkey-server: %w", err)
	}
	if res, err := r.Run(ctx, "systemctl enable --now "+valkeyUnit, nil); err != nil {
		return err
	} else if res.ExitCode != 0 {
		return fmt.Errorf("enable valkey-server: %s", res.Stderr)
	}
	return nil
}

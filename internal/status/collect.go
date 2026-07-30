package status

import (
	"context"
	"fmt"
	"time"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// Options controls a fleet sweep.
type Options struct {
	// Drift adds the full read-only Check sweep — dozens of round trips per
	// host, so it is opt-in.
	Drift bool
	// Offsite additionally queries the offsite repository. That is network
	// traffic to the remote backend, so it is opt-in. Credentials come from
	// the HOST's own /etc/berth/offsite.env, never from the local cache.
	Offsite bool
	// Parallel bounds concurrent hosts (default 4 when zero).
	Parallel int
	// KnownHosts is the path used for host-key verification.
	KnownHosts string
	// Timeout bounds ONE host's whole collection, including the drift sweep.
	// Zero means the defaults below.
	//
	// This is not optional polish. The ssh layer's keepalives only unblock a
	// DEAD transport; a host that keeps answering slowly, or one command that
	// never returns, would otherwise hang the sweep forever — unacceptable for
	// a command meant to run in CI and cron.
	Timeout time.Duration
}

// Default per-host budgets. The cheap probes are a handful of commands, so
// 60s is already generous; a drift sweep runs the whole pipeline's Checks,
// which took 30-70s per host in live validation, so it gets 10 minutes.
const (
	defaultProbeTimeout = 60 * time.Second
	defaultDriftTimeout = 10 * time.Minute
)

// timeout resolves the per-host budget for this run.
func (o Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	if o.Drift {
		return defaultDriftTimeout
	}
	return defaultProbeTimeout
}

// CollectHost gathers every fact about one host. It never returns an error:
// a failure becomes Reachable:false with a reason, because one dead host must
// not cost the operator the rest of the overview.
//
// pipeline nil skips the drift scan; the trailing bool is the offsite flag,
// declared from the start so no later task has to change this signature and
// chase every call site, but unnamed (revive rejects an unused named
// parameter) until Task 15's probe consumes it — false will skip the offsite
// query.
func CollectHost(ctx context.Context, cfgPath string, s *config.Server, r bssh.Runner, pipeline []provision.Step, red provision.Redactor, _ bool) HostStatus {
	h := HostStatus{
		ID:         s.ID,
		ConfigPath: cfgPath,
		Endpoint:   fmt.Sprintf("%s:%d", s.Host, s.SSH.Port),
		ProbedAt:   time.Now().UTC(),
	}
	hostTime, manifest, disks, err := probeHostMeta(ctx, r)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	h.Reachable = true
	h.HostTime = hostTime
	h.Provisioned = manifest
	h.Disk = disks

	// Each partial failure is APPENDED, never assigned to h.Error: assigning
	// let the last probe silently erase the earlier ones, and left the host
	// flagged reachable-and-fine while carrying no facts.
	if svcs, err := probeServices(ctx, r, s); err != nil {
		h.ProbeErrors = append(h.ProbeErrors, "services: "+err.Error())
	} else {
		h.Services = svcs
	}
	certs, err := probeCerts(ctx, r, s, hostTime)
	if err != nil {
		h.ProbeErrors = append(h.ProbeErrors, "certificates: "+err.Error())
	}
	backups, err := probeBackups(ctx, r, s, hostTime)
	if err != nil {
		h.ProbeErrors = append(h.ProbeErrors, "backups: "+err.Error())
	}
	for _, site := range s.Sites {
		h.Sites = append(h.Sites, SiteStatus{
			Domain: site.Domain,
			Cert:   certs[site.Domain],
			Backup: backups[site.Domain],
		})
	}
	if pipeline != nil {
		h.Drift = Drift(ctx, s, r, pipeline, red)
	}
	return h
}

package status

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/provision/steps"
	"github.com/robsonek/berth/internal/secret"
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
// pipeline nil skips the drift scan; offsite false skips the offsite query.
func CollectHost(ctx context.Context, cfgPath string, s *config.Server, r bssh.Runner, pipeline []provision.Step, red provision.Redactor, offsite bool) HostStatus {
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
	// Each site is seeded from the CONFIG first, then overlaid with whatever
	// the probes returned. Cert.Mode and Backup.Enabled/Dir do not depend on
	// the host, and a failed probe must not degrade them to zero values:
	// cert.mode:"" and backup.enabled:false are ANSWERS ("no TLS", "off"),
	// not "unknown", and reporting them for a site the config declares
	// otherwise turns a broken probe into reassurance.
	for _, site := range s.Sites {
		st := SiteStatus{Domain: site.Domain}
		if site.SSL {
			// Empty when the site declares no TLS — that emptiness is what
			// keeps "no TLS" and "declared but missing" apart in the views.
			st.Cert.Mode = site.CertMode()
		}
		if s.BackupsEnabled(site) {
			st.Backup = BackupStatus{Enabled: true, Dir: backupDir(site.Domain)}
		}
		if c, ok := certs[site.Domain]; ok {
			st.Cert = c
		}
		if b, ok := backups[site.Domain]; ok {
			st.Backup = b
		}
		h.Sites = append(h.Sites, st)
	}
	if offsite && s.OffsiteEnabled() {
		o, err := probeOffsite(ctx, r, s.ID, config.OffsiteResticOpts(s.Backups.Offsite))
		switch {
		case err != nil:
			// A transport failure is a PROBE failure: it must reach
			// ProbeErrors so the table shows it and the exit code reflects it.
			// Stuffing it into OffsiteStatus.Error alone made `--offsite`
			// exit 0 on a completely failed query.
			h.ProbeErrors = append(h.ProbeErrors, "offsite: "+err.Error())
		default:
			h.Offsite = o
			if o.Error != "" {
				h.ProbeErrors = append(h.ProbeErrors, "offsite: "+o.Error)
			}
		}
	}
	if pipeline != nil {
		h.Drift = Drift(ctx, s, r, pipeline, red)
	}
	return h
}

// dial opens a connection for a fleet sweep. It is a package-level variable so
// tests can stub it, following the repo's convention for network-dependent
// calls.
//
// TOFU is deliberately DISABLED: there is no sensible way to ask "do you trust
// this key?" for hosts probed concurrently, and a read-only sweep is the worst
// possible place to weaken host-key verification — it is run routinely and
// inattentively, which is exactly when "yes" gets clicked. Only a pinned
// fingerprint or a known_hosts entry is accepted.
var dial = func(ctx context.Context, s *config.Server, knownHosts string) (bssh.Runner, func() error, error) {
	c, err := bssh.Connect(ctx, s, bssh.HostKeyPolicy{
		Pinned:     s.SSH.Fingerprint,
		KnownHosts: knownHosts,
		AllowTOFU:  false,
	})
	if err != nil {
		return nil, nil, err
	}
	return c, c.Close, nil
}

// Collect probes every config in paths, with bounded concurrency, and returns
// one entry per path IN INPUT ORDER so the rendered table is stable.
//
// Unlike the provisioning pipeline this is NOT fail-fast: hosts are
// independent, so one failure never costs the operator the rest of the
// overview.
func Collect(ctx context.Context, paths []string, opt Options) []HostStatus {
	parallel := opt.Parallel
	if parallel <= 0 {
		parallel = 4
	}
	out := make([]HostStatus, len(paths))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, p := range paths {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = collectOne(ctx, p, opt)
		}(i, p)
	}
	wg.Wait()
	return out
}

func collectOne(ctx context.Context, path string, opt Options) HostStatus {
	// Every host gets its own deadline, so one slow-but-alive host cannot hold
	// the sweep open indefinitely. ssh keepalives handle a DEAD transport;
	// they do nothing for a host that keeps answering.
	ctx, cancel := context.WithTimeout(ctx, opt.timeout())
	defer cancel()

	srv, err := config.Load(path)
	if err != nil {
		return HostStatus{ConfigPath: path, Error: err.Error(), ProbedAt: time.Now().UTC()}
	}
	r, closeConn, err := dial(ctx, srv, opt.KnownHosts)
	if err != nil {
		return HostStatus{
			ID: srv.ID, ConfigPath: path,
			Endpoint: fmt.Sprintf("%s:%d", srv.Host, srv.SSH.Port),
			Error:    err.Error(), ProbedAt: time.Now().UTC(),
		}
	}
	defer func() { _ = closeConn() }()

	red := secret.NewRedactor()
	var pipeline []provision.Step
	if opt.Drift {
		// The FULL pipeline (skipSSL false): a scan inspects the whole declared
		// config, and truncating it would hide the steps most worth inspecting.
		pipeline = steps.Pipeline(srv, red, false)
	}
	return CollectHost(ctx, path, srv, r, pipeline, red, opt.Offsite)
}

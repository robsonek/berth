package status

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/hostlock"
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
	// It starts when the host's turn comes: waiting for another config of the
	// same endpoint (see Collect) is not charged to it. Zero means the
	// defaults below.
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
// It takes no lock itself: Collect runs a drift scan under the host session
// lock, and any other caller passing a pipeline must do the same.
func CollectHost(ctx context.Context, cfgPath string, s *config.Server, r bssh.Runner, pipeline []provision.Step, red provision.Redactor, offsite bool) HostStatus {
	h := HostStatus{
		ID:         s.ID,
		ConfigPath: cfgPath,
		Endpoint:   endpoint(s),
		ProbedAt:   time.Now().UTC(),
	}
	meta, err := probeHostMeta(ctx, r)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	h.Reachable = true
	h.HostTime = meta.HostTime
	h.Provisioned = meta.Manifest
	h.Disk = meta.Disk
	// A DEGRADED host-meta answer (df failed for one operand but printed the
	// other) keeps its parsed rows — they are real data — but the failure
	// must reach ProbeErrors and with it the exit code, or a host with a
	// broken mount reads as successfully probed behind a reassuring root
	// percentage.
	if meta.ProbeErr != nil {
		h.ProbeErrors = append(h.ProbeErrors, "host: "+meta.ProbeErr.Error())
	}

	// Each partial failure is APPENDED, never assigned to h.Error: assigning
	// let the last probe silently erase the earlier ones, and left the host
	// flagged reachable-and-fine while carrying no facts.
	svcs, svcWarn, err := probeServices(ctx, r, s)
	if err != nil {
		h.ProbeErrors = append(h.ProbeErrors, "services: "+err.Error())
	} else {
		h.Services = svcs
		// A truncated or garbled answer still yields the full requested unit
		// list (unanswered units read as down), but it is NOT a complete
		// answer and must reach the exit code like any other partial failure.
		if svcWarn != nil {
			h.ProbeErrors = append(h.ProbeErrors, "services: "+svcWarn.Error())
		}
	}
	certs, err := probeCerts(ctx, r, s, meta.HostTime)
	if err != nil {
		h.ProbeErrors = append(h.ProbeErrors, "certificates: "+err.Error())
	}
	backups, err := probeBackups(ctx, r, s, meta.HostTime)
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
				// Recorded in BOTH places on purpose: ProbeErrors drives the
				// exit code and --json, while the human views render the
				// failure once, on the offsite state row — they skip this
				// entry by matching the exact "offsite: " prefix
				// (ui.isOffsiteDuplicate; keep the prefix in sync).
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
var dial = func(ctx context.Context, s *config.Server, knownHosts string) (bssh.Conn, func() error, error) {
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
//
// With Drift, configs that share an endpoint are scanned one after another,
// in input order: each scan holds that host's session lock, and running them
// side by side would make the sweep report its own scans as "busy" (several
// configs may describe one box). Each still gets its own result — they ask
// different questions. Different endpoints stay parallel within Parallel.
func Collect(ctx context.Context, paths []string, opt Options) []HostStatus {
	parallel := opt.Parallel
	if parallel <= 0 {
		parallel = 4
	}
	out := make([]HostStatus, len(paths))
	sem := make(chan struct{}, parallel)
	// last maps an endpoint to the done channel of its latest config so far:
	// the next config of that endpoint waits for it.
	last := map[string]<-chan struct{}{}
	var wg sync.WaitGroup
	for i, p := range paths {
		srv, err := config.Load(p)
		if err != nil {
			// Its own result, never chained: there is no endpoint to share.
			out[i] = HostStatus{ConfigPath: p, Error: err.Error(), ProbedAt: time.Now().UTC()}
			continue
		}
		var turn <-chan struct{}
		done := make(chan struct{})
		if opt.Drift {
			key := endpointKey(srv)
			turn = last[key]
			last[key] = done
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(done)
			// The turn comes BEFORE the semaphore: a config waiting for its
			// endpoint must not sit on a slot another endpoint could use (with
			// Parallel 1 that would deadlock), and before collectOne starts
			// the per-host deadline, so the wait is not charged to its budget.
			if turn != nil {
				<-turn
			}
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = collectOne(ctx, p, srv, opt)
		}()
	}
	wg.Wait()
	return out
}

// endpoint is the host:port a config declares (HostStatus.Endpoint).
func endpoint(s *config.Server) string { return fmt.Sprintf("%s:%d", s.Host, s.SSH.Port) }

// endpointKey groups configs of one host for Collect's turns. Host names are
// case-insensitive, so the key is lower-cased. Two configs naming one box
// differently (an IP and a name) still run side by side, and the second scan
// then honestly reports the host busy.
func endpointKey(s *config.Server) string { return strings.ToLower(endpoint(s)) }

// lockCommand names a drift scan in the host session lock's holder line.
const lockCommand = "status --drift"

func collectOne(ctx context.Context, path string, srv *config.Server, opt Options) HostStatus {
	// Every host gets its own deadline, so one slow-but-alive host cannot hold
	// the sweep open indefinitely. ssh keepalives handle a DEAD transport;
	// they do nothing for a host that keeps answering.
	ctx, cancel := context.WithTimeout(ctx, opt.timeout())
	defer cancel()

	conn, closeConn, err := dial(ctx, srv, opt.KnownHosts)
	if err != nil {
		return HostStatus{
			ID: srv.ID, ConfigPath: path, Endpoint: endpoint(srv),
			Error: err.Error(), ProbedAt: time.Now().UTC(),
		}
	}
	defer func() { _ = closeConn() }()

	red := secret.NewRedactor()
	if !opt.Drift {
		// Plain status never takes the host session lock: it compares nothing
		// against the config, and it must keep answering while a provision
		// holds the host.
		return CollectHost(ctx, path, srv, conn, nil, red, opt.Offsite)
	}
	// The FULL pipeline (skipSSL false): a scan inspects the whole declared
	// config, and truncating it would hide the steps most worth inspecting.
	pipeline := steps.Pipeline(srv, red, false)

	// A drift scan reads the host to compare it against the config, so it
	// holds the host session lock (ReadOnly: it never creates the lock file,
	// and without one it runs unlocked). The whole collection happens inside
	// fn, on the lock's context and Runner — neither is used after fn returns.
	var h HostStatus
	err = hostlock.Run(ctx, conn, hostlock.ReadOnly, lockCommand, func(lctx context.Context, r bssh.Runner) error {
		h = CollectHost(lctx, path, srv, r, pipeline, red, opt.Offsite)
		return nil
	})
	if err == nil {
		return h
	}
	// Busy, not taken, or lost mid-scan: no drift answer is trustworthy (a
	// lost lock means another session may have changed the host while it was
	// compared, so a finished scan is discarded too). The cheap probes are
	// collected — again, outside the lock — so the host still reports every
	// other fact, and the report carries the reason with no StoppedAt: the
	// views render "scan did not run" and the exit code "could not be fully
	// probed".
	h = CollectHost(ctx, path, srv, conn, nil, red, opt.Offsite)
	if h.Reachable {
		h.Drift = &DriftReport{Error: err.Error()}
	}
	return h
}

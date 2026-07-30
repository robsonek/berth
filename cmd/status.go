package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/robsonek/berth/internal/status"
	"github.com/robsonek/berth/internal/ui"
)

type statusFlags struct {
	configDir string
	drift     bool
	offsite   bool
	parallel  int
	timeout   time.Duration
	jsonOut   bool
	noTTY     bool
}

func newStatusCmd() *cobra.Command {
	f := &statusFlags{}
	c := &cobra.Command{
		Use:   "status [server...]",
		Short: "Show a read-only view of one or more provisioned servers",
		// The wording is deliberate and must not be shortened back to "never
		// changes anything": --drift runs the pipeline's validators, and
		// nginx -t can create a missing log file. An absolute promise the
		// code cannot keep is worse than a precise one (spec §2.1).
		Long: "Probes each server read-only and reports drift, certificate expiry, backup\n" +
			"freshness, service health and disk. It never changes a host's configuration,\n" +
			"data, packages, services or certificates: repair stays an explicit\n" +
			"`berth provision <config>`. With --drift it additionally runs the same\n" +
			"validators provisioning runs (nginx -t among them), which can create a\n" +
			"missing log file.",
		RunE: func(cmd *cobra.Command, args []string) error { return runStatus(cmd, args, f) },
	}
	c.Flags().StringVar(&f.configDir, "config-dir", "servers", "directory to scan when no configs are given")
	c.Flags().BoolVar(&f.drift, "drift", false, "also run the full read-only Check sweep (slow)")
	c.Flags().BoolVar(&f.offsite, "offsite", false, "also query the offsite backup repository")
	c.Flags().IntVar(&f.parallel, "parallel", 4, "how many hosts to probe concurrently")
	c.Flags().DurationVar(&f.timeout, "timeout", 0, "per-host budget (default 1m, or 10m with --drift)")
	c.Flags().BoolVar(&f.jsonOut, "json", false, "machine-readable output")
	c.Flags().BoolVar(&f.noTTY, "no-tty", false, "force the plain table (no interactive view)")
	return c
}

func runStatus(cmd *cobra.Command, args []string, f *statusFlags) error {
	paths, err := status.Inventory(args, f.configDir)
	if err != nil {
		return err
	}
	opt := status.Options{
		Drift: f.drift, Offsite: f.offsite,
		Parallel: f.parallel, Timeout: f.timeout, KnownHosts: defaultKnownHosts(),
	}
	hosts := status.Collect(cmd.Context(), paths, opt)

	out := cmd.OutOrStdout()
	switch {
	case f.jsonOut:
		if err := status.WriteJSON(out, hosts); err != nil {
			return err
		}
	case ui.IsTTY(os.Stdout) && !f.noTTY:
		src := func(ctx context.Context, drift bool) []status.HostStatus {
			o := opt
			o.Drift = drift || opt.Drift
			return status.Collect(ctx, paths, o)
		}
		// Reassign hosts to what the operator last SAW: after a refresh or a
		// deep scan the initial sweep is stale, and deriving the exit code
		// from it would report an outcome that was never on screen.
		final, err := ui.RunFleetTUI(cmd.Context(), out, hosts, src)
		if err != nil {
			return err
		}
		hosts = final
	default:
		if err := ui.WriteFleetTable(out, hosts); err != nil {
			return err
		}
	}
	return probeFailure(hosts)
}

// probeFailure turns FAILED PROBING into a non-zero exit — an unreachable
// host, a partial probe failure, a drift scan that aborted before the end, or
// one that never ran at all (status.Drift's pre-flight path: Error set,
// StoppedAt empty). All of these mean "the tool could not tell you what you
// asked".
//
// An expiring certificate, a stale backup or a drifted step deliberately do
// NOT: those are answers, not failures, and conflating them would break
// scripting. Filter with --json instead.
func probeFailure(hosts []status.HostStatus) error {
	var failed []string
	for _, h := range hosts {
		switch {
		case !h.Reachable && h.Endpoint == "":
			// Only a loaded config yields an endpoint (see status.Collect), so
			// an empty one identifies a config that never loaded — a different
			// diagnosis from a dead host, and "unreachable" would send the
			// operator to the network instead of the file.
			failed = append(failed, h.ConfigPath+" (config failed to load: "+h.Error+")")
		case !h.Reachable:
			failed = append(failed, h.ConfigPath+" (unreachable)")
		case len(h.ProbeErrors) > 0:
			failed = append(failed, fmt.Sprintf("%s (%d probes failed)", h.ConfigPath, len(h.ProbeErrors)))
		case h.Drift != nil && h.Drift.StoppedAt != "":
			// Symmetric with the did-not-run arm below: the reason travels with
			// the step. For the expected identity abort the error text IS the
			// remedy (`--only identity --force`), and dropping it left --json
			// the only place to find it.
			msg := h.ConfigPath + " (drift scan aborted at " + h.Drift.StoppedAt
			if h.Drift.Error != "" {
				msg += ": " + h.Drift.Error
			}
			failed = append(failed, msg+")")
		case h.Drift != nil && h.Drift.Error != "":
			// Error without StoppedAt means the scan never reached any step,
			// so the message must not name one.
			failed = append(failed, h.ConfigPath+" (drift scan did not run: "+h.Drift.Error+")")
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return fmt.Errorf("%d of %d hosts could not be fully probed: %v", len(failed), len(hosts), failed)
}

package ui

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/robsonek/berth/internal/status"
)

// Certificate thresholds. They live in the renderer, not the collector: the
// JSON carries raw dates so scripts can apply their own policy.
const (
	// CertWarnDays is the days-left threshold below which a certificate is
	// flagged as expiring soon.
	CertWarnDays = 30
	// CertCritDays is the days-left threshold below which a certificate is
	// flagged as critical.
	CertCritDays = 7
)

// WriteFleetTable prints one line per host: no ANSI, no in-place updates, safe
// for CI and pipes.
//
// Every host-derived string is passed through SanitizeCell at its print site
// (see sanitize.go): the manifest VERSION, probe/drift error text and restic
// output would otherwise carry a hostile host's escape sequences straight to
// the terminal. The cert/backup/disk/services cells are composed purely of
// integers and berth string literals, so they carry nothing to sanitize.
func WriteFleetTable(w io.Writer, hosts []status.HostStatus) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "HOST\tBERTH\tSITES\tDRIFT\tCERTS\tBACKUP\tDISK\tSERVICES"); err != nil {
		return err
	}
	for _, h := range hosts {
		if !h.Reachable {
			if _, err := fmt.Fprintf(tw, "%s\tunreachable\t-\t-\t-\t-\t-\t%s\n", SanitizeCell(hostLabel(h)), SanitizeCell(h.Error)); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			SanitizeCell(hostLabel(h)), SanitizeCell(berthVersion(h)), len(h.Sites),
			SanitizeCell(driftCell(h.Drift)), certCell(h), backupCell(h), diskCell(h),
			servicesCell(h)); err != nil {
			return err
		}
		// A reachable host with partial probe failures previously rendered as
		// fully healthy. Its errors must be visible, not only in --json.
		for _, pe := range h.ProbeErrors {
			if _, err := fmt.Fprintf(tw, "  ! %s\t\t\t\t\t\t\t\n", SanitizeCell(pe)); err != nil {
				return err
			}
		}
		// The drift cell names only the abort point; the reason rides a
		// continuation line because widening the cell would break the table's
		// alignment. For the expected identity abort the reason IS the remedy
		// (endpoint mismatch / renamed id -> `--only identity --force`).
		if h.Drift != nil && h.Drift.Error != "" {
			if _, err := fmt.Fprintf(tw, "  ! drift: %s\t\t\t\t\t\t\t\n", SanitizeCell(h.Drift.Error)); err != nil {
				return err
			}
		}
		// The --offsite answer also rides a continuation row, not a ninth
		// column: the eight-field header is a fixed shape every row matches,
		// and the flag is opt-in, so a column would sit blank on most runs.
		// Without this line a SUCCESSFUL query was invisible in plain output —
		// only failures showed, via the ProbeErrors rows above.
		if h.Offsite != nil {
			if _, err := fmt.Fprintf(tw, "  offsite: %s\t\t\t\t\t\t\t\n", SanitizeCell(offsiteLine(h))); err != nil {
				return err
			}
		}
	}
	return tw.Flush()
}

// offsiteLine covers all four answers a probe can produce. The degraded ones
// are uppercase for the same reason the cert and backup cells shout: a missing
// snapshot or a failed query must never scan as fine.
func offsiteLine(h status.HostStatus) string {
	o := h.Offsite
	switch {
	case !o.Configured:
		// Only reachable when the CONFIG declares offsite, so an unconfigured
		// host is a discrepancy, not a no-op.
		if o.Error != "" {
			return "NOT SET UP: " + o.Error
		}
		return "NOT SET UP"
	case o.Error != "":
		return "FAILED: " + o.Error
	case o.LastSnapshot == nil:
		return "NO SNAPSHOTS"
	}
	return fmt.Sprintf("last snapshot %s (%s)", ageLabel(h.HostTime.Sub(*o.LastSnapshot)), o.SnapshotID)
}

// servicesCell summarises unit health; the spec lists service health as a
// first-class fact, so it gets its own column rather than living only in the
// drill-down.
func servicesCell(h status.HostStatus) string {
	if len(h.Services) == 0 {
		return "?"
	}
	down := 0
	for _, s := range h.Services {
		if !s.Active || !s.Enabled {
			down++
		}
	}
	if down == 0 {
		return fmt.Sprintf("%d ok", len(h.Services))
	}
	return fmt.Sprintf("%d/%d DOWN", down, len(h.Services))
}

func hostLabel(h status.HostStatus) string {
	if h.ID != "" {
		return h.ID
	}
	return h.ConfigPath
}

func berthVersion(h status.HostStatus) string {
	if h.Provisioned == nil {
		return "not provisioned"
	}
	return h.Provisioned.Version
}

// driftCell distinguishes THREE states that must never collapse into one:
// not scanned, scanned-and-clean, and scanned-but-incomplete. Not-clean means
// StoppedAt OR Error is set: status.Drift's defensive pre-flight path can
// populate Error with an empty StoppedAt (the engine failed before any step
// ran), and keying on StoppedAt alone would render that report as clean.
func driftCell(d *status.DriftReport) string {
	switch {
	case d == nil:
		return "not scanned"
	case d.StoppedAt != "":
		return "aborted at " + d.StoppedAt
	case d.Error != "":
		// No step was reached, so there is none to name.
		return "scan did not run"
	case d.Drifted == 0:
		return "clean"
	default:
		return fmt.Sprintf("%d steps", d.Drifted)
	}
}

// certCell must keep "this server declares no TLS" and "a TLS site has NO
// certificate" apart: the first is fine, the second is a broken site, and
// rendering both as "none" hides the one that matters.
func certCell(h status.HostStatus) string {
	// Initialisation is tracked by a separate boolean, NOT a -1 sentinel: an
	// expired certificate has a genuinely negative DaysLeft, and a sentinel
	// that means "unset" below zero let a later healthy site overwrite the
	// expired minimum — rendering an expired certificate as "min 60d".
	minDays, haveMin := 0, false
	declared, missing := 0, 0
	for _, s := range h.Sites {
		if s.Cert.Mode == "" {
			continue // site does not declare TLS at all
		}
		declared++
		if s.Cert.DaysLeft == nil {
			missing++
			continue
		}
		if !haveMin || *s.Cert.DaysLeft < minDays {
			minDays = *s.Cert.DaysLeft
			haveMin = true
		}
	}
	switch {
	case declared == 0:
		return "no TLS"
	case missing > 0 && !haveMin:
		return fmt.Sprintf("MISSING (%d)", missing)
	case missing > 0:
		return fmt.Sprintf("min %dd, %d MISSING", minDays, missing)
	}
	label := fmt.Sprintf("min %dd", minDays)
	switch {
	case minDays < CertCritDays:
		return label + " !!"
	case minDays < CertWarnDays:
		return label + " !"
	}
	return label
}

// backupCell reports the OLDEST site, not the newest. Showing the newest
// alongside a stale flag produced "3h ago (stale)" while another site had not
// been backed up for days — the reassuring number wins the reader's attention
// and the warning is lost.
func backupCell(h status.HostStatus) string {
	var oldest *time.Time
	staleCount, enabled, never := 0, 0, 0
	for _, s := range h.Sites {
		if !s.Backup.Enabled {
			continue
		}
		enabled++
		if s.Backup.Stale {
			staleCount++
		}
		if s.Backup.Newest == nil {
			never++
			continue
		}
		if oldest == nil || s.Backup.Newest.Before(*oldest) {
			oldest = s.Backup.Newest
		}
	}
	switch {
	case enabled == 0:
		return "off"
	case never > 0:
		return fmt.Sprintf("NEVER (%d of %d)", never, enabled)
	case staleCount > 0:
		return fmt.Sprintf("%s, %d STALE", ageLabel(h.HostTime.Sub(*oldest)), staleCount)
	}
	return ageLabel(h.HostTime.Sub(*oldest))
}

func diskCell(h status.HostStatus) string {
	if len(h.Disk) == 0 {
		return "?" // unparsed df must not render as a reassuring 0%
	}
	worst := 0
	for _, m := range h.Disk {
		if m.UsedPct > worst {
			worst = m.UsedPct
		}
	}
	return fmt.Sprintf("%d%%", worst)
}

// humanAge renders a duration the way an operator reads it. Ages are always
// computed against the HOST clock by the caller, never the local one.
func humanAge(d time.Duration) string {
	switch {
	case d < 0:
		// A timestamp AHEAD of the host clock — a skewed clock, or a foreign
		// file's mtime — is an anomaly. It used to satisfy d < time.Minute and
		// render as "just now": the reassuring side of the anomaly.
		return "FUTURE"
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// ageLabel is humanAge plus the " ago" suffix — except for FUTURE, where
// "FUTURE ago" would read as a rendering bug rather than the anomaly marker
// it is.
func ageLabel(d time.Duration) string {
	if d < 0 {
		return humanAge(d)
	}
	return humanAge(d) + " ago"
}

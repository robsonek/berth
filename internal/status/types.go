// Package status collects read-only facts about berth-provisioned hosts.
//
// The probes issue read-only commands and nothing here writes a local file.
// The drift scan runs the provisioning pipeline with DryRun set, so Apply is
// never reached — but a step's Check runs the same validators provisioning
// runs, and one of those (nginx -t, as root) may create a missing log file.
// That is the precise promise: no change to a host's configuration, data,
// packages, service state or certificates, rather than "no writes of any
// kind". The JSON shape produced by WriteJSON is a contract covered by a
// golden test — callers script against it.
package status

import (
	"encoding/json"
	"io"
	"time"
)

// Manifest is /var/lib/berth/manifest: which berth version last FULLY
// provisioned this host, and when. Absent (nil) means berth never completed a
// whole pipeline here.
type Manifest struct {
	Version       string    `json:"version"`
	ProvisionedAt time.Time `json:"provisioned_at"`
}

// CertStatus describes one site's TLS certificate. Mode mirrors
// config.Site.CertMode(); Present is false when no certificate file exists,
// in which case NotAfter and DaysLeft are nil rather than zero.
type CertStatus struct {
	Mode     string     `json:"mode"`
	Present  bool       `json:"present"`
	NotAfter *time.Time `json:"not_after,omitempty"`
	DaysLeft *int       `json:"days_left,omitempty"`
}

// BackupStatus describes one site's local backup directory.
//
// Newest is the mtime of the newest COMPLETION SIDECAR, not of the newest file
// — an in-progress .tmp-*, a crashed run's dump-only leftover, or a foreign
// file must never make a site look freshly backed up. Stale means that sidecar
// predates the previous scheduled run of this site's own cron by more than one
// further cycle, computed from the config's schedule rather than a fixed
// threshold. This is freshness, not restore readiness.
type BackupStatus struct {
	Enabled bool       `json:"enabled"`
	Dir     string     `json:"dir"`
	Newest  *time.Time `json:"newest,omitempty"`
	Count   int        `json:"count"`
	Bytes   int64      `json:"bytes"`
	Stale   bool       `json:"stale"`
}

// SiteStatus is the per-site slice of a host's state.
type SiteStatus struct {
	Domain string       `json:"domain"`
	Cert   CertStatus   `json:"cert"`
	Backup BackupStatus `json:"backup"`
}

// Service is one systemd unit's state. Enabled without Active means it will
// come back on reboot but is down now; the reverse means it is running but
// will not survive a reboot.
type Service struct {
	Name    string `json:"name"`
	Active  bool   `json:"active"`
	Enabled bool   `json:"enabled"`
}

// Mount is one filesystem's occupancy.
type Mount struct {
	Path      string `json:"path"`
	UsedPct   int    `json:"used_pct"`
	FreeBytes int64  `json:"free_bytes"`
}

// StepState is one pipeline step's read-only verdict.
type StepState struct {
	Step      string   `json:"step"`
	Satisfied bool     `json:"satisfied"`
	Changes   []string `json:"changes,omitempty"`
}

// DriftReport is the outcome of the read-only Check sweep. StoppedAt is set
// when the fail-fast pipeline aborted before the end: the report is then
// PARTIAL and must never be presented as clean.
type DriftReport struct {
	Steps     []StepState `json:"steps"`
	Drifted   int         `json:"drifted"`
	StoppedAt string      `json:"stopped_at,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// OffsiteStatus is the remote restic repository's latest snapshot, collected
// only under --offsite (it costs network traffic to the remote backend).
// Configured false means the host carries no offsite env file.
type OffsiteStatus struct {
	Configured   bool       `json:"configured"`
	LastSnapshot *time.Time `json:"last_snapshot,omitempty"`
	SnapshotID   string     `json:"snapshot_id,omitempty"`
	Error        string     `json:"error,omitempty"`
}

// HostStatus is everything known about one host at one moment.
type HostStatus struct {
	ID         string `json:"id"`
	ConfigPath string `json:"config_path"`
	Endpoint   string `json:"endpoint"`
	Reachable  bool   `json:"reachable"`
	// Error is the fatal reason the host could not be probed at all
	// (unreachable, unloadable config). Reachable is false whenever it is set.
	Error string `json:"error,omitempty"`
	// ProbeErrors collects PARTIAL failures on a host that was otherwise
	// reachable — one probe failed, the rest succeeded. They are kept separate
	// from Error and never overwrite each other: collapsing them into a single
	// Error field lost all but the last one, and leaving Reachable true made a
	// half-collected host render as healthy.
	ProbeErrors []string       `json:"probe_errors,omitempty"`
	Provisioned *Manifest      `json:"provisioned,omitempty"`
	Sites       []SiteStatus   `json:"sites,omitempty"`
	Services    []Service      `json:"services,omitempty"`
	Disk        []Mount        `json:"disk,omitempty"`
	Drift       *DriftReport   `json:"drift,omitempty"`
	Offsite     *OffsiteStatus `json:"offsite,omitempty"`
	// ProbedAt is the local clock at collection; HostTime is the host's own
	// clock, and every age shown to the operator is computed against the
	// latter so clock skew cannot make "3h ago" lie.
	ProbedAt time.Time `json:"probed_at"`
	// omitzero, NOT omitempty: encoding/json does not treat a zero time.Time
	// as empty, so omitempty would serialize an unreachable host's clock as
	// "0001-01-01T00:00:00Z" — a real-looking timestamp a script would consume.
	// (omitzero requires Go 1.24+; this module is on 1.26.)
	HostTime time.Time `json:"host_time,omitzero"`
}

// WriteJSON emits the fleet as indented JSON with a trailing newline. The
// shape is a contract: it is golden-tested, and changing it should be a
// deliberate act.
func WriteJSON(w io.Writer, hosts []HostStatus) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Hosts []HostStatus `json:"hosts"`
	}{Hosts: hosts})
}

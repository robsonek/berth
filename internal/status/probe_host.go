package status

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	bssh "github.com/robsonek/berth/internal/ssh"
)

// hostMetaCmd collects the host clock, the provisioning manifest and disk
// occupancy in ONE round trip. SSH latency dominates a fleet sweep, so probes
// are batched; the sections are separated by a literal --- line.
//
// The command string is a constant because FakeRunner stubs exact strings.
// Sections are delimited by whole marker LINES, split line-wise. A substring
// split on "\n---\n" is wrong: when a section is empty (no manifest) the two
// delimiters share a newline, the second match overlaps the first, and the
// output silently yields two sections instead of three.
// The first section carries TWO lines: the epoch and the host's UTC offset
// (`date +%z`, e.g. +0200). cron evaluates schedules in the server's local
// zone, so the returned time is located in that zone — matching a schedule in
// UTC would be wrong by the offset all year.
//
// A fixed offset does not model DST transitions inside the backward scan, so a
// cutoff can be off by at most one hour. Accepted: the staleness rule already
// carries a full cycle of grace, and the alternative (shipping tzdata to
// resolve an IANA name) is disproportionate. Do NOT "improve" this into a
// time.LoadLocation call — the release builds Windows binaries, where the
// system zoneinfo database is absent unless time/tzdata is imported.
const hostMetaCmd = `date -u +%s; date +%z; echo '---'; cat /var/lib/berth/manifest 2>/dev/null; echo '---'; df -P -B1 / /var 2>/dev/null`

// splitSections divides stdout into exactly n parts on lines equal to "---".
func splitSections(stdout string, n int) ([]string, bool) {
	parts := make([]string, n)
	i := 0
	for _, line := range strings.Split(stdout, "\n") {
		if strings.TrimRight(line, "\r") == "---" {
			i++
			if i >= n {
				return nil, false // more delimiters than expected
			}
			continue
		}
		parts[i] += line + "\n"
	}
	return parts, i == n-1
}

// hostMeta is one round trip's parsed answer. ProbeErr is a NON-FATAL
// degradation: the command exited non-zero but still produced usable output —
// df failing for one operand (a broken /var mount) while printing a valid row
// for the other. The caller keeps the parsed facts AND records the failure:
// hard-failing would discard good rows a partial df still prints, and
// ignoring the exit code reported the host as successfully probed while its
// disk figures were incomplete.
type hostMeta struct {
	HostTime time.Time
	Manifest *Manifest
	Disk     []Mount
	ProbeErr error
}

func probeHostMeta(ctx context.Context, r bssh.Runner) (hostMeta, error) {
	res, err := r.Run(ctx, hostMetaCmd, nil)
	if err != nil {
		return hostMeta{}, err
	}
	sections, ok := splitSections(res.Stdout, 3)
	if !ok {
		// A TOTAL failure (sudo denied, empty output) lands here: the section
		// shape is broken, and that stays the hard error it always was.
		return hostMeta{}, fmt.Errorf("host meta probe: unexpected output shape")
	}
	clock := strings.Fields(sections[0])
	if len(clock) < 1 {
		return hostMeta{}, fmt.Errorf("read host clock: empty")
	}
	epoch, err := strconv.ParseInt(clock[0], 10, 64)
	if err != nil {
		return hostMeta{}, fmt.Errorf("read host clock: %w", err)
	}
	// A missing or malformed offset is a MALFORMED PROBE, not a reason to
	// silently assume UTC: falling back would reintroduce exactly the
	// timezone bug this line exists to prevent, invisibly.
	if len(clock) < 2 {
		return hostMeta{}, fmt.Errorf("read host timezone offset: missing")
	}
	off, ok := parseUTCOffset(clock[1])
	if !ok {
		return hostMeta{}, fmt.Errorf("read host timezone offset: malformed %q", clock[1])
	}
	zone := time.FixedZone("host", off)
	m := hostMeta{
		HostTime: time.Unix(epoch, 0).In(zone),
		Manifest: parseManifest(sections[1]),
		Disk:     parseDF(sections[2]),
	}
	// The compound command's exit status is df's — the last command; cat's
	// failure is the expected no-manifest case and date failures already died
	// on the clock parse above. Non-zero means df could not answer for every
	// operand, so whatever WAS parsed must not read as a full answer.
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = "(no stderr)"
		}
		m.ProbeErr = fmt.Errorf("df exit %d — disk figures may be incomplete: %s", res.ExitCode, msg)
	}
	return m, nil
}

// parseUTCOffset reads a `date +%z` value such as "+0200" or "-0530" into
// seconds east of UTC. Out-of-range values are rejected rather than silently
// producing a nonsense zone: real offsets span -12:00..+14:00, and minutes
// above 59 are not an offset at all.
func parseUTCOffset(s string) (int, bool) {
	if len(s) != 5 || (s[0] != '+' && s[0] != '-') {
		return 0, false
	}
	h, errH := strconv.Atoi(s[1:3])
	m, errM := strconv.Atoi(s[3:5])
	if errH != nil || errM != nil || h > 14 || m > 59 {
		return 0, false
	}
	off := h*3600 + m*60
	if s[0] == '-' {
		off = -off
	}
	return off, true
}

// parseManifest reads the VERSION/PROVISIONED_AT pair written by the manifest
// step. Absent or malformed content yields nil: "berth never fully
// provisioned this host" is a normal state, not a failure.
func parseManifest(s string) *Manifest {
	var version, ts string
	for _, line := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(line, "VERSION="):
			version = strings.TrimSpace(strings.TrimPrefix(line, "VERSION="))
		case strings.HasPrefix(line, "PROVISIONED_AT="):
			ts = strings.TrimSpace(strings.TrimPrefix(line, "PROVISIONED_AT="))
		}
	}
	if version == "" {
		return nil
	}
	// The manifest step writes `date -u +%Y-%m-%dT%H:%M:%SZ`.
	at, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil
	}
	return &Manifest{Version: version, ProvisionedAt: at}
}

// parseDF reads POSIX `df -P -B1` output. df prints one row per operand, so
// the same filesystem appears twice when /var is not separate — rows are
// deduplicated by mount point.
func parseDF(s string) []Mount {
	var out []Mount
	seen := map[string]bool{}
	for i, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mount := strings.Join(fields[5:], " ")
		if seen[mount] {
			continue
		}
		free, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			continue
		}
		pct, err := strconv.Atoi(strings.TrimSuffix(fields[4], "%"))
		if err != nil {
			continue
		}
		seen[mount] = true
		out = append(out, Mount{Path: mount, UsedPct: pct, FreeBytes: free})
	}
	return out
}

package status

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// backupBaseDir mirrors the backups step's root (steps/backups.go:17).
const backupBaseDir = "/var/backups/berth"

// backupDir is one site's backup directory. Single-sourced: the probe scans it
// and CollectHost seeds the config-derived BackupStatus.Dir from it, so the
// derivation can never diverge between the two.
func backupDir(domain string) string { return backupBaseDir + "/" + config.PoolName(domain) }

// itoa64 keeps the test fixtures readable.
func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

// backupsCmd reports, per directory: artifact count, total bytes, and the
// newest mtime as a %T@ epoch.
//
// Freshness is keyed on the per-run METADATA SIDECAR (`<pool>-meta-<ts>.manifest`,
// written LAST by the backup script — see internal/templates/backup.sh.tmpl),
// not on any file in the directory. Counting everything let three things fake
// a fresh backup: an in-progress `.tmp-*`, a crashed run that produced only the
// database dump, and any foreign file parked in the directory. The sidecar
// exists only after a run completed, so its mtime is the honest answer to
// "when did a backup last SUCCEED".
//
// The sidecar pattern is scoped to the directory's OWN pool — its basename,
// since backupDir is backupBaseDir/<pool> and the script writes the sidecar as
// `<pool>-meta-<ts>.manifest` into that directory. A bare `*-meta-*.manifest`
// accepted ANOTHER pool's completion file parked here, letting a backup that
// never completed render fresh. The $(basename "$d") substitution happens on
// the host; the `*` stays quoted from the shell so find receives it as a glob.
//
// The directory `manifest` and `.lock` are bookkeeping and are excluded from
// the count and byte total.
//
// The script's ordering makes this sound (verified against
// internal/templates/backup.sh.tmpl): the sidecar is mv'd into place LAST —
// after the database dump and the files archive, before only the retention
// prune — so its presence is equivalent to "this run completed".
func backupsCmd(dirs []string) string {
	const find = `find "$d" -maxdepth 1 -type f ! -name '.lock' ! -name 'manifest' ! -name '.tmp-*'`
	const findSidecar = `find "$d" -maxdepth 1 -type f -name "$(basename "$d")-meta-*.manifest"`
	quoted := make([]string, 0, len(dirs))
	for _, d := range dirs {
		quoted = append(quoted, "'"+d+"'")
	}
	return "for d in " + strings.Join(quoted, " ") + `; do printf '%s\t%s\t%s\t%s\n' "$d" ` +
		`"$(` + find + ` 2>/dev/null | wc -l)" ` +
		`"$(` + find + ` -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{printf "%d", s}')" ` +
		`"$(` + findSidecar + ` -printf '%T@\n' 2>/dev/null | sort -n | tail -1)"; done`
}

func probeBackups(ctx context.Context, r bssh.Runner, s *config.Server, hostTime time.Time) (map[string]BackupStatus, error) {
	out := map[string]BackupStatus{}
	var dirs []string
	byDir := map[string]string{} // dir -> domain
	for _, site := range s.Sites {
		if !s.BackupsEnabled(site) {
			out[site.Domain] = BackupStatus{Enabled: false}
			continue
		}
		d := backupDir(site.Domain)
		dirs = append(dirs, d)
		byDir[d] = site.Domain
		out[site.Domain] = BackupStatus{Enabled: true, Dir: d}
	}
	if len(dirs) == 0 {
		return out, nil
	}
	res, err := r.Run(ctx, backupsCmd(dirs), nil)
	if err != nil {
		return nil, err
	}
	// The loop's own exit status is the last printf's (0) even when individual
	// finds fail, so a non-zero exit means the loop never ran cleanly (sudo -n
	// denied on a half-broken host). That must surface loudly, not as an empty
	// map at exit 0 — same contract as probeServices and probeCerts.
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = "(no stderr)"
		}
		return nil, fmt.Errorf("backups probe: exit %d: %s", res.ExitCode, msg)
	}
	// An unknown cadence yields no cutoff, and staleness is then never claimed
	// (except for the unambiguous zero-artifact case below).
	// ScheduleEff(), NOT the raw field: an omitted schedule is normal and only
	// the *Eff accessor applies the default (config.go:323). Passing the empty
	// string would make the cadence unknown and silently report stale:false on
	// every default-configured server — the exact failure this probe exists to
	// catch.
	cutoff, haveCutoff := StaleCutoff(s.Backups.ScheduleEff(), hostTime)

	for _, line := range strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n") {
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) != 4 {
			continue
		}
		domain, ok := byDir[parts[0]]
		if !ok {
			continue
		}
		b := out[domain]
		b.Count, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		b.Bytes, _ = strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if secs := strings.SplitN(strings.TrimSpace(parts[3]), ".", 2)[0]; secs != "" {
			if epoch, err := strconv.ParseInt(secs, 10, 64); err == nil {
				t := time.Unix(epoch, 0).UTC()
				b.Newest = &t
			}
		}
		switch {
		case b.Newest == nil:
			// Backups are enabled but nothing has ever landed: unambiguous,
			// and independent of whether the cadence could be parsed.
			b.Stale = true
		case haveCutoff:
			b.Stale = b.Newest.Before(cutoff)
		}
		out[domain] = b
	}
	return out, nil
}

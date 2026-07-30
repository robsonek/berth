package status

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// offsiteCmd asks restic for the latest snapshot, loading the credentials
// from the env file the offsite step already wrote on the host
// (config.OffsiteEnvPath, root:root 0600) via the shared parse-don't-source
// loader (config.OffsiteEnvLoader — single-sourced with the managed backup
// script and the provisioning repository probe): a drifted or hand-edited env
// file must never be able to EXECUTE anything, so it is parsed, never
// dot-sourced. A file the loader refuses is reported as BADENV — the
// read-only probe's report-the-discrepancy pattern, mirroring NOENV.
//
// No secret enters this command string, this process, or the local cache: the
// values never leave the host, and restic's JSON output carries none of them.
// The loader exports without echoing.
// --no-cache and --no-lock are LOAD-BEARING, not tuning: restic otherwise
// populates a local cache and takes a repository lock, i.e. writes to the
// remote backend. --host scopes the query to THIS server, matching the tag the
// managed backup script applies (offsite.sh.tmpl's `--host {{.HostID}}`);
// without it a shared repository returns other servers' snapshots and the
// parser would happily report one of those as this host's latest backup.
// --path narrows it further to what berth actually backs up (offsite.sh.tmpl
// runs `restic backup` on backupBaseDir): restic groups `--latest 1` by
// (hostname, paths), so same-host snapshots under a DIFFERENT path form their
// own group and an unrelated backup could stand in for a missing berth one.
//
// The host ID is passed in from the config rather than read from a shell
// variable: it is not a secret, it is known locally, and assuming the env file
// exports one would be a guess.
//
// resticOpts is REQUIRED for correctness on sftp, not a nicety. The env file
// carries only the repository and password; the dedicated key, the pinned
// known_hosts, the port, -F /dev/null, BatchMode and the keepalives live
// exclusively in the `-o sftp.command=...` string that
// config.OffsiteResticOpts builds. Omitting it makes a custom-port sftp
// target fail outright and an ordinary one fall back to root's ambient ssh
// config, keys and trust state — silently bypassing the host-key pin the
// offsite step went to some trouble to establish.
//
// OffsiteResticOpts is a pure function of *config.Offsite, exported from
// config with the steps package delegating, exactly as the other on-host
// derivations are single-sourced. Do not re-derive the option string here.
func offsiteCmd(hostID, resticOpts string) string {
	return config.OffsiteEnvLoader() + `; if [ -r ` + config.OffsiteEnvPath + ` ]; then ` +
		`if ` + config.OffsiteEnvLoadName + ` 2>/dev/null; then ` +
		`restic` + resticOpts + ` --no-cache --no-lock snapshots --latest 1 --host '` + hostID + `' --path '` + backupBaseDir + `' --json 2>/dev/null || echo FAILED; ` +
		`else echo BADENV; fi; else echo NOENV; fi`
}

// resticSnapshot is the subset of restic's snapshot JSON this probe reads.
type resticSnapshot struct {
	Time    time.Time `json:"time"`
	ShortID string    `json:"short_id"`
}

func probeOffsite(ctx context.Context, r bssh.Runner, hostID, resticOpts string) (*OffsiteStatus, error) {
	res, err := r.Run(ctx, offsiteCmd(hostID, resticOpts), nil)
	if err != nil {
		return nil, err
	}
	out := strings.TrimSpace(res.Stdout)
	switch out {
	case "NOENV":
		// The caller only reaches here when the CONFIG declares offsite, so a
		// missing env file is a discrepancy between config and host — not an
		// "offsite not configured" no-op. Returning a clean status here made
		// `--offsite` exit 0 without ever answering the question.
		return &OffsiteStatus{Error: "no " + config.OffsiteEnvPath + " on the host (offsite is declared in the config — has this server been provisioned since?)"}, nil
	case "BADENV":
		// The env file exists but the loader refused it: it holds lines berth
		// never writes. Whatever put them there, the nightly offsite run is
		// failing on the same gate, so this must surface loudly.
		return &OffsiteStatus{Configured: true, Error: "malformed " + config.OffsiteEnvPath + " on the host — refusing to load it (re-run provisioning to rewrite the managed file)"}, nil
	case "FAILED":
		return &OffsiteStatus{Configured: true, Error: "restic could not read the repository"}, nil
	}
	// A parse failure is a repository ANSWER this probe could not read, not a
	// transport failure: it is reported as data on the status (the caller
	// promotes OffsiteStatus.Error to ProbeErrors), so the Go error stays nil.
	st := &OffsiteStatus{Configured: true}
	var snaps []resticSnapshot
	if json.Unmarshal([]byte(out), &snaps) != nil {
		st.Error = "unreadable restic output"
	} else if len(snaps) > 0 {
		// Defensive: --host + --path should leave one group, but restic emits
		// one object PER (hostname, paths) group, so if several still come
		// back the newest wins — never whichever happened to be first.
		newest := snaps[0]
		for _, sn := range snaps[1:] {
			if sn.Time.After(newest.Time) {
				newest = sn
			}
		}
		t := newest.Time.UTC()
		st.LastSnapshot = &t
		st.SnapshotID = newest.ShortID
	}
	return st, nil
}

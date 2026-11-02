package steps

import (
	"context"
	"errors"
	"fmt"
	"strings"

	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
	"github.com/robsonek/berth/internal/version"
)

// versionFloorPath records the NEWEST berth version that has changed this
// host. preflight raises it at the start of every real run (Apply, before the
// first other change) and refuses a binary older than it unless
// --allow-downgrade, so an older berth cannot silently undo what a newer one
// set up. Like the manifest and the reload stamps it lives in berth-exclusive
// /var/lib/berth, so there is no marker guard or --force semantics; the
// content still carries the managed marker so its origin is evident.
//
// FROZEN (E5 stamp rule): the path and the `VERSION=` line are read by every
// future berth — never re-key the file or change what the line means.
const versionFloorPath = berthStateDir + "/version-floor"

// The floor probes: test -e separates absence (exit 1) from a file that
// exists but cannot be read, which cat alone would conflate.
const (
	versionFloorTestCmd = "test -e " + versionFloorPath
	versionFloorCatCmd  = "cat " + versionFloorPath
)

// floorAction is what preflight.Apply does to the floor this run.
type floorAction int

const (
	floorKeep    floorAction = iota // recorded == binary: nothing to write
	floorRecord                     // no floor yet
	floorRaise                      // recorded < binary
	floorLower                      // recorded > binary, --allow-downgrade
	floorRewrite                    // unreadable or malformed, --allow-downgrade
)

// parseVersionFloor returns the version on the first VERSION= line (value
// trimmed of spaces, tabs and \r); a missing line or an unparseable value is an error.
func parseVersionFloor(content string) (version.V, error) {
	for _, line := range strings.Split(content, "\n") {
		raw, ok := strings.CutPrefix(line, "VERSION=")
		if !ok {
			continue
		}
		raw = strings.Trim(raw, " \t\r")
		v, ok := version.ParseBuild(raw)
		if !ok {
			return version.V{}, fmt.Errorf("VERSION=%q is not a berth version", raw)
		}
		return v, nil
	}
	return version.V{}, errors.New("no VERSION= line")
}

// decideVersionFloor is the floor's verdict table (the behavior README
// "Version floors" documents). readFailure != "" means the file exists but
// cat failed. Returns the action and its plan line ("" for keep).
//
//	absent                  -> record
//	recorded <  binary      -> raise
//	recorded == binary      -> keep (by parsed value: VERSION=0.37.0 equals v0.37.0)
//	recorded >  binary      -> refuse; lower with --allow-downgrade
//	unreadable or malformed -> refuse; rewrite with --allow-downgrade
//
// The refusals never mention --force: a bare --force authorizes overwriting
// unmanaged files, never rolling a host back to an older berth.
func decideVersionFloor(present bool, content, readFailure string, bin version.V, allowDowngrade bool) (floorAction, string, error) {
	if !present {
		return floorRecord, fmt.Sprintf("record version floor %s in %s", bin, versionFloorPath), nil
	}
	detail := readFailure
	var recorded version.V
	if detail == "" {
		v, err := parseVersionFloor(content)
		if err != nil {
			detail = err.Error()
		}
		recorded = v
	}
	if detail != "" {
		if allowDowngrade {
			return floorRewrite, fmt.Sprintf("rewrite version floor as %s (--allow-downgrade)", bin), nil
		}
		return floorKeep, "", fmt.Errorf("version floor %s is unreadable or malformed (%s) — re-run `berth provision` with --allow-downgrade to rewrite it as %s", versionFloorPath, detail, bin)
	}
	switch c := recorded.Compare(bin); {
	case c == 0:
		return floorKeep, "", nil
	case c < 0:
		return floorRaise, fmt.Sprintf("raise version floor %s → %s", recorded, bin), nil
	case allowDowngrade:
		return floorLower, fmt.Sprintf("lower version floor %s → %s (--allow-downgrade)", recorded, bin), nil
	default:
		return floorKeep, "", fmt.Errorf("host was last changed by berth %s, this binary is %s — use %s or newer; to roll back deliberately, re-run `berth provision` with --allow-downgrade", recorded, bin, recorded)
	}
}

// probeVersionFloor runs versionFloorTestCmd (exit 0 present, 1 absent, other =
// error) and, when present, versionFloorCatCmd (non-zero exit = readFailure from
// stderr), then returns decideVersionFloor's verdict. Read-only.
func probeVersionFloor(ctx context.Context, r bssh.Runner, bin version.V, allowDowngrade bool) (floorAction, string, error) {
	res, err := r.Run(ctx, versionFloorTestCmd, nil)
	if err != nil {
		return floorKeep, "", err
	}
	switch res.ExitCode {
	case 0:
	case 1:
		return decideVersionFloor(false, "", "", bin, allowDowngrade)
	default:
		return floorKeep, "", fmt.Errorf("probe %s: test exited %d: %s", versionFloorPath, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	res, err = r.Run(ctx, versionFloorCatCmd, nil)
	if err != nil {
		return floorKeep, "", err
	}
	readFailure := ""
	if res.ExitCode != 0 {
		// A file that exists but cannot be read is never "absent": that would
		// re-record the floor over whatever a newer berth left there.
		readFailure = strings.TrimSpace(res.Stderr)
		if readFailure == "" {
			readFailure = fmt.Sprintf("cat exited %d", res.ExitCode)
		}
	}
	return decideVersionFloor(true, res.Stdout, readFailure, bin, allowDowngrade)
}

// writeVersionFloor runs `install -d -o root -g root -m 0755 /var/lib/berth`
// and writes version_floor.tmpl rendered with bin.String(), root:root 0644.
func writeVersionFloor(ctx context.Context, r bssh.Runner, bin version.V) error {
	body, err := templates.Render("version_floor.tmpl", struct{ Version string }{bin.String()})
	if err != nil {
		return err
	}
	if err := runOK(ctx, r, "install -d -o root -g root -m 0755 "+berthStateDir); err != nil {
		return err
	}
	return r.WriteFile(ctx, bssh.FileSpec{Path: versionFloorPath, Content: body, Owner: "root", Group: "root", Mode: 0o644, Sudo: true})
}

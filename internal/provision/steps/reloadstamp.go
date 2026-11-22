package steps

import (
	"context"
	"fmt"

	bssh "github.com/robsonek/berth/internal/ssh"
)

// berthStateDir holds berth's on-host state: per-unit reload stamps. Root-owned
// (0755 dir, root-written stamps) — the stamps gate root-run service reloads,
// so tenants must never be able to create or touch them.
const berthStateDir = "/var/lib/berth"

// stampPath is the reload stamp for a systemd unit (e.g. nginx, php8.5-fpm).
func stampPath(unit string) string { return berthStateDir + "/" + unit + ".reloaded" }

// markReloaded records that a successful reload (or start) of unit just
// happened. Call it ONLY after the final successful reload of an Apply, with
// no unit-affecting mutation after it (pair with invalidateReloaded up front
// — the transactional contract), or reloadedSince would bless a stale running
// config. The stamp is per unit and deliberately shared between steps: any
// successful reload loads ALL of the unit's config present on disk at that
// moment, so every step's files are covered by whichever step reloaded last.
// The stamp is installed as a fresh root:root 0644 regular file (never a bare
// touch): a pre-existing foreign file or symlink at the stamp path must not
// survive, and the mode must not depend on root's umask.
func markReloaded(ctx context.Context, r bssh.Runner, unit string) error {
	stamp := shQuote(stampPath(unit))
	cmd := "install -d -o root -g root -m 0755 " + berthStateDir + " && rm -f " + stamp + " && install -o root -g root -m 0644 /dev/null " + stamp
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("record reload stamp for %s: %s", unit, res.Stderr)
	}
	return nil
}

// invalidateReloaded removes unit's reload stamp. Call it at the START of any
// Apply that is about to mutate the unit's configuration (write, removal,
// rename, symlink change): from that moment until markReloaded after the
// final successful reload, a crash leaves no stamp and the next run
// reconciles with one reload. Removing a missing stamp is a no-op success.
func invalidateReloaded(ctx context.Context, r bssh.Runner, unit string) error {
	res, err := r.Run(ctx, "rm -f "+shQuote(stampPath(unit)), nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("invalidate reload stamp for %s: %s", unit, res.Stderr)
	}
	return nil
}

// reloadedSince reports whether the running unit has loaded every given path:
// either a successful berth reload happened after the last write of each one,
// or the unit itself was (re)started after it.
//
// The stamp test comes first: true iff the stamp exists and no path is newer
// than it (`[ file -nt stamp ]`, exit-code only — -nt is not POSIX but a
// dash/bash extension, and Debian's /bin/sh is dash). A reboot keeps the
// answer truthful: systemd starts the unit with the config on disk and no
// mtime changes, so an up-to-date state stays satisfied.
//
// When the stamp test fails, restartedSince is the second opinion. A package
// upgrade (unattended-upgrades included) bumps the mtime of a config
// directory berth watches and restarts the unit: the stamp is then older
// than the path although nothing is pending, which used to read as drift on
// a healthy host until the next provision.
//
// A missing stamp always reads as "not reloaded": an Apply in flight has
// invalidated it, and only its own final reload may bless the unit again. An
// out-of-band `touch` of a managed file still triggers one reconciling
// reload — intentional, mirroring serviceConfigLoaded's conservative mtime
// semantics. Callers pair this with a liveness probe (serviceUp/
// serviceActive); the fallback also checks is-active itself, because a
// stopped unit keeps its old start time.
func reloadedSince(ctx context.Context, r bssh.Runner, unit string, paths ...string) (bool, error) {
	stamp := shQuote(stampPath(unit))
	cmd := "[ -e " + stamp + " ]"
	for _, p := range paths {
		cmd += " && [ ! " + shQuote(p) + " -nt " + stamp + " ]"
	}
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return false, err
	}
	if res.ExitCode == 0 {
		return true, nil
	}
	return restartedSince(ctx, r, unit, paths...)
}

// restartedSince reports whether unit is active, its stamp exists, and its
// last (re)start is not older than the mtime of any given path — a start
// loads all of the unit's config on disk at that moment. A reload does not
// move ActiveEnterTimestamp, so this never blesses a reload berth did not
// make. Same integer comparison as serviceConfigLoaded (`--timestamp=unix`,
// whole seconds; see its comment for the accepted same-second case); a path
// that cannot be stat'ed, or an empty start time, reads as "not loaded".
func restartedSince(ctx context.Context, r bssh.Runner, unit string, paths ...string) (bool, error) {
	cmd := `s="$(systemctl show -p ActiveEnterTimestamp --value --timestamp=unix ` + unit + ` 2>/dev/null | tr -d @)"; [ -n "$s" ] && [ -e ` + shQuote(stampPath(unit)) + ` ] && systemctl is-active --quiet ` + unit
	for _, p := range paths {
		cmd += ` && [ "$(stat -c %Y ` + shQuote(p) + ` 2>/dev/null)" -le "$s" ]`
	}
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

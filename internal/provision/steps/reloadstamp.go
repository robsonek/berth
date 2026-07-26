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

// reloadedSince reports whether a successful reload of unit happened after the
// last write of every given path: true iff the stamp exists and no path is
// newer than it (`[ file -nt stamp ]`, exit-code only — no timestamp parsing,
// no timezone pitfalls; -nt is not POSIX but a dash/bash extension, and
// Debian's /bin/sh is dash). A missing stamp reads as "not reloaded"
// (first run after introducing stamps performs one reconciling reload). A
// reboot keeps the answer truthful: systemd starts the unit with the config
// on disk and no mtime changes, so an up-to-date state stays satisfied. An
// out-of-band `touch` of a managed file triggers one reconciling reload —
// intentional, mirroring serviceConfigLoaded's conservative mtime semantics.
// Callers must pair this with a liveness probe (serviceUp/serviceActive): a
// stopped unit keeps its old stamp, so the stamp alone would falsely pass.
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
	return res.ExitCode == 0, nil
}

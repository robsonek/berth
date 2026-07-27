package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// phpPoolConflictProbeCmd scans every OTHER PHP version's pool.d for files
// berth must not coexist with after a php.version change: pools berth itself
// rendered (exact managed marker as the FIRST line — same semantics as
// hasManagedMarker, never a grep-anywhere), and foreign pools that bind a
// berth per-site socket (the socket paths are version-independent, so a
// foreign squatter is the same collision with no marker to find). Output is
// one classified line per hit: "M <path>" (berth-marked) or "S <path>"
// (foreign file on a berth socket). The version is rePHPVer-validated
// (digits and a dot), so interpolation is shell-safe.
func phpPoolConflictProbeCmd(version string) string {
	// The listen match tolerates FPM's INI whitespace freedom (`listen=`,
	// indentation, an optional quote) — a rigid `listen = ` would
	// false-negative exactly the foreign files this branch exists for.
	return `for f in /etc/php/*/fpm/pool.d/*.conf; do [ -e "$f" ] || continue; case "$f" in /etc/php/` + version + `/fpm/pool.d/*) continue;; esac; if [ "$(head -n 1 "$f" 2>/dev/null)" = '` + managedMarkerINI + `' ]; then printf 'M %s\n' "$f"; elif grep -Eq '^[[:space:]]*listen[[:space:]]*=[[:space:]]*"?/run/php/berth-' "$f" 2>/dev/null; then printf 'S %s\n' "$f"; fi; done`
}

// assertPHPVersionExclusive refuses to proceed while FPM pools of another PHP
// version could fight over berth's version-independent per-site sockets
// (/run/php/berth-<pool>.sock): whichever master (re)binds last would serve —
// a silent, non-deterministic half-state. It runs FIRST in the Check AND
// Apply of BOTH accounts (which renders the configured version into site
// sudoers and precedes php in the pipeline) and php (before repo setup, the
// reload-stamp invalidation and apt — a refusal must change nothing).
// Deliberately NOT bypassable with --force, mirroring the owner-guard
// precedent: the remedy is reverting php.version or the manual migration in
// the error text. berth does not migrate PHP versions automatically — the old
// master may serve foreign pools, and stopping it is a maintenance decision.
func assertPHPVersionExclusive(ctx context.Context, r bssh.Runner, s *config.Server) error {
	res, err := r.Run(ctx, phpPoolConflictProbeCmd(s.PHP.Version), nil)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("probe for stale PHP-FPM pools of other versions: %s", res.Stderr)
	}
	var marked, squatters []string
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		switch {
		case strings.HasPrefix(line, "M "):
			marked = append(marked, strings.TrimPrefix(line, "M "))
		case strings.HasPrefix(line, "S "):
			squatters = append(squatters, strings.TrimPrefix(line, "S "))
		}
	}
	if len(marked) == 0 && len(squatters) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "php.version is %s but FPM pools of another PHP version would fight over berth's version-independent per-site sockets (/run/php/berth-*.sock):", s.PHP.Version)
	if len(marked) > 0 {
		fmt.Fprintf(&b, " berth-managed pool(s) %s;", strings.Join(marked, ", "))
	}
	if len(squatters) > 0 {
		fmt.Fprintf(&b, " foreign pool(s) bound to a berth socket: %s;", strings.Join(squatters, ", "))
	}
	b.WriteString(" either revert php.version, or migrate manually in a maintenance window: (1) inventory the old version's pool.d — berth's pools carry the exact first line '" + managedMarkerINI + "', anything else belongs to you and must be migrated off that master first; (2) systemctl disable --now php<old>-fpm; (3) remove only the confirmed berth pool files; (4) re-run a full berth provision; (5) verify only php" + s.PHP.Version + "-fpm holds the /run/php/berth-*.sock sockets")
	return fmt.Errorf("%s", b.String())
}

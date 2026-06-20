package steps

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

const (
	swapfilePath       = "/swapfile"
	fstabPath          = "/etc/fstab"
	swapSysctlPath     = "/etc/sysctl.d/99-berth-swap.conf"
	sysctlPath         = "/etc/sysctl.d/99-berth.conf"
	swappinessProcPath = "/proc/sys/vm/swappiness"
	swappinessValue    = "10"
)

// fstabSwapLine is the exact /etc/fstab entry berth appends for its swap file. The
// trailing managed marker is the ownership signal: removal targets only this line,
// and a /swapfile line WITHOUT it is treated as a foreign (operator-managed) swap.
const fstabSwapLine = swapfilePath + " none swap sw 0 0 " + managedMarker

// parseSwapBytes converts a validated swap size ("2G", "512M", case-insensitive)
// to bytes. Units are binary (M = MiB, G = GiB) to match `fallocate -l` and
// `stat -c %s`. It re-rejects bad input defensively (config.Validate already guards).
func parseSwapBytes(size string) (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(size))
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid swap size %q", size)
	}
	num, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
	if err != nil || num <= 0 {
		return 0, fmt.Errorf("invalid swap size %q", size)
	}
	switch s[len(s)-1] {
	case 'M':
		return num * 1024 * 1024, nil
	case 'G':
		return num * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("invalid swap size unit in %q (use M or G)", size)
	}
}

// fstabSwapState scans /etc/fstab content for /swapfile entries. marked is true if a
// /swapfile mount line ENDS WITH the berth marker (berth owns it); foreign is true if a
// /swapfile mount line lacks the marker at end-of-line (operator-managed). Comment lines
// are ignored. Ownership is HasSuffix(trimmed, marker) — NOT Contains — so this matches
// the removal sed (which anchors the marker at `$`); using Contains would classify a
// line with the marker mid-text as owned while the sed left it in place.
func fstabSwapState(content string) (marked, foreign bool) {
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) == 0 || fields[0] != swapfilePath {
			continue
		}
		if strings.HasSuffix(t, managedMarker) {
			marked = true
		} else {
			foreign = true
		}
	}
	return marked, foreign
}

type system struct{}

// System provisions optional host-level OS settings: a swap file (+ vm.swappiness)
// and an opt-in web/DB kernel sysctl drop-in. It is ALWAYS in the pipeline (ungated)
// so disabling a knob can drift-remove berth's artifacts, and runs right after base
// (before php/composer/database) so the swap margin protects provisioning itself.
func System() provision.Step { return system{} }

func (system) Name() string       { return "system" }
func (system) Requires() []string { return []string{"preflight"} }

func (system) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	var changes []string
	if s.System.Swap != "" {
		ok, ch, err := checkSwap(ctx, rc, r, s.System.Swap)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	} else {
		ok, ch, err := checkSwapRemoval(ctx, r)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	}
	if s.System.Sysctl {
		ok, ch, err := checkSysctl(ctx, rc, r)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	} else {
		ok, ch, err := checkSysctlRemoval(ctx, r)
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
	}
	if len(changes) == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "swap & sysctl in desired state"}, nil
	}
	return provision.CheckResult{Satisfied: false, Reason: "system (swap/sysctl) not in desired state", Changes: changes}, nil
}

// catTrim returns the trimmed stdout of `cat <path>` and whether the file was
// readable (exit 0). Read-only; mirrors checkManagedFile's read style.
func catTrim(ctx context.Context, r bssh.Runner, path string) (string, bool, error) {
	res, err := r.Run(ctx, "cat "+shQuote(path), nil)
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(res.Stdout), res.ExitCode == 0, nil
}

// swapfileSize reports whether /swapfile exists and its size in bytes (stat -c %s).
func swapfileSize(ctx context.Context, r bssh.Runner) (exists bool, size int64, err error) {
	res, err := r.Run(ctx, "stat -c %s "+shQuote(swapfilePath)+" 2>/dev/null", nil)
	if err != nil {
		return false, 0, err
	}
	if res.ExitCode != 0 {
		return false, 0, nil
	}
	n, perr := strconv.ParseInt(strings.TrimSpace(res.Stdout), 10, 64)
	if perr != nil {
		return false, 0, nil
	}
	return true, n, nil
}

// swapActive reports whether /swapfile is an active swap area (swapon --show).
func swapActive(ctx context.Context, r bssh.Runner) (bool, error) {
	res, err := r.Run(ctx, "swapon --show=NAME --noheadings", nil)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if strings.TrimSpace(line) == swapfilePath {
			return true, nil
		}
	}
	return false, nil
}

// checkSwap is the read-only predicate for an enabled swap. It enforces the conflict
// guard (a foreign /swapfile fstab line — even alongside a berth-marked one — or a
// /swapfile file with no berth-marked line aborts unless --force), then reports
// satisfied iff the file exists at the configured size, is an active swap area, the
// marked fstab line is present, and the swappiness drop-in is up-to-date AND live
// (running vm.swappiness == 10).
func checkSwap(ctx context.Context, rc provision.RunCtx, r bssh.Runner, size string) (bool, []string, error) {
	wantBytes, err := parseSwapBytes(size)
	if err != nil {
		return false, nil, err
	}
	fstab, _, err := catTrim(ctx, r, fstabPath)
	if err != nil {
		return false, nil, err
	}
	marked, foreign := fstabSwapState(fstab)
	exists, gotBytes, err := swapfileSize(ctx, r)
	if err != nil {
		return false, nil, err
	}
	// Conflict: a foreign fstab line (even if a marked one also exists — a duplicate
	// state berth must not silently bless), or a /swapfile present with no marked line.
	if foreign || (exists && !marked) {
		if !rc.Force {
			return false, nil, fmt.Errorf("%s present but not managed by berth (need %q at the end of its /etc/fstab line); re-run with --force to take it over", swapfilePath, managedMarker)
		}
		return false, []string{"take over and rewrite " + swapfilePath + " (--force)"}, nil
	}
	var changes []string
	if !exists || gotBytes != wantBytes {
		changes = append(changes, fmt.Sprintf("create %s (%s) + mkswap + swapon", swapfilePath, size))
	}
	active, err := swapActive(ctx, r)
	if err != nil {
		return false, nil, err
	}
	if !active {
		changes = append(changes, "swapon "+swapfilePath)
	}
	if !marked {
		changes = append(changes, "add "+swapfilePath+" entry to "+fstabPath)
	}
	swapDropOK, err := swappinessLive(ctx, rc, r)
	if err != nil {
		return false, nil, err
	}
	if !swapDropOK {
		changes = append(changes, "write "+swapSysctlPath+" (vm.swappiness="+swappinessValue+") + sysctl -p")
	}
	if len(changes) == 0 {
		return true, nil, nil
	}
	return false, changes, nil
}

// swappinessLive reports whether the swappiness drop-in is up-to-date (managed-file
// drift; an unmanaged file aborts unless --force) AND the running value is loaded.
func swappinessLive(ctx context.Context, rc provision.RunCtx, r bssh.Runner) (bool, error) {
	want, err := renderSwapSysctl()
	if err != nil {
		return false, err
	}
	state, err := checkManagedFile(ctx, r, swapSysctlPath, want)
	if err != nil {
		return false, err
	}
	fileOK, err := managedFileSatisfied(state, swapSysctlPath, rc.Force)
	if err != nil {
		return false, err
	}
	val, _, err := catTrim(ctx, r, swappinessProcPath)
	if err != nil {
		return false, err
	}
	return fileOK && val == swappinessValue, nil
}

// checkSwapRemoval reports satisfied unless a berth-owned swap lingers while swap is
// off: a marked fstab line or a berth-managed swappiness drop-in. A foreign swap is
// never flagged (berth removes only what it created).
func checkSwapRemoval(ctx context.Context, r bssh.Runner) (bool, []string, error) {
	fstab, _, err := catTrim(ctx, r, fstabPath)
	if err != nil {
		return false, nil, err
	}
	marked, _ := fstabSwapState(fstab)
	dropPresent, err := managedFilePresent(ctx, r, swapSysctlPath)
	if err != nil {
		return false, nil, err
	}
	if marked || dropPresent {
		return false, []string{"remove berth swap (" + swapfilePath + " + fstab entry + " + swapSysctlPath + ")"}, nil
	}
	return true, nil, nil
}

// checkSysctl reports satisfied iff the general drop-in is up-to-date (unmanaged
// aborts unless --force) AND every key's running value matches.
func checkSysctl(ctx context.Context, rc provision.RunCtx, r bssh.Runner) (bool, []string, error) {
	want, err := renderSysctl()
	if err != nil {
		return false, nil, err
	}
	state, err := checkManagedFile(ctx, r, sysctlPath, want)
	if err != nil {
		return false, nil, err
	}
	fileOK, err := managedFileSatisfied(state, sysctlPath, rc.Force)
	if err != nil {
		return false, nil, err
	}
	if !fileOK {
		return false, []string{"write " + sysctlPath + " + sysctl --system"}, nil
	}
	for _, kv := range sysctlKeys {
		res, err := r.Run(ctx, "sysctl -n "+kv.Key, nil)
		if err != nil {
			return false, nil, err
		}
		if strings.TrimSpace(res.Stdout) != kv.Value {
			return false, []string{"reload " + sysctlPath + " (running values stale)"}, nil
		}
	}
	return true, nil, nil
}

// checkSysctlRemoval reports satisfied unless the general drop-in is berth-managed
// while sysctl is off.
func checkSysctlRemoval(ctx context.Context, r bssh.Runner) (bool, []string, error) {
	present, err := managedFilePresent(ctx, r, sysctlPath)
	if err != nil {
		return false, nil, err
	}
	if present {
		return false, []string{"remove " + sysctlPath + " + sysctl --system"}, nil
	}
	return true, nil, nil
}

func (system) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	return nil // Task 5 fills this in
}

// renderSwapSysctl renders the vm.swappiness drop-in (static; '#' marker).
func renderSwapSysctl() ([]byte, error) { return templates.Render("sysctl_swap.conf.tmpl", nil) }

// renderSysctl renders the general web/DB sysctl drop-in (static; '#' marker).
func renderSysctl() ([]byte, error) { return templates.Render("sysctl_berth.conf.tmpl", nil) }

// sysctlKeys mirrors sysctl_berth.conf.tmpl: the (key, value) pairs Check reads back
// via `sysctl -n` to confirm the drop-in is live. Kept in sync with the template by
// TestSysctlKeysMatchTemplate.
var sysctlKeys = []struct{ Key, Value string }{
	{"net.core.somaxconn", "4096"},
	{"net.ipv4.tcp_tw_reuse", "1"},
	{"fs.file-max", "1048576"},
	{"fs.inotify.max_user_watches", "524288"},
}

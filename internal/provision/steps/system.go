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
	return provision.CheckResult{Satisfied: true}, nil // Tasks 4 fills this in
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

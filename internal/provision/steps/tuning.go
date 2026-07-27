package steps

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/templates"
)

const (
	mariadbUnit       = "mariadb.service"
	mariadbTuningPath = "/etc/mysql/mariadb.conf.d/99-berth.cnf"
	// mariadbSlowLogDir hosts the slow query log. Debian 13's mariadb logs to
	// the journal by default and no longer creates /var/log/mysql, yet its
	// logrotate still covers /var/log/mysql/*.log (missingok) — so berth
	// creates the directory (Debian's historical mysql:adm setgid 02750) and rotation
	// comes for free.
	mariadbSlowLogDir = "/var/log/mysql"
	// 02750 spelled five-digit so the setgid bit is visibly INTENDED (the
	// group inheritance is what lets logrotate's adm group read new logs).
	mariadbSlowLogDirEnsure = "install -d -m 02750 -o mysql -g adm " + mariadbSlowLogDir
	// mariadbSlowLogPath mirrors slow_query_log_file in mariadb_tuning.cnf.tmpl
	// (kept in sync by TestRenderMariaDBTuningSlowLogPathConst). Its EXISTENCE is
	// the convergence probe: mariadbd creates the file (with a header) when it
	// successfully opens the slow log at startup — live-verified on Trixie — so
	// a present file is durable evidence logging initialized, while a missing
	// one catches every silent-off state: the directory absent at startup, a
	// root-owned directory mariadbd cannot write into, or a crash between
	// creating the directory and restarting. Probing the directory alone would
	// read Satisfied in all three.
	mariadbSlowLogPath = mariadbSlowLogDir + "/mariadb-slow.log"
)

// mariadbBufferPoolMaxPercent caps innodb_buffer_pool_size at this share of
// the host's MemTotal. A pool that exceeds physical RAM makes mariadbd fail
// at startup (the failure is allocation, so no config parser can catch it)
// and the poison drop-in would fail every subsequent run identically. The
// threshold is a conservative sanity policy, not a startup guarantee: it
// ignores cgroup limits and co-resident workload memory.
const mariadbBufferPoolMaxPercent = 80

const memTotalCmd = `awk '/^MemTotal:/{print $2}' /proc/meminfo`

// parseMariaDBSize converts a MariaDB size value — bare bytes or a K/M/G
// suffix (1024-based, case-insensitive; MariaDB itself accepts lowercase and
// literal-Server callers bypass reMariaDBSize validation entirely) — to bytes.
func parseMariaDBSize(v string) (uint64, error) {
	num, mult := v, uint64(1)
	if len(v) > 0 {
		switch v[len(v)-1] {
		case 'K', 'k':
			num, mult = v[:len(v)-1], 1<<10
		case 'M', 'm':
			num, mult = v[:len(v)-1], 1<<20
		case 'G', 'g':
			num, mult = v[:len(v)-1], 1<<30
		}
	}
	n, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q is not a number with an optional K/M/G suffix", v)
	}
	if n > math.MaxUint64/mult {
		return 0, fmt.Errorf("size %q overflows", v)
	}
	return n * mult, nil
}

// hostMemTotalBytes reads the host's MemTotal from /proc/meminfo. An empty or
// unparsable value is an error, never zero — the guard below must fail loud
// rather than wave an oversized pool through.
func hostMemTotalBytes(ctx context.Context, r bssh.Runner) (uint64, error) {
	res, err := r.Run(ctx, memTotalCmd, nil)
	if err != nil {
		return 0, err
	}
	out := strings.TrimSpace(res.Stdout)
	if res.ExitCode != 0 {
		return 0, fmt.Errorf("cannot determine host RAM: %s", res.Stderr)
	}
	if out == "" {
		return 0, fmt.Errorf("cannot determine host RAM: empty MemTotal from /proc/meminfo")
	}
	kb, err := strconv.ParseUint(out, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot determine host RAM: MemTotal %q: %w", out, err)
	}
	if kb > math.MaxUint64/1024 {
		return 0, fmt.Errorf("cannot determine host RAM: MemTotal %q overflows", out)
	}
	return kb * 1024, nil
}

// checkMariaDBBufferPoolFits errors when the configured (or default)
// innodb_buffer_pool_size exceeds mariadbBufferPoolMaxPercent of host RAM.
// Overflow-safe: divide before multiplying; the sub-1% truncation is noise.
func checkMariaDBBufferPoolFits(ctx context.Context, r bssh.Runner, s *config.Server) error {
	val := s.Tuning.MariaDBBufferPoolEff()
	pool, err := parseMariaDBSize(val)
	if err != nil {
		return fmt.Errorf("tuning.mariadb_innodb_buffer_pool: %w", err)
	}
	total, err := hostMemTotalBytes(ctx, r)
	if err != nil {
		return err
	}
	if pool > total/100*mariadbBufferPoolMaxPercent {
		return fmt.Errorf("tuning.mariadb_innodb_buffer_pool %s exceeds %d%% of host RAM (MemTotal %d MiB); lower it",
			val, mariadbBufferPoolMaxPercent, total/(1<<20))
	}
	return nil
}

type tuning struct{}

// Tuning writes the managed MariaDB performance-tuning drop-in
// (mariadb.conf.d), gated on the engine being mariadb. It runs after database
// so the service is installed. Valkey maxmemory tuning lives in the per-site
// instance units owned by the valkey step.
func Tuning() provision.Step { return tuning{} }

func (tuning) Name() string { return "tuning" }

func (tuning) Requires() []string { return []string{"database"} }

// renderMariaDBTuning renders the managed mariadb.conf.d drop-in. The slow-log
// block is conditional so the default render stays byte-identical to the
// pre-slow-log output (no drift/restart on existing hosts). The log file sits
// in /var/log/mysql, the directory Debian's mariadb packaging already
// logrotates, so no berth logrotate entry is needed; the new settings load on
// the restart Apply already performs (checkTuned's liveness gate covers it).
// The four parity knobs (log file size, tmp/heap table size, max connections,
// max allowed packet) are conditional blocks: unset renders no directive, so
// the default output stays byte-identical to the pre-pack-2 render.
func renderMariaDBTuning(s *config.Server) ([]byte, error) {
	return templates.Render("mariadb_tuning.cnf.tmpl", struct {
		BufferPool       string
		LogFileSize      string
		TmpTableSize     string
		MaxConnections   int
		MaxAllowedPacket string
		SlowQueryLog     bool
		LongQueryTime    int
	}{
		BufferPool:       s.Tuning.MariaDBBufferPoolEff(),
		LogFileSize:      s.Tuning.MariaDBLogFileSize,
		TmpTableSize:     s.Tuning.MariaDBTmpTableSize,
		MaxConnections:   s.Tuning.MariaDBMaxConnections,
		MaxAllowedPacket: s.Tuning.MariaDBMaxAllowedPacket,
		SlowQueryLog:     s.Tuning.MariaDBSlowQueryLog,
		LongQueryTime:    s.Tuning.MariaDBLongQueryTimeEff(),
	})
}

// serviceConfigLoaded reports whether a managed unit-affecting file at path was
// already in place at the unit's last (re)start: loaded iff the file's mtime is not
// newer than the unit's ActiveEnterTimestamp. A file newer than the last start means
// Apply wrote it but the restart has not happened yet (e.g. a crash mid-Apply), so
// the running config is stale. Read-only; an inactive unit (empty timestamp) yields
// a non-zero exit, i.e. "not loaded". Liveness keys on the file's MTIME, not its
// content, so a benign out-of-band `touch` of an otherwise up-to-date drop-in
// triggers one reconciling restart — intentional, conservative behavior.
//
// The timestamp is read with `systemctl show --timestamp=unix` (systemd ≥251;
// Trixie ships 257), which prints `@<epoch>` — `tr -d @` strips the prefix and
// the comparison is pure integers. No `date -d` round-trip: date cannot parse
// some zone abbreviations systemd emits (AEST/ACST), which read as "not loaded"
// and caused a spurious restart on every run in those timezones.
//
// The comparison truncates both the file MTIME and ActiveEnterTimestamp to whole
// seconds, so in the astronomically rare case where a written-but-unloaded drop-in
// shares the same wall-clock second as the unit's last (re)start it could read as
// loaded. This is accepted as negligible: the crash-between-write-and-restart window
// is sub-second and would have to coincide with an unrelated prior start in the same
// second. (serviceUp in checkTuned independently covers the down-service case.)
func serviceConfigLoaded(ctx context.Context, r bssh.Runner, unit, path string) (bool, error) {
	cmd := `[ "$(stat -c %Y ` + shQuote(path) + ` 2>/dev/null)" -le "$(systemctl show -p ActiveEnterTimestamp --value --timestamp=unix ` + unit + ` 2>/dev/null | tr -d @)" ]`
	res, err := r.Run(ctx, cmd, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

// checkTuned reports whether a managed tuning file is up to date, its unit is
// active (running), AND the running config has loaded the file. The contract is
// managedFileSatisfied && serviceActive && liveness, evaluated in that order: a unit
// that was active then STOPPED retains its old ActiveEnterTimestamp, so liveness alone
// would falsely pass for a down service — serviceActive guards that. It checks active
// only (not enabled): enablement is the service's own step's responsibility, and
// tuning's Apply restarts but never enables, so requiring enabled here would never
// converge (an active-but-disabled unit would fail Check forever). It returns a
// human-readable change list when not satisfied.
func checkTuned(ctx context.Context, rc provision.RunCtx, r bssh.Runner, unit, path string, want []byte, what string) (bool, []string, error) {
	state, err := checkManagedFile(ctx, r, path, want)
	if err != nil {
		return false, nil, err
	}
	fileOK, err := managedFileSatisfied(state, path, rc.Force)
	if err != nil {
		return false, nil, err
	}
	if !fileOK {
		return false, []string{"write " + path + " (" + what + "), restart " + unit}, nil
	}
	active, err := serviceActive(ctx, r, unit)
	if err != nil {
		return false, nil, err
	}
	if !active {
		return false, []string{"restart " + unit + " (not running)"}, nil
	}
	loaded, err := serviceConfigLoaded(ctx, r, unit, path)
	if err != nil {
		return false, nil, err
	}
	if !loaded {
		return false, []string{"restart " + unit + " to load " + path}, nil
	}
	return true, nil, nil
}

func (tuning) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	var changes []string
	if s.Database.Engine == "mariadb" {
		if err := checkMariaDBBufferPoolFits(ctx, r, s); err != nil {
			return provision.CheckResult{}, err
		}
		want, err := renderMariaDBTuning(s)
		if err != nil {
			return provision.CheckResult{}, err
		}
		ok, ch, err := checkTuned(ctx, rc, r, mariadbUnit, mariadbTuningPath, want, "mariadb innodb_buffer_pool_size")
		if err != nil {
			return provision.CheckResult{}, err
		}
		if !ok {
			changes = append(changes, ch...)
		}
		// A loaded drop-in is NOT enough for the slow log: when mariadbd cannot
		// open the file at startup (Trixie ships no /var/log/mysql) it disables
		// slow logging for its whole lifetime while slow_query_log still reads
		// ON — a failure the content hash and liveness gate cannot see (found
		// live on a fresh Trixie box). Probe the log file itself; see
		// mariadbSlowLogPath for why file existence is the right evidence.
		if s.Tuning.MariaDBSlowQueryLog {
			fileOK, err := slowLogActive(ctx, r)
			if err != nil {
				return provision.CheckResult{}, err
			}
			if !fileOK {
				changes = append(changes, "ensure "+mariadbSlowLogDir+" and restart "+mariadbUnit+" (slow log inactive)")
			}
		}
	}
	if len(changes) == 0 {
		return provision.CheckResult{Satisfied: true, Reason: "service tuning drop-ins in place and loaded"}, nil
	}
	return provision.CheckResult{Satisfied: false, Reason: "service tuning not applied", Changes: changes}, nil
}

// Apply reconciles only when actually unsatisfied: it re-runs the SAME checkTuned
// predicate Check uses, so a healthy service is skipped entirely (no spurious
// restart). This is re-entrant and idempotent.
func (tuning) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	if s.Database.Engine == "mariadb" {
		cfg, err := renderMariaDBTuning(s)
		if err != nil {
			return err
		}
		ok, _, err := checkTuned(ctx, rc, r, mariadbUnit, mariadbTuningPath, cfg, "mariadb innodb_buffer_pool_size")
		if err != nil {
			return err
		}
		fileOK := true
		if s.Tuning.MariaDBSlowQueryLog {
			if fileOK, err = slowLogActive(ctx, r); err != nil {
				return err
			}
		}
		if !ok || !fileOK {
			// Validation strictly before any mutation (the step's established
			// order): the RAM guard first, then the directory, then the file
			// write, then one restart covering whichever was stale. install -d
			// also RESETS owner/mode on an existing directory, healing e.g. a
			// root-owned /var/log/mysql mariadbd cannot write into (that state
			// surfaces as a missing log file). The restart is required even
			// when only the file was missing: the running mariadbd turned slow
			// logging off for its whole process lifetime.
			if !ok {
				if err := checkMariaDBBufferPoolFits(ctx, r, s); err != nil {
					return err
				}
			}
			if !fileOK {
				if res, err := r.Run(ctx, mariadbSlowLogDirEnsure, nil); err != nil {
					return err
				} else if res.ExitCode != 0 {
					return fmt.Errorf("create %s: %s", mariadbSlowLogDir, res.Stderr)
				}
			}
			if !ok {
				if err := r.WriteFile(ctx, bssh.FileSpec{Path: mariadbTuningPath, Content: cfg, Owner: "root", Group: "root", Mode: 0o644, Sudo: true}); err != nil {
					return fmt.Errorf("write %s: %w", mariadbTuningPath, err)
				}
			}
			if res, err := r.Run(ctx, "systemctl restart "+mariadbUnit, nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("restart %s: %s", mariadbUnit, res.Stderr)
			}
		}
	}
	return nil
}

// slowLogActive reports whether the slow log file exists (test -f, read-only) —
// durable evidence mariadbd opened it at startup; see mariadbSlowLogPath.
func slowLogActive(ctx context.Context, r bssh.Runner) (bool, error) {
	res, err := r.Run(ctx, "test -f "+mariadbSlowLogPath, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0, nil
}

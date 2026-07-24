# fix(tuning): slow query log silently off on Debian 13 — probe the log file, ensure /var/log/mysql

Found during the live validation of #40 on a fresh Debian 13.5 box.

## The bug

Trixie's mariadb packaging logs to the journal and **no longer ships
`/var/log/mysql`**. With `tuning.mariadb_slow_query_log: true`, mariadbd
failed to open the log at startup and **disabled slow logging for the whole
process lifetime** — while `SHOW GLOBAL VARIABLES` still reports
`slow_query_log = ON` and the tuning step's content-hash + liveness Check
reads Satisfied. An invisible failure the drift mechanism cannot see:

```
[ERROR] mariadbd: File '/var/log/mysql/mariadb-slow.log' not found (Errcode: 2)
[ERROR] Could not use /var/log/mysql/mariadb-slow.log for logging
        (error 2). Turning logging off for the whole duration of the
        MariaDB server process.
```

## The fix (two commits — the second hardens the first per review)

1. `Apply` creates `/var/log/mysql` (Debian's historical `mysql:adm` 2750)
   **before** the restart. The distro logrotate already rotates
   `/var/log/mysql/*.log` (`missingok`), so rotation needs nothing from berth.
2. Codex review of commit 1 showed a directory probe is not durable evidence:
   a crash between `install -d` and the restart, an operator-created
   directory, or a **root-owned** directory mariadbd cannot write into all
   leave logging silently off while the directory exists. mariadbd creates
   the log file (with a header) when it successfully opens it at startup —
   live-verified on Trixie, including a restart with zero slow queries — so
   `Check` now probes the **file**, and `Apply` runs `install -d` whenever
   the file is missing (it also resets owner/mode on an existing directory,
   healing the root-owned case) and restarts, with the RAM guard strictly
   before any mutation.

## Testing

- Unit: file-missing → unsatisfied; file-present → satisfied; Apply ensures
  the dir strictly **before** the restart (call-index assertion) without
  rewriting an up-to-date drop-in; converged Apply is a full no-op; the
  slow-log-off path never probes the log path; a sync test pins the Go
  const to the template's `slow_query_log_file`.
- Live on the box: the original silent-off state was detected and healed
  (fresh run), then the adversarial variant — `rm` the log, `chown root:root
  /var/log/mysql`, restart (var reads ON, file absent) — was healed by
  `--only tuning`: ownership back to `mysql:adm 2750`, restart, next slow
  query captured, re-run converged.
- `gofmt` clean, `go vet` clean, `go test -race` green.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

//go:build integration

package integration

import (
	"fmt"
	"strings"
)

// parseEnv parses Laravel-style KEY=VALUE lines into a map (comments and blanks
// skipped; values are not unquoted — berth writes them unquoted).
func parseEnv(content string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

// dbProbeCmd builds a shell command that runs sql against targetDB as the app user
// from a site's .env, the way Laravel connects: MariaDB over DB_SOCKET when set (else
// TCP to DB_HOST), Postgres over TCP to DB_HOST. The password rides in the inline
// MYSQL_PWD= / PGPASSWORD= assignment — off the mysql/psql argv (no -p<pass>); it does
// reach the wrapping sh -c, which is acceptable on the disposable test box. Exit 0 means
// connect + statement succeeded.
func dbProbeCmd(env map[string]string, targetDB, sql string) string {
	user, pass := env["DB_USERNAME"], env["DB_PASSWORD"]
	switch env["DB_CONNECTION"] {
	case "mysql":
		host := env["DB_HOST"]
		if host == "" {
			host = "127.0.0.1"
		}
		conn := "-h" + host
		if sock := env["DB_SOCKET"]; sock != "" {
			conn = "--socket=" + sock
		}
		return fmt.Sprintf("MYSQL_PWD=%s mysql %s -u%s %s -e %s", pass, conn, user, targetDB, sqQuote(sql))
	case "pgsql":
		host := env["DB_HOST"]
		if host == "" {
			host = "127.0.0.1"
		}
		return fmt.Sprintf("PGPASSWORD=%s psql -h%s -U%s -d%s -tAc %s", pass, host, user, targetDB, sqQuote(sql))
	default:
		return "false"
	}
}

// sqQuote single-quotes s for safe embedding in a shell command.
func sqQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// dbServiceName maps a berth engine name to its systemd unit.
func dbServiceName(engine string) string {
	if engine == "postgres" {
		return "postgresql"
	}
	return "mariadb"
}

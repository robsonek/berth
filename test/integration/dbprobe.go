//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
	bssh "github.com/robsonek/berth/internal/ssh"
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

// trustedDBConn carries the engine-level connection identity every root
// probe is built from — the engine's EnvConnection(), never the
// tenant-writable .env.
type trustedDBConn struct {
	driver, host, port, socket string
}

// trustedDBConnFor resolves the configured engine's EnvConnection into a
// trustedDBConn; an unknown engine is fatal.
func trustedDBConnFor(t *testing.T, srv *config.Server) trustedDBConn {
	t.Helper()
	eng, err := dbpkg.Get(srv.Database.Engine)
	if err != nil {
		t.Fatalf("engine %q: %v", srv.Database.Engine, err)
	}
	driver, host, port, socket := eng.EnvConnection()
	return trustedDBConn{driver: driver, host: host, port: port, socket: socket}
}

// assertEnvIdentityFidelity proves a live shared/.env's non-secret DB fields
// agree with the trusted identities root probes are built from: shared/.env
// is seed-if-absent and never rewritten, so a pre-existing file's connection
// fields can legitimately differ from what the current config would seed.
// Every field is exit-code-verified through the production match script
// (nothing rides stdout); a mismatch is fatal — it means the app connects
// elsewhere than berth believes, so probing the trusted endpoint would prove
// nothing about the app. label prefixes every failure.
func assertEnvIdentityFidelity(ctx context.Context, t *testing.T, c *bssh.Client, label, envPath string, conn trustedDBConn, dbUser, dbName string) {
	t.Helper()
	for _, f := range [][2]string{
		{"DB_CONNECTION", conn.driver},
		{"DB_HOST", conn.host},
		{"DB_PORT", conn.port},
		{"DB_USERNAME", dbUser},
		{"DB_DATABASE", dbName},
	} {
		if exit := envFieldExit(ctx, t, c, envPath, f[0], f[1]); exit != 0 {
			fidelityFatal(t, label, f[0], envPath, f[1], exit)
		}
	}
	if conn.socket != "" {
		if exit := envFieldExit(ctx, t, c, envPath, "DB_SOCKET", conn.socket); exit != 0 {
			fidelityFatal(t, label, "DB_SOCKET", envPath, conn.socket, exit)
		}
	} else if exit := envFieldExit(ctx, t, c, envPath, "DB_SOCKET", ""); exit != 3 {
		t.Fatalf("%s: %s carries a DB_SOCKET line but the engine connects over TCP (probe exit %d: %s, want 3 = key absent) — the app connects elsewhere than berth believes",
			label, envPath, exit, envExitMeaning(exit))
	}
}

// fidelityFatal reports a failed fidelity probe with the exit-code contract
// spelled out: exits 1/3 prove the live file disagrees with the trusted
// identity, while exit 2 is an I/O failure that proves nothing about the
// value — the two must never read as the same diagnosis. Non-secret values
// only (the wording includes want).
func fidelityFatal(t *testing.T, label, key, envPath, want string, exit int) {
	t.Helper()
	if exit == 2 {
		t.Fatalf("%s: probing %s in %s failed with an I/O error (exit 2) — the file could not be read, no fidelity verdict",
			label, key, envPath)
	}
	t.Fatalf("%s: live %s in %s disagrees with the trusted value %q (probe exit %d: %s) — the app connects elsewhere than berth believes",
		label, key, envPath, want, exit, envExitMeaning(exit))
}

// dbServiceName maps a berth engine name to its systemd unit.
func dbServiceName(engine string) string {
	if engine == "postgres" {
		return "postgresql"
	}
	return "mariadb"
}

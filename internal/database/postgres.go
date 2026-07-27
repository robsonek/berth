package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/apt"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func init() { Register(Postgres{}) }

// Postgres provisions PostgreSQL. Administrative SQL runs as the postgres OS
// superuser via `sudo -u postgres psql` (peer auth on the local cluster); the
// password is fed on stdin, never on the command line.
type Postgres struct{}

func (Postgres) Name() string { return "postgres" }

// ServerPackage is the Debian/PGDG metapackage (the repo decides the major).
func (Postgres) ServerPackage() string { return "postgresql" }

// UpstreamRepo is the official PostgreSQL Global Development Group repository.
func (Postgres) UpstreamRepo() (apt.Repo, bool) { return apt.PostgresPGDG(), true }

// EnvConnection is Laravel's PostgreSQL driver over TCP loopback (the app role
// cannot use peer-auth socket access).
func (Postgres) EnvConnection() (driver, host, port, socket string) {
	return "pgsql", "127.0.0.1", "5432", ""
}

// runPSQL pipes a SQL script to psql as the postgres superuser. ON_ERROR_STOP
// makes any failing statement abort with a non-zero exit.
func runPSQL(ctx context.Context, r bssh.Runner, sql string) error {
	res, err := r.Run(ctx, "sudo -u postgres psql -v ON_ERROR_STOP=1", []byte(sql))
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("psql: %s", res.Stderr)
	}
	return nil
}

// EnsureDatabase creates the database if it does not already exist. CREATE
// DATABASE cannot run inside a transaction/DO block, so a guard query feeds the
// statement to psql's \gexec only when the database is absent.
func (Postgres) EnsureDatabase(ctx context.Context, r bssh.Runner, name string) error {
	// name is a validated SQL identifier (config.Validate): safe to quote.
	return runPSQL(ctx, r, fmt.Sprintf(
		"SELECT 'CREATE DATABASE \"%[1]s\"' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '%[1]s')\\gexec\n",
		name))
}

// probePSQL runs a read-only scalar query as the postgres superuser (peer
// auth) and reports whether it returned "1". A non-zero exit is false, nil.
func probePSQL(ctx context.Context, r bssh.Runner, query string) (bool, error) {
	res, err := r.Run(ctx, `sudo -u postgres psql -tAc "`+query+`"`, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0 && strings.TrimSpace(res.Stdout) == "1", nil
}

// DatabaseExists probes pg_database. name is a validated SQL identifier.
func (Postgres) DatabaseExists(ctx context.Context, r bssh.Runner, name string) (bool, error) {
	return probePSQL(ctx, r, "SELECT 1 FROM pg_database WHERE datname='"+name+"'")
}

// UserGranted probes ownership: EnsureUser's LAST statement is
// ALTER DATABASE ... OWNER TO, so a positive probe proves the whole batch ran.
func (Postgres) UserGranted(ctx context.Context, r bssh.Runner, user, database string) (bool, error) {
	return probePSQL(ctx, r, "SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba WHERE d.datname='"+database+"' AND r.rolname='"+user+"'")
}

// EnsureUser creates the login role if absent, re-syncs its password, revokes
// PUBLIC's default CONNECT/TEMPORARY on the database (other tenants' roles must
// not even connect — catalog enumeration, connection-slot exhaustion), and makes
// the role the owner of the database (so it has full rights, including on the
// public schema in PostgreSQL 15+). Idempotent. UserGranted probes the ownership
// set by the LAST statement, so ALTER DATABASE ... OWNER TO must stay last for a
// positive probe to prove the whole batch ran.
func (Postgres) EnsureUser(ctx context.Context, r bssh.Runner, user, password, database string) error {
	// user/database are validated identifiers; password is the alphanumeric value
	// from secret.Generate, bound in SQL via stdin.
	sql := fmt.Sprintf(
		"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%[1]s') THEN CREATE ROLE \"%[1]s\" LOGIN PASSWORD '%[3]s'; END IF; END $$;\n"+
			"ALTER ROLE \"%[1]s\" WITH LOGIN PASSWORD '%[3]s';\n"+
			"REVOKE CONNECT, TEMPORARY ON DATABASE \"%[2]s\" FROM PUBLIC;\n"+
			"GRANT ALL PRIVILEGES ON DATABASE \"%[2]s\" TO \"%[1]s\";\n"+
			"ALTER DATABASE \"%[2]s\" OWNER TO \"%[1]s\";\n",
		user, database, password)
	return runPSQL(ctx, r, sql)
}

// DumpCommand writes a plain-SQL dump of database to stdout as the postgres
// superuser (peer auth). Plain format restores with psql (not pg_restore). The
// dump CARRIES ownership (`ALTER ... OWNER TO <approle>`), so restoring as the
// postgres superuser reestablishes app-role ownership — berth always makes the
// app role the database owner. The app role/database must already exist; berth
// provisions them, so for disaster recovery re-run berth before restoring.
// database is a validated SQL identifier, so it carries no shell metacharacters.
// The name is shell-quoted for the same defensive reason as MariaDB's.
func (Postgres) DumpCommand(database string) string {
	return "sudo -u postgres pg_dump " + shQuote(database)
}

// ClientAuthFileName is libpq's per-user password file.
func (Postgres) ClientAuthFileName() string { return ".pgpass" }

// ClientAuthFile emits one full-wildcard match line: the site role exists only
// for its own database, so scoping host/port adds nothing, and the wildcard
// keeps psql/pg_dump working over TCP 127.0.0.1 (the .env transport) and any
// local alias alike. libpq ignores the file unless it is 0600 — the database
// step writes it with exactly that mode.
func (Postgres) ClientAuthFile(database, user, password string) []byte {
	return []byte("*:*:" + database + ":" + user + ":" + password + "\n")
}

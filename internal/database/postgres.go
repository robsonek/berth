package database

import (
	"context"
	"fmt"

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

// EnsureUser creates the login role if absent, re-syncs its password, and makes
// it the owner of the database (so it has full rights, including on the public
// schema in PostgreSQL 15+). Idempotent.
func (Postgres) EnsureUser(ctx context.Context, r bssh.Runner, user, password, database string) error {
	// user/database are validated identifiers; password is the alphanumeric value
	// from secret.Generate, bound in SQL via stdin.
	sql := fmt.Sprintf(
		"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%[1]s') THEN CREATE ROLE \"%[1]s\" LOGIN PASSWORD '%[3]s'; END IF; END $$;\n"+
			"ALTER ROLE \"%[1]s\" WITH LOGIN PASSWORD '%[3]s';\n"+
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
func (Postgres) DumpCommand(database string) string {
	return "sudo -u postgres pg_dump " + database
}

// Package database provides pluggable database engines.
package database

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// Engine is a pluggable database backend. Each engine owns its server package,
// its trusted upstream apt repository, the connection parameters it seeds into
// shared/.env, and its (idempotent) database/user provisioning SQL.
type Engine interface {
	Name() string
	// ServerPackage is the apt package that installs the server.
	ServerPackage() string
	// UpstreamRepo returns the engine's producer apt repository and true, or a
	// zero Repo and false if the engine has no trusted upstream.
	UpstreamRepo() (apt.Repo, bool)
	// EnvConnection returns the Laravel .env DB_CONNECTION driver, DB_HOST, DB_PORT
	// and DB_SOCKET (socket is "" for engines that connect over TCP). Each engine
	// reports its natural local transport: MariaDB the unix socket its
	// '<user>'@'localhost' grant was created for; Postgres TCP to 127.0.0.1 (its
	// app role cannot use the socket — peer auth maps to the OS user name, not the
	// role name).
	EnvConnection() (driver, host, port, socket string)
	// EnsureDatabase creates the application database if absent (idempotent).
	EnsureDatabase(ctx context.Context, r bssh.Runner, name string) error
	// EnsureUser creates the application user/role (or re-syncs its password) and
	// grants it the database (idempotent). Called after EnsureDatabase.
	EnsureUser(ctx context.Context, r bssh.Runner, user, password, database string) error
	// DumpCommand returns the shell command that writes a logical dump of database
	// to stdout. Unlike EnsureDatabase/EnsureUser it does not execute — it is
	// rendered into the managed backup script and run later from root's cron, so it
	// must stay passwordless (socket/peer auth, matching this engine's admin SQL).
	DumpCommand(database string) string
}

var registry = map[string]Engine{}

func Register(e Engine) { registry[e.Name()] = e }

func Get(name string) (Engine, error) {
	e, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown database engine %q", name)
	}
	return e, nil
}

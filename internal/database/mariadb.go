package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/robsonek/berth/internal/apt"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func init() { Register(MariaDB{}) }

type MariaDB struct{}

func (MariaDB) Name() string { return "mariadb" }

// ServerPackage is the Debian/mariadb.org server package.
func (MariaDB) ServerPackage() string { return "mariadb-server" }

// UpstreamRepo is mariadb.org's 12.3 LTS repository.
func (MariaDB) UpstreamRepo() (apt.Repo, bool) { return apt.MariaDBOrg(), true }

// EnvConnection is Laravel's MySQL driver over the local unix socket.
func (MariaDB) EnvConnection() (driver, host, port, socket string) {
	return "mysql", "localhost", "3306", "/run/mysqld/mysqld.sock"
}

// runSQL pipes a statement to the local socket as root (unix_socket auth on Debian).
func runSQL(ctx context.Context, r bssh.Runner, sql string) error {
	res, err := r.Run(ctx, "mysql --protocol=socket", []byte(sql))
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("mysql: %s", res.Stderr)
	}
	return nil
}

func (MariaDB) EnsureDatabase(ctx context.Context, r bssh.Runner, name string) error {
	// name is a validated SQL identifier (config.Validate); safe to interpolate as an identifier.
	return runSQL(ctx, r, fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", name))
}

// probeSQL runs a read-only scalar query inline (no secrets involved) and
// reports whether it returned "1". A non-zero exit is false, nil.
func probeSQL(ctx context.Context, r bssh.Runner, query string) (bool, error) {
	res, err := r.Run(ctx, `mysql --protocol=socket -N -e "`+query+`"`, nil)
	if err != nil {
		return false, err
	}
	return res.ExitCode == 0 && strings.TrimSpace(res.Stdout) == "1", nil
}

// DatabaseExists probes information_schema for the database. name is a
// validated SQL identifier (config.Validate) — no quotes or metacharacters.
func (MariaDB) DatabaseExists(ctx context.Context, r bssh.Runner, name string) (bool, error) {
	return probeSQL(ctx, r, "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+name+"'")
}

// UserGranted probes information_schema for any privilege of
// '<user>'@'localhost' on the database — present once EnsureUser's GRANT ran.
// GRANTEE stores the quoted account literal, so the embedded single quotes are
// doubled inside the SQL string literal.
func (MariaDB) UserGranted(ctx context.Context, r bssh.Runner, user, database string) (bool, error) {
	return probeSQL(ctx, r, "SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='"+database+"' AND GRANTEE='''"+user+"''@''localhost''' LIMIT 1")
}

func (MariaDB) EnsureUser(ctx context.Context, r bssh.Runner, user, password, database string) error {
	// user/database are validated identifiers; password is a value bound in SQL via stdin.
	sql := fmt.Sprintf(
		"CREATE USER IF NOT EXISTS '%[1]s'@'localhost' IDENTIFIED BY '%[3]s';\n"+
			"ALTER USER '%[1]s'@'localhost' IDENTIFIED BY '%[3]s';\n"+
			"GRANT ALL PRIVILEGES ON `%[2]s`.* TO '%[1]s'@'localhost';\n"+
			"FLUSH PRIVILEGES;",
		user, database, password)
	return runSQL(ctx, r, sql)
}

// DumpCommand writes a logical dump of database to stdout, passwordless via the
// local socket as root (matching runSQL's auth). --single-transaction gives a
// consistent InnoDB snapshot; --no-tablespaces avoids needing the PROCESS priv;
// --routines/--events include stored routines and events. database is a validated
// SQL identifier (config.Validate), so it carries no shell metacharacters.
func (MariaDB) DumpCommand(database string) string {
	return "mysqldump --protocol=socket --single-transaction --no-tablespaces --routines --events " + database
}

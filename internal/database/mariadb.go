package database

import (
	"context"
	"fmt"

	"github.com/robsonek/berth/internal/apt"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func init() { Register(MariaDB{}) }

type MariaDB struct{}

func (MariaDB) Name() string { return "mariadb" }

// ServerPackage is the Debian/mariadb.org server package.
func (MariaDB) ServerPackage() string { return "mariadb-server" }

// UpstreamRepo is mariadb.org's 11.8 LTS repository.
func (MariaDB) UpstreamRepo() (apt.Repo, bool) { return apt.MariaDBOrg(), true }

// EnvConnection is Laravel's MySQL-protocol driver and default port.
func (MariaDB) EnvConnection() (driver, port string) { return "mysql", "3306" }

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

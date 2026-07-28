//go:build integration

package integration

import "testing"

func TestParseEnv(t *testing.T) {
	m := parseEnv("# comment\nDB_HOST=localhost\nDB_SOCKET=/run/mysqld/mysqld.sock\n\nDB_USERNAME=sync\n")
	if m["DB_HOST"] != "localhost" || m["DB_SOCKET"] != "/run/mysqld/mysqld.sock" || m["DB_USERNAME"] != "sync" {
		t.Errorf("parseEnv = %+v", m)
	}
}

// dbProbeStdinCmd builds from TRUSTED identities (config + EnvConnection) and
// sqQuotes every token; these pins mirror the two engines' EnvConnection
// shapes the drill actually feeds it.
func TestDBProbeStdinCmdMariaDBSocket(t *testing.T) {
	got := dbProbeStdinCmd("mysql", "localhost", "3306", "/run/mysqld/mysqld.sock", "b_app_1234abcd", "app_db", "SELECT 1")
	want := `IFS= read -r pw; MYSQL_PWD="$pw" mysql --socket='/run/mysqld/mysqld.sock' -u'b_app_1234abcd' 'app_db' -e 'SELECT 1'`
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestDBProbeStdinCmdMySQLTCP(t *testing.T) {
	got := dbProbeStdinCmd("mysql", "127.0.0.1", "3306", "", "b_app_1234abcd", "app_db", "SELECT 1")
	want := `IFS= read -r pw; MYSQL_PWD="$pw" mysql -h'127.0.0.1' -P'3306' -u'b_app_1234abcd' 'app_db' -e 'SELECT 1'`
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestDBProbeStdinCmdPostgresTCP(t *testing.T) {
	got := dbProbeStdinCmd("pgsql", "127.0.0.1", "5432", "", "b_app_1234abcd", "app_db", "SELECT 1")
	want := `IFS= read -r pw; PGPASSWORD="$pw" psql -h'127.0.0.1' -p'5432' -U'b_app_1234abcd' -d'app_db' -tAc 'SELECT 1'`
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestDBProbeStdinCmdUnknownDriver(t *testing.T) {
	if got := dbProbeStdinCmd("sqlite", "", "", "", "u", "d", "SELECT 1"); got != "false" {
		t.Errorf("got %q, want the always-failing command", got)
	}
}

func TestDBServiceName(t *testing.T) {
	if dbServiceName("postgres") != "postgresql" || dbServiceName("mariadb") != "mariadb" {
		t.Fatal("dbServiceName mapping wrong")
	}
}

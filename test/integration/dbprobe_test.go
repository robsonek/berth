//go:build integration

package integration

import "testing"

func TestParseEnv(t *testing.T) {
	m := parseEnv("# comment\nDB_HOST=localhost\nDB_SOCKET=/run/mysqld/mysqld.sock\n\nDB_USERNAME=sync\n")
	if m["DB_HOST"] != "localhost" || m["DB_SOCKET"] != "/run/mysqld/mysqld.sock" || m["DB_USERNAME"] != "sync" {
		t.Errorf("parseEnv = %+v", m)
	}
}

func TestDBProbeCmdMariaDBSocket(t *testing.T) {
	env := map[string]string{"DB_CONNECTION": "mysql", "DB_SOCKET": "/run/mysqld/mysqld.sock", "DB_USERNAME": "sync", "DB_PASSWORD": "pw"}
	got := dbProbeCmd(env, "sync", "SELECT 1")
	want := "MYSQL_PWD=pw mysql --socket=/run/mysqld/mysqld.sock -usync sync -e 'SELECT 1'"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestDBProbeCmdMariaDBTCPFallback(t *testing.T) {
	env := map[string]string{"DB_CONNECTION": "mysql", "DB_HOST": "127.0.0.1", "DB_USERNAME": "sync", "DB_PASSWORD": "pw"}
	got := dbProbeCmd(env, "sync", "SELECT 1")
	want := "MYSQL_PWD=pw mysql -h127.0.0.1 -usync sync -e 'SELECT 1'"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestDBProbeCmdPostgresTCP(t *testing.T) {
	env := map[string]string{"DB_CONNECTION": "pgsql", "DB_HOST": "127.0.0.1", "DB_USERNAME": "sync", "DB_PASSWORD": "pw"}
	got := dbProbeCmd(env, "sync", "SELECT 1")
	want := "PGPASSWORD=pw psql -h127.0.0.1 -Usync -dsync -tAc 'SELECT 1'"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestDBServiceName(t *testing.T) {
	if dbServiceName("postgres") != "postgresql" || dbServiceName("mariadb") != "mariadb" {
		t.Fatal("dbServiceName mapping wrong")
	}
}

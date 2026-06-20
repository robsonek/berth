package database

import "testing"

func TestDumpCommand(t *testing.T) {
	if got := (MariaDB{}).DumpCommand("appdb"); got != "mysqldump --protocol=socket --single-transaction --no-tablespaces --routines --events appdb" {
		t.Errorf("mariadb dump = %q", got)
	}
	if got := (Postgres{}).DumpCommand("appdb"); got != "sudo -u postgres pg_dump --no-owner appdb" {
		t.Errorf("postgres dump = %q", got)
	}
}

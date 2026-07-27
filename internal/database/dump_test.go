package database

import (
	"strings"
	"testing"
)

func TestDumpCommand(t *testing.T) {
	// The database name is shell-quoted defensively: reSQLIdent (enforced by
	// config.Load) already excludes metacharacters, but the command lands in a
	// root cron script, so the quoting must not depend on a validator the
	// caller might have bypassed (literal &config.Server{}).
	if got := (MariaDB{}).DumpCommand("appdb"); got != "mysqldump --protocol=socket --single-transaction --no-tablespaces --routines --events 'appdb'" {
		t.Errorf("mariadb dump = %q", got)
	}
	if got := (Postgres{}).DumpCommand("appdb"); got != "sudo -u postgres pg_dump 'appdb'" {
		t.Errorf("postgres dump = %q", got)
	}
	// Hostile input proves REAL quoting, not decorative quotes: an embedded
	// single quote and a command substitution must come out inert. (Such a
	// name can never pass config validation — this pins the primitive itself.
	// A leading dash is still only blocked by reSQLIdent; quoting cannot
	// prevent option injection.)
	hostile := `ap'db; $(rm -rf /)`
	got := (MariaDB{}).DumpCommand(hostile)
	want := `mysqldump --protocol=socket --single-transaction --no-tablespaces --routines --events 'ap'\''db; $(rm -rf /)'`
	if got != want {
		t.Errorf("hostile mariadb dump:\ngot  %q\nwant %q", got, want)
	}
	if !strings.Contains((Postgres{}).DumpCommand(hostile), `'ap'\''db; $(rm -rf /)'`) {
		t.Errorf("hostile postgres dump not quoted: %q", (Postgres{}).DumpCommand(hostile))
	}
}

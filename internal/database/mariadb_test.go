package database

import (
	"context"
	"strings"
	"testing"

	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestMariaDBEnsureUserUsesStdinNotArgv(t *testing.T) {
	f := bssh.NewFakeRunner()
	// The SQL goes through stdin; the command itself must not contain the password.
	f.On("mysql --protocol=socket", bssh.Result{})
	m := MariaDB{}
	if err := m.EnsureUser(context.Background(), f, "myapp", "s3cr3t", "myapp"); err != nil {
		t.Fatalf("EnsureUser() error = %v", err)
	}
	call := f.Calls()[0]
	if strings.Contains(call.Cmd, "s3cr3t") {
		t.Error("password must not appear in the command string")
	}
	if !strings.Contains(string(call.Stdin), "CREATE USER") || !strings.Contains(string(call.Stdin), "s3cr3t") {
		t.Error("SQL with the password must be passed via stdin")
	}
	if !strings.Contains(string(call.Stdin), "ALTER USER") {
		t.Error("EnsureUser must be idempotent (ALTER to re-sync the password)")
	}
}

func TestMariaDBEnsureDatabaseIdempotent(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("mysql --protocol=socket", bssh.Result{})
	if err := (MariaDB{}).EnsureDatabase(context.Background(), f, "myapp"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(f.Calls()[0].Stdin), "CREATE DATABASE IF NOT EXISTS") {
		t.Error("expected idempotent CREATE DATABASE IF NOT EXISTS")
	}
}

func TestMariaDBMetadata(t *testing.T) {
	m := MariaDB{}
	if m.Name() != "mariadb" {
		t.Errorf("Name = %q", m.Name())
	}
	driver, host, port, socket := m.EnvConnection()
	if driver != "mysql" || host != "localhost" || port != "3306" || socket != "/run/mysqld/mysqld.sock" {
		t.Errorf("EnvConnection = %q/%q/%q/%q, want mysql/localhost/3306//run/mysqld/mysqld.sock", driver, host, port, socket)
	}
}

var errTransport = errString("ssh: broken")

type errString string

func (e errString) Error() string { return string(e) }

func TestMariaDBProbes(t *testing.T) {
	m := MariaDB{}
	dbCmd := `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='myapp'"`
	grantCmd := `mysql --protocol=socket -N -e "SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA='myapp' AND GRANTEE='''myapp''@''localhost''' LIMIT 1"`
	probes := []struct {
		name string
		cmd  string
		call func(r bssh.Runner) (bool, error)
	}{
		{"DatabaseExists", dbCmd, func(r bssh.Runner) (bool, error) {
			return m.DatabaseExists(context.Background(), r, "myapp")
		}},
		{"UserGranted", grantCmd, func(r bssh.Runner) (bool, error) {
			return m.UserGranted(context.Background(), r, "myapp", "myapp")
		}},
	}
	states := []struct {
		name   string
		result bssh.Result
		want   bool
	}{
		{"present", bssh.Result{Stdout: "1\n"}, true},
		{"absent", bssh.Result{Stdout: ""}, false},
		{"server unreachable", bssh.Result{ExitCode: 1, Stderr: "can't connect"}, false},
	}
	for _, p := range probes {
		for _, st := range states {
			t.Run(p.name+" "+st.name, func(t *testing.T) {
				f := bssh.NewFakeRunner()
				f.On(p.cmd, st.result)
				got, err := p.call(f)
				if err != nil || got != st.want {
					t.Fatalf("%s = %v, %v; want %v, nil", p.name, got, err, st.want)
				}
				if f.Calls()[0].Cmd != p.cmd {
					t.Fatalf("probe command = %q, want %q", f.Calls()[0].Cmd, p.cmd)
				}
			})
		}
		t.Run(p.name+" transport error", func(t *testing.T) {
			f := bssh.NewFakeRunner()
			f.OnError(p.cmd, errTransport)
			if _, err := p.call(f); err == nil {
				t.Fatal("transport error must propagate")
			}
		})
	}
}

func TestMariaDBClientAuthFile(t *testing.T) {
	if got := (MariaDB{}).ClientAuthFileName(); got != ".my.cnf" {
		t.Errorf("ClientAuthFileName = %q, want .my.cnf", got)
	}
	got := string(MariaDB{}.ClientAuthFile("app_db", "app_user", "s3cretPW"))
	want := "[client]\nuser = app_user\npassword = s3cretPW\n\n[mysql]\ndatabase = app_db\n"
	if got != want {
		t.Errorf("ClientAuthFile:\n%q\nwant:\n%q", got, want)
	}
}

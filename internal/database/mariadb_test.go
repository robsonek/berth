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

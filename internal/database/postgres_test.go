package database

import (
	"context"
	"strings"
	"testing"

	bssh "github.com/robsonek/berth/internal/ssh"
)

const psqlCmd = "sudo -u postgres psql -v ON_ERROR_STOP=1"

func TestPostgresEnsureUserUsesStdinNotArgv(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(psqlCmd, bssh.Result{})
	if err := (Postgres{}).EnsureUser(context.Background(), f, "myapp", "s3cr3t", "myapp"); err != nil {
		t.Fatalf("EnsureUser() error = %v", err)
	}
	call := f.Calls()[0]
	if strings.Contains(call.Cmd, "s3cr3t") {
		t.Error("password must not appear in the command string")
	}
	stdin := string(call.Stdin)
	if !strings.Contains(stdin, "CREATE ROLE") || !strings.Contains(stdin, "s3cr3t") {
		t.Error("role SQL with the password must be passed via stdin")
	}
	if !strings.Contains(stdin, "ALTER ROLE") {
		t.Error("EnsureUser must be idempotent (ALTER ROLE to re-sync the password)")
	}
	if !strings.Contains(stdin, `ALTER DATABASE "myapp" OWNER TO "myapp"`) {
		t.Error("EnsureUser must make the role own the database (full rights incl. public schema)")
	}
}

func TestPostgresEnsureDatabaseIdempotent(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(psqlCmd, bssh.Result{})
	if err := (Postgres{}).EnsureDatabase(context.Background(), f, "myapp"); err != nil {
		t.Fatal(err)
	}
	stdin := string(f.Calls()[0].Stdin)
	// CREATE DATABASE cannot run in a transaction; the guard runs it via \gexec
	// only when the database is absent.
	if !strings.Contains(stdin, `CREATE DATABASE "myapp"`) || !strings.Contains(stdin, "NOT EXISTS") || !strings.Contains(stdin, `\gexec`) {
		t.Errorf("expected a guarded CREATE DATABASE via \\gexec; got:\n%s", stdin)
	}
}

func TestPostgresMetadata(t *testing.T) {
	p := Postgres{}
	if p.Name() != "postgres" {
		t.Errorf("Name = %q", p.Name())
	}
	if p.ServerPackage() != "postgresql" {
		t.Errorf("ServerPackage = %q", p.ServerPackage())
	}
	driver, port := p.EnvConnection()
	if driver != "pgsql" || port != "5432" {
		t.Errorf("EnvConnection = %q/%q, want pgsql/5432", driver, port)
	}
	repo, ok := p.UpstreamRepo()
	if !ok || repo.Name != "pgdg" {
		t.Errorf("UpstreamRepo = %+v, %v; want the pgdg repo", repo, ok)
	}
	// Registered under its name.
	if got, err := Get("postgres"); err != nil || got.Name() != "postgres" {
		t.Errorf("Get(postgres) = %v, %v", got, err)
	}
}

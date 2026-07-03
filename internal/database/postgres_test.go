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

func TestPostgresEnsureUserRevokesPublicConnect(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(psqlCmd, bssh.Result{})
	// Distinct user vs database names to catch %[1]s/%[2]s mix-ups.
	if err := (Postgres{}).EnsureUser(context.Background(), f, "appuser", "s3cr3t", "appdb"); err != nil {
		t.Fatalf("EnsureUser() error = %v", err)
	}
	stdin := string(f.Calls()[0].Stdin)
	// CONNECT and TEMPORARY are PUBLIC's two default database-level privileges;
	// revoking both keeps other tenants' roles out of this tenant's database.
	if !strings.Contains(stdin, `REVOKE CONNECT, TEMPORARY ON DATABASE "appdb" FROM PUBLIC;`) {
		t.Errorf("EnsureUser must revoke PUBLIC's CONNECT/TEMPORARY on the tenant database; got:\n%s", stdin)
	}
	// UserGranted proves the whole batch ran by probing ownership, which is only
	// sound while ALTER DATABASE ... OWNER TO stays the LAST statement.
	lines := strings.Split(strings.TrimRight(stdin, "\n"), "\n")
	if last := lines[len(lines)-1]; last != `ALTER DATABASE "appdb" OWNER TO "appuser";` {
		t.Errorf("ALTER DATABASE ... OWNER TO must remain the last statement (UserGranted probe invariant); got %q", last)
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
	driver, host, port, socket := p.EnvConnection()
	if driver != "pgsql" || host != "127.0.0.1" || port != "5432" || socket != "" {
		t.Errorf("EnvConnection = %q/%q/%q/%q, want pgsql/127.0.0.1/5432/\"\"", driver, host, port, socket)
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

func TestPostgresProbes(t *testing.T) {
	p := Postgres{}
	dbCmd := `sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='myapp'"`
	ownerCmd := `sudo -u postgres psql -tAc "SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba WHERE d.datname='myapp' AND r.rolname='myapp'"`
	probes := []struct {
		name string
		cmd  string
		call func(r bssh.Runner) (bool, error)
	}{
		{"DatabaseExists", dbCmd, func(r bssh.Runner) (bool, error) {
			return p.DatabaseExists(context.Background(), r, "myapp")
		}},
		{"UserGranted", ownerCmd, func(r bssh.Runner) (bool, error) {
			return p.UserGranted(context.Background(), r, "myapp", "myapp")
		}},
	}
	states := []struct {
		name   string
		result bssh.Result
		want   bool
	}{
		{"present", bssh.Result{Stdout: "1\n"}, true},
		{"absent", bssh.Result{Stdout: "\n"}, false},
		{"server unreachable", bssh.Result{ExitCode: 2, Stderr: "psql: could not connect"}, false},
	}
	for _, pr := range probes {
		for _, st := range states {
			t.Run(pr.name+" "+st.name, func(t *testing.T) {
				f := bssh.NewFakeRunner()
				f.On(pr.cmd, st.result)
				got, err := pr.call(f)
				if err != nil || got != st.want {
					t.Fatalf("%s = %v, %v; want %v, nil", pr.name, got, err, st.want)
				}
				if f.Calls()[0].Cmd != pr.cmd {
					t.Fatalf("probe command = %q, want %q", f.Calls()[0].Cmd, pr.cmd)
				}
			})
		}
		t.Run(pr.name+" transport error", func(t *testing.T) {
			f := bssh.NewFakeRunner()
			f.OnError(pr.cmd, errTransport)
			if _, err := pr.call(f); err == nil {
				t.Fatal("transport error must propagate")
			}
		})
	}
}

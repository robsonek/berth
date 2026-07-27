package steps

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// seedCache seeds a v1 envelope bound to the server's endpoint — the only
// on-disk format production code reads.
func seedCache(t *testing.T, s *config.Server, secrets map[string]string) {
	t.Helper()
	if err := secret.SaveEnvelope(s.CacheKey(), secret.Envelope{
		Endpoint: &secret.Endpoint{Host: s.Host, Port: s.SSH.Port},
		Secrets:  secrets,
	}); err != nil {
		t.Fatal(err)
	}
}

// These pin the verified-cache wiring in the SECRET CONSUMERS (spec §6:
// "accounts/database: wywołania po CacheKey; VerifyEnvelope przed użyciem
// sekretów"): a regression back to host-keyed, unverified reads would pass
// the rest of the suite, because test seeds use the host key and an empty ID
// makes CacheKey()==Host.

func TestDatabaseCheckReadsCacheByIDAndVerifiesEndpoint(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	s.ID = "prod-db-1a2b"

	// A mismatched envelope under the ID key must refuse BEFORE any secret
	// is consumed — and reaching this error at all proves the step reads the
	// ID-keyed file, not the host-keyed one.
	if err := secret.SaveEnvelope(s.ID, secret.Envelope{
		Endpoint: &secret.Endpoint{Host: s.Host, Port: 2222},
		Secrets:  map[string]string{s.SiteDBUser(s.Sites[0]): "pw123"},
	}); err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On("dpkg -s mariadb-server", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"})
	f.On("test -e "+shQuote(s.Sites[0].DeployPath+"/shared/.env"), bssh.Result{ExitCode: 0})
	f.On("grep -m1 '^DB_CONNECTION=' "+shQuote(s.Sites[0].DeployPath+"/shared/.env"), bssh.Result{ExitCode: 0, Stdout: "DB_CONNECTION=mysql\n"})
	_, err := Database(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "2222") {
		t.Fatalf("Check must refuse a mismatched envelope naming the bound endpoint; got %v", err)
	}

	// Same refusal in Apply, before any package/repo mutation reaches the
	// cache window (the load is verified wherever it happens).
	if err := Database(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err == nil {
		t.Fatal("Apply must refuse a mismatched envelope")
	}
}

func TestConsolePasswordOwnedRefusesTombstone(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t) // no ID -> CacheKey()==Host
	if err := secret.SaveEnvelope(s.Host, secret.Envelope{
		Endpoint:   &secret.Endpoint{Host: s.Host, Port: 22},
		MigratedTo: "prod-x",
		Secrets:    map[string]string{},
	}); err != nil {
		t.Fatal(err)
	}
	// accounts' ownership probe goes through the verified loader: a tombstone
	// must be a loud error, never "not berth's password" (which would leave a
	// usable root-equivalent password enabled with break_glass:false).
	_, err := consolePasswordOwned(s)
	if err == nil || !strings.Contains(err.Error(), "prod-x") {
		t.Fatalf("tombstone must refuse naming the id; got %v", err)
	}
}

func TestSaveSecretsWritesEnvelopeUnderID(t *testing.T) {
	chdirTemp(t)
	s := databaseServer()
	s.ID = "prod-db-1a2b"
	if err := saveSecrets(s, map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	if _, err := os.Stat(filepath.Join(home, ".berth", "prod-db-1a2b.secrets.json")); err != nil {
		t.Fatalf("secrets must land under the ID key: %v", err)
	}
	env, legacy, err := secret.LoadEnvelope("prod-db-1a2b")
	if err != nil || legacy || env.Version != 1 || env.Endpoint.Host != s.Host || env.Endpoint.Port != 22 || env.Secrets["k"] != "v" {
		t.Fatalf("saved envelope wrong: %+v legacy=%v err=%v", env, legacy, err)
	}
}

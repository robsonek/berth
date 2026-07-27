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

// identityHome points the secret cache at a throwaway HOME and returns the
// .berth dir. The identity step operates purely on local state; the Runner is
// never used (FakeRunner with zero stubs proves it — any Run call would fail).
func identityHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return filepath.Join(home, ".berth")
}

func identityServer(id string) *config.Server {
	return &config.Server{ID: id, Host: "h.example.com", SSH: config.SSH{Port: 22}}
}

func writeCacheFile(t *testing.T, dir, key, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, key+".secrets.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityIsFirstAndAlwaysRun(t *testing.T) {
	steps := Pipeline(&config.Server{}, nil, true)
	if steps[0].Name() != "identity" {
		t.Fatalf("identity must be the FIRST step (before preflight's apt update); got %s", steps[0].Name())
	}
	ar, ok := steps[0].(provision.AlwaysRun)
	if !ok || !ar.AlwaysRun() {
		t.Fatal("identity must be always-selected (AlwaysRun) so it also runs under --only")
	}
}

func TestIdentityFreshWithIDBindsAndTombstones(t *testing.T) {
	berth := identityHome(t)
	s := identityServer("prod-1a2b")
	f := bssh.NewFakeRunner()

	cr, err := Identity().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil || cr.Satisfied {
		t.Fatalf("fresh Check = %+v err=%v, want unsatisfied", cr, err)
	}
	// Check is side-effect-free: no cache dir contents yet.
	if entries, _ := os.ReadDir(berth); len(entries) != 0 {
		t.Fatalf("Check must not create files; found %v", entries)
	}
	if err := Identity().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	env, err := secret.LoadEnvelope("prod-1a2b")
	if err != nil || env == nil || env.Endpoint.Host != "h.example.com" || env.Endpoint.Port != 22 {
		t.Fatalf("bound envelope wrong: %+v err=%v", env, err)
	}
	tomb, err := secret.LoadEnvelope("h.example.com")
	if err != nil || tomb == nil || tomb.MigratedTo != "prod-1a2b" {
		t.Fatalf("advisory tombstone missing: %+v err=%v", tomb, err)
	}
	cr, err = Identity().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil || !cr.Satisfied {
		t.Fatalf("post-Apply Check = %+v err=%v, want satisfied", cr, err)
	}
	if len(f.Calls()) != 0 {
		t.Errorf("identity must never touch the remote host; ran %v", f.Calls())
	}
}

func TestIdentityFreshWithoutIDBindsHostKey(t *testing.T) {
	identityHome(t)
	s := identityServer("")
	f := bssh.NewFakeRunner()
	if err := Identity().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	env, err := secret.LoadEnvelope("h.example.com")
	if err != nil || env == nil || env.MigratedTo != "" {
		t.Fatalf("host-keyed envelope wrong: %+v err=%v", env, err)
	}
	cr, err := Identity().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil || !cr.Satisfied {
		t.Fatalf("Check = %+v err=%v, want satisfied", cr, err)
	}
}

func TestIdentityMigratesHostKeyedCacheWithoutRotation(t *testing.T) {
	identityHome(t)
	if err := secret.SaveEnvelope("h.example.com", secret.Envelope{
		Endpoint: &secret.Endpoint{Host: "h.example.com", Port: 22},
		Secrets:  map[string]string{"console:berth": "unchanged-pw", "appdb": "dbpw"},
	}); err != nil {
		t.Fatal(err)
	}
	s := identityServer("prod-1a2b")
	f := bssh.NewFakeRunner()

	cr, err := Identity().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil || cr.Satisfied || !strings.Contains(cr.Reason, "migration") {
		t.Fatalf("Check = %+v err=%v, want unsatisfied migration", cr, err)
	}
	if err := Identity().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	env, err := secret.LoadEnvelope("prod-1a2b")
	if err != nil || env.Secrets["console:berth"] != "unchanged-pw" || env.Secrets["appdb"] != "dbpw" {
		t.Fatalf("migration must preserve every secret verbatim: %+v err=%v", env, err)
	}
	tomb, _ := secret.LoadEnvelope("h.example.com")
	if tomb == nil || tomb.MigratedTo != "prod-1a2b" || len(tomb.Secrets) != 0 {
		t.Fatalf("tombstone wrong: %+v", tomb)
	}
}

func TestIdentityEndpointMismatch(t *testing.T) {
	berth := identityHome(t)
	writeCacheFile(t, berth, "prod-1a2b",
		`{"version":1,"endpoint":{"host":"h.example.com","port":2222},"secrets":{"a":"1"}}`)
	s := identityServer("prod-1a2b")
	f := bssh.NewFakeRunner()

	// Without --force: hard error naming both endpoints.
	_, err := Identity().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "2222") || !strings.Contains(err.Error(), ":22") {
		t.Fatalf("mismatch must hard-error naming both endpoints; got %v", err)
	}
	// With --force: unsatisfied (visible work), Apply rewrites the endpoint
	// even though no secret changed.
	cr, err := Identity().Check(context.Background(), provision.RunCtx{Force: true}, s, f)
	if err != nil || cr.Satisfied || !strings.Contains(cr.Reason, "re-bind") {
		t.Fatalf("forced Check = %+v err=%v, want unsatisfied re-bind", cr, err)
	}
	if err := Identity().Apply(context.Background(), provision.RunCtx{Force: true}, s, f); err != nil {
		t.Fatal(err)
	}
	env, err := secret.LoadEnvelope("prod-1a2b")
	if err != nil || env.Endpoint.Port != 22 || env.Secrets["a"] != "1" {
		t.Fatalf("re-bind must rewrite the endpoint and keep secrets: %+v err=%v", env, err)
	}
	// Follow-up run without force: satisfied.
	if cr, err := Identity().Check(context.Background(), provision.RunCtx{}, s, f); err != nil || !cr.Satisfied {
		t.Fatalf("post-rebind Check = %+v err=%v", cr, err)
	}
}

func TestIdentityTombstoneWithoutIDIsHardError(t *testing.T) {
	berth := identityHome(t)
	writeCacheFile(t, berth, "h.example.com",
		`{"version":1,"endpoint":{"host":"h.example.com","port":22},"migratedTo":"prod-1a2b","secrets":{}}`)
	s := identityServer("")
	f := bssh.NewFakeRunner()
	_, err := Identity().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "prod-1a2b") {
		t.Fatalf("tombstone without id must hard-error with the id; got %v", err)
	}
	if err := Identity().Apply(context.Background(), provision.RunCtx{}, s, f); err == nil {
		t.Fatal("Apply must refuse a tombstoned key too")
	}
}

func TestIdentityBothRealCachesIsHardError(t *testing.T) {
	berth := identityHome(t)
	writeCacheFile(t, berth, "h.example.com",
		`{"version":1,"endpoint":{"host":"h.example.com","port":22},"secrets":{"a":"1"}}`)
	writeCacheFile(t, berth, "prod-1a2b",
		`{"version":1,"endpoint":{"host":"h.example.com","port":22},"secrets":{"a":"2"}}`)
	s := identityServer("prod-1a2b")
	f := bssh.NewFakeRunner()
	_, err := Identity().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("two real caches must hard-error; got %v", err)
	}
}

func TestIdentityNewerCacheVersionIsHardError(t *testing.T) {
	berth := identityHome(t)
	writeCacheFile(t, berth, "h.example.com",
		`{"version":2,"endpoint":{"host":"h.example.com","port":22},"secrets":{}}`)
	s := identityServer("")
	f := bssh.NewFakeRunner()
	_, err := Identity().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("v2 cache must hard-error as newer-berth; got %v", err)
	}
}

func TestIdentityRefusesMigrationOfForeignEndpointHostCache(t *testing.T) {
	// Machine B's v1 cache (same hostname, different port) must not be
	// adopted under machine A's id — Check refuses before Apply could rename,
	// naming the bound endpoint so the operator gives B its own id.
	berth := identityHome(t)
	writeCacheFile(t, berth, "h.example.com",
		`{"version":1,"endpoint":{"host":"h.example.com","port":2222},"secrets":{"b":"1"}}`)
	s := identityServer("prod-1a2b")
	f := bssh.NewFakeRunner()
	_, err := Identity().Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "2222") || !strings.Contains(err.Error(), "different machine") {
		t.Fatalf("Check must refuse adopting a foreign-endpoint host cache; got %v", err)
	}
	if err := Identity().Apply(context.Background(), provision.RunCtx{}, s, f); err == nil {
		t.Fatal("Apply (MigrateCache) must refuse too")
	}
	if env, err := secret.LoadEnvelope("h.example.com"); err != nil || env == nil || env.Secrets["b"] != "1" {
		t.Fatalf("the foreign cache must stay untouched: %+v err=%v", env, err)
	}
}

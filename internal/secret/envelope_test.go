package secret

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeRawCache(t *testing.T, berthDir, key, content string) string {
	t.Helper()
	if err := os.MkdirAll(berthDir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(berthDir, key+".secrets.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnvelopeRoundTrip(t *testing.T) {
	cacheHome(t)
	in := Envelope{Endpoint: &Endpoint{Host: "h.example.com", Port: 22},
		Secrets: map[string]string{"console:berth": "pw"}}
	if err := SaveEnvelope("id-1", in); err != nil {
		t.Fatal(err)
	}
	env, legacy, err := LoadEnvelope("id-1")
	if err != nil || legacy || env == nil {
		t.Fatalf("LoadEnvelope = %v legacy=%v err=%v", env, legacy, err)
	}
	if env.Version != 1 || env.Endpoint == nil || env.Endpoint.Host != "h.example.com" ||
		env.Endpoint.Port != 22 || env.Secrets["console:berth"] != "pw" {
		t.Errorf("round-trip mismatch: %+v", env)
	}
}

func TestLoadEnvelopeAbsentIsNilNotError(t *testing.T) {
	cacheHome(t)
	env, legacy, err := LoadEnvelope("never")
	if env != nil || legacy || err != nil {
		t.Fatalf("absent cache must be (nil,false,nil); got %v %v %v", env, legacy, err)
	}
}

func TestLoadEnvelopeLegacyFlatMap(t *testing.T) {
	// A pre-P14 flat map — including one with a LEGAL secret literally named
	// "version" (reSQLIdent accepts a DB user "version", and DB users are
	// direct cache keys): a string-valued version must read as legacy.
	berth := cacheHome(t)
	writeRawCache(t, berth, "h", `{"version":"s3cret-pw","console:berth":"c"}`)
	env, legacy, err := LoadEnvelope("h")
	if err != nil || !legacy || env == nil {
		t.Fatalf("legacy flat map must load: %v legacy=%v err=%v", env, legacy, err)
	}
	if env.Secrets["version"] != "s3cret-pw" || env.Secrets["console:berth"] != "c" {
		t.Errorf("legacy secrets lost: %+v", env.Secrets)
	}
}

func TestLoadEnvelopeVersionValidation(t *testing.T) {
	berth := cacheHome(t)
	cases := []struct{ name, body, wantErr string }{
		{"v0", `{"version":0,"endpoint":{"host":"h","port":22},"secrets":{}}`, "version"},
		{"negative", `{"version":-1,"endpoint":{"host":"h","port":22},"secrets":{}}`, "version"},
		{"v2-newer", `{"version":2,"endpoint":{"host":"h","port":22},"secrets":{}}`, "newer"},
		{"no-endpoint", `{"version":1,"secrets":{}}`, "endpoint"},
		{"bad-port-0", `{"version":1,"endpoint":{"host":"h","port":0},"secrets":{}}`, "endpoint"},
		{"bad-port-high", `{"version":1,"endpoint":{"host":"h","port":70000},"secrets":{}}`, "endpoint"},
		{"truncated", `{"version":1,"endpoint":{"host":`, "parse"},
	}
	for _, c := range cases {
		writeRawCache(t, berth, c.name, c.body)
		_, _, err := LoadEnvelope(c.name)
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: err = %v, want mention of %q", c.name, err, c.wantErr)
		}
	}
}

func TestLoadEnvelopeNullSecretsIsEmptyMap(t *testing.T) {
	berth := cacheHome(t)
	writeRawCache(t, berth, "h", `{"version":1,"endpoint":{"host":"h","port":22},"secrets":null}`)
	env, _, err := LoadEnvelope("h")
	if err != nil || env == nil || env.Secrets == nil {
		t.Fatalf("null secrets must normalize to an empty map: %+v err=%v", env, err)
	}
}

func TestSaveEnvelopeRejectsInvalid(t *testing.T) {
	cacheHome(t)
	if err := SaveEnvelope("k", Envelope{Secrets: map[string]string{}}); err == nil {
		t.Error("SaveEnvelope must refuse a missing endpoint")
	}
	if err := SaveEnvelope("k", Envelope{Endpoint: &Endpoint{Host: "h", Port: 0}, Secrets: map[string]string{}}); err == nil {
		t.Error("SaveEnvelope must refuse an invalid port")
	}
}

func TestVerifyEnvelope(t *testing.T) {
	ep := &Endpoint{Host: "h.example.com", Port: 22}
	env := &Envelope{Version: 1, Endpoint: ep, Secrets: map[string]string{}}
	if err := VerifyEnvelope(env, false, "h.example.com", 22); err != nil {
		t.Errorf("matching endpoint must verify: %v", err)
	}
	if err := VerifyEnvelope(env, false, "other.example.com", 22); err == nil ||
		!strings.Contains(err.Error(), "h.example.com") || !strings.Contains(err.Error(), "other.example.com") {
		t.Errorf("host mismatch must error naming BOTH endpoints; got %v", err)
	}
	if err := VerifyEnvelope(env, false, "h.example.com", 2222); err == nil {
		t.Error("port mismatch must error")
	}
	// Legacy (pre-envelope) has no endpoint to verify — identity upgrades it.
	if err := VerifyEnvelope(&Envelope{Secrets: map[string]string{}}, true, "h.example.com", 22); err != nil {
		t.Errorf("legacy must verify as nil: %v", err)
	}
	// A tombstone must never be used as a secrets source.
	tomb := &Envelope{Version: 1, Endpoint: ep, MigratedTo: "id-1", Secrets: map[string]string{}}
	if err := VerifyEnvelope(tomb, false, "h.example.com", 22); err == nil ||
		!strings.Contains(err.Error(), "id-1") {
		t.Errorf("tombstone must error naming the new id; got %v", err)
	}
	if err := VerifyEnvelope(nil, false, "h.example.com", 22); err != nil {
		t.Errorf("absent cache verifies as nil (identity binds it): %v", err)
	}
}

func TestUpgradePreservesSecretsAndModes(t *testing.T) {
	berth := cacheHome(t)
	writeRawCache(t, berth, "h", `{"a":"1","b":"2"}`)
	env, legacy, err := LoadEnvelope("h")
	if err != nil || !legacy {
		t.Fatal(err)
	}
	env.Endpoint = &Endpoint{Host: "h", Port: 22}
	if err := SaveEnvelope("h", *env); err != nil {
		t.Fatal(err)
	}
	got, legacy2, err := LoadEnvelope("h")
	if err != nil || legacy2 || got.Secrets["a"] != "1" || got.Secrets["b"] != "2" {
		t.Fatalf("upgrade lost secrets: %+v legacy=%v err=%v", got, legacy2, err)
	}
	fi, err := os.Stat(filepath.Join(berth, "h.secrets.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", fi.Mode())
	}
	di, err := os.Stat(berth)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", di.Mode())
	}
}

func TestMigrateCache(t *testing.T) {
	t.Run("renames legacy and leaves tombstone", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "host.example.com", `{"console:berth":"pw"}`)
		if err := MigrateCache("id-1", "host.example.com", 22); err != nil {
			t.Fatal(err)
		}
		env, legacy, err := LoadEnvelope("id-1")
		if err != nil || legacy || env.Secrets["console:berth"] != "pw" ||
			env.Endpoint == nil || env.Endpoint.Host != "host.example.com" || env.Endpoint.Port != 22 {
			t.Fatalf("migrated cache wrong: %+v legacy=%v err=%v", env, legacy, err)
		}
		tomb, legacy, err := LoadEnvelope("host.example.com")
		if err != nil || legacy || tomb == nil || tomb.MigratedTo != "id-1" || len(tomb.Secrets) != 0 {
			t.Fatalf("tombstone wrong: %+v legacy=%v err=%v", tomb, legacy, err)
		}
	})
	t.Run("id equal to host is a no-op", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "h", `{"a":"1"}`)
		if err := MigrateCache("h", "h", 22); err != nil {
			t.Fatal(err)
		}
		env, legacy, err := LoadEnvelope("h")
		if err != nil || !legacy || env.Secrets["a"] != "1" {
			t.Fatalf("ID==Host must not touch the file: %+v legacy=%v err=%v", env, legacy, err)
		}
	})
	t.Run("both real caches is a hard error", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "host.example.com", `{"a":"1"}`)
		writeRawCache(t, berth, "id-1", `{"version":1,"endpoint":{"host":"host.example.com","port":22},"secrets":{"a":"2"}}`)
		err := MigrateCache("id-1", "host.example.com", 22)
		if err == nil || !strings.Contains(err.Error(), "both") {
			t.Fatalf("two real caches must be an ambiguity error; got %v", err)
		}
	})
	t.Run("target present source absent is a no-op", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "id-1", `{"version":1,"endpoint":{"host":"host.example.com","port":22},"secrets":{}}`)
		if err := MigrateCache("id-1", "host.example.com", 22); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("source tombstone is a no-op", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "id-1", `{"version":1,"endpoint":{"host":"host.example.com","port":22},"secrets":{}}`)
		writeRawCache(t, berth, "host.example.com", `{"version":1,"endpoint":{"host":"host.example.com","port":22},"migratedTo":"id-1","secrets":{}}`)
		if err := MigrateCache("id-1", "host.example.com", 22); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("malformed source stays loud", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "host.example.com", `{{{`)
		if err := MigrateCache("id-1", "host.example.com", 22); err == nil {
			t.Fatal("malformed source must fail loudly")
		}
	})
}

func TestMigrateCacheHoldsBothLocks(t *testing.T) {
	// A concurrent writer that has taken the HOST lock must not be able to
	// interleave with a migration: the migration takes both locks, so it
	// cannot start until the host-lock holder releases.
	berth := cacheHome(t)
	writeRawCache(t, berth, "host.example.com", `{"a":"1"}`)
	release, err := LockCache("host.example.com")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	var once sync.Once
	go func() {
		once.Do(func() { close(started) })
		done <- MigrateCache("id-1", "host.example.com", 22)
	}()
	<-started
	// The migration must be blocked on the host lock we hold. There is no
	// portable non-blocking probe, so assert indirectly: the source file must
	// still be intact while we hold the lock.
	if _, err := os.Stat(filepath.Join(berth, "host.example.com.secrets.json")); err != nil {
		t.Fatal("source must not move while the host lock is held")
	}
	b, _ := os.ReadFile(filepath.Join(berth, "host.example.com.secrets.json"))
	var m map[string]string
	if json.Unmarshal(b, &m) != nil || m["a"] != "1" {
		t.Fatalf("source mutated under a held host lock: %s", b)
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("migration after release failed: %v", err)
	}
	if env, legacy, err := LoadEnvelope("id-1"); err != nil || legacy || env.Secrets["a"] != "1" {
		t.Fatalf("post-release migration wrong: %+v legacy=%v err=%v", env, legacy, err)
	}

	// Divergence must be LOUD, never silent (deterministic leg): a stale
	// host-keyed writer that resumes AFTER the migration recreates a real
	// host file over the tombstone — the next migration attempt must refuse
	// with the both-files ambiguity instead of guessing.
	if err := SaveCache("host.example.com", map[string]string{"a": "9"}); err != nil {
		t.Fatal(err)
	}
	err = MigrateCache("id-1", "host.example.com", 22)
	if err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("recreated host cache next to the id cache must be an ambiguity error; got %v", err)
	}
	// And the id-keyed truth is untouched by the refusal.
	if env, _, err := LoadEnvelope("id-1"); err != nil || env.Secrets["a"] != "1" {
		t.Fatalf("refusal must not touch the migrated cache: %+v err=%v", env, err)
	}
}

func TestMigrateCacheRefusesForeignEndpointSource(t *testing.T) {
	// A v1 host-keyed cache bound to a DIFFERENT endpoint belongs to another
	// machine behind the same hostname: adopting it under this id would merge
	// a stranger's secrets. Refused BEFORE the rename.
	berth := cacheHome(t)
	writeRawCache(t, berth, "host.example.com",
		`{"version":1,"endpoint":{"host":"host.example.com","port":2222},"secrets":{"a":"1"}}`)
	err := MigrateCache("id-1", "host.example.com", 22)
	if err == nil || !strings.Contains(err.Error(), "2222") || !strings.Contains(err.Error(), "different machine") {
		t.Fatalf("foreign-endpoint source must refuse naming the bound endpoint; got %v", err)
	}
	// The source file must still be exactly where it was (no rename happened).
	if env, _, err := LoadEnvelope("host.example.com"); err != nil || env == nil || env.Secrets["a"] != "1" || env.MigratedTo != "" {
		t.Fatalf("refusal must leave the source untouched: %+v err=%v", env, err)
	}
	if env, _, err := LoadEnvelope("id-1"); err != nil || env != nil {
		t.Fatalf("no id-keyed file may appear on refusal: %+v err=%v", env, err)
	}
}

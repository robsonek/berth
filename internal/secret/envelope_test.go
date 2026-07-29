package secret

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func writeRawCache(t *testing.T, berthDir, key, content string) {
	t.Helper()
	if err := os.MkdirAll(berthDir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(berthDir, key+".secrets.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	cacheHome(t)
	in := Envelope{Endpoint: &Endpoint{Host: "h.example.com", Port: 22},
		Secrets: map[string]string{"console:berth": "pw"}}
	if err := SaveEnvelope("id-1", in); err != nil {
		t.Fatal(err)
	}
	env, err := LoadEnvelope("id-1")
	if err != nil || env == nil {
		t.Fatalf("LoadEnvelope = %v err=%v", env, err)
	}
	if env.Version != 1 || env.Endpoint == nil || env.Endpoint.Host != "h.example.com" ||
		env.Endpoint.Port != 22 || env.Secrets["console:berth"] != "pw" {
		t.Errorf("round-trip mismatch: %+v", env)
	}
}

func TestLoadEnvelopeAbsentIsNilNotError(t *testing.T) {
	cacheHome(t)
	env, err := LoadEnvelope("never")
	if env != nil || err != nil {
		t.Fatalf("absent cache must be (nil,nil); got %v %v", env, err)
	}
}

func TestLoadEnvelopeRejectsPreEnvelopeFlatMap(t *testing.T) {
	berth := cacheHome(t)
	cases := []struct{ name, body string }{
		// The common flat shape: no "version" member at all.
		{"no-version-key", `{"appuser": "pw1"}`},
		// A flat cache holding a secret literally named "version" (a legal
		// SQL identifier): the probe sees a string, not the envelope number.
		{"string-version-secret", `{"version":"s3cret-pw","console:berth":"c"}`},
	}
	for _, c := range cases {
		writeRawCache(t, berth, c.name, c.body)
		_, err := LoadEnvelope(c.name)
		if err == nil {
			t.Errorf("%s: a flat pre-envelope cache must be rejected with advice, got nil", c.name)
			continue
		}
		// The advice must be safe for a cache that held the break-glass
		// ownership marker: name the manual lock and the marker entry.
		for _, want := range []string{"pre-release", "passwd -l berth", "console:berth"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: err = %v, want mention of %q", c.name, err, want)
			}
		}
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
		_, err := LoadEnvelope(c.name)
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: err = %v, want mention of %q", c.name, err, c.wantErr)
		}
	}
}

func TestLoadEnvelopeNullSecretsIsEmptyMap(t *testing.T) {
	berth := cacheHome(t)
	writeRawCache(t, berth, "h", `{"version":1,"endpoint":{"host":"h","port":22},"secrets":null}`)
	env, err := LoadEnvelope("h")
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
	if err := VerifyEnvelope(env, "h.example.com", 22); err != nil {
		t.Errorf("matching endpoint must verify: %v", err)
	}
	if err := VerifyEnvelope(env, "other.example.com", 22); err == nil ||
		!strings.Contains(err.Error(), "h.example.com") || !strings.Contains(err.Error(), "other.example.com") {
		t.Errorf("host mismatch must error naming BOTH endpoints; got %v", err)
	}
	if err := VerifyEnvelope(env, "h.example.com", 2222); err == nil {
		t.Error("port mismatch must error")
	}
	// A tombstone must never be used as a secrets source.
	tomb := &Envelope{Version: 1, Endpoint: ep, MigratedTo: "id-1", Secrets: map[string]string{}}
	if err := VerifyEnvelope(tomb, "h.example.com", 22); err == nil ||
		!strings.Contains(err.Error(), "id-1") {
		t.Errorf("tombstone must error naming the new id; got %v", err)
	}
	if err := VerifyEnvelope(nil, "h.example.com", 22); err != nil {
		t.Errorf("absent cache verifies as nil (identity binds it): %v", err)
	}
}

func TestMigrateCache(t *testing.T) {
	t.Run("renames host-keyed cache and leaves tombstone", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "host.example.com",
			`{"version":1,"endpoint":{"host":"host.example.com","port":22},"secrets":{"console:berth":"pw"}}`)
		if err := MigrateCache("id-1", "host.example.com", 22); err != nil {
			t.Fatal(err)
		}
		env, err := LoadEnvelope("id-1")
		if err != nil || env.Secrets["console:berth"] != "pw" ||
			env.Endpoint == nil || env.Endpoint.Host != "host.example.com" || env.Endpoint.Port != 22 {
			t.Fatalf("migrated cache wrong: %+v err=%v", env, err)
		}
		tomb, err := LoadEnvelope("host.example.com")
		if err != nil || tomb == nil || tomb.MigratedTo != "id-1" || len(tomb.Secrets) != 0 {
			t.Fatalf("tombstone wrong: %+v err=%v", tomb, err)
		}
	})
	t.Run("id equal to host is a no-op", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "h", `{"version":1,"endpoint":{"host":"h","port":22},"secrets":{"a":"1"}}`)
		if err := MigrateCache("h", "h", 22); err != nil {
			t.Fatal(err)
		}
		env, err := LoadEnvelope("h")
		if err != nil || env.Secrets["a"] != "1" || env.MigratedTo != "" {
			t.Fatalf("ID==Host must not touch the file: %+v err=%v", env, err)
		}
	})
	t.Run("both real caches is a hard error", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "host.example.com",
			`{"version":1,"endpoint":{"host":"host.example.com","port":22},"secrets":{"a":"1"}}`)
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
	// A tombstone pointing at the caller's OWN id with the id-keyed envelope
	// MISSING is a lost cache, not a fresh machine: the `!sourceIsReal`
	// shortcut used to return nil and the caller then bound an EMPTY envelope,
	// disowning every secret the lost cache held (console:berth included).
	t.Run("own tombstone with missing target is refused", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "host.example.com", `{"version":1,"endpoint":{"host":"host.example.com","port":22},"migratedTo":"id-1","secrets":{}}`)
		err := MigrateCache("id-1", "host.example.com", 22)
		if err == nil || !strings.Contains(err.Error(), "restore") || !strings.Contains(err.Error(), "passwd -l berth") {
			t.Fatalf("lost id-keyed cache must be refused with restore/settle advice; got %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(berth, "id-1.secrets.json")); !os.IsNotExist(statErr) {
			t.Fatal("the refusal must not create an envelope at the id")
		}
		tomb, terr := LoadEnvelope("host.example.com")
		if terr != nil || tomb == nil || tomb.MigratedTo != "id-1" {
			t.Fatalf("the tombstone must stay untouched: %+v err=%v", tomb, terr)
		}
	})
	// A tombstone pointing at a DIFFERENT id means the config's id was renamed:
	// proceeding would orphan the old id's cache. Both early-return shortcuts
	// (existing target, non-real source) used to swallow this — guard first.
	t.Run("foreign tombstone is refused with a fresh target", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "host.example.com", `{"version":1,"endpoint":{"host":"host.example.com","port":22},"migratedTo":"old-id","secrets":{}}`)
		err := MigrateCache("id-1", "host.example.com", 22)
		if err == nil || !strings.Contains(err.Error(), "old-id") || !strings.Contains(err.Error(), "id-1") {
			t.Fatalf("foreign tombstone must be refused naming both ids; got %v", err)
		}
	})
	t.Run("foreign tombstone is refused with an existing target", func(t *testing.T) {
		berth := cacheHome(t)
		writeRawCache(t, berth, "id-1", `{"version":1,"endpoint":{"host":"host.example.com","port":22},"secrets":{}}`)
		writeRawCache(t, berth, "host.example.com", `{"version":1,"endpoint":{"host":"host.example.com","port":22},"migratedTo":"old-id","secrets":{}}`)
		err := MigrateCache("id-1", "host.example.com", 22)
		if err == nil || !strings.Contains(err.Error(), "old-id") || !strings.Contains(err.Error(), "id-1") {
			t.Fatalf("foreign tombstone must be refused naming both ids; got %v", err)
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
	if runtime.GOOS == "windows" {
		t.Skip("flock is a no-op on Windows")
	}
	// A concurrent writer that has taken the HOST lock must not be able to
	// interleave with a migration: the migration takes both locks, so it
	// cannot start until the host-lock holder releases.
	berth := cacheHome(t)
	writeRawCache(t, berth, "host.example.com",
		`{"version":1,"endpoint":{"host":"host.example.com","port":22},"secrets":{"a":"1"}}`)
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
	var held Envelope
	if json.Unmarshal(b, &held) != nil || held.Secrets["a"] != "1" {
		t.Fatalf("source mutated under a held host lock: %s", b)
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("migration after release failed: %v", err)
	}
	if env, err := LoadEnvelope("id-1"); err != nil || env.Secrets["a"] != "1" {
		t.Fatalf("post-release migration wrong: %+v err=%v", env, err)
	}

	// Divergence must be LOUD, never silent (deterministic leg): a stale
	// host-keyed writer that resumes AFTER the migration recreates a real
	// host file over the tombstone — the next migration attempt must refuse
	// with the both-files ambiguity instead of guessing.
	if err := SaveEnvelope("host.example.com", Envelope{
		Endpoint: &Endpoint{Host: "host.example.com", Port: 22},
		Secrets:  map[string]string{"a": "9"},
	}); err != nil {
		t.Fatal(err)
	}
	err = MigrateCache("id-1", "host.example.com", 22)
	if err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("recreated host cache next to the id cache must be an ambiguity error; got %v", err)
	}
	// And the id-keyed truth is untouched by the refusal.
	if env, err := LoadEnvelope("id-1"); err != nil || env.Secrets["a"] != "1" {
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
	if env, err := LoadEnvelope("host.example.com"); err != nil || env == nil || env.Secrets["a"] != "1" || env.MigratedTo != "" {
		t.Fatalf("refusal must leave the source untouched: %+v err=%v", env, err)
	}
	if env, err := LoadEnvelope("id-1"); err != nil || env != nil {
		t.Fatalf("no id-keyed file may appear on refusal: %+v err=%v", env, err)
	}
}

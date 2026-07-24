package secret

import (
	"os"
	"strings"
	"testing"
)

func TestEnvFileDeterministicAndComplete(t *testing.T) {
	got := string(EnvFile(map[string]string{"DB_PASSWORD": "p", "APP_ENV": "production"}))
	if !strings.HasPrefix(got, "APP_ENV=production\n") { // sorted
		t.Errorf("env not sorted/deterministic: %q", got)
	}
	if !strings.Contains(got, "DB_PASSWORD=p\n") {
		t.Error("missing DB_PASSWORD line")
	}
}

func TestSaveAndLoadCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)
	if err := SaveCache("srv", map[string]string{"DB_PASSWORD": "x"}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCache("srv")
	if err != nil || got["DB_PASSWORD"] != "x" {
		t.Fatalf("round-trip failed: %v %v", got, err)
	}
	if fi, _ := os.Stat(".berth/srv.secrets.json"); fi.Mode().Perm() != 0o600 {
		t.Errorf("cache mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestLoadCacheMissingIsEmptyNotError(t *testing.T) {
	t.Chdir(t.TempDir())
	m, err := LoadCache("never-written.example.com")
	if err != nil {
		t.Fatalf("a never-written cache must not error: %v", err)
	}
	if m == nil || len(m) != 0 {
		t.Fatalf("want an empty, non-nil map; got %v", m)
	}
}

func TestLoadCacheMalformedIsError(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll(".berth", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".berth/h.secrets.json", []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCache("h"); err == nil {
		t.Fatal("a malformed cache must fail loud, not read as empty (a later save would clobber it)")
	}
}

func TestSaveCacheTightensPermissiveModes(t *testing.T) {
	t.Chdir(t.TempDir())
	// Pre-existing permissive dir + file: SaveCache must tighten both — the
	// cache can hold a root-equivalent console password.
	if err := os.MkdirAll(".berth", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".berth/h.secrets.json", []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveCache("h", map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(".berth")
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf(".berth mode = %v, want 0700", di.Mode().Perm())
	}
	fi, err := os.Stat(".berth/h.secrets.json")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("cache file mode = %v, want 0600", fi.Mode().Perm())
	}
	m, err := LoadCache("h")
	if err != nil || m["k"] != "v" {
		t.Fatalf("round-trip failed: %v %v", m, err)
	}
}

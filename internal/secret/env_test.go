package secret

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEnvFileDeterministicAndComplete(t *testing.T) {
	b, err := EnvFile(map[string]string{"DB_PASSWORD": "p", "APP_ENV": "production"})
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.HasPrefix(got, "APP_ENV=production\n") { // sorted
		t.Errorf("env not sorted/deterministic: %q", got)
	}
	if !strings.Contains(got, "DB_PASSWORD=p\n") {
		t.Error("missing DB_PASSWORD line")
	}
}

// cacheHome points the secret cache at a throwaway HOME (and USERPROFILE for
// Windows) and returns the expected .berth dir inside it.
func cacheHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return filepath.Join(home, ".berth")
}

func TestSaveAndLoadCacheRoundTrip(t *testing.T) {
	berth := cacheHome(t)
	if err := SaveEnvelope("srv", Envelope{
		Endpoint: &Endpoint{Host: "srv", Port: 22},
		Secrets:  map[string]string{"DB_PASSWORD": "x"},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCache("srv")
	if err != nil || got["DB_PASSWORD"] != "x" {
		t.Fatalf("round-trip failed: %v %v", got, err)
	}
	if fi, _ := os.Stat(filepath.Join(berth, "srv.secrets.json")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("cache must be written under $HOME/.berth at mode 0600")
	}
}

func TestLoadCacheMissingIsEmptyNotError(t *testing.T) {
	cacheHome(t)
	m, err := LoadCache("never-written.example.com")
	if err != nil {
		t.Fatalf("a never-written cache must not error: %v", err)
	}
	if m == nil || len(m) != 0 {
		t.Fatalf("want an empty, non-nil map; got %v", m)
	}
}

func TestLoadCacheMalformedIsError(t *testing.T) {
	berth := cacheHome(t)
	if err := os.MkdirAll(berth, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(berth, "h.secrets.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCache("h"); err == nil {
		t.Fatal("a malformed cache must fail loud, not read as empty")
	}
}

func TestLoadCacheNullIsEmptyNotNil(t *testing.T) {
	berth := cacheHome(t)
	if err := os.MkdirAll(berth, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(berth, "h.secrets.json"), []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadCache("h")
	if err != nil {
		t.Fatalf("null cache must not error: %v", err)
	}
	if m == nil {
		t.Fatal("null cache must yield a non-nil map")
	}
	m["k"] = "v" // must not panic
}

func TestSaveCacheTightensPermissiveModes(t *testing.T) {
	berth := cacheHome(t)
	if err := os.MkdirAll(berth, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(berth, "h.secrets.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveEnvelope("h", Envelope{
		Endpoint: &Endpoint{Host: "h", Port: 22},
		Secrets:  map[string]string{"k": "v"},
	}); err != nil {
		t.Fatal(err)
	}
	if di, _ := os.Stat(berth); di == nil || di.Mode().Perm() != 0o700 {
		t.Errorf(".berth mode must be tightened to 0700")
	}
	if fi, _ := os.Stat(filepath.Join(berth, "h.secrets.json")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("cache file mode must be 0600")
	}
}

func TestLockCacheTightensDir(t *testing.T) {
	berth := cacheHome(t)
	if err := os.MkdirAll(berth, 0o755); err != nil { // pre-existing permissive dir
		t.Fatal(err)
	}
	release, err := LockCache("h")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if di, _ := os.Stat(berth); di == nil || di.Mode().Perm() != 0o700 {
		t.Errorf("LockCache must tighten the cache dir to 0700 (it guards a root-equivalent secret)")
	}
}

func TestLockCacheSerialises(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock is a no-op on Windows")
	}
	cacheHome(t)
	release, err := LockCache("h")
	if err != nil {
		t.Fatal(err)
	}
	// A second acquisition of the same host lock must BLOCK until release.
	got := make(chan struct{})
	go func() {
		r2, err := LockCache("h")
		if err == nil {
			r2()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("second LockCache returned while the first was held; the lock is a no-op")
	case <-time.After(150 * time.Millisecond):
		// still blocked, as required
	}
	release()
	select {
	case <-got:
		// proceeded after release, correct
	case <-time.After(2 * time.Second):
		t.Fatal("second LockCache never proceeded after release")
	}
}

func TestEnvFileValidation(t *testing.T) {
	ok, err := EnvFile(map[string]string{"DB_PASSWORD": "p", "_UNDER": "x"})
	if err != nil || !strings.Contains(string(ok), "DB_PASSWORD=p\n") {
		t.Fatalf("valid map must render: %q err=%v", ok, err)
	}
	bad := []map[string]string{
		{"": "v"},             // empty key
		{"1LEAD": "v"},        // leading digit
		{"A-B": "v"},          // hyphen
		{"A=B": "v"},          // equals in key
		{"A\nB": "v"},         // control char in key
		{"K": "line1\nline2"}, // LF in value
		{"K": "line1\rline2"}, // CR in value
		{"K": "nul\x00byte"},  // NUL in value
	}
	for _, m := range bad {
		if _, err := EnvFile(m); err == nil {
			t.Errorf("EnvFile(%q) must be rejected", m)
		} else if strings.Contains(err.Error(), "line1") || strings.Contains(err.Error(), "nul") {
			t.Errorf("error must not reproduce a secret value: %v", err)
		}
	}
}

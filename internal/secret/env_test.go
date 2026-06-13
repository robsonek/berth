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

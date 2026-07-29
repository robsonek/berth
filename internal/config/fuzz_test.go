package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzValidFingerprint asserts the fingerprint validator never panics on
// arbitrary input (it guards operator-typed config values).
func FuzzValidFingerprint(f *testing.F) {
	f.Add("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")
	f.Add("MD5:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99")
	f.Add("sha256:lowercase")
	f.Add("")
	f.Add("SHA256:")
	f.Fuzz(func(_ *testing.T, fp string) {
		_ = ValidFingerprint(fp) // errors are fine; panics are the bug
	})
}

// FuzzConfigLoad asserts the whole YAML->Server pipeline (viper unmarshal,
// defaults, validation) never panics on arbitrary config bytes.
func FuzzConfigLoad(f *testing.F) {
	// Deep seed: a config that PASSES validation, so the corpus mutates from
	// inside the full pipeline rather than dying on an early reject.
	seed, err := os.ReadFile("testdata/valid.yml")
	if err != nil {
		f.Fatalf("deep seed fixture missing: %v", err)
	}
	f.Add(seed)
	f.Add([]byte("{"))
	f.Add([]byte("id: [1,2,3]\n"))
	f.Add([]byte(""))
	f.Add([]byte("\xff\xfe"))
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "server.yml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = Load(path) // errors are fine; panics are the bug
	})
}

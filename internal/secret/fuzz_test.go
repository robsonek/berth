package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envKeyValid re-implements the dotenv key grammar ([A-Za-z_][A-Za-z0-9_]*)
// as a rune loop, independent of the reEnvKey regexp, so the accept/reject
// oracle in FuzzEnvFile is differential rather than a tautology. Invalid
// UTF-8 decodes to U+FFFD, which fails both implementations alike.
func envKeyValid(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		alpha := r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
		digit := r >= '0' && r <= '9'
		if !alpha && !digit {
			return false
		}
		if i == 0 && digit {
			return false
		}
	}
	return true
}

// FuzzEnvFile asserts the .env renderer never panics, and enforces its full
// documented contract: a pair is rejected iff the key falls outside the
// env-identifier grammar or the value contains CR/LF/NUL, and every accepted
// pair renders as exactly "key=value\n". EnvFile does no quoting, the key
// grammar excludes '=' and the accepted value excludes newlines, so
// exact-equality round-trip is well-defined (a bare "non-empty output" check
// would bless garbage output).
func FuzzEnvFile(f *testing.F) {
	f.Add("APP_KEY", "base64:abc123==")
	f.Add("DB_PASSWORD", "p@ss w0rd\nnewline")
	f.Add("", "")
	f.Add("A=B", "value")
	f.Add("REDIS_URL", "redis://:p@host:6379/0?a=b=c")
	f.Add("9LEADING", "digit key")
	f.Add("UNICODE_VALUE", "zażółć gęślą jaźń")
	f.Fuzz(func(t *testing.T, k, v string) {
		wantReject := !envKeyValid(k) || strings.ContainsAny(v, "\r\n\x00")
		out, err := EnvFile(map[string]string{k: v})
		if (err != nil) != wantReject {
			t.Fatalf("EnvFile(%q: %q) err = %v, want rejection %v", k, v, err, wantReject)
		}
		if err != nil {
			return
		}
		if want := k + "=" + v + "\n"; string(out) != want {
			t.Fatalf("EnvFile(%q: %q) = %q, want %q", k, v, out, want)
		}
	})
}

// FuzzLoadEnvelope asserts the envelope reader never panics on arbitrary
// cache-file bytes, and pins its postconditions: with the file present a
// (nil, nil) return is impossible, and a successful load always carries the
// supported version, a valid endpoint, and a non-nil secrets map (LoadEnvelope
// validates and normalizes both before returning).
//
// HOME/USERPROFILE are redirected ONCE before f.Fuzz: per-iteration
// t.Setenv/t.TempDir would be perfectly legal (this target is not parallel,
// which is Go's only restriction) but is deliberately avoided — it would
// spend most of every exec on setup instead of on LoadEnvelope. USERPROFILE
// is set alongside HOME because it is what os.UserHomeDir reads on Windows.
// Every fuzz worker process re-runs this prologue with its own TempDir, so
// workers never share a home and the real ~/.berth is never touched.
func FuzzLoadEnvelope(f *testing.F) {
	home := f.TempDir()
	f.Setenv("HOME", home)
	f.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".berth")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		f.Fatal(err)
	}
	target := filepath.Join(dir, "fuzzkey.secrets.json")
	f.Add([]byte(`{"version":1,"endpoint":{"host":"h","port":22},"secrets":{"db:app":"x"}}`))
	f.Add([]byte(`{"version":1,"endpoint":{"host":"h","port":22},"migratedTo":"other","secrets":{}}`))
	f.Add([]byte(`{"version":1,"endpoint":{"host":"","port":0}}`))
	f.Add([]byte(`{"version":99}`))
	f.Add([]byte(`{"version":"flat"}`))
	f.Add([]byte(`{"secrets":{"a":"b"}}`))
	f.Add([]byte("{"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatal(err)
		}
		env, err := LoadEnvelope("fuzzkey")
		if err != nil {
			if env != nil {
				t.Fatalf("LoadEnvelope returned both an envelope and an error: %v", err)
			}
			return // rejection is fine; panics are the bug
		}
		if env == nil {
			t.Fatalf("LoadEnvelope = (nil, nil) with the cache file present (input %q)", data)
		}
		if env.Version != envelopeVersion {
			t.Fatalf("accepted envelope has version %d, want %d (input %q)", env.Version, envelopeVersion, data)
		}
		if !env.Endpoint.valid() {
			t.Fatalf("accepted envelope has invalid endpoint %s (input %q)", env.Endpoint, data)
		}
		if env.Secrets == nil {
			t.Fatalf("accepted envelope has a nil secrets map (input %q)", data)
		}
	})
}

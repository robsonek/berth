package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// reEnvKey is the dotenv key grammar (shell-identifier shape). Anything else
// — an empty key, a leading digit, '=', control characters — would change the
// parsed meaning of the rendered file.
var reEnvKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// EnvFile renders a .env body from key/value pairs (deterministic order).
// Defence in depth: every production value is validated or generated
// alphanumeric today, but the renderer itself must refuse a key outside the
// env-identifier grammar and any CR/LF/NUL in a value — a newline would
// inject a second variable line (the same class chpasswd guards against).
// Error messages name the key, never the (possibly secret) value.
func EnvFile(kv map[string]string) ([]byte, error) {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys) // sorted BEFORE validation: deterministic first error
	for _, k := range keys {
		if !reEnvKey.MatchString(k) {
			return nil, fmt.Errorf("env key %q is not a valid identifier ([A-Za-z_][A-Za-z0-9_]*)", k)
		}
		if strings.ContainsAny(kv[k], "\r\n\x00") {
			return nil, fmt.Errorf("env value for key %q contains a newline or NUL byte; refusing to render it", k)
		}
	}
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, kv[k])
	}
	return []byte(b.String()), nil
}

// cacheDir is the per-user directory holding berth's local secret caches,
// anchored under $HOME (NOT the working directory) so the cache — which can
// hold a root-equivalent break-glass console password — is found regardless of
// where berth is invoked from. A non-absolute home is rejected: the whole point
// is that the path is never CWD-relative.
func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory for secret cache: %w", err)
	}
	if !filepath.IsAbs(home) {
		return "", fmt.Errorf("home directory %q is not absolute; refusing a CWD-relative secret cache", home)
	}
	return filepath.Join(home, ".berth"), nil
}

// LoadCache reads just the secrets map of a v1 envelope cache. A
// never-written cache is an empty map, a tombstone is an error. It performs
// NO endpoint verification — production steps go through their verified
// helper; this is for read-only consumers (assertions, tests).
func LoadCache(server string) (map[string]string, error) {
	env, err := LoadEnvelope(server)
	if err != nil {
		return nil, err
	}
	if env == nil {
		return map[string]string{}, nil
	}
	if env.MigratedTo != "" {
		return nil, fmt.Errorf("cache for %s is a tombstone (migrated to %q)", server, env.MigratedTo)
	}
	return env.Secrets, nil
}

// LockCache takes an exclusive per-host advisory lock and returns a release
// closure. Hold it across a whole load→modify→save window so two concurrent
// berth runs against the same host cannot lost-update the cache. It also
// tightens the cache dir to 0700 up front, because a cache-hit path may never
// reach SaveEnvelope (which does the same) yet the dir guards a root-equivalent
// password. It is a low-level primitive: the caller still calls
// LoadEnvelope/SaveEnvelope itself (some call sites must persist before a side
// effect, an ordering a save-last wrapper could not express).
func LockCache(host string) (func(), error) {
	dir, err := cacheDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod %s: %w", dir, err)
	}
	lockPath := filepath.Join(dir, host+".lock")
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open cache lock %s: %w", lockPath, err)
	}
	if err := lockFile(lf); err != nil {
		lf.Close()
		return nil, fmt.Errorf("lock %s: %w", lockPath, err)
	}
	return func() { unlockFile(lf); lf.Close() }, nil
}

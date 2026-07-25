package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// EnvFile renders a .env body from key/value pairs (deterministic order).
func EnvFile(kv map[string]string) []byte {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, kv[k])
	}
	return []byte(b.String())
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

// SaveCache writes a local, mode-0600 copy of generated secrets under
// $HOME/.berth. The replace is atomic (temp file + rename): the per-server
// file holds every generated credential — database passwords and, with
// break_glass, a root-equivalent console password — so a crash mid-write must
// never truncate it. MkdirAll/WriteFile modes apply only on creation, so
// pre-existing permissive paths are explicitly tightened.
func SaveCache(server string, secrets map[string]string) error {
	dir, err := cacheDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal secrets cache: %w", err)
	}
	path := filepath.Join(dir, server+".secrets.json")
	tmp, err := os.CreateTemp(dir, server+".secrets.*.tmp")
	if err != nil {
		return fmt.Errorf("temp cache file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// LoadCache reads a previously saved secrets cache (used to reuse, not rotate).
// A cache that has never been written is NOT an error (empty map, nil); any
// other failure — unreadable file, malformed JSON — is returned so callers
// fail loud instead of treating a cache they could not read as empty and then
// clobbering it on the next SaveCache.
func LoadCache(server string) (map[string]string, error) {
	dir, err := cacheDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, server+".secrets.json")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m == nil { // a file containing literally `null` unmarshals to a nil map
		m = map[string]string{}
	}
	return m, nil
}

// LockCache takes an exclusive per-host advisory lock and returns a release
// closure. Hold it across a whole load→modify→save window so two concurrent
// berth runs against the same host cannot lost-update the cache. It also
// tightens the cache dir to 0700 up front, because a cache-hit path may never
// reach SaveCache (which does the same) yet the dir guards a root-equivalent
// password. It is a low-level primitive: the caller still calls
// LoadCache/SaveCache itself (some call sites must persist before a side
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

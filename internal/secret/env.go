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

// SaveCache writes a gitignored local copy of generated secrets (mode 600).
// The replace is atomic (temp file + rename): the per-server file holds every
// generated credential — database passwords and, with break_glass, a
// root-equivalent console password — so a crash mid-write must never truncate
// it. MkdirAll/WriteFile modes apply only on creation, so pre-existing
// permissive paths are explicitly tightened.
func SaveCache(server string, secrets map[string]string) error {
	dir := ".berth"
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
	path := filepath.Join(".berth", server+".secrets.json")
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
	return m, nil
}

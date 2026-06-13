package secret

import (
	"encoding/json"
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
func SaveCache(server string, secrets map[string]string) error {
	dir := ".berth"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal secrets cache: %w", err)
	}
	path := filepath.Join(dir, server+".secrets.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// LoadCache reads a previously saved secrets cache (used to reuse, not rotate).
func LoadCache(server string) (map[string]string, error) {
	path := filepath.Join(".berth", server+".secrets.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return m, nil
}

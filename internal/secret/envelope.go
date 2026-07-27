package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Endpoint is the SSH endpoint a secrets cache is bound to. It is an
// operator-error tripwire (accidental server-id reuse, un-coordinated
// host/port change), NOT authentication: a port-forward retargeted to a
// different machine at the same host:port is only caught by SSH host-key
// verification, which always runs first and is never bypassed by --force.
type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (e *Endpoint) String() string {
	if e == nil {
		return "<none>"
	}
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

func (e *Endpoint) valid() bool {
	return e != nil && e.Host != "" && e.Port >= 1 && e.Port <= 65535
}

// Envelope is the versioned on-disk cache format (v1). A legacy pre-v1 cache
// is a bare JSON object of secrets; LoadEnvelope reads both. MigratedTo turns
// an envelope into a tombstone: a non-secret marker left at the old host-keyed
// path after a migration to an id-keyed file, so a stale config still keyed by
// host fails loudly instead of regenerating (or silently disowning) secrets.
type Envelope struct {
	Version    int               `json:"version"`
	Endpoint   *Endpoint         `json:"endpoint"`
	MigratedTo string            `json:"migratedTo,omitempty"`
	Secrets    map[string]string `json:"secrets"`
}

const envelopeVersion = 1

// cachePath returns the secrets file for a cache key (server id or host).
func cachePath(key string) (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, key+".secrets.json"), nil
}

// LoadEnvelope reads a secrets cache. Returns (nil, false, nil) when the file
// has never been written. legacy=true means a pre-v1 flat map was read (its
// secrets are in Envelope.Secrets, Version is 0, Endpoint nil) — the identity
// step upgrades it on its next Apply.
//
// Envelope detection keys on a NUMERIC "version" member only: a legacy cache
// can legally contain a secret literally named "version" (DB user names are
// direct cache keys and the SQL identifier grammar accepts it), and such a
// value is a JSON string, not a number.
func LoadEnvelope(key string) (*Envelope, bool, error) {
	path, err := cachePath(key)
	if err != nil {
		return nil, false, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	var probe struct {
		Version any `json:"version"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	switch v := probe.Version.(type) {
	case nil, string:
		// Legacy flat map (absent version, or a secret named "version").
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, false, fmt.Errorf("parse %s: %w", path, err)
		}
		if m == nil {
			m = map[string]string{}
		}
		return &Envelope{Secrets: m}, true, nil
	case float64:
		if v != envelopeVersion {
			if v > envelopeVersion {
				return nil, false, fmt.Errorf("%s: cache version %v is from a newer berth; upgrade this binary", path, v)
			}
			return nil, false, fmt.Errorf("%s: unsupported cache version %v", path, v)
		}
	default:
		return nil, false, fmt.Errorf("%s: cache \"version\" member has an unexpected JSON type", path)
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	if !env.Endpoint.valid() {
		return nil, false, fmt.Errorf("%s: v1 cache envelope is missing a valid endpoint", path)
	}
	if env.Secrets == nil {
		env.Secrets = map[string]string{}
	}
	return &env, false, nil
}

// SaveEnvelope atomically writes a v1 envelope (same temp+rename and
// mode-tightening contract as the legacy SaveCache). The endpoint is
// mandatory: an envelope without one could never be verified again.
func SaveEnvelope(key string, env Envelope) error {
	if !env.Endpoint.valid() {
		return fmt.Errorf("save cache %s: envelope requires a valid endpoint (host + port 1-65535)", key)
	}
	env.Version = envelopeVersion
	if env.Secrets == nil {
		env.Secrets = map[string]string{}
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal secrets cache: %w", err)
	}
	return writeCacheBytes(key, b)
}

// writeCacheBytes is the shared atomic write path (0700 dir, 0600 file,
// temp + rename).
func writeCacheBytes(key string, b []byte) error {
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
	path := filepath.Join(dir, key+".secrets.json")
	tmp, err := os.CreateTemp(dir, key+".secrets.*.tmp")
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
	// fsync file THEN directory: the cache is persisted BEFORE the remote
	// side effect it recovers (a generated password), so a power loss right
	// after the rename must not leave an empty or missing file. Returning an
	// error after the rename is safe — a retry rewrites the cache
	// idempotently.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s for fsync: %w", dir, err)
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return fmt.Errorf("fsync %s: %w", dir, err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dir, err)
	}
	return nil
}

// VerifyEnvelope guards every secret consumer (defense in depth behind the
// identity step): a tombstone must never serve secrets, and a bound endpoint
// must match the config's. Legacy and absent caches verify clean — the
// identity step is responsible for upgrading/binding them.
func VerifyEnvelope(env *Envelope, legacy bool, host string, port int) error {
	if env == nil || legacy {
		return nil
	}
	if env.MigratedTo != "" {
		return fmt.Errorf("this host's secret cache was migrated to server id %q; add `id: %s` to this config", env.MigratedTo, env.MigratedTo)
	}
	if env.Endpoint.Host != host || env.Endpoint.Port != port {
		return fmt.Errorf("secret cache is bound to endpoint %s but the config targets %s:%d — if this is a DIFFERENT server, give it its own `id`; if the endpoint really changed, re-run with --force to re-bind", env.Endpoint, host, port)
	}
	return nil
}

// MigrateCache moves a legacy host-keyed cache to an id-keyed file (atomic
// rename), upgrades it to a v1 envelope bound to the given endpoint, and
// leaves a tombstone at the old path so a stale host-keyed config fails
// loudly instead of silently regenerating or disowning secrets. It takes BOTH
// per-key locks in deterministic (lexical) order: a single lock would let a
// concurrent host-keyed run recreate a divergent cache mid-migration.
//
// A host-keyed source that is ALREADY a v1 envelope bound to a different
// endpoint is refused BEFORE the rename: that cache belongs to another
// machine reachable through the same hostname (the exact ambiguity `id`
// exists for), and adopting it would merge a stranger's secrets under this
// id. A legacy source has no endpoint to compare — accepted, single-endpoint
// rule applies.
func MigrateCache(id, host string, port int) error {
	if id == host {
		return nil
	}
	release, err := lockBoth(id, host)
	if err != nil {
		return err
	}
	defer release()

	target, _, err := LoadEnvelope(id)
	if err != nil {
		return err
	}
	source, sourceLegacy, err := LoadEnvelope(host)
	if err != nil {
		return err
	}
	sourceIsReal := source != nil && source.MigratedTo == ""
	if target != nil && sourceIsReal {
		return fmt.Errorf("both %s.secrets.json and %s.secrets.json exist — refusing to guess which holds the truth; inspect them, keep one under the id, and remove (or tombstone) the other", id, host)
	}
	if target != nil || !sourceIsReal {
		return nil // already migrated (or nothing to migrate)
	}
	if !sourceLegacy && (source.Endpoint.Host != host || source.Endpoint.Port != port) {
		return fmt.Errorf("the host-keyed cache %s.secrets.json is bound to endpoint %s, not %s:%d — it belongs to a different machine behind the same hostname; give THAT machine its own `id` (do not adopt its secrets under %q)", host, source.Endpoint, host, port, id)
	}
	// Rename first (crash-safe: a re-run sees the id-keyed file and no real
	// source), then upgrade in place, then tombstone the old path.
	srcPath, err := cachePath(host)
	if err != nil {
		return err
	}
	dstPath, err := cachePath(id)
	if err != nil {
		return err
	}
	if err := os.Rename(srcPath, dstPath); err != nil {
		return fmt.Errorf("migrate cache %s -> %s: %w", srcPath, dstPath, err)
	}
	ep := &Endpoint{Host: host, Port: port}
	env := Envelope{Endpoint: ep, Secrets: source.Secrets}
	if !sourceLegacy {
		env.Endpoint = source.Endpoint // keep an already-bound endpoint
	}
	if err := SaveEnvelope(id, env); err != nil {
		return err
	}
	return SaveEnvelope(host, Envelope{Endpoint: ep, MigratedTo: id, Secrets: map[string]string{}})
}

// lockBoth acquires the two per-key cache locks in lexical order and returns
// one release closure (reverse order).
func lockBoth(a, b string) (func(), error) {
	keys := []string{a, b}
	sort.Strings(keys)
	rel1, err := LockCache(keys[0])
	if err != nil {
		return nil, err
	}
	rel2, err := LockCache(keys[1])
	if err != nil {
		rel1()
		return nil, err
	}
	return func() { rel2(); rel1() }, nil
}

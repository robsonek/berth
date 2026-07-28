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

// Envelope is the versioned on-disk cache format (v1). MigratedTo turns
// an envelope into a tombstone: a non-secret marker left at the old host-keyed
// path after a migration to an id-keyed file, so a stale config still keyed by
// host fails loudly instead of regenerating (or silently disowning) secrets.
//
// The secrets-map key grammar is FROZEN as of the first real deployment:
// bare "<dbUser>" (DB password), "appkey:<dbUser>" (APP_KEY backup),
// "console:berth" (break-glass ownership marker). New secret kinds get NEW
// "<kind>:" prefixes; the three existing spellings never change (renaming
// them would orphan every live cache).
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

// LoadEnvelope reads a secrets cache. Returns (nil, nil) when the file has
// never been written.
func LoadEnvelope(key string) (*Envelope, error) {
	path, err := cachePath(key)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var probe struct {
		Version any `json:"version"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	switch v := probe.Version.(type) {
	case nil, string:
		return nil, fmt.Errorf("%s: not a berth secret-cache envelope (pre-release flat format?); no released berth wrote this for a real host — remove or move the file aside, then re-run provision (database secrets re-seed from the host's live shared/.env). If system.break_glass was ever enabled on this machine, the discarded file held the console-password ownership marker: lock the account manually (passwd -l berth) or copy the console:berth entry into the new cache first", path)
	case float64:
		if v != envelopeVersion {
			if v > envelopeVersion {
				return nil, fmt.Errorf("%s: cache version %v is from a newer berth; upgrade this binary", path, v)
			}
			return nil, fmt.Errorf("%s: unsupported cache version %v", path, v)
		}
	default:
		return nil, fmt.Errorf("%s: cache \"version\" member has an unexpected JSON type", path)
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if !env.Endpoint.valid() {
		return nil, fmt.Errorf("%s: v1 cache envelope is missing a valid endpoint", path)
	}
	if env.Secrets == nil {
		env.Secrets = map[string]string{}
	}
	return &env, nil
}

// SaveEnvelope writes a v1 envelope (atomic temp+rename write, 0700 dir /
// 0600 file). The endpoint is mandatory: an envelope without one could never
// be verified again.
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
// must match the config's. An absent cache verifies clean — the identity
// step is responsible for binding it.
func VerifyEnvelope(env *Envelope, host string, port int) error {
	if env == nil {
		return nil
	}
	if env.MigratedTo != "" {
		return fmt.Errorf("this host's secret cache was migrated to server id %q; add `id: %s` to this config", env.MigratedTo, env.MigratedTo)
	}
	if env.Endpoint.Host != host || env.Endpoint.Port != port {
		return fmt.Errorf("secret cache is bound to endpoint %s but the config targets %s:%d — if this is a DIFFERENT server, give it its own `id`; if the endpoint really changed, re-bind with the narrow form: berth provision <config> --only identity --force (a bare --force would ALSO authorize overwriting unmanaged files in every other step of the run)", env.Endpoint, host, port)
	}
	return nil
}

// TombstoneWithoutEnvelope renders the refusal for a host tombstone that
// points at the caller's OWN id while the id-keyed envelope is missing (lost,
// deleted, restored incompletely). The tombstone proves an id-keyed cache
// existed, so silently binding a fresh EMPTY one would disown every secret it
// held — including the console-password ownership marker, without which
// `break_glass: false` leaves a still-usable berth-set root-equivalent
// password behind forever. Shared by MigrateCache and the identity step so
// all three guard sites speak with one voice.
func TombstoneWithoutEnvelope(id, host string) error {
	return fmt.Errorf("the tombstone at ~/.berth/%s.secrets.json records a migration to server id %q, but ~/.berth/%s.secrets.json is missing — rebinding fresh would disown every secret that cache held (including the console-password ownership marker); restore ~/.berth/%s.secrets.json from backup, or settle the console password manually (`passwd -l berth` on the host) and remove the tombstone to let berth rebuild the cache", host, id, id, id)
}

// MigrateCache moves a host-keyed cache to an id-keyed file (atomic rename)
// and leaves a tombstone at the old path so a stale host-keyed config fails
// loudly instead of silently regenerating or disowning secrets. It takes BOTH
// per-key locks in deterministic (lexical) order: a single lock would let a
// concurrent host-keyed run recreate a divergent cache mid-migration.
//
// A host-keyed source bound to a different endpoint is refused BEFORE the
// rename: that cache belongs to another machine reachable through the same
// hostname (the exact ambiguity `id` exists for), and adopting it would merge
// a stranger's secrets under this id.
func MigrateCache(id, host string, port int) error {
	if id == host {
		return nil
	}
	release, err := lockBoth(id, host)
	if err != nil {
		return err
	}
	defer release()

	target, err := LoadEnvelope(id)
	if err != nil {
		return err
	}
	source, err := LoadEnvelope(host)
	if err != nil {
		return err
	}
	// A tombstone pointing at a DIFFERENT id means the caller's id was
	// renamed; both shortcuts below would swallow it (and the fresh-target
	// path would then bind an empty cache, orphaning the old id's secrets).
	if source != nil && source.MigratedTo != "" && source.MigratedTo != id {
		return fmt.Errorf("the cache for host %s was already migrated to server id %q but this run declares id %q — a renamed id would orphan the existing cache (including the console-password ownership marker); restore `id: %s`, or migrate deliberately by renaming ~/.berth/%s.secrets.json to %s.secrets.json and updating the tombstone", host, source.MigratedTo, id, source.MigratedTo, source.MigratedTo, id)
	}
	// A tombstone pointing at OUR id with the id-keyed envelope gone is a lost
	// cache, not a fresh machine: the `!sourceIsReal` shortcut below would
	// return nil and let the caller bind an empty envelope over it.
	if source != nil && source.MigratedTo == id && target == nil {
		return TombstoneWithoutEnvelope(id, host)
	}
	sourceIsReal := source != nil && source.MigratedTo == ""
	if target != nil && sourceIsReal {
		return fmt.Errorf("both %s.secrets.json and %s.secrets.json exist — refusing to guess which holds the truth; inspect them, keep one under the id, and remove (or tombstone) the other", id, host)
	}
	if target != nil || !sourceIsReal {
		return nil // already migrated (or nothing to migrate)
	}
	if source.Endpoint.Host != host || source.Endpoint.Port != port {
		return fmt.Errorf("the host-keyed cache %s.secrets.json is bound to endpoint %s, not %s:%d — it belongs to a different machine behind the same hostname; give THAT machine its own `id` (do not adopt its secrets under %q)", host, source.Endpoint, host, port, id)
	}
	// Rename first (crash-safe: a re-run sees the id-keyed file and no real
	// source), then tombstone the old path.
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
	// Deliberately re-save instead of trusting the renamed bytes: SaveEnvelope
	// canonicalizes the envelope (stamps the version, normalizes nil secrets,
	// stable indentation) and, like every cache write, re-tightens the file to
	// 0600 under a 0700 dir — a hand-loosened host-keyed file would otherwise
	// carry its permissive mode into the id-keyed cache unnoticed, because
	// loads never check modes. Looks redundant; is load-bearing.
	env := Envelope{Endpoint: source.Endpoint, Secrets: source.Secrets}
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

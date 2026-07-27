package steps

import (
	"context"
	"fmt"
	"sort"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// Identity reconciles the LOCAL secret-cache identity before any remote
// mutation: it binds the cache to the config's declared server id (or the
// host when no id is declared), migrates host-keyed files to id-keyed ones
// (leaving a tombstone so a stale host-keyed config fails loudly instead of
// regenerating or disowning secrets — a lost console:berth marker can leave
// a usable root-equivalent password behind), and verifies the recorded
// endpoint against the config.
// It runs FIRST in the pipeline and implements AlwaysRun so it is also
// selected under --only: later steps consume cached secrets, so their
// identity must be settled before preflight's apt update touches the host.
// The endpoint check is an operator-error tripwire, not authentication —
// SSH host-key verification runs before the engine and --force never
// bypasses it.
type identity struct{}

func Identity() provision.Step { return identity{} }

func (identity) Name() string       { return "identity" }
func (identity) Requires() []string { return nil }
func (identity) AlwaysRun() bool    { return true }

// endpointOf is the config's SSH endpoint in cache-envelope form.
func endpointOf(s *config.Server) *secret.Endpoint {
	return &secret.Endpoint{Host: s.Host, Port: s.SSH.Port}
}

// tombstoneAdvice renders the operator instruction for a tombstoned cache
// key (usually the host of an id-less config; an id colliding with a foreign
// tombstone lands here too).
func tombstoneAdvice(key, migratedTo string) error {
	return fmt.Errorf("the secret cache for %s was migrated to server id %q; if this config targets the same machine add `id: %s` to it, if it targets a different machine give that machine its own `id`", key, migratedTo, migratedTo)
}

func (identity) Check(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) (provision.CheckResult, error) {
	key := s.CacheKey()
	env, err := secret.LoadEnvelope(key)
	if err != nil {
		return provision.CheckResult{}, err
	}
	if env != nil && env.MigratedTo != "" {
		// The active key resolves to a tombstone (an id-less config whose
		// host cache moved, or an id colliding with a foreign tombstone).
		return provision.CheckResult{}, tombstoneAdvice(key, env.MigratedTo)
	}
	migrated := s.ID != "" && s.ID != s.Host
	var hostEnv *secret.Envelope
	if migrated {
		hostEnv, err = secret.LoadEnvelope(s.Host)
		if err != nil {
			return provision.CheckResult{}, err
		}
		hostReal := hostEnv != nil && hostEnv.MigratedTo == ""
		if hostReal && env != nil {
			return provision.CheckResult{}, fmt.Errorf("both %s.secrets.json and %s.secrets.json exist under ~/.berth — refusing to guess which holds this machine's secrets; keep the correct one under the id and remove (or tombstone) the other", s.ID, s.Host)
		}
		if hostReal {
			// A host-keyed cache bound to ANOTHER endpoint belongs to a
			// different machine behind the same hostname — refusing here (and
			// in MigrateCache, before its rename) keeps a stranger's secrets
			// from being adopted under this id.
			if hostEnv.Endpoint.Host != s.Host || hostEnv.Endpoint.Port != s.SSH.Port {
				return provision.CheckResult{}, fmt.Errorf("the host-keyed cache %s.secrets.json is bound to endpoint %s, not %s:%d — it belongs to a different machine behind the same hostname; give THAT machine its own `id` (do not adopt its secrets under %q)", s.Host, hostEnv.Endpoint, s.Host, s.SSH.Port, s.ID)
			}
			return provision.CheckResult{Satisfied: false, Reason: "host-keyed secret cache pending migration to id " + s.ID, Changes: identityChanges(s)}, nil
		}
	}
	if env == nil {
		return provision.CheckResult{Satisfied: false, Reason: "secret cache not yet bound to this server identity", Changes: identityChanges(s)}, nil
	}
	ep := endpointOf(s)
	if env.Endpoint.Host != ep.Host || env.Endpoint.Port != ep.Port {
		if !rc.Force {
			return provision.CheckResult{}, secret.VerifyEnvelope(env, ep.Host, ep.Port)
		}
		return provision.CheckResult{Satisfied: false, Reason: fmt.Sprintf("re-bind cache endpoint %s -> %s (--force)", env.Endpoint, ep), Changes: identityChanges(s)}, nil
	}
	if migrated && hostEnv == nil {
		// The advisory tombstone protects mixed id/no-id configs; converge it.
		return provision.CheckResult{Satisfied: false, Reason: "tombstone for the old host key missing", Changes: identityChanges(s)}, nil
	}
	return provision.CheckResult{Satisfied: true, Reason: "secret cache bound to " + key + " @ " + env.Endpoint.String()}, nil
}

func identityChanges(s *config.Server) []string {
	return []string{
		"bind the local secret cache to " + s.CacheKey() + " @ " + endpointOf(s).String(),
		"migrate a host-keyed cache file (tombstone the old host key)",
	}
}

func (identity) Apply(ctx context.Context, rc provision.RunCtx, s *config.Server, r bssh.Runner) error {
	key := s.CacheKey()
	migrated := s.ID != "" && s.ID != s.Host
	if migrated {
		// Takes both per-key locks itself (deterministic order).
		if err := secret.MigrateCache(s.ID, s.Host, s.SSH.Port); err != nil {
			return err
		}
	}
	// Converge the active file (and the tombstone) under the relevant locks,
	// re-reading state after acquisition: Check ran unlocked.
	locks := []string{key}
	if migrated {
		locks = append(locks, s.Host)
		sort.Strings(locks)
	}
	var releases []func()
	for _, l := range locks {
		rel, err := secret.LockCache(l)
		if err != nil {
			for _, held := range releases {
				held()
			}
			return err
		}
		releases = append(releases, rel)
	}
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()

	env, err := secret.LoadEnvelope(key)
	if err != nil {
		return err
	}
	if env != nil && env.MigratedTo != "" {
		return tombstoneAdvice(key, env.MigratedTo)
	}
	ep := endpointOf(s)
	switch {
	case env == nil:
		if err := secret.SaveEnvelope(key, secret.Envelope{Endpoint: ep, Secrets: map[string]string{}}); err != nil {
			return err
		}
	case env.Endpoint.Host != ep.Host || env.Endpoint.Port != ep.Port:
		if !rc.Force {
			return secret.VerifyEnvelope(env, ep.Host, ep.Port)
		}
		env.Endpoint = ep
		if err := secret.SaveEnvelope(key, *env); err != nil {
			return err
		}
	}
	if migrated {
		hostEnv, err := secret.LoadEnvelope(s.Host)
		if err != nil {
			return err
		}
		if hostEnv != nil && hostEnv.MigratedTo == "" {
			return fmt.Errorf("a host-keyed cache %s.secrets.json reappeared during identity reconciliation (a concurrent run without `id`?); re-run after making every config of this machine use `id: %s`", s.Host, s.ID)
		}
		if hostEnv == nil {
			if err := secret.SaveEnvelope(s.Host, secret.Envelope{Endpoint: ep, MigratedTo: key, Secrets: map[string]string{}}); err != nil {
				return err
			}
		}
	}
	return nil
}

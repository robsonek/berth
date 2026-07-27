package steps

import (
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/secret"
)

// loadVerifiedSecrets loads the local secret cache for this server and
// verifies its envelope binding (tombstone, endpoint) against the config —
// defense in depth behind the identity step, which normally settles both
// before any secret consumer runs (it is always-selected, --only included).
// An absent cache verifies clean; identity binds it.
func loadVerifiedSecrets(s *config.Server) (map[string]string, error) {
	env, err := secret.LoadEnvelope(s.CacheKey())
	if err != nil {
		return nil, err
	}
	if err := secret.VerifyEnvelope(env, s.Host, s.SSH.Port); err != nil {
		return nil, err
	}
	if env == nil {
		return map[string]string{}, nil
	}
	return env.Secrets, nil
}

// saveSecrets persists the secrets map as a v1 envelope bound to the
// config's endpoint. Callers hold the cache lock across load→modify→save.
func saveSecrets(s *config.Server, secrets map[string]string) error {
	return secret.SaveEnvelope(s.CacheKey(), secret.Envelope{
		Endpoint: &secret.Endpoint{Host: s.Host, Port: s.SSH.Port},
		Secrets:  secrets,
	})
}

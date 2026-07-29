// Package secret generates credentials and redacts them from output.
package secret

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
)

// alphabet excludes shell- and URL-unsafe characters on purpose.
const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Generate returns a cryptographically random password of length n.
func Generate(n int) (string, error) {
	b := make([]byte, n)
	bound := big.NewInt(int64(len(alphabet)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, bound)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[idx.Int64()]
	}
	return string(b), nil
}

// Settable secret names — the `berth secret set` allowlist. The offsite cloud
// credentials are operator-owned (berth cannot generate them); the restic
// repository password is auto-generated on first use but may be set ahead of
// time (or corrected after a cache restore).
//
//nolint:gosec // G101 false positive: these are secret NAMES (envelope map keys), never credential values.
const (
	OffsiteS3AccessKey    = "offsite_s3_access_key"
	OffsiteS3SecretKey    = "offsite_s3_secret_key"
	OffsiteResticPassword = "offsite_restic_password"
)

// SettableNames lists the names `berth secret set` accepts, in display order.
func SettableNames() []string {
	return []string{OffsiteS3AccessKey, OffsiteS3SecretKey, OffsiteResticPassword}
}

// ValidateSecretValue enforces the quoting contract for values that land
// single-quoted inside a root-sourced env file on the host: single line,
// non-empty, bounded, no quotes and no control characters. It runs at
// ingestion (berth secret set) AND after every cache load in the offsite
// step — the cache file is operator-editable and restorable, so a loaded
// value is untrusted input until revalidated.
func ValidateSecretValue(v string) error {
	if v == "" {
		return fmt.Errorf("secret value is empty")
	}
	if len(v) > 4096 {
		return fmt.Errorf("secret value exceeds 4096 bytes")
	}
	if strings.ContainsAny(v, "\n\r") {
		return fmt.Errorf("secret value must be a single line")
	}
	if strings.Contains(v, "'") {
		return fmt.Errorf("secret value must not contain single quotes (it is stored single-quoted in /etc/berth/offsite.env)")
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("secret value must not contain control characters")
		}
	}
	return nil
}

// AppKey returns a Laravel APP_KEY: "base64:" followed by 32 cryptographically
// random bytes, base64-encoded — the format Laravel's AES-256-CBC cipher expects.
func AppKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "base64:" + base64.StdEncoding.EncodeToString(b), nil
}

// Redactor masks registered secret values in arbitrary strings. Steps call
// Add when a secret is acquired (from the engine goroutine); the engine calls
// Apply on every event field before it leaves for the renderers, and the CLI
// calls it on returned errors — those can run on different goroutines (a TUI
// quit returns to the command while the engine goroutine still unwinds), so
// access is mutex-guarded. Both methods are nil-receiver-safe: a typed-nil
// *Redactor behaves as a no-op.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

func NewRedactor() *Redactor { return &Redactor{} }

// Add registers a secret to mask. Empty strings are ignored, duplicates are
// dropped (deterministic output), and the slice is kept sorted LONGEST FIRST
// under the write lock: registering "abc" before "abcdef" must not shred the
// longer secret into "***def" (the prefix bug), and sorting here keeps Apply
// a pure reader.
func (r *Redactor) Add(s string) {
	if r == nil || s == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, have := range r.secrets {
		if have == s {
			return
		}
	}
	r.secrets = append(r.secrets, s)
	sort.Slice(r.secrets, func(i, j int) bool {
		if len(r.secrets[i]) != len(r.secrets[j]) {
			return len(r.secrets[i]) > len(r.secrets[j])
		}
		return r.secrets[i] < r.secrets[j] // stable tie-break for determinism
	})
}

// Apply replaces every registered secret with "***". Not guaranteed
// idempotent for arbitrary inputs (a registered secret containing the
// replacement token could compound) — irrelevant for berth's secret domain,
// where every generated/validated credential is `*`-free.
func (r *Redactor) Apply(s string) string {
	if r == nil {
		return s
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, "***")
	}
	return s
}

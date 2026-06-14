// Package secret generates credentials and redacts them from output.
package secret

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"strings"
)

// alphabet excludes shell- and URL-unsafe characters on purpose.
const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Generate returns a cryptographically random password of length n.
func Generate(n int) (string, error) {
	b := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[idx.Int64()]
	}
	return string(b), nil
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

// Redactor masks registered secret values in arbitrary strings.
type Redactor struct{ secrets []string }

func NewRedactor() *Redactor { return &Redactor{} }

// Add registers a secret to mask. Empty strings are ignored.
func (r *Redactor) Add(s string) {
	if s != "" {
		r.secrets = append(r.secrets, s)
	}
}

// Apply replaces every registered secret with "***".
func (r *Redactor) Apply(s string) string {
	for _, sec := range r.secrets {
		s = strings.ReplaceAll(s, sec, "***")
	}
	return s
}

package wizard

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerateServerID derives a fresh stable machine identity for a new config:
// a lowercase slug of the config name plus an 8-hex crypto/rand suffix (the
// name alone is not unique, and the wizard's name field is only required to
// be non-empty — capitals, spaces and path characters must not leak into the
// id, which keys files in ~/.berth). An empty slug (a name with no usable
// characters) degrades to the random suffix alone.
func GenerateServerID(name string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	slug := strings.Trim(b.String(), "._-")
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	const suffixLen = 4 // bytes -> 8 hex chars
	raw := make([]byte, suffixLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate server id: %w", err)
	}
	suffix := hex.EncodeToString(raw)
	if slug == "" {
		return suffix, nil
	}
	const maxID = 64
	if len(slug) > maxID-len(suffix)-1 {
		slug = strings.Trim(slug[:maxID-len(suffix)-1], "._-")
	}
	return slug + "-" + suffix, nil
}

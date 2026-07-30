package ui

import (
	"strings"
	"unicode/utf8"
)

// Host-derived text — the manifest's VERSION, probe stderr, drift change
// descriptions, step reasons and warnings, error text — ends up on the
// operator's terminal. A compromised or drifted host can embed ANSI/OSC
// sequences in any of it: clear the screen, overwrite rows, or (on terminals
// that honor OSC 52) write the clipboard. Every renderer therefore passes
// each host-derived string through one of these helpers at the point the DATA
// enters the renderer — before any lipgloss styling is composed around it, so
// berth's own styling is never stripped (external adversarial review
// finding).
//
// Control characters are visibly ESCAPED (\t, \r, \x1b, …), never silently
// deleted: an operator should see that something was there. Multi-byte UTF-8
// (ż, æ, 日本語) passes through untouched; bytes that are not valid UTF-8 are
// escaped byte-wise, so a raw 0x9b can never reach a terminal that would read
// it as an 8-bit CSI. Escaping is idempotent — the output contains no control
// characters, so double-wrapping a call site is harmless.

// SanitizeCell escapes EVERY control character, including \t and \n: cells
// and single-line rows must stay one line, and a literal tab inside data
// would fabricate a tabwriter column (the layout's own tabs live in the
// format strings, not in the data).
func SanitizeCell(s string) string { return sanitize(s, false) }

// SanitizeBlock keeps \n — for error text whose multi-line remedies are part
// of the message contract (e.g. the `berth secret set` recipes) — and escapes
// everything else SanitizeCell does. Exported for cmd's final error print,
// the one terminal write outside this package.
func SanitizeBlock(s string) string { return sanitize(s, true) }

func sanitize(s string, keepNewline bool) string {
	needsWork := func(r rune) bool {
		if r == '\n' {
			return !keepNewline
		}
		return r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == utf8.RuneError
	}
	if strings.IndexFunc(s, needsWork) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			// Invalid byte: escape it raw rather than emitting U+FFFD, which
			// would both mangle the data and hide what the host sent.
			writeHexEscape(&b, rune(s[i]))
		case r == '\n' && keepNewline:
			b.WriteByte('\n')
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			writeHexEscape(&b, r) // C0/DEL/C1 all fit one byte
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// writeHexEscape appends the visible `\xNN` form of a single-byte rune (every
// caller passes a value ≤ 0xff; the masks bound the indexes regardless).
func writeHexEscape(b *strings.Builder, r rune) {
	const hexdigits = "0123456789abcdef"
	b.WriteString(`\x`)
	b.WriteByte(hexdigits[(r>>4)&0xf])
	b.WriteByte(hexdigits[r&0xf])
}

// sanitizeAll maps SanitizeCell over a slice (drift/step change lists).
func sanitizeAll(items []string) []string {
	if len(items) == 0 {
		return items
	}
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = SanitizeCell(s)
	}
	return out
}

// sanitizeErr renders an error for the terminal, keeping its deliberate
// newlines. Nil-safe: EventFailed always carries an error today, but a
// renderer must never panic on an event stream.
func sanitizeErr(e error) string {
	if e == nil {
		return ""
	}
	return SanitizeBlock(e.Error())
}

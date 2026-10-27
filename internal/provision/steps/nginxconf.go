package steps

import (
	"fmt"
	"strings"
)

// nginxHTTPDirectives returns the simple directives that sit DIRECTLY in
// nginx.conf's http block — name → arguments of the first occurrence — and
// nothing from main level, events, or any block nested inside http (server,
// location, map, upstream …). nginx's duplicate rule is per context, so only
// these can collide with a conf.d drop-in, which nginx.conf includes at http
// level. The lexer follows nginx's own: `#` comments to end of line, single
// and double quotes group one argument, `;` ends a directive wherever it
// stands (`gzip on ;` is valid), `{` opens the block named by the statement's
// first token. A conf without an http block yields an empty map (a fresh host
// has no nginx.conf yet).
func nginxHTTPDirectives(conf string) map[string][]string {
	out := map[string][]string{}
	var stack []string // enclosing block names, innermost last
	var args []string  // tokens of the statement being read
	var tok strings.Builder
	inTok, quote := false, byte(0)
	flush := func() {
		if inTok {
			args = append(args, tok.String())
			tok.Reset()
			inTok = false
		}
	}
	for i := 0; i < len(conf); i++ {
		c := conf[i]
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			tok.WriteByte(c)
			continue
		}
		switch c {
		case '#':
			flush()
			for i < len(conf) && conf[i] != '\n' {
				i++
			}
		case '"', '\'':
			inTok, quote = true, c
		case ' ', '\t', '\r', '\n':
			flush()
		case ';':
			flush()
			if len(args) > 0 && len(stack) == 1 && stack[0] == "http" {
				if _, seen := out[args[0]]; !seen {
					out[args[0]] = append([]string(nil), args[1:]...)
				}
			}
			args = nil
		case '{':
			flush()
			name := ""
			if len(args) > 0 {
				name = args[0]
			}
			stack = append(stack, name)
			args = nil
		case '}':
			flush()
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			args = nil
		default:
			inTok = true
			tok.WriteByte(c)
		}
	}
	return out
}

// nginxGzipShape says which directives the gzip drop-in writes: each is left
// out when nginx.conf already sets it at http level, since nginx rejects a
// second gzip / gzip_vary / gzip_proxied / gzip_comp_level / gzip_min_length
// in one context as a duplicate. gzip_types is additive (several directives
// merge) and is always written, so the drop-in is never empty.
type nginxGzipShape struct {
	Gzip, Vary, Proxied, CompLevel, MinLength bool
}

// nginxGzipShapeFor derives the drop-in's shape from nginx.conf's http-level
// directives (nginxHTTPDirectives). An http-level `gzip off;` is the
// operator's intent, which the knob could only contradict with a duplicate:
// refused with the two ways out, in Check and Apply alike.
func nginxGzipShapeFor(http map[string][]string) (nginxGzipShape, error) {
	if g, ok := http["gzip"]; ok && len(g) > 0 && g[0] == "off" {
		return nginxGzipShape{}, fmt.Errorf("%s sets gzip off in its http block, which berth's gzip drop-in cannot override (nginx rejects a second gzip directive in the same context): remove that line, or set nginx.gzip: false to leave gzip unmanaged", nginxConfPath)
	}
	absent := func(name string) bool { _, ok := http[name]; return !ok }
	return nginxGzipShape{
		Gzip:      absent("gzip"),
		Vary:      absent("gzip_vary"),
		Proxied:   absent("gzip_proxied"),
		CompLevel: absent("gzip_comp_level"),
		MinLength: absent("gzip_min_length"),
	}, nil
}

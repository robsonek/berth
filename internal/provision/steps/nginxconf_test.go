package steps

import (
	"reflect"
	"testing"
)

// nginxHTTPDirectives must read ONLY the directives that sit directly in the
// http block — nginx's duplicate rule is per context, so a `gzip off;` inside
// a nested server block is no conflict and a `gzip_vary on;` at http level
// is one. Comments, nginx's permissive spacing (`gzip on ;`) and quoted
// arguments must be handled the way nginx's own lexer does.
func TestNginxHTTPDirectivesReadsOnlyTheHTTPBlock(t *testing.T) {
	conf := `
user www-data;
worker_processes auto; # main-level directive, ignored
events {
    worker_connections 768;
    gzip on; # wrong context, ignored
}
http {
    include /etc/nginx/mime.types;
    # gzip_vary on;   <- commented out, ignored
    gzip on ;
    gzip_vary on;
    gzip_proxied expired no-cache;
    gzip_types "text/plain" application/json;
    server {
        listen 80;
        gzip off; # nested, ignored
        location / { gzip_comp_level 9; }
    }
    map $http_x $y { default 0; }
    gzip_min_length 1k; gzip_vary off;
}
`
	got := nginxHTTPDirectives(conf)
	want := map[string][]string{
		"include":         {"/etc/nginx/mime.types"},
		"gzip":            {"on"},
		"gzip_vary":       {"on"}, // first occurrence wins (nginx would reject the second anyway)
		"gzip_proxied":    {"expired", "no-cache"},
		"gzip_types":      {"text/plain", "application/json"},
		"gzip_min_length": {"1k"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nginxHTTPDirectives =\n%v\nwant\n%v", got, want)
	}
}

func TestNginxHTTPDirectivesStockShapes(t *testing.T) {
	// nginx.org mainline: gzip commented out, nothing active.
	org := "user  nginx;\nhttp {\n    #gzip  on;\n    include /etc/nginx/conf.d/*.conf;\n}\n"
	if got := nginxHTTPDirectives(org); got["gzip"] != nil {
		t.Errorf("nginx.org stock must have no active gzip; got %v", got["gzip"])
	}
	// Debian 13: tab-indented `gzip on;` with the tuning commented out.
	deb := "http {\n\t##\n\t# Gzip Settings\n\t##\n\n\tgzip on;\n\n\t# gzip_vary on;\n\t# gzip_comp_level 6;\n}\n"
	got := nginxHTTPDirectives(deb)
	if !reflect.DeepEqual(got["gzip"], []string{"on"}) || got["gzip_vary"] != nil || got["gzip_comp_level"] != nil {
		t.Errorf("Debian stock must read gzip on and nothing else; got %v", got)
	}
	// No http block at all (a fresh host's missing file reads as "").
	if got := nginxHTTPDirectives(""); len(got) != 0 {
		t.Errorf("empty conf must yield no directives; got %v", got)
	}
}

// The drop-in's shape: every directive nginx.conf already sets at http level
// is left out (a repeat is a duplicate nginx rejects); gzip_types is additive
// and always written; an http-level `gzip off;` is the operator's intent and
// is refused.
func TestNginxGzipShapeFromHTTPDirectives(t *testing.T) {
	for _, tc := range []struct {
		name    string
		http    map[string][]string
		want    nginxGzipShape
		wantErr bool
	}{
		{"nothing active (nginx.org)", nil, nginxGzipShape{Gzip: true, Vary: true, Proxied: true, CompLevel: true, MinLength: true}, false},
		{"gzip on (Debian)", map[string][]string{"gzip": {"on"}}, nginxGzipShape{Vary: true, Proxied: true, CompLevel: true, MinLength: true}, false},
		{"operator tuned everything", map[string][]string{"gzip": {"on"}, "gzip_vary": {"on"}, "gzip_proxied": {"any"}, "gzip_comp_level": {"6"}, "gzip_min_length": {"1k"}, "gzip_types": {"text/css"}}, nginxGzipShape{}, false},
		{"gzip off refused", map[string][]string{"gzip": {"off"}}, nginxGzipShape{}, true},
	} {
		got, err := nginxGzipShapeFor(tc.http)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("%s: shape = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// Greptile P1 (PR #103, second round): nginx's lexer escapes the next
// character after a backslash, inside and outside quotes, so `\"` never
// closes a double-quoted argument — a valid log_format with an escaped
// quote before `gzip on;` must not swallow the gzip directive. `${var}`
// inside an argument is a variable, not a block, and a `}` inside a token
// is a plain character (only a `}` that starts a token closes a block).
func TestNginxHTTPDirectivesEscapesAndVariables(t *testing.T) {
	conf := `
http {
    log_format custom "quote: \" $request" '\'s' ;
    set $x ${foo}bar;
    gzip on;
    gzip_vary on\;;
}
`
	got := nginxHTTPDirectives(conf)
	want := map[string][]string{
		"log_format": {"custom", `quote: " $request`, `'s`},
		"set":        {"$x", "${foo}bar"},
		"gzip":       {"on"},
		"gzip_vary":  {`on\;`}, // an escaped `;` is no terminator and, like nginx, keeps its backslash
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nginxHTTPDirectives =\n%v\nwant\n%v", got, want)
	}
}

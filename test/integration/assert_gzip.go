//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	bssh "github.com/robsonek/berth/internal/ssh"
)

const gzipDropInPath = "/etc/nginx/conf.d/berth-gzip.conf"

// assertGzipResponses proves the nginx.gzip knob end to end. With the knob
// on (the default) the managed drop-in must exist AND a dynamic PHP response
// of every tenant — 4 KiB of text/html, well past gzip_min_length — must come
// back gzip-encoded, with Vary: Accept-Encoding, when the client offers gzip,
// and uncompressed when it insists on identity. The body is decoded and
// compared, so a Content-Encoding header on an unencoded body cannot pass.
// With the knob off only the drop-in's absence is asserted: Debian's stock
// nginx.conf compresses text/html on its own, so the wire format proves
// nothing about berth there.
//
// The probe is served by PHP-FPM through the tenant's own vhost (Host header,
// SNI), so it also covers the http-context drop-in reaching a server block
// loaded via sites-enabled — the layout the nginx.org bridge exists for.
func assertGzipResponses(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server, sslExplicit bool) {
	t.Helper()
	if !srv.Nginx.GzipEnabled() {
		assertExitZero(ctx, t, c, "gzip drop-in absent (nginx.gzip: false)", "test ! -e "+shQuote(gzipDropInPath))
		return
	}
	assertExitZero(ctx, t, c, "gzip drop-in managed", "head -n 1 "+shQuote(gzipDropInPath)+" | grep -qx '# managed by berth'")
	const chunk = "<p>berth gzip probe: dynamic text/html must leave the host compressed.</p>\n"
	want := strings.Repeat(chunk, 64)
	php := "<?php header('Content-Type: text/html; charset=UTF-8'); echo str_repeat(" + phpSingleQuoted(chunk) + ", 64);\n"
	for _, site := range srv.Sites {
		useHTTPS, insecureTLS := siteHTTPSProbe(ctx, t, c, site, sslExplicit)
		func() {
			leaf, cleanup := stageTenantPHP(ctx, t, c, srv, site, php)
			defer cleanup()

			// Offer gzip explicitly: Go's transport then neither adds its own
			// Accept-Encoding nor decodes transparently, so the wire encoding
			// is observable.
			resp, err := tenantGET(ctx, srv, site, useHTTPS, insecureTLS, leaf, http.Header{"Accept-Encoding": {"gzip"}})
			if err != nil {
				t.Errorf("%s: GET /%s with Accept-Encoding gzip: %v", site.Domain, leaf, err)
				return
			}
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s: gzip probe: want 200, got %d %q", site.Domain, resp.StatusCode, firstLine(raw))
				return
			}
			if enc := resp.Header.Get("Content-Encoding"); enc != "gzip" {
				t.Errorf("%s: dynamic text/html must be gzip-encoded when the client offers it; Content-Encoding %q (body %d bytes)", site.Domain, enc, len(raw))
				return
			}
			if !strings.Contains(strings.ToLower(resp.Header.Get("Vary")), "accept-encoding") {
				t.Errorf("%s: gzip responses must carry Vary: Accept-Encoding (gzip_vary on); got %q", site.Domain, resp.Header.Get("Vary"))
			}
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Errorf("%s: Content-Encoding gzip but the body is not a gzip stream: %v", site.Domain, err)
				return
			}
			got, err := io.ReadAll(zr)
			if err != nil {
				t.Errorf("%s: decode gzip body: %v", site.Domain, err)
				return
			}
			if string(got) != want {
				t.Errorf("%s: decoded gzip body differs from the staged probe (%d vs %d bytes)", site.Domain, len(got), len(want))
			}
			t.Logf("%s: gzip probe: %d bytes on the wire for %d bytes of text/html", site.Domain, len(raw), len(want))

			// A client that refuses compression must get the identity body.
			resp, err = tenantGET(ctx, srv, site, useHTTPS, insecureTLS, leaf, http.Header{"Accept-Encoding": {"identity"}})
			if err != nil {
				t.Errorf("%s: GET /%s with Accept-Encoding identity: %v", site.Domain, leaf, err)
				return
			}
			plain, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			if enc := resp.Header.Get("Content-Encoding"); enc != "" {
				t.Errorf("%s: Accept-Encoding identity must not be compressed; Content-Encoding %q", site.Domain, enc)
			} else if string(plain) != want {
				t.Errorf("%s: identity body differs from the staged probe (%d vs %d bytes)", site.Domain, len(plain), len(want))
			}
		}()
	}
}

// phpSingleQuoted renders s as a PHP single-quoted string literal.
func phpSingleQuoted(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// firstLine trims a response body to its first line for readable failures.
func firstLine(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\n")
	return line
}

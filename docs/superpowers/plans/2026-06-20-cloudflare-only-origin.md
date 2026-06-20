# Cloudflare-only Origin Lockdown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `cloudflare_only` flag that restricts a site at the nginx layer to traffic whose real TCP peer is a Cloudflare edge range, while restoring the real client IP for logs/fail2ban.

**Architecture:** A global http-context snippet (`/etc/nginx/conf.d/berth-cloudflare.conf`) defines a `geo $realip_remote_addr $berth_cloudflare` map plus `set_real_ip_from`/`real_ip_header CF-Connecting-IP`. Per-site nginx server blocks gain a `if ($berth_cloudflare = 0) { return 444; }` guard in their dynamic locations. Both artifacts are owned by the existing `site` step so one `nginx -t` validates the geo map together with the vhost that references it. No new pipeline step; ufw and the Let's Encrypt path are untouched (the ACME location stays unguarded).

**Tech Stack:** Go 1.25, `text/template` (embedded `*.tmpl`), Viper config, the berth idempotent Step pipeline, golden-file tests, `FakeRunner` SSH double.

**Spec:** `docs/superpowers/specs/2026-06-20-cloudflare-only-origin-lockdown-design.md`

## Global Constraints

- **Go version 1.25**; CI runs `go test -race ./...` and `go vet ./...`. No linter.
- **Never run `go mod tidy`** — it prunes pre-listed Charm v2 deps. No new dependencies are needed for this feature.
- **Public MIT repo** — all code, comments, commits English-only; no personal/host-identifying data.
- **Every config struct field needs BOTH `mapstructure` and `yaml` tags** (mapstructure drives unmarshal; an out-of-sync tag silently won't bind).
- **Managed files** are written via `templates.Render` so the `# managed by berth` marker is prepended; the marker is part of the SHA-256-hashed content.
- **Byte-identical idempotency:** the `CloudflareOnly:false` render of `nginx_http.conf.tmpl` / `nginx_https.conf.tmpl` MUST stay byte-identical to today's goldens, or every deployed vhost is misclassified and `site` re-runs forever. `CloudflareOnly` is derived purely from static config (like `HSTS`), never from cert presence, so the `site`↔`tls` re-render stays byte-identical.
- **Any `nginxData` field change must be mirrored** in the test-local copy in `internal/templates/templates_test.go`.
- The `site` step's struct is unexported; tests live in `package steps` and may reference unexported identifiers (`cloudflareConfPath`, `shQuote`, `renderCloudflareConf`, `cloudflareIPRanges`).
- `FakeRunner.Run` returns an error for any **unstubbed** command, so every command a code path runs must be stubbed in its test.

---

## File Structure

- `internal/config/config.go` — add `Server.CloudflareOnly`, `Site.CloudflareOnly`, helpers `CloudflareOnlyEnabled` / `AnyCloudflareOnly`.
- `internal/config/config_test.go` — helper + decode tests.
- `internal/provision/steps/cloudflare.go` *(new)* — the embedded Cloudflare range list, the `/etc/nginx/conf.d/berth-cloudflare.conf` path constant, and `renderCloudflareConf()`.
- `internal/templates/cloudflare.conf.tmpl` *(new)* — the geo/realip snippet body.
- `internal/templates/nginx_http.conf.tmpl`, `internal/templates/nginx_https.conf.tmpl` — add the `{{- if .CloudflareOnly }}` guard.
- `internal/templates/templates.go` — unchanged (Render already handles the marker).
- `internal/templates/templates_test.go` — mirror the `CloudflareOnly` field, add golden tests.
- `internal/templates/testdata/cloudflare.golden`, `nginx_http_cloudflare.golden`, `nginx_https_cloudflare.golden` *(new, generated)*.
- `internal/provision/steps/site.go` — add `CloudflareOnly` to `nginxData`/`nginxRenderData`; wire `renderCloudflareConf` into `managedSiteFiles` and `Apply`.
- `internal/provision/steps/site_test.go` — render-guard tests, Apply write/remove tests, stub updates.
- `README.md` + `examples/` — document and demonstrate the flag.

---

## Task 1: Config flag fields + helpers

**Files:**
- Modify: `internal/config/config.go` (Server struct ~line 239-251; Site struct ~line 120-133; helpers near `SchedulerEnabled` ~line 160)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `Server.CloudflareOnly bool`; `Site.CloudflareOnly *bool`; `func (s *Server) CloudflareOnlyEnabled(site Site) bool`; `func (s *Server) AnyCloudflareOnly() bool`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/config/config_test.go`:

```go
func TestCloudflareOnlyEnabled(t *testing.T) {
	tru, fls := true, false
	s := &Server{CloudflareOnly: false, Sites: []Site{
		{Domain: "a"},                      // nil override -> inherits server (false)
		{Domain: "b", CloudflareOnly: &tru}, // per-site true beats server false
	}}
	if s.CloudflareOnlyEnabled(s.Sites[0]) {
		t.Error("nil override should inherit server default false")
	}
	if !s.CloudflareOnlyEnabled(s.Sites[1]) {
		t.Error("per-site true override should win over server false")
	}
	s.CloudflareOnly = true
	s.Sites = append(s.Sites, Site{Domain: "c", CloudflareOnly: &fls})
	if !s.CloudflareOnlyEnabled(s.Sites[0]) {
		t.Error("nil override should inherit server default true")
	}
	if s.CloudflareOnlyEnabled(s.Sites[2]) {
		t.Error("per-site false override should win over server true")
	}
}

func TestAnyCloudflareOnly(t *testing.T) {
	fls := false
	none := &Server{CloudflareOnly: false, Sites: []Site{{Domain: "a"}}}
	if none.AnyCloudflareOnly() {
		t.Error("no site enabled -> AnyCloudflareOnly false")
	}
	mixed := &Server{CloudflareOnly: true, Sites: []Site{
		{Domain: "a", CloudflareOnly: &fls}, {Domain: "b"},
	}}
	if !mixed.AnyCloudflareOnly() {
		t.Error("one inheriting site enabled -> true")
	}
	allOff := &Server{CloudflareOnly: true, Sites: []Site{
		{Domain: "a", CloudflareOnly: &fls}, {Domain: "b", CloudflareOnly: &fls},
	}}
	if allOff.AnyCloudflareOnly() {
		t.Error("all sites overridden off -> false even with server true")
	}
}

func TestCloudflareOnlyDecodes(t *testing.T) {
	s, err := Load(writeTmpConfig(t, "cloudflare_only: true\n"+baseCfg+"    cloudflare_only: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.CloudflareOnly {
		t.Error("server cloudflare_only should decode true")
	}
	if s.Sites[0].CloudflareOnly == nil || *s.Sites[0].CloudflareOnly {
		t.Fatalf("site cloudflare_only should decode to *false; got %v", s.Sites[0].CloudflareOnly)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestCloudflareOnly|TestAnyCloudflareOnly'`
Expected: FAIL — compile error `s.CloudflareOnly undefined` / `CloudflareOnlyEnabled undefined`.

- [ ] **Step 3: Add the struct fields**

In `internal/config/config.go`, add to the `Site` struct (after the `Scheduler *bool` field, ~line 130):

```go
	CloudflareOnly *bool `mapstructure:"cloudflare_only" yaml:"cloudflare_only,omitempty"` // per-site override; nil = inherit server default
```

Add to the `Server` struct (after the `Scheduler bool` field, ~line 247):

```go
	CloudflareOnly bool `mapstructure:"cloudflare_only" yaml:"cloudflare_only"`
```

- [ ] **Step 4: Add the helpers**

In `internal/config/config.go`, after `SchedulerEnabled` (~line 165), add:

```go
// CloudflareOnlyEnabled reports whether origin lockdown applies to a site: an
// explicit per-site sites[].cloudflare_only wins; otherwise the server-level
// default applies. Twin of SchedulerEnabled.
func (s *Server) CloudflareOnlyEnabled(site Site) bool {
	if site.CloudflareOnly != nil {
		return *site.CloudflareOnly
	}
	return s.CloudflareOnly
}

// AnyCloudflareOnly reports whether at least one site resolves to enabled, which
// drives whether the global nginx http-context snippet is written or removed.
func (s *Server) AnyCloudflareOnly() bool {
	for _, site := range s.Sites {
		if s.CloudflareOnlyEnabled(site) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/`
Expected: PASS (all config tests, including the three new ones and the existing `TestServerYAMLOmitsEmptyOptionalFields`, which still passes because `Site.CloudflareOnly` is `omitempty` and `Server.CloudflareOnly` mirrors the non-omitempty `scheduler` field).

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add cloudflare_only flag (server + per-site) and helpers"
```

---

## Task 2: Cloudflare range list + conf.d template + renderer

**Files:**
- Create: `internal/provision/steps/cloudflare.go`
- Create: `internal/templates/cloudflare.conf.tmpl`
- Create (generated): `internal/templates/testdata/cloudflare.golden`
- Test: `internal/provision/steps/cloudflare_test.go` (new), `internal/templates/templates_test.go`

**Interfaces:**
- Produces: `cloudflareConfPath` (const `"/etc/nginx/conf.d/berth-cloudflare.conf"`); `cloudflareIPRanges []string`; `func renderCloudflareConf() ([]byte, error)`.

- [ ] **Step 1: Write the failing renderer test**

Create `internal/provision/steps/cloudflare_test.go`:

```go
package steps

import (
	"strings"
	"testing"
)

func TestRenderCloudflareConf(t *testing.T) {
	b, err := renderCloudflareConf()
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if !strings.HasPrefix(out, "# managed by berth") {
		t.Error("cloudflare conf must carry the managed marker")
	}
	if !strings.Contains(out, "real_ip_header CF-Connecting-IP;") {
		t.Error("must set real_ip_header to CF-Connecting-IP")
	}
	if !strings.Contains(out, "geo $realip_remote_addr $berth_cloudflare {") {
		t.Error("must define the geo map keyed on $realip_remote_addr")
	}
	if len(cloudflareIPRanges) < 20 {
		t.Fatalf("expected the full Cloudflare range list, got %d", len(cloudflareIPRanges))
	}
	for _, cidr := range cloudflareIPRanges {
		if !strings.Contains(out, "set_real_ip_from "+cidr+";") {
			t.Errorf("missing set_real_ip_from for %s", cidr)
		}
		if !strings.Contains(out, "    "+cidr+" 1;") {
			t.Errorf("missing geo entry for %s", cidr)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/provision/steps/ -run TestRenderCloudflareConf`
Expected: FAIL — compile error `renderCloudflareConf undefined` / `cloudflareIPRanges undefined`.

- [ ] **Step 3: Create the template**

Create `internal/templates/cloudflare.conf.tmpl` (the `# managed by berth` marker is prepended by `templates.Render`):

```
{{ range .Ranges -}}
set_real_ip_from {{ . }};
{{ end -}}
real_ip_header CF-Connecting-IP;

geo $realip_remote_addr $berth_cloudflare {
    default 0;
{{ range .Ranges -}}
    {{ . }} 1;
{{ end -}}
}
```

- [ ] **Step 4: Create the Go source**

Create `internal/provision/steps/cloudflare.go`:

```go
package steps

import "github.com/robsonek/berth/internal/templates"

// cloudflareConfPath is the global http-context snippet berth writes when any
// site enables cloudflare_only: it restores the real client IP from
// CF-Connecting-IP and defines the $berth_cloudflare geo flag the per-site
// guards test. Lives in conf.d so both supported nginx sources load it (their
// nginx.conf includes /etc/nginx/conf.d/*.conf in the http context).
const cloudflareConfPath = "/etc/nginx/conf.d/berth-cloudflare.conf"

// cloudflareIPRanges are Cloudflare's published edge IP ranges, snapshot
// 2026-06-20. Source: https://www.cloudflare.com/ips-v4 and
// https://www.cloudflare.com/ips-v6. These ranges are extremely stable (the v4
// list has been unchanged for years); refresh on release if Cloudflare publishes
// a change. A baked snapshot keeps the render byte-identical (idempotent) and
// free of any provision-time network dependency.
var cloudflareIPRanges = []string{
	// IPv4
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	// IPv6
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// renderCloudflareConf renders the managed http-context geo/realip snippet.
func renderCloudflareConf() ([]byte, error) {
	return templates.Render("cloudflare.conf.tmpl", struct{ Ranges []string }{cloudflareIPRanges})
}
```

- [ ] **Step 5: Run the renderer test to verify it passes**

Run: `go test ./internal/provision/steps/ -run TestRenderCloudflareConf`
Expected: PASS.

- [ ] **Step 6: Add the template golden test**

Add to `internal/templates/templates_test.go`:

```go
func TestRenderCloudflareGolden(t *testing.T) {
	checkGolden(t, "cloudflare.conf.tmpl", "cloudflare.golden", struct{ Ranges []string }{
		[]string{"203.0.113.0/24", "2001:db8::/32"},
	})
}
```

- [ ] **Step 7: Generate the golden and verify**

Run: `go test -update ./internal/templates/ -run TestRenderCloudflareGolden`
Then run: `go test ./internal/templates/ -run TestRenderCloudflareGolden`
Expected: PASS. Inspect `internal/templates/testdata/cloudflare.golden` — it must start with `# managed by berth`, contain `set_real_ip_from 203.0.113.0/24;`, `set_real_ip_from 2001:db8::/32;`, `real_ip_header CF-Connecting-IP;`, and a `geo $realip_remote_addr $berth_cloudflare { ... default 0; ... 203.0.113.0/24 1; ... 2001:db8::/32 1; ... }` block.

- [ ] **Step 8: Commit**

```bash
git add internal/provision/steps/cloudflare.go internal/provision/steps/cloudflare_test.go internal/templates/cloudflare.conf.tmpl internal/templates/testdata/cloudflare.golden internal/templates/templates_test.go
git commit -m "feat(nginx): add Cloudflare geo/realip http-context snippet + template"
```

---

## Task 3: Per-site guard in the nginx vhost templates

**Files:**
- Modify: `internal/templates/nginx_http.conf.tmpl` (`location /` ~line 17, `location ~ \.php$` ~line 38)
- Modify: `internal/templates/nginx_https.conf.tmpl` (port-80 redirect `location /` ~line 12, 443 `location /` ~line 56, 443 `location ~ \.php$` ~line 77)
- Modify: `internal/provision/steps/site.go` (`nginxData` ~line 161-164, `nginxRenderData` ~line 166-178)
- Modify: `internal/templates/templates_test.go` (test-local `nginxData` ~line 46-49; add golden tests)
- Create (generated): `internal/templates/testdata/nginx_http_cloudflare.golden`, `nginx_https_cloudflare.golden`
- Test: `internal/provision/steps/site_test.go` (render-guard unit tests)

**Interfaces:**
- Consumes: `Server.CloudflareOnlyEnabled` (Task 1).
- Produces: `nginxData.CloudflareOnly bool`, populated by `nginxRenderData`.

- [ ] **Step 1: Write the failing render tests**

Add to `internal/provision/steps/site_test.go`:

```go
func TestNginxGuardWhenCloudflareOnly(t *testing.T) {
	s := siteServer()
	tru := true
	s.Sites[0].CloudflareOnly = &tru
	s.Sites[0].SSL = true
	guard := "if ($berth_cloudflare = 0) { return 444; }"

	http, err := renderNginxHTTP(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(http), guard) != 2 {
		t.Errorf("HTTP block must guard location / and the php location:\n%s", http)
	}

	https, err := renderNginxHTTPS(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	hs := string(https)
	if strings.Count(hs, guard) != 3 {
		t.Errorf("HTTPS must guard the 80 redirect /, the 443 /, and the php location:\n%s", hs)
	}
	// ACME must stay reachable so Let's Encrypt HTTP-01 still works.
	acme := strings.Index(hs, "location /.well-known/acme-challenge/")
	nextGuard := strings.Index(hs[acme:], guard)
	closeBrace := strings.Index(hs[acme:], "}")
	if nextGuard != -1 && nextGuard < closeBrace {
		t.Error("the ACME challenge location must NOT be guarded")
	}
}

func TestNginxNoGuardWhenNotCloudflareOnly(t *testing.T) {
	s := siteServer() // cloudflare_only unset -> false
	http, err := renderNginxHTTP(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(http), "$berth_cloudflare") {
		t.Errorf("no guard expected when cloudflare_only is off:\n%s", http)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/provision/steps/ -run TestNginxGuard`
Expected: FAIL — compile error `s.Sites[0].CloudflareOnly undefined` is already resolved by Task 1, so the real failure is the assertion: the guard string is absent (count 0, not 2/3).

- [ ] **Step 3: Add the `CloudflareOnly` field to `nginxData` and populate it**

In `internal/provision/steps/site.go`, change the `nginxData` struct (~line 161-164):

```go
type nginxData struct {
	Domain, DeployPath, ACMEWebroot, Socket, CertPath, KeyPath string
	HTTP3, QUICReuseport, HSTS, CloudflareOnly                 bool
}
```

In `nginxRenderData` (~line 166-178), add the field to the returned literal (after `HSTS: ...`):

```go
		// CloudflareOnly is derived purely from static config (like HSTS), never
		// from cert presence, so the site re-render and the tls swap stay
		// byte-identical.
		CloudflareOnly: s.CloudflareOnlyEnabled(site),
```

- [ ] **Step 4: Add the guard to `nginx_http.conf.tmpl`**

Change the `location /` block (~line 17):

```
    location / {
{{- if .CloudflareOnly }}
        if ($berth_cloudflare = 0) { return 444; }
{{- end }}
        try_files $uri $uri/ /index.php?$query_string;
    }
```

Change the `location ~ \.php$` block (~line 38) — insert the guard as the first line inside the block:

```
    location ~ \.php$ {
{{- if .CloudflareOnly }}
        if ($berth_cloudflare = 0) { return 444; }
{{- end }}
        fastcgi_pass unix:{{ .Socket }};
```

- [ ] **Step 5: Add the guard to `nginx_https.conf.tmpl`**

Change the port-80 redirect block's `location /` (~line 12):

```
    location / {
{{- if .CloudflareOnly }}
        if ($berth_cloudflare = 0) { return 444; }
{{- end }}
        return 301 https://$host$request_uri;
    }
```

Change the 443 block's `location /` (~line 56):

```
    location / {
{{- if .CloudflareOnly }}
        if ($berth_cloudflare = 0) { return 444; }
{{- end }}
        try_files $uri $uri/ /index.php?$query_string;
    }
```

Change the 443 block's `location ~ \.php$` (~line 77) — insert as the first line inside the block:

```
    location ~ \.php$ {
{{- if .CloudflareOnly }}
        if ($berth_cloudflare = 0) { return 444; }
{{- end }}
        fastcgi_pass unix:{{ .Socket }};
```

- [ ] **Step 6: Run the render tests to verify they pass**

Run: `go test ./internal/provision/steps/ -run TestNginxGuard`
Expected: PASS.

- [ ] **Step 7: Mirror the field in the test-local `nginxData` and add golden tests**

In `internal/templates/templates_test.go`, change the local `nginxData` struct (~line 46-49):

```go
type nginxData struct {
	Domain, DeployPath, ACMEWebroot, Socket, CertPath, KeyPath string
	HTTP3, QUICReuseport, HSTS, CloudflareOnly                 bool
}
```

Add the true-case golden tests:

```go
func TestRenderNginxHTTPCloudflareGolden(t *testing.T) {
	d := nginxGoldenData()
	d.CloudflareOnly = true
	checkGolden(t, "nginx_http.conf.tmpl", "nginx_http_cloudflare.golden", d)
}

func TestRenderNginxHTTPSCloudflareGolden(t *testing.T) {
	d := nginxGoldenData()
	d.CloudflareOnly = true
	checkGolden(t, "nginx_https.conf.tmpl", "nginx_https_cloudflare.golden", d)
}
```

- [ ] **Step 8: Generate the new goldens and verify the OLD ones are unchanged**

Run: `go test -update ./internal/templates/`
Then run: `git status --short internal/templates/testdata/`
Expected: ONLY two new untracked files — `nginx_http_cloudflare.golden`, `nginx_https_cloudflare.golden` (and `cloudflare.golden` already committed in Task 2). The four existing goldens (`nginx_http.golden`, `nginx_https.golden`, `nginx_https_http3.golden`, `nginx_https_nohsts.golden`) MUST show no modification. If any existing golden changed, the `{{- ... }}` whitespace trim is wrong — fix the template (the `{{- end }}` must keep its left dash and must NOT have a right dash) and regenerate.

Run: `go test ./internal/templates/`
Expected: PASS. Inspect the two new goldens: the guard line `        if ($berth_cloudflare = 0) { return 444; }` appears on its own 8-space-indented line in `location /` and `location ~ \.php$` (and, in the https golden, also in the port-80 redirect block), while `location /.well-known/acme-challenge/` has no guard.

- [ ] **Step 9: Run the cross-step render-equivalence test**

Run: `go test ./internal/provision/steps/ -run TestSiteHTTPSRenderMatchesTLSSwap`
Expected: PASS — confirms `site` and `tls` still render byte-identical HTTPS blocks with the new field.

- [ ] **Step 10: Commit**

```bash
git add internal/templates/nginx_http.conf.tmpl internal/templates/nginx_https.conf.tmpl internal/provision/steps/site.go internal/provision/steps/site_test.go internal/templates/templates_test.go internal/templates/testdata/nginx_http_cloudflare.golden internal/templates/testdata/nginx_https_cloudflare.golden
git commit -m "feat(nginx): guard dynamic locations with the cloudflare_only 444 rule"
```

---

## Task 4: Wire the snippet into the `site` step (Check + Apply)

**Files:**
- Modify: `internal/provision/steps/site.go` (`managedSiteFiles` ~line 62-118; `Apply` ~line 418-607)
- Test: `internal/provision/steps/site_test.go` (stub helper update + two new tests)

**Interfaces:**
- Consumes: `cloudflareConfPath`, `renderCloudflareConf` (Task 2); `Server.AnyCloudflareOnly` (Task 1); existing `siteFile{remove}`, `managedFilePresent`, `shQuote`.
- Produces: a `siteFile{path: cloudflareConfPath}` entry in `managedSiteFiles`; an Apply step that writes (enabled) or drift-removes (disabled) the snippet.

- [ ] **Step 1: Write the failing Check-side test**

Add to `internal/provision/steps/site_test.go`:

```go
func TestManagedSiteFilesIncludesCloudflareConf(t *testing.T) {
	s := siteServer()
	tru := true
	s.Sites[0].CloudflareOnly = &tru
	f := bssh.NewFakeRunner()
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, mf := range mfs {
		if mf.path == cloudflareConfPath {
			found = true
			if mf.remove {
				t.Error("cloudflare conf should be present (content), not marked for removal")
			}
			if !strings.Contains(string(mf.content), "geo $realip_remote_addr $berth_cloudflare {") {
				t.Errorf("cloudflare conf content missing geo block:\n%s", mf.content)
			}
		}
	}
	if !found {
		t.Errorf("managedSiteFiles must include %s when a site is cloudflare_only", cloudflareConfPath)
	}
}

func TestManagedSiteFilesRemovesCloudflareConfWhenDisabled(t *testing.T) {
	s := siteServer() // cloudflare_only off
	f := bssh.NewFakeRunner()
	f.On("ls -1 /etc/supervisor/conf.d/berth-*.conf 2>/dev/null", bssh.Result{})
	mfs, err := managedSiteFiles(context.Background(), f, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.path == cloudflareConfPath {
			if !mf.remove {
				t.Error("cloudflare conf should be marked for removal when no site is cloudflare_only")
			}
			return
		}
	}
	t.Errorf("managedSiteFiles must include a remove entry for %s when disabled", cloudflareConfPath)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/provision/steps/ -run TestManagedSiteFilesIncludesCloudflareConf`
Expected: FAIL — no `cloudflareConfPath` entry is produced yet (`managedSiteFiles must include ...`).

- [ ] **Step 3: Add the snippet entry to `managedSiteFiles`**

In `internal/provision/steps/site.go`, inside `managedSiteFiles`, just before the closing `return files, nil` (after the logrotate append, ~line 116), add:

```go
	// Global http-context snippet defining the $berth_cloudflare geo flag +
	// real-IP restoration. Present when any site is cloudflare_only; otherwise a
	// remove entry drift-cleans a lingering berth-managed copy (guarded so a
	// foreign conf.d file is never clobbered).
	if s.AnyCloudflareOnly() {
		cf, err := renderCloudflareConf()
		if err != nil {
			return nil, err
		}
		files = append(files, siteFile{path: cloudflareConfPath, content: cf})
	} else {
		files = append(files, siteFile{path: cloudflareConfPath, remove: true})
	}
```

- [ ] **Step 4: Run the Check-side tests to verify they pass**

Run: `go test ./internal/provision/steps/ -run TestManagedSiteFiles`
Expected: PASS for both new tests.

- [ ] **Step 5: Write the failing Apply-side tests**

Add to `internal/provision/steps/site_test.go`:

```go
func TestSiteApplyWritesCloudflareConfWhenEnabled(t *testing.T) {
	s := siteServer()
	tru := true
	s.Sites[0].CloudflareOnly = &tru
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var wrote bool
	for _, w := range f.Writes() {
		if w.Path == cloudflareConfPath {
			wrote = true
			if !strings.Contains(string(w.Content), "geo $realip_remote_addr $berth_cloudflare {") {
				t.Errorf("cloudflare conf write missing geo block:\n%s", w.Content)
			}
		}
	}
	if !wrote {
		t.Errorf("Apply must write %s when a site is cloudflare_only", cloudflareConfPath)
	}
	// NOTE: FakeRunner records WriteFile (Writes) and Run (Calls) in separate logs,
	// so the "snippet written before the first nginx -t" ordering cannot be asserted
	// here — it is guaranteed structurally by step 0 being the first action in Apply
	// (see Task 4 Step 7) and is covered by code review, not this test.
}

func TestSiteApplyRemovesCloudflareConfWhenDisabled(t *testing.T) {
	s := siteServer() // cloudflare_only off
	f := bssh.NewFakeRunner()
	f.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	f.On("nginx -t", bssh.Result{ExitCode: 0})
	f.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, f)
	// A lingering berth-managed snippet is present -> Apply must rm it.
	f.On("cat "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 0, Stdout: "# managed by berth\nold\n"})
	f.On("rm -f "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 0})

	if err := Site().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var removed bool
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote(cloudflareConfPath) {
			removed = true
		}
	}
	if !removed {
		t.Error("Apply must rm the lingering berth-managed cloudflare conf when disabled")
	}
}
```

- [ ] **Step 6: Run the Apply tests to verify they fail**

Run: `go test ./internal/provision/steps/ -run 'TestSiteApplyWritesCloudflareConfWhenEnabled|TestSiteApplyRemovesCloudflareConfWhenDisabled'`
Expected: FAIL — the enabled test fails (`Apply must write ...`); the disabled test fails on the unstubbed `cat` (no step-0 logic yet) or the missing `rm`.

- [ ] **Step 7: Add the Apply step-0 reconciliation**

In `internal/provision/steps/site.go`, at the very top of `Apply` (immediately after the function opens, before the `// 1) Per-site nginx server block` comment ~line 419), add:

```go
	// 0) Reconcile the global http-context Cloudflare snippet BEFORE the per-site
	//    vhosts so the $berth_cloudflare geo flag is defined when nginx -t validates
	//    a vhost that references it. When disabled, drift-remove a lingering
	//    berth-managed copy (guarded so a foreign conf.d file is never clobbered).
	if s.AnyCloudflareOnly() {
		cf, err := renderCloudflareConf()
		if err != nil {
			return err
		}
		if err := r.WriteFile(ctx, bssh.FileSpec{
			Path: cloudflareConfPath, Content: cf, Owner: "root", Group: "root", Mode: 0o644, Sudo: true,
		}); err != nil {
			return fmt.Errorf("write %s: %w", cloudflareConfPath, err)
		}
	} else {
		present, err := managedFilePresent(ctx, r, cloudflareConfPath)
		if err != nil {
			return err
		}
		if present {
			if res, err := r.Run(ctx, "rm -f "+shQuote(cloudflareConfPath), nil); err != nil {
				return err
			} else if res.ExitCode != 0 {
				return fmt.Errorf("remove %s: %s", cloudflareConfPath, res.Stderr)
			}
		}
	}
```

- [ ] **Step 8: Stub the cloudflare `cat` in the existing Apply tests**

The disabled step-0 path runs `cat '<cloudflareConfPath>'` via `managedFilePresent`. Existing `site.Apply` success-path tests now hit it. Add this one line after each `stubFPMApply(s, f)` call in `TestSiteApplyValidatesNginxBeforeReload`, `TestSiteApplyWritesManagedFiles`, and `TestSiteApplyWritesLogrotate` (return ExitCode 1 = absent, so no rm):

```go
	f.On("cat "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 1})
```

`TestSiteApplyAbortsOnNginxTestFailure` aborts at `nginx -t` (step 2), which is AFTER step 0, so step 0's `cat` DOES run there too — add the same stub right after its `f.On("nginx -t", ...)` line.

For `TestSiteCheckSatisfiedAfterTLSSwap`'s Apply phase (the `fApply` runner, ~line 492), the site is `selfsigned` SSL with `cloudflare_only` off, so step 0 also cats — add `fApply.On("cat "+shQuote(cloudflareConfPath), bssh.Result{ExitCode: 1})` alongside the other `fApply.On(...)` stubs.

- [ ] **Step 9: Run the full steps package test suite**

Run: `go test ./internal/provision/steps/`
Expected: PASS — all existing tests plus the four new ones. If any existing Apply test fails with `unstubbed command "cat '/etc/nginx/conf.d/berth-cloudflare.conf'"`, a stub from Step 8 is missing there.

- [ ] **Step 10: Commit**

```bash
git add internal/provision/steps/site.go internal/provision/steps/site_test.go
git commit -m "feat(site): write/remove the Cloudflare snippet, drift-managed like the scheduler cron"
```

---

## Task 5: Documentation + example config

**Files:**
- Modify: `README.md` (configuration reference section)
- Modify or create: an `examples/` config demonstrating `cloudflare_only`
- Test: `go test ./...` (the examples validity test, if present, re-validates example configs)

**Interfaces:** none (docs only).

- [ ] **Step 1: Find the README config-reference anchor and the examples test**

Run: `grep -n "scheduler" README.md | head` and `ls examples/` and `grep -rln "examples/" --include=*_test.go .`
Expected: locate where `scheduler` is documented in the README table/section (the new flag is documented right beside it) and identify the example-config validity test so a new/edited example stays valid.

- [ ] **Step 2: Document `cloudflare_only` in the README**

Add an entry next to `scheduler` in the configuration reference describing: server-level `cloudflare_only: true` (opt-in, default false) with per-site `cloudflare_only:` override; that it is enforced at the nginx layer (non-Cloudflare requests get `444`); that it restores the real client IP from `CF-Connecting-IP` for logs/fail2ban; and the cert guidance — pair a *proxied* `cloudflare_only` site with `ssl_mode: selfsigned` (Cloudflare Origin Certificate / Full mode), because berth skips Let's Encrypt issuance when the A record points at Cloudflare. Match the surrounding README style (heading depth, table vs prose, code-fence language) exactly.

- [ ] **Step 3: Add an example**

Add a `cloudflare_only: true` line (server-level) to an appropriate `examples/` config, or create a small dedicated example mirroring an existing one's structure. Keep it secret-free and host-agnostic (use `example.com`).

- [ ] **Step 4: Validate everything**

Run: `go test ./...`
Expected: PASS (including any examples-validity test). Then `gofmt -l internal/ cmd/` — expected: no output (nothing unformatted).

- [ ] **Step 5: Commit**

```bash
git add README.md examples/
git commit -m "docs: document and demonstrate the cloudflare_only flag"
```

---

## Final verification (run after all tasks)

- [ ] `go test -race ./...` — Expected: PASS (this is what CI runs).
- [ ] `go vet ./...` — Expected: clean (the only static check in CI).
- [ ] `gofmt -l .` — Expected: no output.
- [ ] `git diff --stat main...HEAD` — review the full change set: config (1 file + tests), new `cloudflare.go` + template + 3 goldens, two vhost templates + 2 goldens, `site.go` wiring + tests, README + examples. Confirm the four pre-existing nginx goldens are NOT in the diff.

## Self-Review (completed during planning)

- **Spec coverage:** §3 config → Task 1; §4.1/§5.1 snippet+ranges → Task 2; §4.2/§4.3/§5.2/§5.3/§5.4 guard+nginxData+mirror → Task 3; §6 step wiring (Check + Apply ordering + drift removal) → Task 4; §7 tests → distributed across Tasks 1-4 with the live-validation item deferred to manual testing (noted below); §9 docs → Task 5. §8 module assumption and §10 future options need no code.
- **Live validation (§7):** the from-scratch Debian 13 provision + `nginx -V`/`nginx -t`/444/real-IP/idempotency/drift round-trip is a MANUAL step on the disposable test box, performed after the unit work merges — it is not an automated task here.
- **Type consistency:** `nginxData.CloudflareOnly bool` is defined identically in `site.go` (Task 3 Step 3) and the test-local copy (Task 3 Step 7); `renderCloudflareConf`/`cloudflareConfPath`/`cloudflareIPRanges` defined in Task 2 and consumed unchanged in Task 4; `CloudflareOnlyEnabled`/`AnyCloudflareOnly` defined in Task 1 and consumed in Tasks 3-4.
- **Placeholder scan:** every code step shows complete code; every run step states the exact command and expected output.

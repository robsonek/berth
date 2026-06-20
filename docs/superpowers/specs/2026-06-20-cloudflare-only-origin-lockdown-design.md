# Design: Cloudflare-only origin lockdown (nginx layer)

**Status:** approved design, pending implementation plan
**Date:** 2026-06-20
**Branch:** `feat/cloudflare-only-origin`

## 1. Problem & goal

When a site sits behind Cloudflare (DNS proxied / "orange cloud"), an attacker who
discovers the origin's bare IP can bypass Cloudflare's WAF, rate limiting and DDoS
protection by hitting the origin directly. The standard mitigation is **origin
lockdown**: the origin only honours web traffic that arrived through Cloudflare's
published edge ranges.

berth should offer this as an opt-in, idempotent, declarative feature — one flag in
the YAML, enforced at the nginx layer, consistent with berth's existing managed-file
drift model.

### Goal

For a site with the feature enabled, any HTTP/HTTPS request whose **real TCP peer**
is not a Cloudflare edge address is refused at nginx, while the true client IP is
restored for logs/fail2ban from Cloudflare's `CF-Connecting-IP` header.

### Non-goals (explicit)

- **No firewall (ufw) restriction.** ufw stays open on 80/443 to the world. (Decision:
  enforce at nginx only — a firewall lockdown is harder to reason about, collides with
  Let's Encrypt HTTP-01, and was explicitly declined for v1 of this feature.) A future
  ufw-layer option is noted in §10.
- **Not hiding the existence of the server.** Public static paths (`/.well-known/acme-challenge/`,
  `/favicon.ico`, `/robots.txt`, `/build/assets/`) stay directly reachable by design
  (see §4.3). The goal is blocking *application* access from non-Cloudflare clients,
  not concealing that an HTTP server is listening (the open port already reveals that).
- **No Authenticated Origin Pulls (mTLS).** IP allowlisting only. mTLS with Cloudflare's
  origin CA is a possible future addition (§10).
- **No wizard integration in this PR.** The `init` wizard prompt is deferred to a
  separate, smaller change (§9).

## 2. Why the nginx layer (and the two hard constraints it must respect)

Two berth subsystems make the *layer choice* load-bearing:

1. **Let's Encrypt HTTP-01.** The `tls` step issues certs with `certbot --webroot`;
   LE's validation servers must reach port 80 **directly** (not via Cloudflare) when the
   domain is not yet proxied. A firewall lockdown to CF ranges would break first
   issuance. Enforcing at nginx (port 80 still open) keeps LE working, and we
   additionally exempt the ACME challenge location from the guard (§4.3).
2. **fail2ban + real client IP (mandatory).** If traffic arrives via Cloudflare, nginx
   sees Cloudflare edge IPs as the source. Without restoring the real client IP, any
   nginx-log-based fail2ban jail (Tier 2 roadmap) would ban **Cloudflare's edge =
   whole site down**. Therefore real-IP restoration (`set_real_ip_from` +
   `real_ip_header CF-Connecting-IP`) is bundled into this feature, not optional.

**Operational interplay with cert issuance (important).** When a `cloudflare_only` site
is actually proxied (orange cloud), its public A record points at Cloudflare, not the
origin. berth's `tls` step pre-checks DNS and *skips Let's Encrypt issuance with a
warning when DNS doesn't point at the host* — so a proxied site will not get an LE cert
from berth at all. The recommended pairing is therefore `ssl_mode: selfsigned` (a
self-signed origin cert, accepted by Cloudflare "Full" mode, or swapped operationally
for a long-lived Cloudflare Origin Certificate). Let's Encrypt stays supported for the
grey-cloud (DNS-only) case and the initial pre-proxy issuance window — which is exactly
why the guard exempts the ACME challenge location (§4.3) so HTTP-01 still completes.

## 3. Configuration surface

Mirrors the existing `scheduler` pattern exactly (flat server bool + per-site `*bool`
override; `nil` inherits the server value).

```yaml
cloudflare_only: true          # server-wide default (opt-in; default false)
sites:
  - domain: app.example.com    # inherits server default -> enabled
  - domain: api.example.com
    cloudflare_only: false     # per-site override -> disabled
```

### Struct changes (`internal/config/config.go`)

```go
type Server struct {
    // ...existing fields...
    CloudflareOnly bool `mapstructure:"cloudflare_only" yaml:"cloudflare_only"`
}

type Site struct {
    // ...existing fields...
    CloudflareOnly *bool `mapstructure:"cloudflare_only" yaml:"cloudflare_only,omitempty"`
}
```

- Both `mapstructure` and `yaml` tags are required (CLAUDE.md: an out-of-sync tag
  silently won't bind).
- No `SetDefault` needed — the zero value `false` is the intended default (opt-in). The
  feature is therefore inert for every existing config.

### Helpers (`internal/config/config.go`)

```go
// CloudflareOnlyEnabled reports whether origin lockdown applies to a site:
// an explicit per-site override wins, else the server-wide default.
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

`CloudflareOnlyEnabled` is the twin of `SchedulerEnabled` (config.go ~line 160).

## 4. nginx mechanism (two coupled artifacts)

### 4.1 Global http-context snippet — `/etc/nginx/conf.d/berth-cloudflare.conf`

Written whenever `AnyCloudflareOnly()`. Included in the `http` context by both supported
nginx sources (Debian's `nginx.conf` and nginx.org's `nginx.conf` both carry
`include /etc/nginx/conf.d/*.conf;`). Rendered via `templates.Render` (nginx uses `#`
comments, so the `# managed by berth` marker is valid).

```nginx
# managed by berth
set_real_ip_from 173.245.48.0/20;
# ... one line per Cloudflare v4 + v6 range ...
real_ip_header CF-Connecting-IP;

geo $realip_remote_addr $berth_cloudflare {
    default 0;
    173.245.48.0/20 1;
    # ... same ranges ...
}
```

**Why `$realip_remote_addr` (not `$remote_addr`).** The realip module rewrites
`$remote_addr` to the real client (from `CF-Connecting-IP`) but preserves the original
TCP peer in `$realip_remote_addr`. So:

- Request via Cloudflare: TCP peer = CF edge (in `set_real_ip_from`) → `$remote_addr`
  becomes the real visitor (good for logs/fail2ban), `$realip_remote_addr` = CF edge →
  `geo` yields `$berth_cloudflare = 1` → allowed.
- Direct hit to the origin IP: peer not in `set_real_ip_from` → no substitution →
  `$realip_remote_addr` = attacker IP → `geo` yields `0` → blocked.

The realip phase runs before the rewrite/`if` phase, so `$realip_remote_addr` and
`$berth_cloudflare` are populated before the per-site guard evaluates. Both `geo` and
`set_real_ip_from`/`real_ip_header` are http-context directives, available to every
server block regardless of include order within `http`.

`real_ip_recursive` is intentionally **omitted**: `CF-Connecting-IP` carries a single
client IP, not a multi-hop `X-Forwarded-For` chain, so recursion is a no-op.

**Header-spoofing safety.** On a non-Cloudflare site that is directly exposed, an
attacker sending a forged `CF-Connecting-IP` header is ignored: realip only trusts the
header when the connection originates from a `set_real_ip_from` range, which the
attacker is not in.

### 4.2 Per-site guard (injected into the server block)

Only when `CloudflareOnlyEnabled(site)`. Added inside every `location /` and PHP location
across **both** templates, so a direct non-Cloudflare client gets an identical no-response
on either port:

- `nginx_http.conf.tmpl` (the serving block for non-SSL sites, and the pre-issuance block
  for an SSL site before its cert exists): guard `location /` and `location ~ \.php$`.
- `nginx_https.conf.tmpl`: guard the 443 serving block's `location /` and
  `location ~ \.php$`, **and** the port-80 redirect block's `location /` (so a direct
  port-80 scan gets `444`, not a `301` that leaks the host/domain).

The injected directive:

```nginx
    location / {
        if ($berth_cloudflare = 0) { return 444; }
        try_files $uri $uri/ /index.php?$query_string;
    }
    # ...
    location ~ \.php$ {
        if ($berth_cloudflare = 0) { return 444; }
        fastcgi_pass unix:{{ .Socket }};
        # ...
    }
```

- `if (...) { return 444; }` inside a `location` is on nginx's documented 100%-safe
  list (`return` / `rewrite ... last` are the only blessed uses of `if`). `444` closes
  the connection with no response — cheapest refusal and reveals nothing to a direct
  scanner.
- Guarding `location /` and `location ~ \.php$` covers **every dynamic request**: app
  routes funnel through `location /` → `try_files` → `/index.php`, and a direct
  `/index.php` matches the regex PHP location (regex locations take precedence over the
  `/` prefix). Direct file access under the doc-root also routes through `location /`
  and is blocked. An internal redirect (`try_files` fallback or `error_page 404 /index.php`)
  re-runs location matching and re-enters the guarded PHP location, so there is no
  unguarded path into FastCGI.
- The guard lives in the 443 server block, which carries both the TCP and (when HTTP/3
  is enabled) the QUIC `listen` directives — `$realip_remote_addr` is set for QUIC too,
  so the guard applies uniformly. Note Cloudflare connects to the origin over HTTP/1.1 or
  HTTP/2, never HTTP/3, so enabling `http3` on a `cloudflare_only` site is redundant but
  harmless.

### 4.3 What stays directly reachable (and why)

Locations deliberately **not** guarded:

- `location /.well-known/acme-challenge/` — so Let's Encrypt HTTP-01 succeeds even when
  the domain is not yet proxied through Cloudflare (the narrow but real grey-cloud setup
  window). Serving public ACME challenge tokens to a direct client is harmless.
- `location = /favicon.ico`, `location = /robots.txt`, `location ^~ /build/assets/` —
  public static assets, also cached at the Cloudflare edge; direct origin access leaks
  nothing not already public. Leaving them unguarded keeps the guard insertions to the
  dynamic locations and avoids `if` in static-file locations.

The port-80 redirect block's `location /` **is** guarded (§4.2), so a direct port-80 scan
of an SSL site gets `444` rather than a `301` that would echo the domain — but the ACME
location in that same block stays exempt, so HTTP-01 on port 80 still works.

This is the §1 non-goal made concrete: block the application, not conceal the server —
while still avoiding a gratuitous host-leaking redirect to a direct scanner.

## 5. Template & rendering changes

### 5.1 New template `internal/templates/cloudflare.conf.tmpl`

Renders §4.1 from a `Ranges []string` field. The canonical Cloudflare range list lives
as a Go slice (not a second `embed.FS`) so it is reviewable and trivially testable:

```go
// internal/provision/steps/cloudflare.go
//
// Cloudflare edge IP ranges, snapshot 2026-06-20.
// Source: https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6
// These ranges are extremely stable (the v4 list has been unchanged for years);
// refresh on release if Cloudflare publishes a change.
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
```

Template body (the `# managed by berth` marker is prepended by `templates.Render`):

```
{{- range .Ranges }}
set_real_ip_from {{ . }};
{{- end }}
real_ip_header CF-Connecting-IP;

geo $realip_remote_addr $berth_cloudflare {
    default 0;
{{- range .Ranges }}
    {{ . }} 1;
{{- end }}
}
```

### 5.2 Edit `nginx_http.conf.tmpl` and `nginx_https.conf.tmpl`

Add a `CloudflareOnly` field to the `nginxData` render struct and wrap each guard in
`{{- if .CloudflareOnly }} ... {{- end }}`. The exact whitespace-trim form (verified
empirically by rendering both cases through `text/template` and diffing against the
current golden) keeps the **CloudflareOnly:false output byte-identical to today's**.
Two trim pitfalls to avoid: `{{- end }}` MUST keep its left dash (a plain `{{ end }}`
injects a blank line on the false path → golden drift), and it MUST NOT gain a right
dash (`{{- end -}}` would swallow the newline before `try_files`, corrupting both cases):

```
    location / {
{{- if .CloudflareOnly }}
        if ($berth_cloudflare = 0) { return 444; }
{{- end }}
        try_files $uri $uri/ /index.php?$query_string;
    }
```

When false the `{{- if }}` trims the newline after `location / {`, the body is skipped,
and `        try_files` follows on the next line exactly as in the current golden. When
true, the guard line is emitted between them (8-space indent, its own line). The same
wrapping is added to the `location ~ \.php$` block in both templates, **and** to the
port-80 redirect block's `location /` in `nginx_https.conf.tmpl` (§4.2).

> **Byte-identical idempotency is the load-bearing invariant.** The existing goldens
> (`nginx_http.golden`, `nginx_https.golden`, `nginx_https_http3.golden`,
> `nginx_https_nohsts.golden`) carry `CloudflareOnly:false` and MUST stay unchanged
> after the edit. If they drift, every already-deployed managed vhost is misclassified
> and `site` re-runs forever. Run `go test -update ./internal/templates/...`, then
> **diff the goldens and confirm only the new true-case files changed.**

### 5.3 `nginxData` plumbing (`internal/provision/steps/site.go`)

```go
type nginxData struct {
    Domain, DeployPath, ACMEWebroot, Socket, CertPath, KeyPath string
    HTTP3, QUICReuseport, HSTS, CloudflareOnly                 bool
}

func nginxRenderData(s *config.Server, site config.Site) nginxData {
    return nginxData{
        // ...existing...
        CloudflareOnly: s.CloudflareOnlyEnabled(site),
    }
}
```

`CloudflareOnly` is derived **purely from static config**, never from cert presence —
exactly like `HSTS`. This is what keeps the cert-aware `site` re-render and the `tls`
`swapToHTTPS` re-render byte-identical: both call `renderNginxHTTPS` →
`nginxRenderData`, so re-running `site` after issuance reproduces the identical guarded
block (hash matches) and never reverts TLS.

### 5.4 Mirror the test-local copy (CLAUDE.md requirement)

`internal/templates/templates_test.go` keeps its own copy of `nginxData`. Add the
`CloudflareOnly bool` field there too, and add golden cases for the true variant (see §7).

## 6. Step wiring (`site` step owns both artifacts)

The global snippet and the per-site guard **must live in the same step** (`site`).
Otherwise `--only site` could render a vhost referencing `$berth_cloudflare` while the
`geo` that defines it is owned by a different step — `nginx -t` then fails with
"unknown variable $berth_cloudflare". Keeping both in `site` means one Apply writes them
together and one `nginx -t` validates them together.

### 6.1 `managedSiteFiles` (Check side)

Append (or, when disabled, mark for removal) the snippet, alongside the existing global
logrotate entry:

```go
const cloudflareConfPath = "/etc/nginx/conf.d/berth-cloudflare.conf"

if s.AnyCloudflareOnly() {
    conf, err := renderCloudflareConf()      // templates.Render("cloudflare.conf.tmpl", {Ranges: cloudflareIPRanges})
    if err != nil { return nil, err }
    files = append(files, siteFile{path: cloudflareConfPath, content: conf})
} else {
    files = append(files, siteFile{path: cloudflareConfPath, remove: true})
}
```

The existing `siteFile.remove` machinery handles drift exactly like the scheduler cron:
`Check` flags a lingering berth-managed snippet via `managedFilePresent`, and only a
berth-managed file is ever removed (a foreign `conf.d` file is never clobbered, even
with `--force`).

### 6.2 `Apply` ordering (critical)

In `site.Apply`, write/remove the snippet **before** the per-site vhost loop and the
first `nginx -t`, so validation never sees a vhost referencing an undefined variable:

```
0) reconcile /etc/nginx/conf.d/berth-cloudflare.conf:
     - AnyCloudflareOnly() -> WriteFile(snippet)
     - else -> if managedFilePresent: rm -f   (guarded; never a foreign file)
1) per-site nginx server block (cert-aware) + enable   [existing]
2) nginx -t  +  reload                                  [existing]
   ...
```

Reuse the `managedFilePresent`-guarded `rm -f` pattern already used for the scheduler
cron (site.go ~lines 518–530).

### 6.3 No new pipeline step, no new `Requires()`

Everything folds into `site` (which already owns vhosts + the global logrotate file).
The step DAG is unchanged. ufw/`hardening` is untouched.

## 7. Testing

- **Config unit tests** (`internal/config`): `CloudflareOnlyEnabled` — per-site `true`
  override beats server `false`, per-site `false` beats server `true`, `nil` inherits;
  `AnyCloudflareOnly` over mixed site sets.
- **Golden tests** (`internal/templates`):
  - New `cloudflare.golden` for `cloudflare.conf.tmpl` (assert every v4+v6 range appears
    in both `set_real_ip_from` and the `geo` block, the `# managed by berth` marker, and
    `real_ip_header CF-Connecting-IP`).
  - New true-case goldens: `nginx_http_cloudflare.golden`, `nginx_https_cloudflare.golden`
    (assert the `if ($berth_cloudflare = 0) { return 444; }` guard appears in `location /`
    and the PHP location — and, for the https golden, in the port-80 redirect block's
    `location /` too — while `/.well-known/acme-challenge/` stays **un**guarded).
  - Confirm the four existing false-case goldens are unchanged after `-update`.
- **Step tests** (`internal/provision/steps`, FakeRunner): `site` Apply writes
  `berth-cloudflare.conf` when enabled and removes it (drift) when disabled; the rendered
  vhost contains the guard; stub the exact command strings (`cat`, `ln -sfn`, `nginx -t`,
  `systemctl reload nginx`, the guarded `rm -f`) and assert `Calls()`/`Writes()`.
- **Live validation** (manual, on the disposable Debian 13 test box): from-scratch
  provision with `cloudflare_only: true`, confirm `nginx -V 2>&1 | grep -q http_realip`
  (realip module present) and `nginx -t` passes, a direct origin hit returns no response
  (444), a request carrying a `set_real_ip_from`-trusted source + `CF-Connecting-IP` is
  served and logs the real client; then an all-Satisfied re-run (idempotency) and a
  disable→re-run drift-removal round-trip.

## 8. Dependency assumptions

Both berth-supported nginx sources ship the required modules: `ngx_http_realip_module`
and `ngx_http_geo_module` are compiled into Debian 13's `nginx` package and the
nginx.org mainline packages (verified during design — Debian's build carries
`--with-http_realip_module` and `geo` is a default-built standard module). The §7 live
test asserts module presence once via `nginx -V`; no runtime probe runs inside the
`site` step — a missing module would otherwise surface loudly as an `nginx -t` failure.

## 9. Documentation & follow-ups

- Update the README configuration reference: document `cloudflare_only` (server-level and
  per-site), the nginx-layer enforcement, the bundled real-IP restoration, and the
  Let's Encrypt / proxied-domain interaction — including the explicit recommendation to
  pair a proxied `cloudflare_only` site with `ssl_mode: selfsigned` (Cloudflare Origin
  Certificate / Full mode), since berth skips LE issuance when the A record points at
  Cloudflare (§2).
- Update / add an `examples/` config showing `cloudflare_only`.
- **Deferred (separate PR):** an `init` wizard prompt for the flag, to keep this change
  focused.

## 10. Future options (out of scope here)

- **ufw-layer lockdown** restricting inbound 80/443 to Cloudflare ranges (stronger:
  the origin never answers non-CF packets at all), gated to avoid breaking Let's Encrypt
  (e.g. require `ssl_mode: selfsigned` / a Cloudflare Origin Certificate, or keep port 80
  open for LE). Deliberately deferred per the §1 layer decision.
- **Splitting real-IP restoration from blocking** into two flags, for operators who want
  correct logging behind Cloudflare without hard-blocking direct access.
- **Authenticated Origin Pulls (mTLS)** with Cloudflare's origin CA — stronger than IP
  allowlisting, but a larger surface (cert distribution, rotation).
- **Refresh command / live fetch** of the Cloudflare range list. Rejected for now: a
  baked snapshot keeps the render byte-identical (idempotent) and free of a provision-time
  network dependency; the ranges change rarely and can be refreshed at release.

## 11. Design verification

This design was adversarially verified by four independent agents before approval:

- **nginx semantics** — all eight behavior claims confirmed against official nginx docs:
  `$realip_remote_addr` is the documented (1.9.7) preserved original peer and the correct
  (and only safe) variable to allowlist; realip runs at `POST_READ`, before location/`if`
  (nginx trac #1589); `if { return 444; }` is on the blessed safe list; `geo`/realip are
  http-context with global variable availability; `conf.d/*.conf` is http-included by both
  Debian 13 and nginx.org configs; `--with-http_realip_module` is in the Debian build and
  `geo` is a default-built standard module (the design uses `ngx_http_geo_module`, not the
  optional GeoIP module).
- **codebase fit** — every referenced function/struct/path/line verified against source
  (scheduler twin, `siteFile{remove}`/`managedFilePresent`, Apply ordering, `swapToHTTPS`
  sharing `renderNginxHTTPS`, `nginxData` + its test-local mirror, marker mechanics); no
  CLAUDE.md contradictions.
- **security / bypass** — no path for a non-Cloudflare client to reach PHP; PATH_INFO
  tricks, `^~ /build/assets/`, internal redirects, and header spoofing all close cleanly;
  embedded ranges match the live `cloudflare.com/ips` lists exactly (2026-06-20); TCP/QUIC
  handshake defeats source-IP spoofing. Surfaced the port-80-redirect disclosure now fixed
  in §4.2/§4.3.
- **idempotency / template** — empirically rendered both cases through `text/template`:
  the `CloudflareOnly:false` output is byte-identical to the current goldens, the true case
  is correctly indented, and the two trim pitfalls are avoided (§5.2).

# Design: validation guard for cloudflare_only + Let's Encrypt

Date: 2026-07-02
Status: approved (user; approach chosen over auto-selecting selfsigned and over
supporting LE issuance through the Cloudflare proxy — the latter was explicitly
REJECTED for the roadmap too, because it would route ACME traffic over plain
port 80 through the proxy and cannot be live-tested without a CF-proxied domain)
Source: design-review finding M2 (docs/improvement-roadmap.md § Design-review
findings — 2026-07-02)

## Problem

`cloudflare_only` (origin lockdown) is by definition used with a proxied
(orange-cloud) DNS record, so the domain's A record resolves to Cloudflare edge
IPs, never to `s.Host`. The `tls` step's `dnsPointsAtHost` gate therefore always
fails and Let's Encrypt issuance is skipped with a single, easy-to-miss warning
(`tls.go:78-81`). Result: the origin has no `:443` listener; Cloudflare SSL
mode Full/Full-strict gets 521; only insecure Flexible "works". The correct
pairing — `ssl_mode: selfsigned` served behind CF "Full" — is documented in
`examples/multisite-postgres.yml` but nothing enforces it, and the init wizard
can generate the broken combination.

## Decision

Hard validation error. No auto-correction (mutating declared config is against
the repo's explicit-toggle philosophy), no warning-only (leaves the silent-521
deploy possible), no LE-through-proxy support (rejected, see Status).

## Design

### 1. Validation rule (internal/config/validate.go)

In `Server.Validate()`'s per-site loop (server level — the rule needs
`s.CloudflareOnlyEnabled(site)`, which resolves the per-site `*bool` override
against the server default; `Site.validate()` cannot see the server):

```go
if st.SSL && s.CloudflareOnlyEnabled(st) && st.CertMode() == "letsencrypt" {
    return fmt.Errorf("site %s: cloudflare_only cannot issue a Let's Encrypt certificate (a proxied DNS record never points at the origin); use ssl_mode: selfsigned (Cloudflare SSL mode \"Full\") or disable cloudflare_only for this site", st.Domain)
}
```

Cases: `ssl: false` + cloudflare_only is fine (no cert involved);
cloudflare_only + selfsigned is the documented pairing and passes; a per-site
`cloudflare_only: false` override under a server-wide `true` passes with LE.

### 2. Wizard enforcement (internal/wizard/run.go)

- Server-wide case (`cloudflare_only` answered in ServerOps, before the site
  loop) is already caught by the existing incremental per-site
  `cand.ToServer().Validate()` after `SiteCore` — re-prompts with the pointed
  message. No change.
- Ordering gap: the per-site override (`SiteOverrides`) and queue/daemons are
  collected AFTER that incremental validation, so an override-introduced
  violation would surface only at final `Write()`. Fix: run a SECOND
  `cand.ToServer().Validate()` after the advanced block completes; on failure
  `ShowError` and retry the site from `SiteCore`. This adds no prompts (existing
  scripted tests unaffected on the happy path) and also closes the pre-existing
  gap where cross-site queue/daemon program collisions surfaced only at
  `Write()` (design-review wizard finding L4).

### 3. Unchanged

- `examples/` — the proxied tenant already uses `ssl_mode: selfsigned`;
  `TestExampleConfigsAreValid` stays green.
- The `tls` step and its DNS gate (protects LE rate limits) — untouched.
- The `fmt.Printf` renderer-bypass in tls.go — separate LOW finding.
- README: verify the Cloudflare origin-lockdown section states the
  selfsigned pairing requirement; add one sentence only if missing.

## Tests (TDD)

- `internal/config/validate_test.go` — table:
  server-wide `cloudflare_only: true` + site `ssl: true` (default LE) → error
  containing "cloudflare_only";
  per-site override `cloudflare_only: &true` + LE → error;
  cloudflare_only + `ssl_mode: selfsigned` → valid;
  cloudflare_only + `ssl: false` → valid;
  per-site override `&false` under server-wide `true` + LE → valid.
- `internal/wizard` — matrix negative scenario asserting the exact rejection
  for a wizard-built config; scripted `run()` test for the second-validate
  retry path: SiteOverrides sets cloudflare on for an LE site → ShowError →
  site re-prompted → corrected (selfsigned) → completes.

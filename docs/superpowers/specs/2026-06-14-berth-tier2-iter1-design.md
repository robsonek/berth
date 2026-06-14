# berth — Tier 2, Iteration 1: test-insurance foundation (design)

> Status: approved design, pre-implementation
> Date: 2026-06-14
> Source: `docs/improvement-roadmap.md` "Tests to run next" items 18, 30, 33
> Decisions locked with the maintainer 2026-06-14; design reviewed and ACCEPTed by Codex
> (two of Codex's three revision points were refuted from code; see "Review resolution").

## Goal

Lay the cheap, high-ROI safety net under all later Tier 2 feature work **before** any feature
that stresses berth's most fragile contracts touches the code. This iteration adds only tests
(plus one intentional change to the integration harness's TLS-skip logic). It proves three
load-bearing invariants the current suite does not:

1. The cross-step `site`↔`tls` cert-aware re-render does not detect drift after issuance (#18).
2. A second full pipeline run over the same host reports every step satisfied — berth's defining
   idempotency contract (#30).
3. Self-signed TLS issuance + the HTTPS swap actually work on a live host, by default, with no DNS
   dependency (#33).

These three reinforce each other: when the smoke config carries a self-signed SSL site, the #30
second run is exactly where the #18 contract is proven hash-stable on a real host.

## Scope

**In scope (3 items, test-only):**

- **A. #18** — add the missing cross-step *sequence* test (`tls.Apply` → `site.Check` ⇒ Satisfied),
  unit-level, in `internal/provision/steps/`.
- **B. #30** — add a second-run idempotency assertion to the integration smoke test
  (`test/integration/provision_test.go`).
- **C. #33** — exercise self-signed TLS by default in the integration smoke test (no DNS), with the
  end-state assertions; reinterpret `BERTH_TEST_SKIP_SSL` semantics (the only non-test change).

**Out of scope (later Tier 2 test work, deferred):**

- Live multi-site cross-tenant isolation (#31), app-user DB auth over TCP (#32), Postgres e2e (#29),
  hardening end-state (#37), flag behavior (#34), source switching (#35), queue/FPM runtime (#36).
  These are a larger live-host harness expansion and were explicitly deferred to a later iteration.
- Real Let's Encrypt (non-staging) issuance — stays opt-in, needs real public DNS.
- Any new feature (queue/daemons, nginx cluster, swap/sysctl/tuning, backups, per-site PHP).

## Key discovery (scope correction)

The roadmap lists #18 as fully open, but **half of it already shipped with Tier 1**:
`TestSiteHTTPSRenderMatchesTLSSwap` (`internal/provision/steps/site_test.go:309`) already asserts
byte-equality between `site`'s cert-aware HTTPS render (`renderSiteNginx` with cert present) and
`tls`'s `swapToHTTPS` source (`renderNginxHTTPS`). It landed with the HSTS work (commit `36b78fe`).

So #18 reduces to the **second, missing half**: a cross-step *sequence* test proving that after the
`tls` step issues a cert and swaps the vhost to the 443 block, a subsequent `site.Check` returns
`Satisfied:true` with no further write. Byte-equality of the renderer is necessary but not
sufficient — the sequence test proves the full live ordering (`site` runs before `tls`; `tls`
overwrites the vhost; a `site` re-run must see the converged state, not drift).

## Locked decisions

1. **#18 sequence-test fidelity — high fidelity, self-signed path.** Drive the full live ordering:
   `site.Apply` (HTTP block, no cert) → `tls.Apply` (self-signed issuance + `swapToHTTPS`) →
   `site.Check`. Self-signed avoids DNS/certbot stubbing entirely.
2. **#18 runner strategy — separate, freshly-seeded FakeRunner for the Check phase.** Build a
   `path → content` map from the Apply phase's `Writes()` (a Go map is last-write-wins, so `tls`'s
   HTTPS overwrite of the vhost is correctly reflected), seed a fresh `FakeRunner` with `cat '<path>'`
   stubs from that map, and flip `test -e '<cert>'` to present (exit 0). Contained in the `steps`
   test package — **no change to `internal/ssh/fake.go`.**
3. **#30 exemption — only `preflight`, by name.** It is the sole `AlwaysRun` step
   (`preflight.go:23`); its `Check` returns `Satisfied:false` by design to re-`apt-get update`.
   Events carry only `Step string` (`internal/provision` `Event`), so a by-name whitelist is the
   only option. **No other step is whitelisted.** Adding a "just in case" exemption (e.g. the
   scheduler cron) would mask the exact idempotency-regression class #30 exists to catch.
4. **#33 skipSSL semantics — driven by `CertMode()`, intentional default change.** Self-signed
   needs no DNS, so it runs by default; Let's Encrypt stays opt-in. Documented as a behavior change.

## Review resolution (Codex)

Codex's initial verdict was REVISE with three points; resolved as follows, confirmed by Codex:

- **A (alleged FakeRunner FIFO / stub-collision) — REFUTED.** `On()` is a map assignment
  (`internal/ssh/fake.go:28`, `f.responses[cmd] = r`), i.e. last-write-wins; only `OnSeq` appends to
  the `sequences` slice and is consumed FIFO. Re-stubbing a command via `On()` cleanly overrides.
  The separate-runner strategy (decision 2) is adopted for clarity regardless, not to dodge a FIFO
  hazard that does not exist.
- **B (alleged need for a `scheduler: true` config guard) — REFUTED.** The `siteFile{remove:true}`
  drift-removal converges in run 1: when the scheduler is disabled and a managed cron exists, run 1
  `Check` is unsatisfied (`managedFilePresent == true`) → run 1 `Apply` `rm -f`s it; run 2 `Check`
  sees the file absent → satisfied. `Check` and `Apply` share the `managedFilePresent` guard
  (`site.go:231-240`, `site.go:363-375`), so the second run never re-applies regardless of the
  scheduler setting. No config guard, no extra whitelist.
- **C (BERTH_TEST_SKIP_SSL behavior change) — ACCEPTED, documented below.**

## A. #18 — cross-step sequence test (unit)

**Location:** `internal/provision/steps/site_test.go` (new test, e.g. `TestSiteCheckSatisfiedAfterTLSSwap`)
plus a local replay helper in the same package.

**Fixture:** a single-site server with `Sites[0].SSL = true` and `Sites[0].SSLMode = "selfsigned"`,
scheduler left at its default (on). Self-signed because `issueSelfSigned` (`tls.go:121`) is pure
local `openssl` over SSH — zero DNS, no certbot, no resolver stub.

**Flow (high fidelity, models the live registry order — `site` before `tls`, `registry.go`):**

1. `fApply` (fresh `FakeRunner`). Stub `test -e '<certFullchainPath>'` → exit 1 (no cert yet) so
   `renderSiteNginx`'s `certInstalled` (`site.go:115`) takes the HTTP branch, and `certValid` for
   self-signed (`tls.go:177-188`) returns false without calling `openssl x509` (it returns early on
   absent). Stub the rest of both Apply paths:
   - `site.Apply`: `ln -sfn …`, `nginx -t` (0), `systemctl reload nginx`, the www-pool disable
     (`test -f … && mv …`), `php-fpm<ver> -t` (0), `systemctl reload php<ver>-fpm`,
     `logrotate -d '<logrotatePath>'` (0). (Mirror the existing `stubFPMApply` helper.)
   - `tls.Apply` self-signed: `apt-get install -y openssl`, `install -d -m 0755 '<certDir>'`, the
     `openssl req -x509 …` line, `chmod 600 '<key>'`, `nginx -t` (0), `systemctl reload nginx`.
2. Run `Site().Apply(fApply)` then `TLS().Apply(fApply)`. The vhost is written twice (HTTP by site,
   then HTTPS by tls's `swapToHTTPS`).
3. Build `latest := map[path]content` from `fApply.Writes()` iterating in order (last write wins ⇒
   vhost = the tls HTTPS block; other managed files = what `site.Apply` wrote).
4. `fCheck` (fresh `FakeRunner`): for each `(path, content)` in `latest`, stub
   `cat '<path>'` → `{Stdout: content, ExitCode: 0}`. Flip `test -e '<cert>'` → exit 0 (cert now
   present). Stub `nginx -t` (0) and `php-fpm<ver> -t` (0).
5. Assert `Site().Check(fCheck)` returns `Satisfied:true`, and `len(fCheck.Writes()) == 0`
   (Check is side-effect-free; this documents that the engine would skip `site.Apply`, so the TLS
   443 block is never reverted).

**Why it holds:** in step 4, `site.Check` recomputes `managedSiteFiles` with the cert present, so the
desired vhost is `renderNginxHTTPS` — byte-identical to what `tls` wrote in step 2 (same renderer);
`checkManagedFile` (`common.go:85`) hashes the `cat` content against the desired and reports
`uptodate`. Every other managed file's desired re-render equals its seeded content. With `nginx -t`
and `php-fpm -t` green, `Check` is satisfied.

**Replay helper:** a small unexported test helper that takes `fApply.Writes()` and a target
`FakeRunner` and registers the last-write-wins `cat` stubs. Lives in the test package only.

**Verification:** standard `go test ./internal/provision/steps/...` — a real red→green (the test
fails today because no such sequence assertion exists).

## B. #30 — second-run idempotency assertion (integration)

**Location:** `test/integration/provision_test.go`, extending `TestProvisionFreshDebian13` (or a
helper `assertSecondRunIdempotent`) after the existing first run drains its events
(`provision_test.go:68-82`).

**Design:** immediately invoke the pipeline a **second time** over the same `client` (reuse `eng`;
steps are stateless), drain the event channel, and assert:

- zero `EventFailed` (any failure fails the test with the step name + error),
- zero `EventApplied` **except** for `ev.Step == "preflight"` (the documented `AlwaysRun` exception),
- implicitly, every other step emits `EventSatisfied`.

A second-run `EventApplied` from any step other than `preflight` is a real idempotency regression and
must fail the test — that is the entire point of the assertion (catches managed-marker/template hash
drift, the `env.tmpl` divergence trap, and the `site`↔`tls` cert-aware re-render reversion class).

**Coverage interaction:** the second run uses the same config as the first. When the smoke config
carries a self-signed SSL site (recommended, see C), the second run drives the `site`/`tls`
re-render live and proves it hash-stable on a real host — the strongest available end-to-end check
of the #18 contract.

**Verification:** behind the `integration` build tag — `go test ./...` does not compile it. Real
red→green is a live run on a Debian 13 host (smoke.example.com), not local `go test`.

## C. #33 — self-signed TLS smoke, default-on (integration)

**Location:** `test/integration/provision_test.go`.

**Current behavior:** `skipSSL := os.Getenv("BERTH_TEST_SKIP_SSL") != "false"` (`provision_test.go:64`)
— TLS is skipped unless the operator sets `=false`; `steps.Pipeline(srv, red, skipSSL)` then omits
the `tls` step entirely.

**New semantics (CertMode-driven):**

```go
sslEnv := os.Getenv("BERTH_TEST_SKIP_SSL")
// Self-signed TLS needs no public DNS, so it runs by default. Let's Encrypt
// (HTTP-01 / ACME) needs real DNS, so it stays opt-in via BERTH_TEST_SKIP_SSL=false.
skipSSL := sslEnv == "true" || (sslEnv == "" && !anySiteSelfSigned(srv))
```

- `""` (default) → TLS runs iff the config has a self-signed site; otherwise skipped.
- `"false"` → TLS runs for everything, including Let's Encrypt (unchanged from today).
- `"true"` → hard skip, even self-signed (new explicit escape hatch).

`anySiteSelfSigned(srv)` is pure static config: `site.SSL && site.CertMode() == "selfsigned"`.
Running the `tls` step on a mixed or LE-only config is safe: `tls.Apply` is per-site and skips LE
sites with a logged warning (not an error) when DNS does not point at the host (`tls.go:78-81`);
self-signed sites issue unconditionally; there is no cross-site state.

**Behavior change (intentional, documented):** for a config that **has a self-signed site** and is
run **without** `BERTH_TEST_SKIP_SSL`, TLS now runs by default (previously skipped). Configs without
a self-signed site and without the env var are unaffected (still skipped). berth's existing
self-signed test configs (e.g. smoke.yml) will start exercising TLS by default in the gate — the
desired outcome of #33. This will be called out in the iteration's README/changelog note.

**Assertions when a self-signed site was provisioned (helper `assertSelfSignedCert`):**

- `<certDir>/fullchain.pem` exists, where `certDir = /etc/ssl/berth/<domain>` (`site.go:103`).
- `openssl x509 -checkend <certRenewWindow-seconds> -noout -in <fullchain>` exits 0 (valid beyond
  the renew window), matching `certValid`'s own self-signed check (`tls.go:182-187`).
- `https://<host>/` serves (reuse `assertHTTPServes`; a pre-deploy 502 is acceptable).
- No-revert-to-HTTP across runs is proven by B (the second run leaves `site` satisfied).

**Live-test precondition:** the smoke config on smoke.example.com should include a site with
`ssl: true` and `ssl_mode: selfsigned` so A (unit) + B + C reinforce each other in one provision.

**Verification:** behind the `integration` tag — live host only.

## Error handling / edge cases

- **A:** the `openssl req` stub string must match `tls.go:131-133` exactly (FakeRunner requires exact
  command strings); reuse the construction already mirrored in `TestTLSSelfSignedIssuesWithoutCertbotOrDNS`
  (`tls_test.go:228-230`). The FPM-pool file uses the `;` INI marker (`RenderINI`); `hasManagedMarker`
  (`common.go:27`) accepts both `#` and `;`, so the replayed `cat` content classifies as managed.
- **B:** the first run is fail-fast (`engine.go`), so if it emits any `EventFailed` the test already
  fails before the second run — the second-run assertion only ever runs against a converged host.
- **C:** if the operator's config has no self-signed site and no env var, the gate behaves exactly as
  before (TLS skipped) — no surprise for existing LE-only or no-SSL configs.

## Verification strategy (summary)

| Item | Tag | Red→green proof |
|------|-----|-----------------|
| A #18 | none (unit) | `go test ./internal/provision/steps/...` — fails today, passes after |
| B #30 | `integration` | live provision on smoke.example.com; second run all-satisfied (preflight excepted) |
| C #33 | `integration` | live provision with a self-signed site; cert + 443 assertions pass |

Local `go vet ./...` and `go test -race ./...` must stay green. The live gate sequence (per the
maintainer's workflow): wipe smoke.example.com → re-pin the ECDSA host fingerprint → first provision of the
fresh box with `--force` → run the integration test.

## Out of scope / future

The remaining Tier 2 live-host test expansion (#29, #31, #32, #34, #35, #36, #37) and all Tier 2
features follow in later iterations, each with its own spec → plan → TDD → review → live-test cycle.

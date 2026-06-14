# Tier 2 Iteration 1 — Test-Insurance Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the three test-insurance items (#18 cross-step `site`↔`tls` sequence test, #30 second-run idempotency assertion, #33 default-on self-signed TLS smoke) that lock in berth's most fragile contracts before any later Tier 2 feature work touches them.

**Architecture:** Test-only. #18 is a unit test in the `steps` package driven through the real `site.Apply` → `tls.Apply` → `site.Check` ordering, using a fresh FakeRunner for the Check phase seeded from the Apply phase's writes (last-write-wins). #30 and #33 extend the single integration smoke test (`integration` build tag); #33's only non-test change is reinterpreting the `BERTH_TEST_SKIP_SSL` gate via `CertMode()`.

**Tech Stack:** Go 1.25, standard `testing`, the in-repo `bssh.FakeRunner` test double, the `integration` build tag, `openssl`/`nginx`/`certbot` on a live Debian 13 host for the integration green.

**Source spec:** `docs/superpowers/specs/2026-06-14-berth-tier2-iter1-design.md`

**Branch:** `feat/tier2-iter1-test-insurance` (already created off `main`; spec already committed as `e2a4fb8`).

**TDD note for characterization tests:** #18/#30/#33 guard behavior that already works, so a naively-written test passes immediately. To keep TDD honest, each task includes a **vacuity check**: temporarily break the production contract, watch the new test go RED, then revert and watch it go GREEN. A test that cannot fail is worthless. For the integration tasks (B/C), the local check is *compile + clean skip* under the `integration` tag; the real RED→GREEN happens on the live host (Task 4).

---

### Task 1: #18 — cross-step `site`→`tls`→`site` sequence test (unit)

**Files:**
- Modify (add helper + test): `internal/provision/steps/site_test.go`

**Background (verified against code):**
- The byte-equality half of #18 already exists: `TestSiteHTTPSRenderMatchesTLSSwap` (`site_test.go:309`). Do NOT duplicate it.
- `site` runs before `tls` (`registry.go`). `tls`'s `swapToHTTPS` overwrites the vhost with `renderNginxHTTPS` (`tls.go:149`). `site.Check` re-renders cert-aware via `renderSiteNginx` (`site.go:123`), which calls `certInstalled` → `fileExists` → `test -e '<cert>'` (`common.go:66`).
- `FakeRunner.On` is a map assignment (`fake.go:28`) — last-write-wins, not FIFO.
- `certValid` for self-signed returns early on an absent cert without calling `openssl x509` (`tls.go:177-188`).
- Reuse existing helpers `stubFPMApply` (`site_test.go:447`) and the fixture `siteServer()` (`site_test.go:14`).

- [ ] **Step 1: Add the replay helper and the sequence test**

Append both to `internal/provision/steps/site_test.go` (no new imports — `context`, `fmt`, `bssh`, `provision`, `config` are already imported):

```go
// replayWritesAsReads seeds dst with `cat '<path>'` stubs for every file written
// during an Apply phase, last-write-wins: a Go map dedupes by path, so a later
// overwrite (e.g. the tls step swapping the vhost to the 443 block) wins. This
// models a real host where the files an earlier step wrote are what a later
// Check reads back via `cat`.
func replayWritesAsReads(dst *bssh.FakeRunner, writes []bssh.FileSpec) {
	latest := map[string][]byte{}
	for _, w := range writes {
		latest[w.Path] = w.Content
	}
	for path, content := range latest {
		dst.On("cat "+shQuote(path), bssh.Result{Stdout: string(content), ExitCode: 0})
	}
}

// TestSiteCheckSatisfiedAfterTLSSwap proves the cross-step contract end to end:
// after `site` writes the HTTP block (no cert yet) and `tls` issues a self-signed
// cert + swaps the vhost to the 443 block, a subsequent `site.Check` is satisfied
// with no further write — so the engine never re-applies `site` and never reverts
// TLS back to HTTP. Self-signed avoids any DNS/certbot dependency.
func TestSiteCheckSatisfiedAfterTLSSwap(t *testing.T) {
	s := siteServer()
	s.Sites[0].SSL = true
	s.Sites[0].SSLMode = "selfsigned"
	site := s.Sites[0]
	ctx := context.Background()

	// --- Apply phase: site.Apply then tls.Apply over one runner; cert absent. ---
	fApply := bssh.NewFakeRunner()
	fApply.On("test -e "+shQuote(certFullchainPath(site)), bssh.Result{ExitCode: 1}) // no cert yet
	// site.Apply commands:
	fApply.On("ln -sfn '/etc/nginx/sites-available/app.example.com' '/etc/nginx/sites-enabled/app.example.com'", bssh.Result{})
	fApply.On("nginx -t", bssh.Result{ExitCode: 0})
	fApply.On("systemctl reload nginx", bssh.Result{})
	stubFPMApply(s, fApply)
	// tls.Apply (self-signed) commands:
	fApply.On("DEBIAN_FRONTEND=noninteractive apt-get install -y openssl", bssh.Result{})
	fApply.On("install -d -m 0755 "+shQuote(certDir(site)), bssh.Result{})
	openssl := fmt.Sprintf("openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout %s -out %s -subj %s -addext %s",
		shQuote(certKeyPath(site)), shQuote(certFullchainPath(site)),
		shQuote("/CN="+site.Domain), shQuote("subjectAltName=DNS:"+site.Domain))
	fApply.On(openssl, bssh.Result{})
	fApply.On("chmod 600 "+shQuote(certKeyPath(site)), bssh.Result{})

	if err := Site().Apply(ctx, provision.RunCtx{}, s, fApply); err != nil {
		t.Fatalf("site.Apply: %v", err)
	}
	if err := TLS().Apply(ctx, provision.RunCtx{}, s, fApply); err != nil {
		t.Fatalf("tls.Apply: %v", err)
	}

	// --- Check phase: fresh runner seeded from what Apply wrote; cert now present. ---
	fCheck := bssh.NewFakeRunner()
	replayWritesAsReads(fCheck, fApply.Writes())
	fCheck.On("test -e "+shQuote(certFullchainPath(site)), bssh.Result{ExitCode: 0})
	fCheck.On("nginx -t", bssh.Result{ExitCode: 0})
	fCheck.On("php-fpm"+s.PHP.Version+" -t", bssh.Result{ExitCode: 0})

	cr, err := Site().Check(ctx, provision.RunCtx{}, s, fCheck)
	if err != nil {
		t.Fatalf("site.Check after tls swap: %v", err)
	}
	if !cr.Satisfied {
		t.Errorf("site.Check must be satisfied after the tls swap (no drift); got %+v", cr)
	}
	if n := len(fCheck.Writes()); n != 0 {
		t.Errorf("site.Check must be side-effect-free; got %d writes", n)
	}
}
```

- [ ] **Step 2: Run the test — expect PASS (the contract already holds)**

Run: `go test -run '^TestSiteCheckSatisfiedAfterTLSSwap$' ./internal/provision/steps/ -v`
Expected: PASS. (If it fails with an "unstubbed command" error, the stub set is incomplete — reconcile the missing command string against `site.go`/`tls.go` and re-run.)

- [ ] **Step 3: Vacuity check — prove the test can fail**

Temporarily edit `internal/provision/steps/tls.go` in `swapToHTTPS` (line ~150): change
`https, err := renderNginxHTTPS(s, site)` to `https, err := renderNginxHTTP(s, site)`.

Run: `go test -run '^TestSiteCheckSatisfiedAfterTLSSwap$' ./internal/provision/steps/ -v`
Expected: FAIL — `site.Check` now sees the HTTP block where it expects HTTPS (drift), proving the test guards the byte-identical swap contract.

**Revert the edit** (`renderNginxHTTP` → `renderNginxHTTPS`) and re-run.
Expected: PASS.

- [ ] **Step 4: Run the full steps package + vet/fmt**

Run: `go test ./internal/provision/steps/... && go vet ./internal/provision/steps/... && gofmt -l internal/provision/steps/site_test.go`
Expected: tests PASS, vet clean, `gofmt -l` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add internal/provision/steps/site_test.go
git commit -m "test(site): prove site.Check is satisfied after the tls HTTPS swap (#18)

Cross-step sequence test (site.Apply -> tls.Apply -> site.Check) closing the
half of roadmap #18 not already covered by TestSiteHTTPSRenderMatchesTLSSwap.
Drives the real self-signed issuance ordering and asserts no drift / no revert
of the 443 block. Fresh FakeRunner for the Check phase, seeded last-write-wins
from the Apply writes via replayWritesAsReads.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: #33 — self-signed TLS smoke, default-on (integration)

**Files:**
- Modify: `test/integration/provision_test.go`

**Background (verified against code):**
- Current gate: `skipSSL := os.Getenv("BERTH_TEST_SKIP_SSL") != "false"` (`provision_test.go:64`).
- Self-signed cert path is `/etc/ssl/berth/<domain>/fullchain.pem` (`site.go:103-110`, `certDir`).
- `steps.certRenewWindow` is `30*24h` (`tls.go:17`) but is **unexported** — the test must hardcode the seconds with a comment, not import it.
- The package is `integration`; it may NOT reference unexported `steps` identifiers (`shQuote`, `certDir`, `certRenewWindow`). Domains are validated (no shell metacharacters), so paths are built by string concatenation without quoting.
- Reuse existing helper `assertExitZero(ctx, t, c, label, cmd)` (`provision_test.go:131`).

- [ ] **Step 1: Replace the skipSSL gate**

In `test/integration/provision_test.go`, replace these lines (currently around `:62-64`):

```go
	// TLS is skipped by default (the ACME challenge needs real public DNS). Set
	// BERTH_TEST_SKIP_SSL=false to also exercise TLS and assert HTTPS.
	skipSSL := os.Getenv("BERTH_TEST_SKIP_SSL") != "false"
```

with:

```go
	// Self-signed TLS needs no public DNS, so it is exercised by DEFAULT; Let's
	// Encrypt (HTTP-01/ACME) needs real DNS, so it stays opt-in via
	// BERTH_TEST_SKIP_SSL=false. BERTH_TEST_SKIP_SSL=true forces a hard skip even
	// for self-signed. BEHAVIOR CHANGE: a config WITH a self-signed site and NO
	// env var now runs TLS by default; configs without a self-signed site are
	// unaffected (still skipped).
	sslEnv := os.Getenv("BERTH_TEST_SKIP_SSL")
	skipSSL := sslEnv == "true" || (sslEnv == "" && !anySiteSelfSigned(srv))
```

- [ ] **Step 2: Add the `anySiteSelfSigned` helper**

Add near `anySiteSSL` (`provision_test.go:98`):

```go
// anySiteSelfSigned reports whether any site uses a self-signed certificate
// (CertMode "selfsigned"), which needs no DNS/ACME and so can be exercised in
// the gate by default.
func anySiteSelfSigned(srv *config.Server) bool {
	for _, site := range srv.Sites {
		if site.SSL && site.CertMode() == "selfsigned" {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: Add the `assertSelfSignedCert` helper**

Add near the other `assert*` helpers:

```go
// assertSelfSignedCert verifies each self-signed site has a berth-managed
// certificate under /etc/ssl/berth/<domain> (site.go certDir) that is valid
// beyond the renewal window — the same condition the tls step's certValid uses,
// so a re-run's tls.Check stays satisfied.
func assertSelfSignedCert(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server) {
	t.Helper()
	const renewWindowSecs = 30 * 24 * 60 * 60 // mirror steps.certRenewWindow (30 days)
	for _, site := range srv.Sites {
		if !site.SSL || site.CertMode() != "selfsigned" {
			continue
		}
		fullchain := "/etc/ssl/berth/" + site.Domain + "/fullchain.pem"
		assertExitZero(ctx, t, c, "self-signed cert present "+site.Domain,
			"test -e "+fullchain)
		assertExitZero(ctx, t, c, "self-signed cert valid "+site.Domain,
			fmt.Sprintf("openssl x509 -checkend %d -noout -in %s", renewWindowSecs, fullchain))
	}
}
```

- [ ] **Step 4: Call the assertion after the first run's end-state checks**

In `TestProvisionFreshDebian13`, immediately after the existing HTTPS-serves block (`provision_test.go:92-94`):

```go
	// When TLS was actually provisioned, the site must answer over HTTPS too.
	if !skipSSL && anySiteSSL(srv) {
		assertHTTPServes(t, "https://"+srv.Host+"/")
	}
```

add:

```go
	// Self-signed certs are asserted directly on disk (no public CA to validate).
	if !skipSSL && anySiteSelfSigned(srv) {
		assertSelfSignedCert(ctx, t, client, srv)
	}
```

- [ ] **Step 5: Compile-check under the integration tag (local)**

Run: `go vet -tags integration ./test/integration/... && BERTH_TEST_SERVER= go test -tags integration ./test/integration/... -count=1`
Expected: vet clean; the test compiles and SKIPS (`set BERTH_TEST_SERVER ...`), exit 0. Also run `gofmt -l test/integration/provision_test.go` → prints nothing.

- [ ] **Step 6: Commit**

```bash
git add test/integration/provision_test.go
git commit -m "test(integration): exercise self-signed TLS by default, no DNS (#33)

BERTH_TEST_SKIP_SSL is now CertMode-driven: self-signed sites run TLS by
default (no DNS), Let's Encrypt stays opt-in via =false, =true hard-skips all.
Assert the self-signed cert under /etc/ssl/berth/<domain> is present and valid
beyond the renew window. Behavior change documented inline.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: #30 — second-run idempotency assertion (integration)

**Files:**
- Modify: `test/integration/provision_test.go`

**Background (verified against code):**
- `preflight` is the ONLY `AlwaysRun` step (`preflight.go:23`); its `Check` always returns `Satisfied:false` to re-`apt-get update`, so it emits `EventApplied` on every run.
- Events carry only `Step string` (`internal/provision` `Event`), so the exemption is by name.
- The engine is reusable: steps are stateless; `eng.Run` a second time over the same `client` is valid. `eng` is `*provision.Engine` (`provision.New`, `provision_test.go:68`).
- Do NOT whitelist any step other than `preflight` — the drift-removal cron converges in run 1, and a broader whitelist would mask the regressions this assertion exists to catch (per spec "Review resolution B").

- [ ] **Step 1: Add the `assertSecondRunIdempotent` helper**

Add near the other helpers:

```go
// assertSecondRunIdempotent runs the pipeline a SECOND time over the same
// connection and asserts berth's defining contract: every step is already
// satisfied. The SOLE exception is `preflight`, the only AlwaysRun step (it
// re-runs `apt-get update` every run by design). Any other EventApplied, or any
// EventFailed, on the second run is an idempotency regression and fails the test.
func assertSecondRunIdempotent(ctx context.Context, t *testing.T, eng *provision.Engine, srv *config.Server, client *bssh.Client) {
	t.Helper()
	events, err := eng.Run(ctx, srv, client, provision.Options{SSLStaging: os.Getenv("BERTH_TEST_SSL_STAGING") == "true"})
	if err != nil {
		t.Fatalf("second run pre-flight: %v", err)
	}
	for ev := range events {
		switch ev.Kind {
		case provision.EventFailed:
			t.Fatalf("second run: step %q failed: %v", ev.Step, ev.Err)
		case provision.EventApplied:
			if ev.Step != "preflight" {
				t.Errorf("second run: step %q re-applied — berth is not idempotent (only preflight may re-apply)", ev.Step)
			}
		}
	}
}
```

- [ ] **Step 2: Call it at the end of the test**

In `TestProvisionFreshDebian13`, after the self-signed assertion added in Task 2 (the last assertion in the function, before the closing brace):

```go
	// berth's defining contract: an immediate second run must change nothing
	// (every step satisfied), except preflight which re-runs apt by design.
	assertSecondRunIdempotent(ctx, t, eng, srv, client)
```

- [ ] **Step 3: Compile-check under the integration tag (local)**

Run: `go vet -tags integration ./test/integration/... && BERTH_TEST_SERVER= go test -tags integration ./test/integration/... -count=1`
Expected: vet clean; compiles and SKIPS, exit 0. `gofmt -l test/integration/provision_test.go` → nothing.

- [ ] **Step 4: Commit**

```bash
git add test/integration/provision_test.go
git commit -m "test(integration): assert a second run is all-satisfied (#30)

Re-run the pipeline over the same connection and require zero EventApplied
(except preflight, the sole AlwaysRun step) and zero EventFailed. Directly
proves berth's idempotency contract and catches managed-marker/template drift
and the site<->tls cert-aware re-render reversion class.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Live verification on ovh.onee.pl (the real green for #30/#33)

**Files:** none (operational). The `integration`-tagged tests only compile+skip locally; this is their RED→GREEN.

**Preconditions:**
- The smoke config used as `BERTH_TEST_SERVER` (e.g. `servers/ovh.yml`, local-only/gitignored) must contain a site with `ssl: true` and `ssl_mode: selfsigned`, so #18-on-a-real-host (via #30) + #33 all exercise in one provision.
- The box must be a fresh, systemd Debian 13 (trixie) host.

- [ ] **Step 1: Wipe + re-pin the host key**

After wiping/reinstalling ovh.onee.pl, the ECDSA host key changes. Re-pin it: either update `ssh.fingerprint` in the smoke config, or refresh known_hosts:

Run: `ssh-keygen -R ovh.onee.pl; ssh-keyscan -t ecdsa ovh.onee.pl >> ~/.ssh/known_hosts`
(Or set the new fingerprint under `ssh.fingerprint` in the config.)

- [ ] **Step 2: First provision of the fresh box (requires --force)**

A fresh OVH Debian image ships an unmanaged `/etc/apt/apt.conf.d/20auto-upgrades`, so the first `base` run aborts without `--force` (per CLAUDE.md / Tier 1 notes).

Run: `./berth provision -c servers/ovh.yml --force`
(Build first if needed: `make build`.) Expected: full provision succeeds; the self-signed `tls` step issues a cert and swaps the vhost to 443.

- [ ] **Step 3: Run the integration smoke test against the live host**

Run: `BERTH_TEST_SERVER=servers/ovh.yml go test -tags integration -v ./test/integration/...`
Expected: PASS. Specifically:
- end-state assertions pass (services active, nginx -t, DB, HTTP serves),
- `assertSelfSignedCert` passes (`/etc/ssl/berth/<domain>/fullchain.pem` present + `openssl x509 -checkend` exit 0),
- `https://ovh.onee.pl/` serves (502 acceptable pre-deploy),
- `assertSecondRunIdempotent` passes: the second run logs every step `satisfied` except `preflight` (which logs `applied`), and no step fails.

- [ ] **Step 4: Sanity-confirm the no-revert invariant from the logs**

In the second-run output, confirm `satisfied site` and `satisfied tls` appear (not `applied`). This is the live proof that the self-signed 443 block is hash-stable across runs (the #18 contract on a real host).

---

## Self-Review

**1. Spec coverage:**
- Spec A (#18 sequence test, high fidelity, self-signed, separate Check runner) → Task 1. ✓
- Spec B (#30 second run, preflight-only exemption by name) → Task 3. ✓
- Spec C (#33 CertMode-driven skipSSL + self-signed cert assertions + documented behavior change) → Task 2. ✓
- Spec "Key discovery" (don't duplicate `TestSiteHTTPSRenderMatchesTLSSwap`) → honored in Task 1 background. ✓
- Spec "Verification strategy" (A local `go test`; B/C live) → Tasks 1 vs 2/3/4. ✓
- Spec live precondition (self-signed site in smoke config; wipe→repin→--force) → Task 4. ✓

**2. Placeholder scan:** No TBD/TODO; every code step has complete code; every command has expected output. ✓

**3. Type consistency:** `replayWritesAsReads(dst *bssh.FakeRunner, writes []bssh.FileSpec)`, `anySiteSelfSigned(srv *config.Server) bool`, `assertSelfSignedCert(ctx, *testing.T, *bssh.Client, *config.Server)`, `assertSecondRunIdempotent(ctx, *testing.T, *provision.Engine, *config.Server, *bssh.Client)` — names and signatures used identically where called. `eng` is `*provision.Engine` from `provision.New`. No new imports required in either file (all symbols come from already-imported packages). ✓

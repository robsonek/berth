# Cloudflare-only + Let's Encrypt Validation Guard — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `Server.Validate()` rejects the silently-broken `cloudflare_only` + `ssl_mode: letsencrypt` pairing with a pointed error, and the init wizard can no longer produce it (including via the per-site override collected after the current incremental validation).

**Architecture:** One new rule in `Server.Validate()`'s per-site loop (server level, because `CloudflareOnlyEnabled` resolves the per-site `*bool` override against the server default). The wizard's site loop gains an outer site-retry loop whose bottom re-runs `cand.ToServer().Validate()` after the advanced block (overrides/queue/daemons) — no new prompts, so existing scripted tests are unaffected on the happy path; this also closes the pre-existing gap where cross-site queue/daemon program collisions surfaced only at final `Write()`.

**Tech Stack:** Go 1.25, stdlib only.

**Spec:** `docs/superpowers/specs/2026-07-02-cloudflare-le-guard-design.md` (approved).

## Global Constraints

- Go 1.25; NEVER run `go mod tidy`; no new dependencies.
- Public MIT repo: code/comments/commits English-only, no personal data.
- Error message EXACTLY: `site %s: cloudflare_only cannot issue a Let's Encrypt certificate (a proxied DNS record never points at the origin); use ssl_mode: selfsigned (Cloudflare SSL mode "Full") or disable cloudflare_only for this site` (with `%s` = site domain).
- The rule fires only when ALL of: `site.SSL`, `s.CloudflareOnlyEnabled(site)`, `site.CertMode() == "letsencrypt"`. Allowed and must stay valid: cloudflare_only+selfsigned; cloudflare_only+`ssl: false`; per-site override `false` under server-wide `true` with LE.
- The `tls` step, `examples/`, and `env.tmpl` are untouched. Do NOT add an LE-through-proxy roadmap note (explicitly rejected by the user).
- After each task: `gofmt -l .` prints nothing; `go test ./...` passes.
- Branch: `fix/cloudflare-le-guard` (created; spec committed on it).
- Commit messages end with the trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

---

### Task 1: validation rule in Server.Validate()

**Files:**
- Modify: `internal/config/validate.go` (per-site loop in `Server.Validate()`, ~line 193)
- Test: `internal/config/validate_test.go` (append)

**Interfaces:**
- Consumes: existing `Server.CloudflareOnlyEnabled(site Site) bool` (config.go:215) and `Site.CertMode() string` (config.go:181).
- Produces: the validation error above; Tasks 2-3 rely on `Validate()` rejecting the combo with a message containing `cloudflare_only`.

- [ ] **Step 1: Write the failing test**

Append to `internal/config/validate_test.go` (add `"strings"` to its imports if not present):

```go
func TestValidateCloudflareOnlyLetsEncrypt(t *testing.T) {
	base := func() *Server {
		s := validQueueServer()
		s.Sites[0].SSL = true
		s.Sites[0].SSLEmail = "ops@example.com"
		return s
	}
	on, off := true, false
	cases := []struct {
		name    string
		mutate  func(*Server)
		wantErr bool
	}{
		{"server-wide cloudflare_only with default letsencrypt", func(s *Server) { s.CloudflareOnly = true }, true},
		{"per-site override on with explicit letsencrypt", func(s *Server) { s.Sites[0].CloudflareOnly = &on; s.Sites[0].SSLMode = "letsencrypt" }, true},
		{"cloudflare_only with selfsigned", func(s *Server) { s.CloudflareOnly = true; s.Sites[0].SSLMode = "selfsigned" }, false},
		{"cloudflare_only without ssl", func(s *Server) { s.CloudflareOnly = true; s.Sites[0].SSL = false; s.Sites[0].SSLEmail = "" }, false},
		{"per-site override off under server-wide on", func(s *Server) { s.CloudflareOnly = true; s.Sites[0].CloudflareOnly = &off }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mutate(s)
			err := s.Validate()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "cloudflare_only") {
					t.Fatalf("Validate() = %v, want cloudflare_only pairing error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run '^TestValidateCloudflareOnlyLetsEncrypt$' ./internal/config/`
Expected: FAIL — the two `wantErr` cases get `Validate() = <nil>`.

- [ ] **Step 3: Write minimal implementation**

In `internal/config/validate.go`, inside the `for i := range s.Sites {` loop, directly after the `if err := site.validate(); err != nil { ... }` block:

```go
		if site.SSL && s.CloudflareOnlyEnabled(site) && site.CertMode() == "letsencrypt" {
			return fmt.Errorf("site %s: cloudflare_only cannot issue a Let's Encrypt certificate (a proxied DNS record never points at the origin); use ssl_mode: selfsigned (Cloudflare SSL mode %q) or disable cloudflare_only for this site", site.Domain, "Full")
		}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ ./...`
Expected: PASS everywhere (root `TestExampleConfigsAreValid` included — `examples/multisite-postgres.yml`'s proxied tenant is already `selfsigned`).

- [ ] **Step 5: Commit**

```bash
git add internal/config/validate.go internal/config/validate_test.go
git commit -m "feat(config): reject cloudflare_only with Let's Encrypt

A proxied (orange-cloud) DNS record never points at the origin, so the tls
step's dnsPointsAtHost gate always skips issuance: the origin ends up with
no :443 listener and Cloudflare Full/Full-strict gets 521. Validate() now
rejects the pairing per site (via CloudflareOnlyEnabled, so per-site
overrides are honored) and points at the documented alternative:
ssl_mode: selfsigned behind Cloudflare SSL mode \"Full\".

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: wizard site-retry loop (post-advanced re-validation)

**Files:**
- Modify: `internal/wizard/run.go` (the site loop inside `run`, lines ~24-99)
- Test: `internal/wizard/run_test.go` (append)

**Interfaces:**
- Consumes: Task 1's validation rule; existing `fakePrompter` (run_test.go) whose `siteOverrides` is a single func invoked on every `SiteOverrides` call and whose `confirms` queue feeds every `Confirm` in call order.
- Produces: `run()` re-prompts a whole site (fresh `SiteAnswers`) when the fully-assembled site fails validation after the advanced block. No new prompt methods.

- [ ] **Step 1: Write the failing test**

Append to `internal/wizard/run_test.go`:

```go
// A per-site cloudflare_only override is collected AFTER the core validation,
// so only the post-advanced re-validation can catch cloudflare_only+letsencrypt.
// First attempt: LE site + override "on" -> rejected, site re-prompted from
// scratch. Second attempt: selfsigned + same override -> valid.
func TestRunRepromptsSiteWhenOverrideBreaksValidation(t *testing.T) {
	f := &fakePrompter{
		serverCore: baseServer,
		siteCore: []func(int, *SiteAnswers){
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
				sa.SSL, sa.SSLMode, sa.SSLEmail = true, "letsencrypt", "ops@example.com"
			},
			func(_ int, sa *SiteAnswers) {
				sa.Domain, sa.DeployPath, sa.DBName, sa.DBUser = "a.example.com", "/srv/a", "adb", "ausr"
				sa.SSL, sa.SSLMode = true, "selfsigned"
			},
		},
		siteOverrides: func(sa *SiteAnswers) { sa.CloudflareOverride = "on" },
		confirms: []bool{
			false, // server advanced gate
			true,  // site advanced (attempt 1)
			false, // dedicated queue worker? (attempt 1)
			false, // add a daemon? (attempt 1)
			true,  // site advanced (attempt 2)
			false, // dedicated queue worker? (attempt 2)
			false, // add a daemon? (attempt 2)
			false, // add another site?
		},
	}
	a, err := run(f)
	if err != nil {
		t.Fatalf("run error = %v", err)
	}
	if len(f.errors) != 1 || !strings.Contains(f.errors[0].Error(), "cloudflare_only") {
		t.Fatalf("errors = %v, want exactly one cloudflare_only rejection", f.errors)
	}
	if len(a.Sites) != 1 || a.Sites[0].SSLMode != "selfsigned" || a.Sites[0].CloudflareOverride != "on" {
		t.Fatalf("sites = %+v, want one selfsigned site with the override kept", a.Sites)
	}
	if verr := a.ToServer().Validate(); verr != nil {
		t.Fatalf("assembled server invalid: %v", verr)
	}
}
```

Add `"strings"` to run_test.go's imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run '^TestRunRepromptsSiteWhenOverrideBreaksValidation$' ./internal/wizard/`
Expected: FAIL — today nothing re-validates after SiteOverrides, so `run` returns with zero recorded errors and the invalid combination in `a.Sites` (the `len(f.errors) != 1` assertion fires; the fake's confirm queue also over-supplies, which is harmless).

- [ ] **Step 3: Restructure the site loop**

In `internal/wizard/run.go`, replace the entire site loop (from `for {` after the server-advanced block, through the closing brace after the `if !more { break }` block) with:

```go
	for {
		var sa SiteAnswers
		// Site-retry loop: core fields AND advanced options (overrides, queue,
		// daemons) are validated as one unit at the bottom. An override- or
		// worker-introduced violation (cloudflare_only + letsencrypt, duplicate
		// supervisor program) re-prompts this site instead of surfacing only at
		// the final Write().
		for {
			sa = SiteAnswers{SchedulerOverride: "inherit", CloudflareOverride: "inherit", BackupsOverride: "inherit"}

			// Collect core fields, resolving HTTP/3↔nginx and validating after each
			// attempt. Server-level fields are already inline-valid, so a failure here
			// is site-local or a cross-site duplicate: re-prompt this same site.
			for {
				if err := p.SiteCore(len(a.Sites), &sa); err != nil {
					return Answers{}, err
				}
				if sa.HTTP3 && a.NginxSource == "debian" {
					sw, err := p.Confirm("HTTP/3 requires the nginx.org package; switch the server's nginx source to nginx.org?")
					if err != nil {
						return Answers{}, err
					}
					if sw {
						a.NginxSource = "nginx"
					} else {
						sa.HTTP3 = false
					}
				}
				// Shallow copy is safe here: sa has no pointer fields populated yet
				// (Queue/Daemons are filled only after this validate loop), so cand
				// shares nothing mutable with sa. If that ordering ever changes, this
				// copy would alias sa.Queue's pointer — deep-copy then.
				cand := a
				cand.Sites = append(append([]SiteAnswers(nil), a.Sites...), sa)
				if verr := cand.ToServer().Validate(); verr != nil {
					p.ShowError(verr)
					continue
				}
				break
			}

			// Optional advanced gate: scheduler override, dedicated queue, daemons.
			adv, err := p.Confirm("Configure advanced options for this site?")
			if err != nil {
				return Answers{}, err
			}
			if adv {
				if err := p.SiteOverrides(&sa); err != nil {
					return Answers{}, err
				}
				wantQueue, err := p.Confirm("Dedicated queue worker for this site?")
				if err != nil {
					return Answers{}, err
				}
				if wantQueue {
					var q QueueAnswers
					if err := p.Queue(&q); err != nil {
						return Answers{}, err
					}
					sa.Queue = &q
				}
				daemons, err := collectDaemons(p)
				if err != nil {
					return Answers{}, err
				}
				sa.Daemons = daemons
			}

			// Re-validate the fully-assembled site: overrides, queue, and daemons
			// were collected after the core validation above. The shallow copy is
			// read-only here — cand aliases sa.Queue/sa.Daemons, but ToServer only
			// reads them.
			cand := a
			cand.Sites = append(append([]SiteAnswers(nil), a.Sites...), sa)
			if verr := cand.ToServer().Validate(); verr != nil {
				p.ShowError(verr)
				continue
			}
			break
		}

		a.Sites = append(a.Sites, sa)

		// Valkey caps multi-site at 16 logical Redis DBs — whole-config state that
		// re-prompting a site cannot fix, so gate the "add another?" offer.
		if a.Valkey && len(a.Sites) >= 16 {
			p.ShowError(fmt.Errorf("valkey caps multi-site at 16 sites (one Redis logical DB each); stopping at 16"))
			break
		}
		more, err := p.Confirm("Add another site?")
		if err != nil {
			return Answers{}, err
		}
		if !more {
			break
		}
	}
```

(The inner core loop, HTTP/3 switch, advanced block, valkey cap and "add another?" bodies are byte-identical to today's code — only the new outer retry loop, the `sa` reset at its top, and the second `cand` validation are new.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/wizard/`
Expected: PASS — the new test plus every existing run/matrix/wizard test (the happy path consumes the same prompt sequence as before).

- [ ] **Step 5: Commit**

```bash
git add internal/wizard/run.go internal/wizard/run_test.go
git commit -m "fix(wizard): re-validate the fully-assembled site after advanced options

SiteOverrides, queue, and daemons are collected after the incremental
per-site validation, so a violation they introduce (cloudflare_only +
letsencrypt via the per-site override, or a cross-site supervisor program
collision) surfaced only at the final Write(), discarding the session. The
site loop now re-runs Validate() on the fully-assembled site and re-prompts
that site on failure. No prompts were added or reordered.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: matrix coverage for the guard

**Files:**
- Test: `internal/wizard/matrix_test.go` (append two subtests inside `TestConfigMatrix`, next to the existing ops/* and ssl subtests)
- Modify (conditional): `README.md` — ONLY if its Cloudflare origin-lockdown section does not already state the selfsigned pairing requirement, add one sentence: `cloudflare_only` requires `ssl_mode: selfsigned` (or `ssl: false`) — validation rejects Let's Encrypt because a proxied DNS record never points at the origin.

**Interfaces:**
- Consumes: Task 1's rule; matrix helpers `base(name, host)`, `validSingleSite(t)`, `writeInvalid(t, a) error`, `mustContain(t, err, sub)` (all already in matrix_test.go).
- Produces: nothing downstream.

- [ ] **Step 1: Write the two subtests (one must fail)**

Inside `TestConfigMatrix`, after the existing `single-site-letsencrypt-missing-email-invalid` subtest:

```go
	t.Run("ops/cloudflare-letsencrypt-invalid", func(t *testing.T) {
		a := validSingleSite(t)
		a.CloudflareOnly = true
		a.Sites[0].SSL = true
		a.Sites[0].SSLMode = "letsencrypt"
		a.Sites[0].SSLEmail = "ops@example.com"
		err := writeInvalid(t, a)
		mustContain(t, err, "cloudflare_only")
	})

	t.Run("ops/cloudflare-selfsigned-valid", func(t *testing.T) {
		a := validSingleSite(t)
		a.CloudflareOnly = true
		a.Sites[0].SSL = true
		a.Sites[0].SSLMode = "selfsigned"
		if err := a.ToServer().Validate(); err != nil {
			t.Fatalf("cloudflare_only + selfsigned must stay valid: %v", err)
		}
	})
```

- [ ] **Step 2: Run to verify the intended states**

Run: `go test -run '^TestConfigMatrix$' ./internal/wizard/`
Expected: PASS (Task 1 already merged the rule on this branch — the negative subtest passes because `writeInvalid` gets its error; if it FAILS with "expected error", Task 1 is missing: stop and report BLOCKED).
Note: this task's "failing first" evidence is the negative subtest run BEFORE Task 1 would have been red; since tasks land sequentially on one branch, run both subtests and verify the assertions hold — the deliverable here is pinned coverage, not a fresh RED.

- [ ] **Step 3: README check**

Run: `grep -n -i "cloudflare" README.md`
Read the origin-lockdown section. If the selfsigned pairing requirement is already stated, change nothing. Otherwise add the single sentence from **Files** above at the end of that section's prose.

- [ ] **Step 4: Full suite**

Run: `go test ./... && go vet ./... && gofmt -l .`
Expected: all PASS, vet clean, gofmt silent.

- [ ] **Step 5: Commit**

```bash
git add internal/wizard/matrix_test.go README.md
git commit -m "test(wizard): pin the cloudflare_only+letsencrypt rejection in the matrix

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

(Drop README.md from the `git add` if Step 3 changed nothing.)

---

### Task 4: whole-branch verification (controller-run)

**Files:** none (verification only)

- [ ] **Step 1: Full suite with race detector**

Run: `go test -race -count=1 ./... && go vet ./...`
Expected: PASS, vet clean.

- [ ] **Step 2: CLI smoke — validation fires before any SSH**

```bash
make build
cat > /tmp/cf-le-bad.yml <<'EOF'
host: 203.0.113.10
ssh: { user: root, key: ~/.ssh/id_rsa }
cloudflare_only: true
sites:
  - domain: bad.example.com
    deploy_path: /var/www/bad
    ssl: true
    ssl_email: ops@example.com
    database: { name: bad, user: bad }
EOF
./berth provision /tmp/cf-le-bad.yml; echo "exit=$?"
```

Expected: `error: site bad.example.com: cloudflare_only cannot issue a Let's Encrypt certificate ...` and `exit=1`, with NO connection attempt (validation runs in config.Load before Connect).

- [ ] **Step 3: Roadmap bookkeeping (local only, never commit docs/)**

In `docs/improvement-roadmap.md` § "Design-review findings — 2026-07-02", prefix the M2/cloudflare bullet with `[FIXED fix/cloudflare-le-guard]`. Do NOT add any LE-through-proxy roadmap entry (explicitly rejected).

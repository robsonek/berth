package steps

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
)

// expectedRefusals lists the ONLY steps allowed to return an error under the
// foreign profile, with a substring of the refusal each must give. A refusal is
// a correct outcome there — foreign files and a foreign-owned site tree are
// exactly what the ownership and drift guards exist to reject — but accepting
// ANY error as "intended" would let a genuine failure hide. Under every other
// profile a Check must return nil.
var expectedRefusals = map[string]string{
	// accounts: the same tree-ownership guard as appdirs, and it fires FIRST —
	// accounts.Check runs assertSiteTreeOwners as a tree-safety preflight
	// BEFORE any managed-file probe (accounts.go: an existing tree under a
	// different identity must refuse before any account, key or sudoers is
	// created), so under foreign the owner refusal is the one the step means
	// to give, not the drift policy's.
	"accounts": "owned by",
	"appdirs":  "owned by",
	// hardening: a foreign sshd drop-in at berth's path aborts unless --force
	// (standard managed-file drift policy — the sshd_config.d probe is the
	// first managed file hardening.Check classifies).
	"hardening": "not managed by berth",
	"site":      "not managed by berth",
	// preflight: the foreign apt lock-timeout drop-in aborts unless --force —
	// deliberate (preflight.go: without this gate even `--only identity` would
	// clobber a foreign file, preflight being always-run).
	"preflight": "not managed by berth",
	// base: a foreign 20auto-upgrades aborts unless --force (systembase.go —
	// content outside the stockAutoUpgrades adoption allowlist is operator
	// intent, the exact case the drift policy exists to protect).
	"base": "not managed by berth",
	// apt: a foreign file at a DECLARED repo's source-list path aborts unless
	// --force (aptextras.go, standard managed-file policy). Undeclared foreign
	// files in the namespace are merely skipped — the refusal is only for the
	// path berth is about to write.
	"apt": "not managed by berth",
	// php: a foreign file at the OPcache drop-in path aborts unless --force —
	// the FIRST managed file php.Check classifies. Guard order verified: the
	// version-exclusivity probe and the sury-linger probe run earlier but
	// both read clean under this profile (no foreign pools, no sury list),
	// so the drift policy's refusal is the one the step means to give.
	"php": "not managed by berth",
	// valkey: a foreign file at the per-site instance-unit path aborts unless
	// --force. Guard order verified: pkgInstalled and the stock-service
	// probes are data-only; the per-site checkManagedFile is the first guard
	// that can refuse.
	"valkey": "not managed by berth",
	// tuning: a foreign file at the MariaDB drop-in path aborts unless
	// --force. Guard order verified: the RAM guard runs first but reads
	// clean from /proc/meminfo; checkTuned's managedFileSatisfied is the
	// first refusal.
	"tuning": "not managed by berth",
	// Task 5 completes this map from the discovery run. Every entry must be a
	// refusal the step MEANS to give, never a symptom of an incomplete model.
	// database deliberately has NO entry: its foreign truth is a tree berth
	// never provisioned (no shared/.env), where the step honestly reports
	// "credential not yet persisted" — unsatisfied, not a refusal.
}

// TestChecksAreReadOnly is the contract.
//
// WHAT THIS DOES NOT PROVE — read before trusting it. It does not prove a Check
// is read-only on a REAL host. It proves that the commands a Check ISSUES under
// five modelled states fall in a classified set. Three gaps remain: a path none
// of the five profiles visits; a shape the model answers so generically that it
// masks a branch; and a Go-side effect that never reaches the Runner at all —
// a Check calling os.WriteFile, os/exec or a network API is invisible here. The
// fleet-status spec's original "strictly read-only" claim was wrong in exactly
// this way, so this test states its limits rather than implying it has none.
func TestChecksAreReadOnly(t *testing.T) {
	srv := contractServer(t)
	pipeline := Pipeline(srv, secret.NewRedactor(), false)

	// Guard 1: the pipeline must be EXACTLY the expected set, by name. A count
	// alone would pass if one step were replaced by a duplicate of another, and
	// a new conditionally-registered step could be omitted while the old total
	// still matched.
	wantSteps := []string{
		"identity", "preflight", "base", "system", "apt", "php", "nginx",
		"composer", "valkey", "supervisor", "accounts", "hardening", "appdirs",
		"database", "site", "tls", "tuning", "backups", "offsite", "manifest",
	}
	var gotSteps []string
	for _, st := range pipeline {
		gotSteps = append(gotSteps, st.Name())
	}
	sort.Strings(gotSteps)
	wantSorted := append([]string(nil), wantSteps...)
	sort.Strings(wantSorted)
	if strings.Join(gotSteps, ",") != strings.Join(wantSorted, ",") {
		t.Fatalf("pipeline steps changed.\n got: %v\nwant: %v\n"+
			"If a step was added, add it to wantSteps AND make sure contractServer()\n"+
			"registers it — otherwise this contract silently skips it.", gotSteps, wantSorted)
	}

	type key struct{ step, profile string }
	issued := map[key]int{}
	sawException := map[string]bool{} // exception command -> observed
	sawGPG := false
	var violations []string
	add := func(format string, a ...any) { violations = append(violations, fmt.Sprintf(format, a...)) }

	for _, profile := range fakeHostProfiles {
		for _, st := range pipeline {
			h := newFakeHost(t, profile, srv)
			r := newRecordingRunner(h)
			rc := provision.RunCtx{FullRun: true}
			if profile == "foreign" {
				// Force changes whether an aggregating Check continues past the
				// unmanaged-file refusal, so foreign is run BOTH ways below.
				rc.Force = false
			}

			_, checkErr := st.Check(context.Background(), rc, srv, r)

			// Guard 2: every command must have been answerable, regardless of
			// what the Check returned. A Check may swallow a probe error
			// (sshdConflictSources degrades deliberately), so the Check's own
			// error is not a reliable signal.
			for _, u := range r.unanswered() {
				add("%s.Check asked the fake host a question it cannot answer under %q:\n"+
					"    %s\n"+
					"  Teach answer() in fakehost_runner_test.go this shape so the Check can\n"+
					"  complete. Until then this profile's coverage of %s.Check is a PREFIX.",
					st.Name(), profile, u, st.Name())
			}

			// Guard 3: the error policy, per profile.
			switch {
			case profile == "foreign":
				if checkErr != nil {
					want, allowed := expectedRefusals[st.Name()]
					if !allowed {
						add("%s.Check errored under %q but is not in expectedRefusals:\n    %v\n"+
							"  Either this is the refusal the step MEANS to give — add it with the\n"+
							"  substring to match — or the model is incomplete and the error is a symptom.",
							st.Name(), profile, checkErr)
					} else if !strings.Contains(checkErr.Error(), want) {
						add("%s.Check's refusal under %q changed:\n    got:  %v\n    want substring: %q",
							st.Name(), profile, checkErr, want)
					}
				}
			case checkErr != nil:
				add("%s.Check errored under %q, where a verdict is required:\n    %v\n"+
					"  Only the foreign profile may produce refusals. An error here means the\n"+
					"  fixture or the model cannot drive this Check to a verdict.",
					st.Name(), profile, checkErr)
			}

			// A Check must never write a file, whatever its verdict.
			for _, w := range r.writes() {
				add("%s.Check called WriteFile(%s) under %q — a Check must never write.",
					st.Name(), w.Path, profile)
			}

			for _, rec := range r.recorded() {
				issued[key{st.Name(), profile}]++
				verdict, detail := classifyCommand(rec.cmd, rec.stdin)
				switch verdict {
				case cmdReadOnly, cmdAudited:
					// allowed
				case cmdException:
					sawException[strings.Fields(rec.cmd)[0]] = true
				default:
					add("%s.Check issued a REJECTED command under %q:\n    %s\n  reason: %s\n"+
						"  A Check must be side-effect-free. Either move this to Apply, or — if it\n"+
						"  genuinely only reads — add its exact shape to cmdclass_test.go with a\n"+
						"  one-line justification. If it is a generated script, register its exact\n"+
						"  text in auditedScripts after reading every command inside it.",
						st.Name(), profile, rec.cmd, detail)
				}
				if strings.HasPrefix(rec.cmd, "gpg ") {
					sawGPG = true
				}
			}
		}
	}

	// Guard 4a: no step may be silently unexercised. identity is the one step
	// that legitimately issues nothing — its Check discards the Runner in its
	// signature — but it is still INVOKED above and must have recorded zero.
	for _, st := range pipeline {
		total := 0
		for _, profile := range fakeHostProfiles {
			total += issued[key{st.Name(), profile}]
		}
		switch st.Name() {
		case "identity":
			if total != 0 {
				add("identity.Check issued %d command(s). Its signature discards the Runner today;\n"+
					"  if that changed, it must join the classified set rather than stay excluded.", total)
			}
		default:
			if total == 0 {
				add("%s.Check issued NO commands under any profile — either the harness never\n"+
					"  reached it, or it returns before probing. Both make this contract vacuous\n"+
					"  for that step.", st.Name())
			}
		}
	}

	// Guard 4b: the declared exceptions must have been OBSERVED. Declaring
	// nginx -t and php-fpm -t as exceptions proves nothing if no profile ever
	// reaches them — which is precisely what the first draft of this plan got
	// wrong: site.Check returns at its first unsatisfied managed file, before
	// the validators, so a shallow converged profile never recorded either.
	if !sawException["nginx"] {
		add("nginx -t was never observed. It is declared an exception, so a run that never\n" +
			"  reaches it proves nothing about it. Make the converged profile deep enough that\n" +
			"  site.Check gets past its managed-file loop to the validators.")
	}
	if !sawException["php-fpm8.4"] {
		add("php-fpm -t was never observed — same reason as nginx -t above.")
	}
	// And the gpg keyring probe, the original offender this contract exists for.
	if !sawGPG {
		add("the gpg keyring probe was never observed. contractServer() must declare an apt\n" +
			"  repo whose source list and keyring are reachable, or the command that started\n" +
			"  this whole line of work is not actually covered.")
	}

	for _, st := range pipeline {
		row := st.Name() + ":"
		for _, profile := range fakeHostProfiles {
			row += fmt.Sprintf("  %s=%d", profile, issued[key{st.Name(), profile}])
		}
		t.Log(row)
	}

	if len(violations) > 0 {
		out := ""
		for i, v := range violations {
			out += fmt.Sprintf("[%d] %s\n\n", i+1, v)
		}
		t.Fatalf("read-only Check contract violated in %d place(s):\n\n%s", len(violations), out)
	}
}

// TestConvergedIsGenuinelySatisfied pins what makes the converged profile
// worth its name: every Check must reach a genuine Satisfied:true there — a
// profile that merely avoids errors would let the contract's deepest paths
// (site's validators, the value-agreement probes, the runtime tails) go
// unwalked while everything stayed green. Two steps are exempt, each for a
// stated reason, and their reasons are pinned so a THIRD unsatisfied step can
// never hide among them:
//
//   - preflight is AlwaysRun with a deliberately unsatisfied Check (it
//     re-runs apt-get update every run by design);
//   - identity's verdict is about the LOCAL cache binding, not the host: the
//     fixture seeds the cache under the declared id with no tombstone at the
//     host key, which identity honestly reports as not-yet-converged
//     (wave-3 note; a fixture tombstone would change this, not the host).
func TestConvergedIsGenuinelySatisfied(t *testing.T) {
	srv := contractServer(t)
	wantUnsatisfied := map[string]string{
		"preflight": "Debian 13 detected",
		"identity":  "tombstone",
	}
	for _, st := range Pipeline(srv, secret.NewRedactor(), false) {
		r := newRecordingRunner(newFakeHost(t, "converged", srv))
		res, err := st.Check(context.Background(), provision.RunCtx{FullRun: true}, srv, r)
		if err != nil {
			t.Errorf("%s.Check under converged: %v", st.Name(), err)
			continue
		}
		if want, exempt := wantUnsatisfied[st.Name()]; exempt {
			if res.Satisfied || !strings.Contains(res.Reason, want) {
				t.Errorf("%s.Check under converged = (satisfied=%v, %q) — the exemption expects an unsatisfied verdict mentioning %q; if the step changed, re-argue the exemption rather than widening it",
					st.Name(), res.Satisfied, res.Reason, want)
			}
			continue
		}
		if !res.Satisfied {
			t.Errorf("%s.Check is not Satisfied under converged (%q) — the profile no longer converges this step, so its Check tail is unwalked and the contract's coverage silently shrank",
				st.Name(), res.Reason)
		}
	}
}

// TestChecksAreReadOnlyUnderForce covers the one RunCtx flag that changes
// control flow rather than just content: Force lets an aggregating Check
// continue PAST the unmanaged-file refusal, reaching commands the plain foreign
// run never gets to. SSLStaging and FullRun:false change content and messages
// rather than which commands are issued, so they stay deferred.
func TestChecksAreReadOnlyUnderForce(t *testing.T) {
	srv := contractServer(t)
	var violations []string
	for _, st := range Pipeline(srv, secret.NewRedactor(), false) {
		r := newRecordingRunner(newFakeHost(t, "foreign", srv))
		_, _ = st.Check(context.Background(), provision.RunCtx{FullRun: true, Force: true}, srv, r)
		for _, rec := range r.recorded() {
			if v, detail := classifyCommand(rec.cmd, rec.stdin); v == cmdRejected {
				violations = append(violations, fmt.Sprintf("%s.Check under foreign+Force: %s (%s)", st.Name(), rec.cmd, detail))
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("rejected commands under foreign+Force:\n  %s", strings.Join(violations, "\n  "))
	}
}

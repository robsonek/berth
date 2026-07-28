//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/robsonek/berth/internal/config"
	dbpkg "github.com/robsonek/berth/internal/database"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/provision/steps"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
	"github.com/robsonek/berth/internal/version"
)

// managedMarkerLine mirrors steps.managedMarker (unexported): the exact first
// line templates.Render prepends to every berth-managed file.
const managedMarkerLine = "# managed by berth"

// hostManifestPath mirrors steps.manifestPath: which berth version last FULLY
// provisioned this host.
const hostManifestPath = "/var/lib/berth/manifest"

// assertManifests verifies the two provenance manifests the upgrade machinery
// writes. The host manifest (expectHost) exists only when the manifest step was
// registered — steps.Pipeline drops it when --skip-ssl artificially truncated a
// pipeline that would otherwise carry TLS, so the caller passes the same
// condition. It must be berth-marked and record exactly this binary's version
// (the suite imports internal packages, so version.Version IS the binary under
// test). Every backups-enabled site must additionally have a self-describing
// root:root 0600 manifest beside its archives whose derivation facts match the
// loaded config — the offsite restore contract.
func assertManifests(ctx context.Context, t *testing.T, c *bssh.Client, srv *config.Server, expectHost bool) {
	t.Helper()

	if expectHost {
		if content, ok := readRootFile(ctx, t, c, hostManifestPath); ok {
			assertManagedMarker(t, hostManifestPath, content)
			kv := parseEnv(content)
			if got := kv["VERSION"]; got != version.Version {
				t.Errorf("%s: VERSION = %q, want %q (the binary under test)", hostManifestPath, got, version.Version)
			}
			if kv["PROVISIONED_AT"] == "" {
				t.Errorf("%s: PROVISIONED_AT missing or empty", hostManifestPath)
			}
		}
	} else {
		t.Logf("host manifest not asserted: skip-ssl truncated the pipeline, so the manifest step is unregistered")
	}

	for _, site := range srv.Sites {
		if !srv.BackupsEnabled(site) {
			continue
		}
		pool := config.PoolName(site.Domain)
		path := "/var/backups/berth/" + pool + "/manifest"
		assertStatMode(ctx, t, c, path, "root:root 600")
		content, ok := readRootFile(ctx, t, c, path)
		if !ok {
			continue
		}
		assertManagedMarker(t, path, content)
		kv := parseEnv(content)
		want := [][2]string{
			{"BERTH_VERSION", version.Version},
			{"DOMAIN", site.Domain},
			{"POOL", pool},
			{"ENGINE", srv.Database.Engine},
			{"DB_NAME", srv.SiteDBName(site)},
			{"DB_USER", srv.SiteDBUser(site)},
			{"SITE_USER", srv.SiteUser(site)},
			{"DEPLOY_PATH", site.DeployPath},
		}
		for _, w := range want {
			if got := kv[w[0]]; got != w[1] {
				t.Errorf("%s: %s = %q, want %q", path, w[0], got, w[1])
			}
		}
	}
}

// readRootFile cats path (Run auto-elevates, so root-only files are readable)
// and returns its content; a missing/unreadable file is a test error, not a
// fatal, so the remaining manifests still get checked.
func readRootFile(ctx context.Context, t *testing.T, c *bssh.Client, path string) (string, bool) {
	t.Helper()
	res, err := c.Run(ctx, "cat "+sqQuote(path), nil)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if res.ExitCode != 0 {
		t.Errorf("%s missing or unreadable (exit %d): %s", path, res.ExitCode, strings.TrimSpace(res.Stderr))
		return "", false
	}
	return res.Stdout, true
}

// assertManagedMarker fails unless content's first line is exactly berth's
// managed marker (steps.isManagedMarker compares whole lines, so a prefix or
// suffix variant would misclassify on the host too).
func assertManagedMarker(t *testing.T, path, content string) {
	t.Helper()
	first := strings.TrimRight(strings.SplitN(content, "\n", 2)[0], "\r")
	if first != managedMarkerLine {
		t.Errorf("%s: first line = %q, want the managed marker %q", path, first, managedMarkerLine)
	}
}

// assertRestoreDrill is the automated restore-divergence drill: it overwrites
// one site's live shared/.env DB_PASSWORD and APP_KEY with fresh random
// secrets — simulating a shared/.env restored from a backup while the local
// cache still holds newer (now wrong) values — then proves the database step
// (a) SEES the divergence (a read-only dry-run plans with a "disagrees"
// reason), (b) heals it (a real run re-applies: role password, local cache and
// the seeded client-auth file all converge toward .env), and (c) converges (a
// further full run reports the step Satisfied and nothing but preflight
// re-applies).
//
// Secret hygiene is a hard rule here: replacement values are freshly random
// (secret.Generate / secret.AppKey), travel exclusively over SSH stdin — never
// argv, never the command string, never test output, never stdout (every
// on-host verification is exit-code-only through the production
// envValueMatchScript; the drill never reads the .env back) — and are
// registered with the suite's shared redactor before any engine run can
// mention them.
//
// It runs LAST in the suite on purpose: it deliberately mutates live state.
func assertRestoreDrill(t *testing.T, eng *provision.Engine, red *secret.Redactor, srv *config.Server, client *bssh.Client) {
	t.Helper()
	if len(srv.Sites) == 0 {
		t.Logf("restore drill skipped: no sites configured")
		return
	}
	site := drillSite(srv)
	dbUser := srv.SiteDBUser(site)
	dbName := srv.SiteDBName(site)
	// appKeyCK mirrors steps.appKeyCacheKey (unexported): the cache key a
	// site's APP_KEY backup lives under, beside the DB password.
	appKeyCK := "appkey:" + dbUser
	dbEng, err := dbpkg.Get(srv.Database.Engine)
	if err != nil {
		t.Fatalf("restore drill: engine %q: %v", srv.Database.Engine, err)
	}
	driver, host, port, socket := dbEng.EnvConnection()
	envPath := site.DeployPath + "/shared/.env"

	// Fresh deadline (mirrors assertSecondRunIdempotent): re-runs over a
	// converged host are Check-dominated and fast.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Fidelity guard, BEFORE the drill mutates or probes anything: the
	// role-login probe below is built EXCLUSIVELY from the trusted identities
	// above, so the live .env must first be proven to agree with them — see
	// assertEnvIdentityFidelity.
	assertEnvIdentityFidelity(ctx, t, client, "restore drill", envPath,
		trustedDBConn{driver: driver, host: host, port: port, socket: socket}, dbUser, dbName)

	// Precondition: the local cache holds the site's CURRENT secrets — the
	// suite's provision converged them. Without that, the drill would not be
	// creating the cache↔.env disagreement it claims to heal.
	cache, err := secret.LoadCache(srv.CacheKey())
	if err != nil {
		t.Fatalf("restore drill: load local secret cache: %v", err)
	}
	if cache[dbUser] == "" || cache[appKeyCK] == "" {
		t.Fatalf("restore drill: local cache lacks the DB credential or APP_KEY backup for %s; the provision should have converged them", site.Domain)
	}

	newPW, err := secret.Generate(32)
	if err != nil {
		t.Fatalf("restore drill: generate password: %v", err)
	}
	newKey, err := secret.AppKey()
	if err != nil {
		t.Fatalf("restore drill: generate APP_KEY: %v", err)
	}
	// Registered BEFORE anything can echo them: every later engine event and
	// error is masked through this redactor.
	red.Add(newPW)
	red.Add(newKey)

	// 1. Diverge: overwrite the live .env values as root. Both secrets ride
	// SSH stdin (one per line) straight into awk — see envOverwriteScript.
	res, err := client.Run(ctx, envOverwriteScript(envPath), []byte(newPW+"\n"+newKey+"\n"))
	if err != nil {
		t.Fatalf("restore drill: overwrite %s: %v", envPath, err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("restore drill: overwrite %s: exit %d, stderr %q", envPath, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	// The overwrite took — proven WITHOUT reading the file back: each fresh
	// value rides stdin into the production match script and only the exit
	// code answers, so the new secrets never travel over SSH stdout.
	if exit := envFieldExit(ctx, t, client, envPath, "DB_PASSWORD", newPW); exit != 0 {
		t.Fatalf("restore drill: %s did not take the fresh DB_PASSWORD (probe exit %d)", envPath, exit)
	}
	if exit := envFieldExit(ctx, t, client, envPath, "APP_KEY", newKey); exit != 0 {
		t.Fatalf("restore drill: %s did not take the fresh APP_KEY (probe exit %d)", envPath, exit)
	}

	// 2. A read-only dry-run must SEE the divergence: the database step plans,
	// and its Check reason names the cache/.env disagreement. (EventApplied
	// carries no Reason, so the dry-run is the only place the reason is
	// observable from the event stream.)
	planned := drillRun(ctx, t, eng, red, srv, client, true, "restore drill dry-run")
	if ev, ok := planned["database"]; !ok || ev.Kind != provision.EventPlanned {
		t.Errorf("restore drill: database step did not plan on the diverged host (got kind %v)", ev.Kind)
	} else if !strings.Contains(ev.Reason, "disagrees") {
		t.Errorf("restore drill: database plan reason = %q, want it to name the cache/.env disagreement", ev.Reason)
	}

	// 3. Heal: a real run re-applies the database step; any failure is fatal
	// inside drillRun.
	healed := drillRun(ctx, t, eng, red, srv, client, false, "restore drill heal run")
	if ev := healed["database"]; ev.Kind != provision.EventApplied {
		t.Errorf("restore drill: database step did not re-apply on the diverged host (got kind %v)", ev.Kind)
	}

	// 4a. The role authenticates with the NEW password over the connection
	// path the app uses — rebuilt here from the TRUSTED identities the
	// fidelity guard proved the live .env agrees with, never from the
	// tenant-writable file itself; the password rides stdin into an env
	// assignment, never argv.
	res, err = client.Run(ctx, dbProbeStdinCmd(driver, host, port, socket, dbUser, dbName, "SELECT 1"), []byte(newPW+"\n"))
	if err != nil {
		t.Fatalf("restore drill: role login probe: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("restore drill: role %s does not authenticate with the restored password (exit %d, stderr %q)",
			dbUser, res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	// 4b. The local cache converged toward .env. Values are compared in Go
	// and never printed.
	cache, err = secret.LoadCache(srv.CacheKey())
	if err != nil {
		t.Fatalf("restore drill: reload local secret cache: %v", err)
	}
	if cache[dbUser] != newPW {
		t.Errorf("restore drill: local cache still holds the pre-restore DB password for %s", site.Domain)
	}
	if cache[appKeyCK] != newKey {
		t.Errorf("restore drill: local cache still holds the pre-restore APP_KEY for %s", site.Domain)
	}

	// 4c. The seeded client-auth file (~/.my.cnf / ~/.pgpass) was rewritten
	// with the NEW password — it provably held berth's old cached one.
	authPath := "/home/" + srv.SiteUser(site) + "/" + dbEng.ClientAuthFileName()
	res, err = client.Run(ctx, clientAuthContainsCmd(authPath), []byte(newPW+"\n"))
	if err != nil {
		t.Fatalf("restore drill: probe %s: %v", authPath, err)
	}
	if res.ExitCode != 0 {
		t.Errorf("restore drill: %s does not hold the restored password (exit %d)", authPath, res.ExitCode)
	}

	// 4d. Converged: a further full run reports the database step Satisfied,
	// and — berth's idempotency contract — nothing but preflight re-applies.
	final := drillRun(ctx, t, eng, red, srv, client, false, "restore drill converged run")
	if ev := final["database"]; ev.Kind != provision.EventSatisfied {
		t.Errorf("restore drill: database step not Satisfied after the heal (got kind %v)", ev.Kind)
	}
	for step, ev := range final {
		if ev.Kind == provision.EventApplied && step != "preflight" {
			t.Errorf("restore drill: step %q re-applied on the post-heal run — the heal did not converge", step)
		}
	}
}

// drillSite picks the site the drill diverges: the first backups-enabled site
// (the restore story is "shared/.env came back from a backup"), falling back
// to the first site — the database step's healing contract is identical for
// every site, so a config without backups still exercises the drill.
func drillSite(srv *config.Server) config.Site {
	for _, site := range srv.Sites {
		if srv.BackupsEnabled(site) {
			return site
		}
	}
	return srv.Sites[0]
}

// drillRun executes one pipeline pass and returns each step's terminal event
// (Satisfied / Planned / Applied) keyed by step name; any EventFailed is
// fatal. It reuses the suite's engine and redactor so secrets registered by
// earlier passes stay masked. Fatal mid-stream is safe: the engine's channel
// is buffered for every event it can send, so its goroutine never blocks on
// an abandoned consumer.
func drillRun(ctx context.Context, t *testing.T, eng *provision.Engine, red *secret.Redactor, srv *config.Server, client *bssh.Client, dryRun bool, label string) map[string]provision.Event {
	t.Helper()
	events, err := eng.Run(ctx, srv, client, provision.Options{
		DryRun:     dryRun,
		SSLStaging: os.Getenv("BERTH_TEST_SSL_STAGING") == "true",
		Redact:     red,
	})
	if err != nil {
		t.Fatalf("%s: pipeline pre-flight: %v", label, err)
	}
	terminal := map[string]provision.Event{}
	for ev := range events {
		switch ev.Kind {
		case provision.EventFailed:
			t.Fatalf("%s: step %q failed: %v", label, ev.Step, ev.Err)
		case provision.EventStarted:
		default:
			terminal[ev.Step] = ev
		}
	}
	return terminal
}

// dbProbeStdinCmd runs sql against dbName as the app's DB role, the way
// Laravel connects (socket or TCP), with the password OFF the command string:
// `IFS= read -r` takes it from SSH stdin into a shell variable, and it reaches
// the client only as an environment assignment (MYSQL_PWD / PGPASSWORD) — never
// argv. This command runs as ROOT, so every connection parameter comes from
// TRUSTED identities — the loaded config (dbUser, dbName) and the engine's
// EnvConnection() (driver, host, port, socket) — never from the tenant-writable
// .env; every caller first proves the live .env agrees with these values via
// assertEnvIdentityFidelity. Every interpolated token is sqQuoted anyway
// (defence in depth).
func dbProbeStdinCmd(driver, host, port, socket, dbUser, dbName, sql string) string {
	switch driver {
	case "mysql":
		conn := "-h" + sqQuote(host)
		if socket != "" {
			conn = "--socket=" + sqQuote(socket)
		} else if port != "" {
			conn += " -P" + sqQuote(port)
		}
		return fmt.Sprintf(`IFS= read -r pw; MYSQL_PWD="$pw" mysql %s -u%s %s -e %s`, conn, sqQuote(dbUser), sqQuote(dbName), sqQuote(sql))
	case "pgsql":
		return fmt.Sprintf(`IFS= read -r pw; PGPASSWORD="$pw" psql -h%s -p%s -U%s -d%s -tAc %s`, sqQuote(host), sqQuote(port), sqQuote(dbUser), sqQuote(dbName), sqQuote(sql))
	default:
		return "false"
	}
}

// envFieldExit runs the PRODUCTION envValueMatchScript (bridged from the steps
// package so the drill exercises the exact bytes provisioning runs) against a
// live .env: the expected KEY=value line rides SSH stdin and ONLY the exit
// code comes back (0 match / 1 present-but-different / 3 no such key / 2 I/O
// error) — safe for secrets and non-secrets alike, nothing rides stdout. A
// transport error is fatal; exit-code interpretation is the caller's.
func envFieldExit(ctx context.Context, t *testing.T, c *bssh.Client, envPath, key, want string) int {
	t.Helper()
	res, err := c.Run(ctx, steps.EnvValueMatchScript(envPath, key), []byte(key+"="+want+"\n"))
	if err != nil {
		t.Fatalf("probe %s in %s: %v", key, envPath, err)
	}
	return res.ExitCode
}

// clientAuthContainsCmd mirrors steps.clientAuthContainsScript: stdin carries
// the password, printf pipes it to grep as the PATTERN (-f -) while the auth
// file is grep's named INPUT — pattern-from-pipe and data-from-file ride
// separate fds, and the secret never touches argv or stdout (-q).
func clientAuthContainsCmd(path string) string {
	return `IFS= read -r pw; printf '%s\n' "$pw" | grep -qF -f - ` + sqQuote(path)
}

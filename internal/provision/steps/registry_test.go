package steps_test

import (
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/provision/steps"
	"github.com/robsonek/berth/internal/secret"
)

func TestPipelineHonorsToggles(t *testing.T) {
	s := &config.Server{Valkey: false, Queue: false, Sites: []config.Site{{}}}
	names := stepNames(steps.Pipeline(s, secret.NewRedactor(), true))
	if contains(names, "supervisor") || contains(names, "tls") {
		t.Errorf("disabled steps present: %v", names)
	}
	// valkey is ALWAYS registered: with valkey:false its disabled mode sweeps
	// instances a previous valkey:true provision left behind (P14) — omitting
	// the step entirely made the flip an undeclared state transition.
	if !contains(names, "valkey") {
		t.Errorf("valkey step must be registered even when disabled: %v", names)
	}
	if indexOf(names, "appdirs") > indexOf(names, "database") {
		t.Error("appdirs must come before database (secrets need shared/ first)")
	}
}

func TestPipelineIncludesEnabledToggles(t *testing.T) {
	s := &config.Server{
		Valkey: true,
		Queue:  true,
		Sites:  []config.Site{{Domain: "app.example.com", SSL: true}},
	}
	names := stepNames(steps.Pipeline(s, secret.NewRedactor(), false))
	for _, want := range []string{"valkey", "supervisor", "tls"} {
		if !contains(names, want) {
			t.Errorf("enabled step %q missing: %v", want, names)
		}
	}
}

func TestPipelineSkipSSLOmitsTLS(t *testing.T) {
	s := &config.Server{Sites: []config.Site{{Domain: "app.example.com", SSL: true}}}
	names := stepNames(steps.Pipeline(s, secret.NewRedactor(), true))
	if contains(names, "tls") {
		t.Errorf("tls present despite skipSSL: %v", names)
	}
}

// TestPipelineIncludesTLSWithoutSiteSSL asserts tls is registered even when
// no site requests SSL: outside --skip-ssl the step still owns the orphan
// sweep and the deploy-hook drift-removal for traces earlier SSL configs left.
func TestPipelineIncludesTLSWithoutSiteSSL(t *testing.T) {
	s := &config.Server{Sites: []config.Site{{Domain: "app.example.com", SSL: false}}}
	names := stepNames(steps.Pipeline(s, secret.NewRedactor(), false))
	if !contains(names, "tls") {
		t.Errorf("tls missing for a no-SSL config: %v", names)
	}
	if names[len(names)-1] != "manifest" {
		t.Errorf("manifest must remain the LAST step; got %v", names)
	}
}

// TestTLSAndManifestTrackSkipSSLOnly asserts both gates depend on --skip-ssl
// alone, regardless of whether any site requests SSL: skipSSL omits both tls
// and manifest; without it both are present and manifest closes the pipeline.
func TestTLSAndManifestTrackSkipSSLOnly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ssl     bool
		skipSSL bool
	}{
		{"ssl-on", true, false},
		{"ssl-off", false, false},
		{"ssl-on-skipped", true, true},
		{"ssl-off-skipped", false, true},
	} {
		s := &config.Server{Sites: []config.Site{{Domain: "app.example.com", SSL: tc.ssl}}}
		names := stepNames(steps.Pipeline(s, secret.NewRedactor(), tc.skipSSL))
		want := !tc.skipSSL
		if got := contains(names, "tls"); got != want {
			t.Errorf("%s: tls presence = %v, want %v (names=%v)", tc.name, got, want, names)
		}
		if got := contains(names, "manifest"); got != want {
			t.Errorf("%s: manifest presence = %v, want %v (names=%v)", tc.name, got, want, names)
		}
		if want && names[len(names)-1] != "manifest" {
			t.Errorf("%s: manifest must be the LAST step; got %v", tc.name, names)
		}
	}
}

// TestPipelineManifestLastAndSkipSSLGate asserts the manifest step closes
// every pipeline that is not artificially truncated, and is absent under
// --skip-ssl entirely — tls is an always-run step now, so every --skip-ssl
// run omits it and a "fully provisioned" attestation would be a lie.
func TestPipelineManifestLastAndSkipSSLGate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ssl     bool
		skipSSL bool
		want    bool // manifest registered
	}{
		{"ssl-on", true, false, true},
		{"ssl-off", false, false, true},
		{"ssl-off-skip-flag", false, true, false},
		{"ssl-on-skipped", true, true, false},
	} {
		s := &config.Server{Sites: []config.Site{{Domain: "app.example.com", SSL: tc.ssl}}}
		names := stepNames(steps.Pipeline(s, secret.NewRedactor(), tc.skipSSL))
		if got := contains(names, "manifest"); got != tc.want {
			t.Errorf("%s: manifest presence = %v, want %v (names=%v)", tc.name, got, tc.want, names)
			continue
		}
		if tc.want && names[len(names)-1] != "manifest" {
			t.Errorf("%s: manifest must be the LAST step; got %v", tc.name, names)
		}
	}
}

func TestPipelineOmitsSupervisorWhenOnlySiteQueueNone(t *testing.T) {
	s := &config.Server{
		PHP: config.PHP{Version: "8.4"}, Nginx: config.Nginx{Source: "debian"},
		Database: config.Database{Engine: "mariadb", Source: "mariadb"},
		// Server-wide queue: true, but the ONLY site opts out with queue: none
		// and has no daemons -> nothing needs supervisor.
		Queue: true,
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/var/www/a",
			Queue: &config.QueueConfig{Driver: "none"}}},
	}
	names := stepNames(steps.Pipeline(s, secret.NewRedactor(), true))
	if contains(names, "supervisor") {
		t.Errorf("queue: none on the only site must drop the supervisor step: %v", names)
	}
}

func TestPipelineIncludesSupervisorForDaemonOnlySite(t *testing.T) {
	s := &config.Server{
		PHP: config.PHP{Version: "8.4"}, Nginx: config.Nginx{Source: "debian"},
		Database: config.Database{Engine: "mariadb", Source: "mariadb"},
		// Queue false, but a daemon exists -> supervisor must be included.
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/var/www/a",
			Daemons: []config.Daemon{{Name: "reverb", Command: "php artisan reverb:start"}}}},
	}
	names := stepNames(steps.Pipeline(s, secret.NewRedactor(), true))
	if !contains(names, "supervisor") {
		t.Error("a daemon-only site (Server.Queue false) must still include the supervisor step")
	}
}

func TestPipelineIncludesTuningForMariaDB(t *testing.T) {
	s := &config.Server{Database: config.Database{Engine: "mariadb"}, Sites: []config.Site{{Domain: "a.example.com"}}}
	names := stepNames(steps.Pipeline(s, nil, true))
	if !contains(names, "tuning") {
		t.Errorf("expected tuning step for mariadb; got %v", names)
	}
}

func TestPipelineOmitsTuningForValkeyOnly(t *testing.T) {
	// Valkey no longer pulls in the tuning step: maxmemory lives in the
	// per-site instance units owned by the valkey step.
	s := &config.Server{Valkey: true, Database: config.Database{Engine: "postgres"}, Sites: []config.Site{{Domain: "a.example.com"}}}
	names := stepNames(steps.Pipeline(s, nil, true))
	if contains(names, "tuning") {
		t.Errorf("did not expect tuning step for valkey-only config; got %v", names)
	}
}

func TestPipelineOmitsTuningForPostgresNoValkey(t *testing.T) {
	s := &config.Server{Valkey: false, Database: config.Database{Engine: "postgres"}, Sites: []config.Site{{Domain: "a.example.com"}}}
	names := stepNames(steps.Pipeline(s, nil, true))
	if contains(names, "tuning") {
		t.Errorf("did not expect tuning step; got %v", names)
	}
}

func TestPipelineTuningAfterDatabase(t *testing.T) {
	s := &config.Server{Database: config.Database{Engine: "mariadb"}, Sites: []config.Site{{Domain: "a.example.com"}}}
	names := stepNames(steps.Pipeline(s, nil, true))
	dbIdx, tuneIdx := indexOf(names, "database"), indexOf(names, "tuning")
	if dbIdx < 0 || tuneIdx < 0 || tuneIdx < dbIdx {
		t.Errorf("tuning must come after database; names=%v", names)
	}
}

func TestPipelineIncludesSystemAfterBase(t *testing.T) {
	s := &config.Server{Database: config.Database{Engine: "postgres"}, Sites: []config.Site{{Domain: "a.example.com"}}}
	names := stepNames(steps.Pipeline(s, secret.NewRedactor(), true))
	idx := func(want string) int {
		for i, n := range names {
			if n == want {
				return i
			}
		}
		return -1
	}
	if idx("system") < 0 {
		t.Fatalf("system step missing from pipeline: %v", names)
	}
	if !(idx("base") < idx("system") && idx("system") < idx("php")) {
		t.Errorf("system must sit between base and php; got base=%d system=%d php=%d",
			idx("base"), idx("system"), idx("php"))
	}
}

func TestPipelineIncludesBackupsAfterSite(t *testing.T) {
	s := &config.Server{
		PHP: config.PHP{Version: "8.5"}, Database: config.Database{Engine: "mariadb"},
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/srv/a"}},
	}
	names := stepNames(steps.Pipeline(s, nil, true))
	si, bi := indexOf(names, "site"), indexOf(names, "backups")
	if si < 0 || bi < 0 || bi != si+1 {
		t.Errorf("backups must immediately follow site; got %v", names)
	}
}

func stepNames(ss []provision.Step) []string {
	names := make([]string, len(ss))
	for i, s := range ss {
		names[i] = s.Name()
	}
	return names
}

func contains(names []string, want string) bool {
	return indexOf(names, want) >= 0
}

func indexOf(names []string, want string) int {
	for i, n := range names {
		if n == want {
			return i
		}
	}
	return -1
}

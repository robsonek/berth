package steps

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

// stubFileState stubs the probes managedFileOK+statOwnerMode make for one
// managed file: content read (exact shape copied from backups_test.go's
// convention) and the stat. uptodate=true stubs the desired content and
// meta; uptodate=false stubs an absent file.
func stubFileState(f *bssh.FakeRunner, path string, desired []byte, meta string, uptodate bool) {
	if uptodate {
		f.On("cat "+shQuote(path), bssh.Result{Stdout: string(desired)})
		f.On("stat -c '%U:%G %a' "+shQuote(path), bssh.Result{Stdout: meta + "\n"})
		return
	}
	f.On("cat "+shQuote(path), bssh.Result{ExitCode: 1})
	f.On("stat -c '%U:%G %a' "+shQuote(path), bssh.Result{ExitCode: 1})
}

// stubManagedAbsent stubs the managedFilePresent read probe for an absent file.
func stubManagedAbsent(f *bssh.FakeRunner, path string) {
	f.On("cat "+shQuote(path), bssh.Result{ExitCode: 1})
}

// stubManagedPresent stubs the managedFilePresent read probe for a
// berth-marked file at the path.
func stubManagedPresent(f *bssh.FakeRunner, path string) {
	f.On("cat "+shQuote(path), bssh.Result{Stdout: "# managed by berth\nsome content\n"})
}

// stubManagedForeign stubs the managedFilePresent read probe for a file that
// exists WITHOUT the berth marker (foreign/operator-owned content).
func stubManagedForeign(f *bssh.FakeRunner, path string) {
	f.On("cat "+shQuote(path), bssh.Result{Stdout: "some foreign content\n"})
}

// offsiteS3Server returns a server with one backups-enabled site and an s3
// offsite target; the secret cache is pre-seeded via a temp HOME.
func offsiteS3Server(t *testing.T) *config.Server {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	s := &config.Server{
		ID:   "offsite-test-1",
		Host: "203.0.113.30",
		SSH:  config.SSH{User: "deploy", Port: 22},
		PHP:  config.PHP{Version: "8.4", Source: "auto"},
		Backups: config.Backups{
			Enabled: true,
			Offsite: &config.Offsite{Backend: "s3", Endpoint: "s3.example.com", Bucket: "bkt"},
		},
		Sites: []config.Site{{Domain: "app.example.com", DeployPath: "/var/www/app", User: "deploy"}},
	}
	seedOffsiteSecrets(t, s, map[string]string{
		secret.OffsiteS3AccessKey:    "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey:    "fake-secret",
		secret.OffsiteResticPassword: "fake-restic-pw",
	})
	return s
}

// seedOffsiteSecrets writes the given secrets into the (temp-HOME) cache
// bound to the server's endpoint.
func seedOffsiteSecrets(t *testing.T, s *config.Server, kv map[string]string) {
	t.Helper()
	if err := secret.SaveEnvelope(s.CacheKey(), secret.Envelope{
		Endpoint: &secret.Endpoint{Host: s.Host, Port: s.SSH.Port},
		Secrets:  kv,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOffsiteCheckDisabledCleanHost(t *testing.T) {
	f := bssh.NewFakeRunner()
	for _, p := range []string{offsiteScriptPath, offsiteCronPath, offsiteEnvPath} {
		stubManagedAbsent(f, p) // same read-probe shape as stubFileState, absent variant
	}
	s := offsiteS3Server(t)
	s.Backups.Offsite = nil
	res, err := Offsite(nil).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("clean disabled host must be satisfied; got %s %v", res.Reason, res.Changes)
	}
	if res.Reason != "no offsite target configured" {
		t.Errorf("Reason = %q", res.Reason)
	}
}

func TestOffsiteCheckDisabledSweepsLingeringArtifacts(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubManagedPresent(f, offsiteScriptPath) // berth-marked content at the path
	stubManagedAbsent(f, offsiteCronPath)
	stubManagedAbsent(f, offsiteEnvPath)
	s := offsiteS3Server(t)
	s.Backups.Offsite = nil
	res, err := Offsite(nil).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("lingering offsite script must be drift")
	}
	want := []string{"remove " + offsiteScriptPath + " (offsite disabled)"}
	if !reflect.DeepEqual(res.Changes, want) {
		t.Errorf("Changes = %v, want %v", res.Changes, want)
	}
}

func TestOffsiteCheckEnabledConverged(t *testing.T) {
	s := offsiteS3Server(t)
	f := bssh.NewFakeRunner()
	f.On("dpkg -s restic", bssh.Result{Stdout: "Status: install ok installed\n"})
	f.On("stat -c '%U:%G %a' "+shQuote(offsiteEnvDir), bssh.Result{Stdout: "root:root 755\n"})
	secrets := map[string]string{
		secret.OffsiteS3AccessKey:    "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey:    "fake-secret",
		secret.OffsiteResticPassword: "fake-restic-pw",
	}
	env, err := renderOffsiteEnv(s, secrets)
	if err != nil {
		t.Fatal(err)
	}
	stubFileState(f, offsiteEnvPath, env, "root:root 600", true)
	script, err := renderOffsiteScript(s)
	if err != nil {
		t.Fatal(err)
	}
	stubFileState(f, offsiteScriptPath, script, "root:root 755", true)
	cron, err := renderOffsiteCron(s)
	if err != nil {
		t.Fatal(err)
	}
	stubFileState(f, offsiteCronPath, cron, "root:root 644", true)
	f.On("stat -c '%U:%G %a' '/var/lib/berth'", bssh.Result{Stdout: "root:root 755\n"})
	repo := s.Backups.Offsite.Repository(s.ID)
	stubFileState(f, offsiteStampPath(repo), offsiteStampContent(repo), "root:root 600", true)

	res, err := Offsite(nil).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("converged host must be satisfied; got %s %v", res.Reason, res.Changes)
	}
	if res.Reason != "offsite backups converged" {
		t.Errorf("Reason = %q", res.Reason)
	}
}

func TestOffsiteCheckCorruptCachedValueIsLoudError(t *testing.T) {
	// The cache file is operator-editable: a value violating the quoting
	// contract must be a loud error NAMING THE KEY (never the value),
	// before anything is rendered or probed beyond the package check.
	s := offsiteS3Server(t)
	seedOffsiteSecrets(t, s, map[string]string{
		secret.OffsiteS3AccessKey:    "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey:    "evil' ; rm -rf / #",
		secret.OffsiteResticPassword: "fake-restic-pw",
	})
	f := bssh.NewFakeRunner()
	f.On("dpkg -s restic", bssh.Result{Stdout: "Status: install ok installed\n"})
	_, err := Offsite(nil).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), secret.OffsiteS3SecretKey) {
		t.Fatalf("corrupt cached value must hard-error naming the key; got %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "evil") {
		t.Fatalf("the error must never echo the secret value: %v", err)
	}
}

func TestOffsiteCheckMissingStampDemandsInit(t *testing.T) {
	// Files converged but no stamp: the repo was never verified/initialized
	// (e.g. the first Apply hit a network failure) — Check must stay
	// unsatisfied so Apply retries the probe.
	s := offsiteS3Server(t)
	f := bssh.NewFakeRunner()
	f.On("dpkg -s restic", bssh.Result{Stdout: "Status: install ok installed\n"})
	f.On("stat -c '%U:%G %a' "+shQuote(offsiteEnvDir), bssh.Result{Stdout: "root:root 755\n"})
	secrets := map[string]string{
		secret.OffsiteS3AccessKey:    "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey:    "fake-secret",
		secret.OffsiteResticPassword: "fake-restic-pw",
	}
	env, _ := renderOffsiteEnv(s, secrets)
	stubFileState(f, offsiteEnvPath, env, "root:root 600", true)
	script, _ := renderOffsiteScript(s)
	stubFileState(f, offsiteScriptPath, script, "root:root 755", true)
	cron, _ := renderOffsiteCron(s)
	stubFileState(f, offsiteCronPath, cron, "root:root 644", true)
	f.On("stat -c '%U:%G %a' '/var/lib/berth'", bssh.Result{Stdout: "root:root 755\n"})
	repo := s.Backups.Offsite.Repository(s.ID)
	stubFileState(f, offsiteStampPath(repo), offsiteStampContent(repo), "", false) // absent

	res, err := Offsite(nil).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("missing init stamp must be unsatisfied")
	}
	want := "initialize or verify the restic repository (" + repo + ")"
	if len(res.Changes) != 1 || res.Changes[0] != want {
		t.Errorf("Changes = %v, want [%s]", res.Changes, want)
	}
}

func TestOffsiteCheckMissingPasswordPlansGeneration(t *testing.T) {
	s := offsiteS3Server(t)
	seedOffsiteSecrets(t, s, map[string]string{
		secret.OffsiteS3AccessKey: "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey: "fake-secret",
	}) // no restic password
	f := bssh.NewFakeRunner()
	f.On("dpkg -s restic", bssh.Result{Stdout: "Status: install ok installed\n"})
	f.On("stat -c '%U:%G %a' "+shQuote(offsiteEnvDir), bssh.Result{Stdout: "root:root 755\n"})
	// env content is unknowable without the password: Check plans the write
	// unconditionally and must NOT probe the env file's content.
	script, _ := renderOffsiteScript(s)
	stubFileState(f, offsiteScriptPath, script, "root:root 755", true)
	cron, _ := renderOffsiteCron(s)
	stubFileState(f, offsiteCronPath, cron, "root:root 644", true)
	f.On("stat -c '%U:%G %a' '/var/lib/berth'", bssh.Result{Stdout: "root:root 755\n"})
	repo := s.Backups.Offsite.Repository(s.ID)
	stubFileState(f, offsiteStampPath(repo), offsiteStampContent(repo), "root:root 600", true)

	res, err := Offsite(nil).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("missing restic password must be unsatisfied")
	}
	joined := strings.Join(res.Changes, "\n")
	for _, want := range []string{"generate restic repository password", "write " + offsiteEnvPath} {
		if !strings.Contains(joined, want) {
			t.Errorf("Changes missing %q: %v", want, res.Changes)
		}
	}
}

func TestOffsiteCheckMissingS3SecretsIsLoudError(t *testing.T) {
	s := offsiteS3Server(t)
	seedOffsiteSecrets(t, s, map[string]string{}) // wipe
	f := bssh.NewFakeRunner()
	f.On("dpkg -s restic", bssh.Result{Stdout: "Status: install ok installed\n"})
	_, err := Offsite(nil).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "berth secret set") {
		t.Fatalf("missing s3 credentials must hard-error with the recipe; got %v", err)
	}
}

// stubOffsiteApplyBase stubs everything Apply converges BEFORE the repo
// probe on an s3 host whose files are all absent: package present, dirs,
// env/script/cron write probes, plus the bash -n validation.
func stubOffsiteApplyBase(t *testing.T, f *bssh.FakeRunner, s *config.Server, secrets map[string]string) {
	t.Helper()
	f.On("dpkg -s restic", bssh.Result{Stdout: "Status: install ok installed\n"})
	f.On("install -d -o root -g root -m 0755 "+shQuote(offsiteEnvDir), bssh.Result{})
	env, err := renderOffsiteEnv(s, secrets)
	if err != nil {
		t.Fatal(err)
	}
	stubFileState(f, offsiteEnvPath, env, "", false) // absent -> write
	script, err := renderOffsiteScript(s)
	if err != nil {
		t.Fatal(err)
	}
	stubFileState(f, offsiteScriptPath, script, "", false)
	f.On("bash -n "+shQuote(offsiteScriptPath), bssh.Result{})
	cron, err := renderOffsiteCron(s)
	if err != nil {
		t.Fatal(err)
	}
	stubFileState(f, offsiteCronPath, cron, "", false)
	f.On("install -d -o root -g root -m 0755 '/var/lib/berth'", bssh.Result{})
	// writeManagedFile probes the stamp path before writing it (exact-match
	// FakeRunner: the success paths would otherwise die on an unstubbed cat).
	repo := s.Backups.Offsite.Repository(s.ID)
	stubFileState(f, offsiteStampPath(repo), offsiteStampContent(repo), "", false)
}

func TestOffsiteApplyInitializesRepoAndStamps(t *testing.T) {
	s := offsiteS3Server(t)
	secrets := map[string]string{
		secret.OffsiteS3AccessKey:    "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey:    "fake-secret",
		secret.OffsiteResticPassword: "fake-restic-pw",
	}
	f := bssh.NewFakeRunner()
	stubOffsiteApplyBase(t, f, s, secrets)
	// restic 0.18 (Debian 13): exit code 10 = repository does not exist.
	probe := "set -a && . " + shQuote(offsiteEnvPath) + " && restic cat config >/dev/null"
	f.On(probe, bssh.Result{ExitCode: 10, Stderr: "Fatal: repository does not exist: unable to open config file\n"})
	f.On("set -a && . "+shQuote(offsiteEnvPath)+" && restic init", bssh.Result{ExitCode: 0, Stdout: "created restic repository\n"})

	if err := Offsite(nil).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	repo := s.Backups.Offsite.Repository(s.ID)
	stamped := false
	for _, w := range f.Writes() {
		if w.Path == offsiteStampPath(repo) && string(w.Content) == string(offsiteStampContent(repo)) {
			stamped = true
		}
	}
	if !stamped {
		t.Fatal("successful init must write the per-repository stamp")
	}
}

func TestOffsiteApplyExistingRepoSkipsInit(t *testing.T) {
	s := offsiteS3Server(t)
	secrets := map[string]string{
		secret.OffsiteS3AccessKey:    "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey:    "fake-secret",
		secret.OffsiteResticPassword: "fake-restic-pw",
	}
	f := bssh.NewFakeRunner()
	stubOffsiteApplyBase(t, f, s, secrets)
	f.On("set -a && . "+shQuote(offsiteEnvPath)+" && restic cat config >/dev/null", bssh.Result{ExitCode: 0})

	if err := Offsite(nil).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "restic init") {
			t.Fatal("existing repository must never be re-initialized")
		}
	}
}

func TestOffsiteApplyNetworkFailureWarnsAndMarksUnconverged(t *testing.T) {
	s := offsiteS3Server(t)
	secrets := map[string]string{
		secret.OffsiteS3AccessKey:    "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey:    "fake-secret",
		secret.OffsiteResticPassword: "fake-restic-pw",
	}
	f := bssh.NewFakeRunner()
	stubOffsiteApplyBase(t, f, s, secrets)
	f.On("set -a && . "+shQuote(offsiteEnvPath)+" && restic cat config >/dev/null",
		bssh.Result{ExitCode: 1, Stderr: "Fatal: unable to open config file\ndial tcp: connection refused\n"})

	var warned, unconverged []string
	rc := provision.RunCtx{
		Warn:            func(msg string) { warned = append(warned, msg) },
		NoteUnconverged: func(reason string) { unconverged = append(unconverged, reason) },
	}
	if err := Offsite(nil).Apply(context.Background(), rc, s, f); err != nil {
		t.Fatal(err)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "next run") {
		t.Errorf("expected one retry-promising warning; got %v", warned)
	}
	if len(unconverged) != 1 {
		t.Errorf("a knowingly unverified repository must mark the run unconverged; got %v", unconverged)
	}
	repo := s.Backups.Offsite.Repository(s.ID)
	for _, w := range f.Writes() {
		if w.Path == offsiteStampPath(repo) {
			t.Fatal("no stamp may be written when the repository was not verified")
		}
	}
}

func TestOffsiteApplyWrongPasswordIsFatal(t *testing.T) {
	s := offsiteS3Server(t)
	secrets := map[string]string{
		secret.OffsiteS3AccessKey:    "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey:    "fake-secret",
		secret.OffsiteResticPassword: "fake-restic-pw",
	}
	f := bssh.NewFakeRunner()
	stubOffsiteApplyBase(t, f, s, secrets)
	// restic 0.18 (Debian 13): exit code 12 = wrong password.
	f.On("set -a && . "+shQuote(offsiteEnvPath)+" && restic cat config >/dev/null",
		bssh.Result{ExitCode: 12, Stderr: "Fatal: wrong password or no key found\n"})

	err := Offsite(nil).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "berth secret set") {
		t.Fatalf("wrong password must be a hard error with the recovery recipe; got %v", err)
	}
}

func TestOffsiteApplyLegacyMessageClassification(t *testing.T) {
	// Message fallback for restic versions without the 10/12 exit codes:
	// the classic "Is there a repository at" phrasing must still classify
	// as missing-repo (init), not as a transient warning.
	s := offsiteS3Server(t)
	secrets := map[string]string{
		secret.OffsiteS3AccessKey:    "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey:    "fake-secret",
		secret.OffsiteResticPassword: "fake-restic-pw",
	}
	f := bssh.NewFakeRunner()
	stubOffsiteApplyBase(t, f, s, secrets)
	f.On("set -a && . "+shQuote(offsiteEnvPath)+" && restic cat config >/dev/null",
		bssh.Result{ExitCode: 1, Stderr: "Fatal: unable to open config file\nIs there a repository at the following location?\n"})
	f.On("set -a && . "+shQuote(offsiteEnvPath)+" && restic init", bssh.Result{ExitCode: 0})

	if err := Offsite(nil).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	initRan := false
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "restic init") {
			initRan = true
		}
	}
	if !initRan {
		t.Fatal("legacy missing-repo message must classify as init, not transient")
	}
}

func TestOffsiteApplyGeneratesPasswordOnce(t *testing.T) {
	s := offsiteS3Server(t)
	seedOffsiteSecrets(t, s, map[string]string{
		secret.OffsiteS3AccessKey: "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey: "fake-secret",
	}) // no password yet
	f := bssh.NewFakeRunner()
	// The env content depends on the GENERATED password, so stub the env
	// write probe as absent WITHOUT pinning content, then assert afterwards.
	stubOffsiteApplyBase(t, f, s, map[string]string{
		secret.OffsiteS3AccessKey: "AKIAEXAMPLE",
		secret.OffsiteS3SecretKey: "fake-secret",
	})
	f.On("set -a && . "+shQuote(offsiteEnvPath)+" && restic cat config >/dev/null", bssh.Result{ExitCode: 0})

	if err := Offsite(nil).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	env, err := secret.LoadEnvelope(s.CacheKey())
	if err != nil {
		t.Fatal(err)
	}
	pw := env.Secrets[secret.OffsiteResticPassword]
	if pw == "" {
		t.Fatal("Apply must generate and persist the restic password")
	}
	found := false
	for _, w := range f.Writes() {
		if w.Path == offsiteEnvPath && strings.Contains(string(w.Content), "RESTIC_PASSWORD='"+pw+"'") {
			found = true
		}
	}
	if !found {
		t.Fatal("the generated password must land in the written env file")
	}
}

func TestOffsiteApplyDisabledSweepsMarkerGuarded(t *testing.T) {
	s := offsiteS3Server(t)
	s.Backups.Offsite = nil
	f := bssh.NewFakeRunner()
	stubManagedPresent(f, offsiteScriptPath)
	f.On("rm -f "+shQuote(offsiteScriptPath), bssh.Result{})
	stubManagedAbsent(f, offsiteCronPath)
	stubManagedForeign(f, offsiteEnvPath) // exists WITHOUT the marker
	if err := Offsite(nil).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "rm -f "+shQuote(offsiteEnvPath) {
			t.Fatal("a foreign (unmarked) file must never be removed")
		}
	}
}

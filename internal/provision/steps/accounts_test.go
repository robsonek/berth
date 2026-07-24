package steps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	"github.com/robsonek/berth/internal/secret"
	bssh "github.com/robsonek/berth/internal/ssh"
)

const testOperatorKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYFORUNITTESTSONLY operator@berth"

// writeOperatorKey writes a fake "<key>.pub" file and returns the private-key
// path (without the .pub suffix), as config.SSH.Key expects.
func writeOperatorKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath+".pub", []byte(testOperatorKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyPath
}

func testServerWithKey(t *testing.T) *config.Server {
	return &config.Server{
		SSH:   config.SSH{Key: writeOperatorKey(t)},
		PHP:   config.PHP{Version: "8.4"},
		Sites: []config.Site{{Domain: "app.example.com", DeployPath: "/home/deploy/app"}},
	}
}

// stubAccountExists stubs the read-only checks that report a fully-provisioned
// account (user present, sudoers content up to date, authorized_keys up to date).
func stubAccountExists(f *bssh.FakeRunner, user string, sudoers, want []byte) {
	f.On("id "+user, bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(sudoersPath(user)), bssh.Result{Stdout: string(sudoers), ExitCode: 0})
	f.On("cat "+shQuote(authorizedKeysPath(user)), bssh.Result{Stdout: string(want), ExitCode: 0})
}

// stubAccountCreate stubs the mutating commands for creating + configuring an
// account during Apply (user absent → useradd; home lockdown; sudoers validate;
// ssh dir; write-guard reads report both managed files absent).
func stubAccountCreate(f *bssh.FakeRunner, user string) {
	f.On("id "+user, bssh.Result{ExitCode: 1})
	f.On("useradd -m -s /bin/bash "+user, bssh.Result{})
	f.On("getent passwd "+user, bssh.Result{Stdout: fmt.Sprintf("%s:x:1000:1000::/home/%s:/bin/bash\n", user, user)})
	f.On(fmt.Sprintf("install -d -o %s -g %s -m 700 ", user, user)+shQuote(fmt.Sprintf("/home/%s", user)), bssh.Result{})
	f.On("visudo -cf "+shQuote(sudoersPath(user)), bssh.Result{ExitCode: 0})
	f.On(fmt.Sprintf("install -d -o %s -g %s -m 700 ", user, user)+shQuote(fmt.Sprintf("/home/%s/.ssh", user)), bssh.Result{})
	f.On("cat "+shQuote(sudoersPath(user)), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(authorizedKeysPath(user)), bssh.Result{ExitCode: 1})
}

// stubFullApply stubs a complete Apply pass for the single-site test server
// (berth + deploy created fresh), so break-glass tests can focus on the
// password commands appended at the end of Apply.
func stubFullApply(t *testing.T, s *config.Server) *bssh.FakeRunner {
	t.Helper()
	f := bssh.NewFakeRunner()
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	return f
}

func TestAccountsRequiresBase(t *testing.T) {
	if got := Accounts(secret.NewRedactor()).Requires(); len(got) != 1 || got[0] != "base" {
		t.Fatalf("Requires() = %v, want [base]", got)
	}
}

func TestAccountsCheckUnsatisfiedWhenUserMissing(t *testing.T) {
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	f.On("id berth", bssh.Result{ExitCode: 1}) // berth missing
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when an account is missing")
	}
}

func TestAccountsCheckSatisfiedWhenAllPresent(t *testing.T) {
	s := testServerWithKey(t)
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want) // single site -> legacy "deploy"
	stubConsoleLocked(f)
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestAccountsCheckUnsatisfiedWhenSudoersDrifted(t *testing.T) {
	s := testServerWithKey(t)
	want := authorizedKeys(testOperatorKey)
	f := bssh.NewFakeRunner()
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	// deploy's sudoers carries the managed marker but has stale content (e.g. an
	// out-of-date program list) — Check must content-drift detect and report
	// unsatisfied so a changed program list converges on an already-provisioned host.
	stale := []byte(managedMarker + "\ndeploy ALL=(root) NOPASSWD: /usr/bin/supervisorctl restart berth-old\\:*\n")
	stubAccountExists(f, "deploy", stale, want)
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Errorf("expected unsatisfied when site sudoers content has drifted; got %+v", cr)
	}
}

func TestSiteSudoersIsolationPerProgram(t *testing.T) {
	s := &config.Server{
		PHP: config.PHP{Version: "8.4"}, Queue: true,
		Sites: []config.Site{
			{Domain: "a.example.com", DeployPath: "/var/www/a", User: "auser"},
			{Domain: "b.example.com", DeployPath: "/var/www/b", User: "buser"},
		},
	}
	bBody, err := renderSiteSudoers(s, s.Sites[1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bBody), "berth-a_example_com") {
		t.Errorf("site B sudoers must NOT reference site A's program:\n%s", bBody)
	}
	if !strings.Contains(string(bBody), `supervisorctl restart berth-b_example_com\:\*`) {
		t.Errorf("site B sudoers must control its own program:\n%s", bBody)
	}
}

func TestSiteSudoersEscapesWildcardForIsolation(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}, Queue: true,
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/var/www/a", User: "auser"}}}
	body, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	// The wildcard MUST be escaped (literal) so the sudoers arg cannot cross
	// whitespace into another tenant's program.
	if !strings.Contains(string(body), `restart berth-a_example_com\:\*`) {
		t.Errorf("supervisorctl grant must escape the wildcard (\\:\\*) for tenant isolation:\n%s", body)
	}
	if strings.Contains(string(body), `berth-a_example_com\:*`+"\n") {
		t.Errorf("unescaped \\:* wildcard must not appear:\n%s", body)
	}
}

func TestSiteSudoersIncludesDaemonPrograms(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}, Queue: true,
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/var/www/a", User: "auser",
			Daemons: []config.Daemon{{Name: "reverb", Command: "php artisan reverb:start"}}}}}
	body, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`start berth-a_example_com\:\*`, `start berth-a_example_com-reverb\:\*`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing grant %q in:\n%s", want, body)
		}
	}
}

func TestSiteSudoersHasNoUnscopedSupervisorGrants(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}, Queue: true,
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/var/www/a", User: "auser"}}}
	body, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	// `supervisorctl update` restarts OTHER tenants' changed programs and
	// `reread` serves no deployer purpose (berth runs both as root in site.Apply)
	// — neither may appear in a site user's grants.
	for _, banned := range []string{"supervisorctl reread", "supervisorctl update"} {
		if strings.Contains(string(body), banned) {
			t.Errorf("site sudoers must not grant unscoped %q:\n%s", banned, body)
		}
	}
}

func TestAccountsApplyCreatesUsersAndWritesSudoers(t *testing.T) {
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")

	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	joined := strings.Join(callCmds(f), "\n")
	for _, want := range []string{"useradd -m -s /bin/bash berth", "useradd -m -s /bin/bash deploy", "getent passwd deploy", "install -d -o deploy -g deploy -m 700 " + shQuote("/home/deploy")} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in calls:\n%s", want, joined)
		}
	}

	writes := map[string]bssh.FileSpec{}
	for _, w := range f.Writes() {
		writes[w.Path] = w
	}
	berthSudo, ok := writes[sudoersBerthPath]
	if !ok || berthSudo.Mode != 0o440 || !strings.Contains(string(berthSudo.Content), "berth ALL=(ALL) NOPASSWD:ALL") {
		t.Errorf("berth sudoers wrong: %+v", berthSudo)
	}
	deploySudo, ok := writes[sudoersPath("deploy")]
	if !ok || !strings.Contains(string(deploySudo.Content), "deploy ALL=(root) NOPASSWD") {
		t.Errorf("deploy sudoers wrong/missing: %+v", deploySudo)
	}
	for _, u := range []string{"berth", "deploy"} {
		ak, ok := writes[authorizedKeysPath(u)]
		if !ok || !strings.Contains(string(ak.Content), testOperatorKey) || ak.Mode != 0o600 {
			t.Errorf("%s authorized_keys wrong: %+v", u, ak)
		}
	}
}

func TestAccountsApplyMultiSiteIsolatesUsers(t *testing.T) {
	s := &config.Server{
		SSH:   config.SSH{Key: writeOperatorKey(t)},
		PHP:   config.PHP{Version: "8.5"},
		Sites: []config.Site{{Domain: "one.example.com", DeployPath: "/var/www/one"}, {Domain: "two.example.com", DeployPath: "/var/www/two"}},
	}
	u1, u2 := s.SiteUser(s.Sites[0]), s.SiteUser(s.Sites[1])
	if u1 == u2 || u1 == "deploy" {
		t.Fatalf("multi-site users must be distinct and derived; got %q, %q", u1, u2)
	}
	f := bssh.NewFakeRunner()
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, u1)
	stubAccountCreate(f, u2)

	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	writes := map[string]bssh.FileSpec{}
	for _, w := range f.Writes() {
		writes[w.Path] = w
	}
	// Each site has its own sudoers naming only its own user + program.
	for i, u := range []string{u1, u2} {
		sd, ok := writes[sudoersPath(u)]
		if !ok {
			t.Errorf("sudoers for %s not written", u)
			continue
		}
		if !strings.Contains(string(sd.Content), u+" ALL=(root)") {
			t.Errorf("sudoers for site %d must reference its own user %s: %s", i, u, sd.Content)
		}
		if _, ok := writes[authorizedKeysPath(u)]; !ok {
			t.Errorf("authorized_keys for %s not written", u)
		}
	}
}

func TestAccountsApplyRefusesForeignAuthorizedKeys(t *testing.T) {
	// Check's per-account loop returns unsatisfied at the FIRST conflict, so a
	// later account's pre-existing authorized_keys may reach Apply unclassified;
	// the write path itself must refuse to clobber a file berth does not manage.
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	f.On("cat "+shQuote(sudoersBerthPath), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(sudoersPath("deploy")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(authorizedKeysPath("berth")), bssh.Result{ExitCode: 1})
	// deploy already has a hand-installed authorized_keys (no berth marker).
	f.On("cat "+shQuote(authorizedKeysPath("deploy")), bssh.Result{ExitCode: 0, Stdout: "ssh-rsa AAAAOPERATORMANUALKEY manual@ops\n"})

	err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	for _, w := range f.Writes() {
		if w.Path == authorizedKeysPath("deploy") {
			t.Error("a foreign authorized_keys must not be overwritten without --force")
		}
	}
}

func TestAccountsApplyOverwritesForeignAuthorizedKeysWithForce(t *testing.T) {
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	f.On("cat "+shQuote(sudoersBerthPath), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(sudoersPath("deploy")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(authorizedKeysPath("berth")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(authorizedKeysPath("deploy")), bssh.Result{ExitCode: 0, Stdout: "ssh-rsa AAAAOPERATORMANUALKEY manual@ops\n"})

	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{Force: true}, s, f); err != nil {
		t.Fatalf("Apply() with --force error = %v", err)
	}
	var overwritten bool
	for _, w := range f.Writes() {
		if w.Path == authorizedKeysPath("deploy") {
			overwritten = true
		}
	}
	if !overwritten {
		t.Error("--force must overwrite the foreign authorized_keys")
	}
}

func TestAccountsApplyGeneratesDeployKeyWhenRepository(t *testing.T) {
	s := testServerWithKey(t)
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	f := bssh.NewFakeRunner()
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	f.On("test -e '/home/deploy/.ssh/id_ed25519'", bssh.Result{ExitCode: 1}) // key absent
	f.On("sudo -u deploy ssh-keygen -t ed25519 -N '' -f '/home/deploy/.ssh/id_ed25519' -C 'deploy@github.com'", bssh.Result{})
	f.On("sudo -u deploy sh -c 'ssh-keygen -F github.com -f /home/deploy/.ssh/known_hosts >/dev/null 2>&1 || ssh-keyscan github.com >> /home/deploy/.ssh/known_hosts'", bssh.Result{})

	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	joined := strings.Join(callCmds(f), "\n")
	if !strings.Contains(joined, "ssh-keygen -t ed25519") {
		t.Errorf("expected ssh-keygen for deploy; calls:\n%s", joined)
	}
	if !strings.Contains(joined, "ssh-keyscan github.com") {
		t.Errorf("expected ssh-keyscan of git host; calls:\n%s", joined)
	}
}

func TestAccountsApplySkipsDeployKeyWithoutRepository(t *testing.T) {
	s := testServerWithKey(t) // no repository
	f := bssh.NewFakeRunner()
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")

	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "ssh-keygen") || strings.Contains(c.Cmd, "ssh-keyscan") {
			t.Errorf("unexpected deploy-key command without repository: %q", c.Cmd)
		}
	}
}

func TestEnsureUserCreatesAndLocksHome(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("id app", bssh.Result{ExitCode: 1})
	f.On("useradd -m -s /bin/bash app", bssh.Result{})
	f.On("getent passwd app", bssh.Result{Stdout: "app:x:1002:1002::/home/app:/bin/bash\n"})
	f.On("install -d -o app -g app -m 700 "+shQuote("/home/app"), bssh.Result{})
	if err := ensureUser(context.Background(), f, "app"); err != nil {
		t.Fatalf("ensureUser() error = %v", err)
	}
}

// A pre-existing account whose home is not /home/<user> (e.g. Debian's stock
// "sync" with home /bin) must be refused with an actionable error rather than a
// blind chmod of a path that does not exist.
func TestEnsureUserRejectsForeignHome(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("id sync", bssh.Result{ExitCode: 0})
	f.On("getent passwd sync", bssh.Result{Stdout: "sync:x:4:65534:sync:/bin:/bin/sync\n"})
	err := ensureUser(context.Background(), f, "sync")
	if err == nil {
		t.Fatal("expected error for a user whose home is not /home/sync")
	}
	if !strings.Contains(err.Error(), "reserved system account") {
		t.Errorf("error should explain the reserved-account collision; got %v", err)
	}
}

// callCmds returns the recorded command strings of a FakeRunner.
func callCmds(f *bssh.FakeRunner) []string {
	var out []string
	for _, c := range f.Calls() {
		out = append(out, c.Cmd)
	}
	return out
}

func TestAccountsCheckUnsatisfiedWhenDeployKeyMissing(t *testing.T) {
	// Adding repository: to an already-provisioned site must re-trigger Apply
	// (which owns ensureDeployKey) — otherwise the key is never generated and
	// `berth site key`'s "run provision first" advice loops forever.
	s := testServerWithKey(t)
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	f.On("test -e '/home/deploy/.ssh/id_ed25519'", bssh.Result{ExitCode: 1}) // key missing
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while a repository site's deploy key is missing")
	}
	if !strings.Contains(cr.Reason, "deploy key") {
		t.Errorf("Reason = %q", cr.Reason)
	}
}

func TestAccountsCheckSatisfiedWithDeployKeyPresent(t *testing.T) {
	s := testServerWithKey(t)
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	f.On("test -e '/home/deploy/.ssh/id_ed25519'", bssh.Result{ExitCode: 0})
	stubConsoleLocked(f)
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied with the deploy key present; got %+v", cr)
	}
}

// stubConsoleLocked stubs the break-glass probe as "locked" (useradd's default
// state), the satisfied posture for the default break_glass: false.
func stubConsoleLocked(f *bssh.FakeRunner) {
	f.On("passwd -S berth", bssh.Result{ExitCode: 0, Stdout: "berth L 07/24/2026 0 99999 7 -1\n"})
}

func TestAccountsCheckBreakGlassOnPasswordMissingUnsatisfied(t *testing.T) {
	s := testServerWithKey(t)
	s.System.BreakGlass = true
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubConsoleLocked(f)
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("break_glass on with a locked berth password must be unsatisfied")
	}
}

func TestAccountsCheckBreakGlassOffPasswordSetUnsatisfied(t *testing.T) {
	// A usable password WITH the local ownership marker (berth set it) must
	// reconcile back to locked when the knob is off.
	chdirTemp(t)
	s := testServerWithKey(t)
	if err := secret.SaveCache(s.Host, map[string]string{"console:berth": "OwnedPW123"}); err != nil {
		t.Fatal(err)
	}
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	f.On("passwd -S berth", bssh.Result{ExitCode: 0, Stdout: "berth P 07/24/2026 0 99999 7 -1\n"})
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("break_glass off with a usable berth password must be unsatisfied (lock it back)")
	}
}

func TestAccountsCheckBreakGlassOffForeignPasswordSatisfied(t *testing.T) {
	// A usable password WITHOUT the ownership marker is the operator's, not
	// berth's — the swap-file rule: berth removes only what it created.
	chdirTemp(t)
	s := testServerWithKey(t)
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	f.On("passwd -S berth", bssh.Result{ExitCode: 0, Stdout: "berth P 07/24/2026 0 99999 7 -1\n"})
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("an operator-set password with break_glass off must be left alone; got %+v", cr)
	}
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, stubForeignPasswordApply(t, s)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
}

// stubForeignPasswordApply stubs a full Apply with a usable but unowned
// password; the assertion is implicit — an unstubbed `passwd -l berth` would
// fail the FakeRunner if Apply tried to lock it.
func stubForeignPasswordApply(t *testing.T, s *config.Server) *bssh.FakeRunner {
	t.Helper()
	f := stubFullApply(t, s)
	f.On("passwd -S berth", bssh.Result{ExitCode: 0, Stdout: "berth P 07/24/2026 0 99999 7 -1\n"})
	return f
}

func TestAccountsCheckBreakGlassSatisfiedBothWays(t *testing.T) {
	want := authorizedKeys(testOperatorKey)
	for _, tc := range []struct {
		name   string
		knob   bool
		status string
	}{
		{"off locked", false, "L"},
		{"off no password", false, "NP"},
		{"on usable", true, "P"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServerWithKey(t)
			s.System.BreakGlass = tc.knob
			deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
			if err != nil {
				t.Fatal(err)
			}
			f := bssh.NewFakeRunner()
			stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
			stubAccountExists(f, "deploy", deploySudoers, want)
			f.On("passwd -S berth", bssh.Result{ExitCode: 0, Stdout: "berth " + tc.status + " 07/24/2026 0 99999 7 -1\n"})
			cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
			if err != nil {
				t.Fatal(err)
			}
			if !cr.Satisfied {
				t.Errorf("expected satisfied; got %+v", cr)
			}
		})
	}
}

func TestAccountsApplyBreakGlassSetsPasswordViaStdin(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	s.System.BreakGlass = true
	f := stubFullApply(t, s)
	stubConsoleLocked(f)
	f.On("chpasswd", bssh.Result{})
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var pw string
	for _, c := range f.Calls() {
		if c.Cmd == "chpasswd" {
			line := strings.TrimSuffix(string(c.Stdin), "\n")
			var ok bool
			if pw, ok = strings.CutPrefix(line, "berth:"); !ok || pw == "" {
				t.Fatalf("chpasswd stdin has the wrong shape (len %d), want berth:<password>", len(line))
			}
		}
		if strings.Contains(c.Cmd, pw) && pw != "" {
			t.Errorf("password leaked into a command string: %q", c.Cmd)
		}
	}
	if pw == "" {
		t.Fatal("chpasswd never ran")
	}
	// The credential is persisted locally so the operator can read it.
	cache, err := secret.LoadCache(s.Host)
	if err != nil {
		t.Fatal(err)
	}
	if cache["console:berth"] != pw {
		t.Error("console password missing from the local secret cache")
	}
}

func TestAccountsApplyBreakGlassReusesCachedPassword(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	s.System.BreakGlass = true
	if err := secret.SaveCache(s.Host, map[string]string{"console:berth": "CachedPW123"}); err != nil {
		t.Fatal(err)
	}
	f := stubFullApply(t, s)
	stubConsoleLocked(f)
	f.On("chpasswd", bssh.Result{})
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "chpasswd" && string(c.Stdin) != "berth:CachedPW123\n" {
			t.Errorf("cached password must be reused (stdin mismatch, len %d)", len(c.Stdin))
		}
	}
}

func TestAccountsApplyBreakGlassNeverRotatesUsablePassword(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	s.System.BreakGlass = true
	f := stubFullApply(t, s)
	f.On("passwd -S berth", bssh.Result{ExitCode: 0, Stdout: "berth P 07/24/2026 0 99999 7 -1\n"})
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "chpasswd" {
			t.Error("a usable password must never be rotated")
		}
	}
}

func TestAccountsApplyBreakGlassOffLocksOwnedPassword(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	if err := secret.SaveCache(s.Host, map[string]string{"console:berth": "OwnedPW123", "other": "keep"}); err != nil {
		t.Fatal(err)
	}
	f := stubFullApply(t, s)
	f.On("passwd -S berth", bssh.Result{ExitCode: 0, Stdout: "berth P 07/24/2026 0 99999 7 -1\n"})
	f.On("passwd -l berth", bssh.Result{})
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, "passwd -l berth") {
		t.Error("break_glass off must lock the berth-set password back")
	}
	cache, err := secret.LoadCache(s.Host)
	if err != nil {
		t.Fatal(err)
	}
	if cache["console:berth"] != "" {
		t.Error("locking must drop the cached plaintext (a stale root credential)")
	}
	if cache["other"] != "keep" {
		t.Error("dropping the marker must not clobber other cached secrets")
	}
}

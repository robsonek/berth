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
// account (user present, sudoers present+valid, authorized_keys up to date).
func stubAccountExists(f *bssh.FakeRunner, user string, want []byte) {
	f.On("id "+user, bssh.Result{ExitCode: 0})
	f.On("test -e "+shQuote(sudoersPath(user)), bssh.Result{ExitCode: 0})
	f.On("visudo -cf "+shQuote(sudoersPath(user)), bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(authorizedKeysPath(user)), bssh.Result{Stdout: string(want), ExitCode: 0})
}

// stubAccountCreate stubs the mutating commands for creating + configuring an
// account during Apply (user absent → useradd; home lockdown; sudoers validate;
// ssh dir).
func stubAccountCreate(f *bssh.FakeRunner, user string) {
	f.On("id "+user, bssh.Result{ExitCode: 1})
	f.On("useradd -m -s /bin/bash "+user, bssh.Result{})
	f.On("getent passwd "+user, bssh.Result{Stdout: fmt.Sprintf("%s:x:1000:1000::/home/%s:/bin/bash\n", user, user)})
	f.On(fmt.Sprintf("install -d -o %s -g %s -m 700 ", user, user)+shQuote(fmt.Sprintf("/home/%s", user)), bssh.Result{})
	f.On("visudo -cf "+shQuote(sudoersPath(user)), bssh.Result{ExitCode: 0})
	f.On(fmt.Sprintf("install -d -o %s -g %s -m 700 ", user, user)+shQuote(fmt.Sprintf("/home/%s/.ssh", user)), bssh.Result{})
}

func TestAccountsRequiresBase(t *testing.T) {
	if got := Accounts().Requires(); len(got) != 1 || got[0] != "base" {
		t.Fatalf("Requires() = %v, want [base]", got)
	}
}

func TestAccountsCheckUnsatisfiedWhenUserMissing(t *testing.T) {
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	f.On("id berth", bssh.Result{ExitCode: 1}) // berth missing
	cr, err := Accounts().Check(context.Background(), provision.RunCtx{}, s, f)
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
	f := bssh.NewFakeRunner()
	stubAccountExists(f, "berth", want)
	stubAccountExists(f, "deploy", want) // single site -> legacy "deploy"
	cr, err := Accounts().Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied; got %+v", cr)
	}
}

func TestAccountsApplyCreatesUsersAndWritesSudoers(t *testing.T) {
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")

	if err := Accounts().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
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

	if err := Accounts().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
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

func TestAccountsApplyGeneratesDeployKeyWhenRepository(t *testing.T) {
	s := testServerWithKey(t)
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	f := bssh.NewFakeRunner()
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	f.On("test -e '/home/deploy/.ssh/id_ed25519'", bssh.Result{ExitCode: 1}) // key absent
	f.On("sudo -u deploy ssh-keygen -t ed25519 -N '' -f '/home/deploy/.ssh/id_ed25519' -C 'deploy@github.com'", bssh.Result{})
	f.On("sudo -u deploy sh -c 'ssh-keygen -F github.com -f /home/deploy/.ssh/known_hosts >/dev/null 2>&1 || ssh-keyscan github.com >> /home/deploy/.ssh/known_hosts'", bssh.Result{})

	if err := Accounts().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
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

	if err := Accounts().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
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

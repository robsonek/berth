package steps

import (
	"context"
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
	f.On("id berth", bssh.Result{ExitCode: 0})
	f.On("id deploy", bssh.Result{ExitCode: 0})
	f.On("test -e "+shQuote(sudoersBerthPath), bssh.Result{ExitCode: 0})
	f.On("test -e "+shQuote(sudoersDeployPath), bssh.Result{ExitCode: 0})
	f.On("visudo -cf "+shQuote(sudoersBerthPath), bssh.Result{ExitCode: 0})
	f.On("visudo -cf "+shQuote(sudoersDeployPath), bssh.Result{ExitCode: 0})
	f.On("cat "+shQuote(authorizedKeysPath("berth")), bssh.Result{Stdout: string(want), ExitCode: 0})
	f.On("cat "+shQuote(authorizedKeysPath("deploy")), bssh.Result{Stdout: string(want), ExitCode: 0})
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
	// Users absent → useradd runs.
	f.On("id berth", bssh.Result{ExitCode: 1})
	f.On("id deploy", bssh.Result{ExitCode: 1})
	f.On("useradd -m -s /bin/bash berth", bssh.Result{})
	f.On("useradd -m -s /bin/bash deploy", bssh.Result{})
	f.On("visudo -cf "+shQuote(sudoersBerthPath), bssh.Result{ExitCode: 0})
	f.On("visudo -cf "+shQuote(sudoersDeployPath), bssh.Result{ExitCode: 0})
	f.On("install -d -o berth -g berth -m 700 "+shQuote("/home/berth/.ssh"), bssh.Result{})
	f.On("install -d -o deploy -g deploy -m 700 "+shQuote("/home/deploy/.ssh"), bssh.Result{})

	if err := Accounts().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	// useradd issued for both.
	var saw []string
	for _, c := range f.Calls() {
		saw = append(saw, c.Cmd)
	}
	joined := strings.Join(saw, "\n")
	for _, want := range []string{"useradd -m -s /bin/bash berth", "useradd -m -s /bin/bash deploy"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in calls:\n%s", want, joined)
		}
	}

	// Sudoers and authorized_keys written via WriteFile.
	writes := map[string]bssh.FileSpec{}
	for _, w := range f.Writes() {
		writes[w.Path] = w
	}
	berthSudo, ok := writes[sudoersBerthPath]
	if !ok {
		t.Fatalf("berth sudoers not written; writes=%v", writes)
	}
	if berthSudo.Mode != 0o440 {
		t.Errorf("berth sudoers mode = %o, want 440", berthSudo.Mode)
	}
	if !strings.Contains(string(berthSudo.Content), "berth ALL=(ALL) NOPASSWD:ALL") {
		t.Errorf("berth sudoers body = %q", berthSudo.Content)
	}
	if _, ok := writes[sudoersDeployPath]; !ok {
		t.Error("deploy sudoers not written")
	}
	for _, u := range managedUsers {
		ak, ok := writes[authorizedKeysPath(u)]
		if !ok {
			t.Errorf("%s authorized_keys not written", u)
			continue
		}
		if !strings.Contains(string(ak.Content), testOperatorKey) {
			t.Errorf("%s authorized_keys missing operator key", u)
		}
		if ak.Mode != 0o600 {
			t.Errorf("%s authorized_keys mode = %o, want 600", u, ak.Mode)
		}
	}
}

func TestAccountsApplyGeneratesDeployKeyWhenRepository(t *testing.T) {
	s := testServerWithKey(t)
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	f := bssh.NewFakeRunner()
	f.On("id berth", bssh.Result{ExitCode: 0})
	f.On("id deploy", bssh.Result{ExitCode: 0})
	f.On("visudo -cf "+shQuote(sudoersBerthPath), bssh.Result{ExitCode: 0})
	f.On("visudo -cf "+shQuote(sudoersDeployPath), bssh.Result{ExitCode: 0})
	f.On("install -d -o berth -g berth -m 700 "+shQuote("/home/berth/.ssh"), bssh.Result{})
	f.On("install -d -o deploy -g deploy -m 700 "+shQuote("/home/deploy/.ssh"), bssh.Result{})
	f.On("test -e '/home/deploy/.ssh/id_ed25519'", bssh.Result{ExitCode: 1}) // key absent
	f.On("sudo -u deploy ssh-keygen -t ed25519 -N '' -f '/home/deploy/.ssh/id_ed25519' -C 'deploy@github.com'", bssh.Result{})
	f.On("sudo -u deploy sh -c 'ssh-keyscan github.com >> /home/deploy/.ssh/known_hosts'", bssh.Result{})

	if err := Accounts().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var joined string
	for _, c := range f.Calls() {
		joined += c.Cmd + "\n"
	}
	if !strings.Contains(joined, "ssh-keygen -t ed25519") {
		t.Errorf("expected ssh-keygen for deploy; calls:\n%s", joined)
	}
	if !strings.Contains(joined, "ssh-keyscan") || !strings.Contains(joined, "github.com") {
		t.Errorf("expected ssh-keyscan of git host; calls:\n%s", joined)
	}
}

func TestAccountsApplySkipsDeployKeyWithoutRepository(t *testing.T) {
	s := testServerWithKey(t) // no repository
	f := bssh.NewFakeRunner()
	f.On("id berth", bssh.Result{ExitCode: 0})
	f.On("id deploy", bssh.Result{ExitCode: 0})
	f.On("visudo -cf "+shQuote(sudoersBerthPath), bssh.Result{ExitCode: 0})
	f.On("visudo -cf "+shQuote(sudoersDeployPath), bssh.Result{ExitCode: 0})
	f.On("install -d -o berth -g berth -m 700 "+shQuote("/home/berth/.ssh"), bssh.Result{})
	f.On("install -d -o deploy -g deploy -m 700 "+shQuote("/home/deploy/.ssh"), bssh.Result{})

	if err := Accounts().Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "ssh-keygen") || strings.Contains(c.Cmd, "ssh-keyscan") {
			t.Errorf("unexpected deploy-key command without repository: %q", c.Cmd)
		}
	}
}

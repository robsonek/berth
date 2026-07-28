package steps

import (
	"bytes"
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
		Host:  "app.example.com",
		SSH:   config.SSH{Key: writeOperatorKey(t), Port: 22},
		PHP:   config.PHP{Version: "8.4"},
		Sites: []config.Site{{Domain: "app.example.com", DeployPath: "/var/www/app", User: "deploy"}},
	}
}

// stubAccountExists stubs the read-only checks that report a fully-provisioned
// account (user present, sudoers content AND root:root 0440 metadata up to
// date, authorized_keys up to date).
func stubAccountExists(f *bssh.FakeRunner, user string, sudoers, want []byte) {
	f.On("id "+user, bssh.Result{ExitCode: 0})
	f.On(groupProbeCmd(user), bssh.Result{Stdout: user + "\n"})
	f.On(sshDirOwnerCmd(user), bssh.Result{Stdout: user + " directory\n"})
	f.On("cat "+shQuote(accountSudoersPath(user)), bssh.Result{Stdout: string(sudoers), ExitCode: 0})
	f.On(sudoersStatCmd(user), bssh.Result{Stdout: "root:root 440\n"})
	f.On("cat "+shQuote(authorizedKeysPath(user)), bssh.Result{Stdout: string(want), ExitCode: 0})
}

// sudoersStatCmd mirrors statOwnerMode's probe for an account's sudoers file.
func sudoersStatCmd(user string) string {
	return "stat -c '%U:%G %a' " + shQuote(accountSudoersPath(user))
}

// stubAccountCreate stubs the mutating commands for creating + configuring an
// account during Apply (user absent → useradd; home lockdown; sudoers validate;
// ssh dir; write-guard reads report both managed files absent).
func stubAccountCreate(f *bssh.FakeRunner, user string) {
	f.On("id "+user, bssh.Result{ExitCode: 1})
	f.On(groupProbeCmd(user), bssh.Result{Stdout: user + "\n"})
	f.On(sshDirOwnerCmd(user), bssh.Result{ExitCode: 92}) // ~/.ssh absent
	f.On("useradd -m -s /bin/bash "+user, bssh.Result{})
	f.On("getent passwd "+user, bssh.Result{Stdout: fmt.Sprintf("%s:x:1000:1000::/home/%s:/bin/bash\n", user, user)})
	f.On(fmt.Sprintf("install -d -o %s -g %s -m 00700 ", user, user)+shQuote(fmt.Sprintf("/home/%s", user)), bssh.Result{})
	f.On("visudo -cf "+shQuote(accountSudoersPath(user)), bssh.Result{ExitCode: 0})
	f.On(fmt.Sprintf("sudo -u %s install -d -g %s -m 00700 ", user, user)+shQuote(fmt.Sprintf("/home/%s/.ssh", user)), bssh.Result{})
	f.On("cat "+shQuote(accountSudoersPath(user)), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(authorizedKeysPath(user)), bssh.Result{ExitCode: 1})
	f.On(writeAsUserCmd(user, authorizedKeysPath(user), 0o600), bssh.Result{})
}

// groupProbeCmd / sshDirOwnerCmd mirror the production probes so FakeRunner
// stubs match. Keep in lockstep with assertGroupMembership / assertOwnSSHDir.
// The ~/.ssh probe signals absence with exit 92 and a failed stat on an
// existing entry with exit 91.
func groupProbeCmd(user string) string { return "LC_ALL=C id -nG " + shQuote(user) }
func sshDirOwnerCmd(user string) string {
	q := shQuote("/home/" + user + "/.ssh")
	return "export LC_ALL=C; if [ -e " + q + " ] || [ -L " + q + " ]; then stat -c '%U %F' " + q + " || exit 91; else exit 92; fi"
}

func TestGroupMembershipAcceptsEponymousPrimaryGroup(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On(groupProbeCmd("deploy"), bssh.Result{Stdout: "deploy\n"})
	if err := assertGroupMembership(context.Background(), f, "deploy", true); err != nil {
		t.Fatalf("membership in the eponymous group must pass; got %v", err)
	}
}

func TestGroupMembershipAcceptsSupplementaryGroup(t *testing.T) {
	// A pinned account whose PRIMARY group differs is fine as long as <user>
	// is one of its groups: chgrp needs membership, not primacy.
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On(groupProbeCmd("deploy"), bssh.Result{Stdout: "www-data deploy\n"})
	if err := assertGroupMembership(context.Background(), f, "deploy", true); err != nil {
		t.Fatalf("a supplementary eponymous group must pass; got %v", err)
	}
}

func TestGroupMembershipRefusesNonMember(t *testing.T) {
	// Root could chgrp to a group it is not in; the account cannot. Refuse with
	// the remedy instead of leaking a raw EPERM out of install.
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On(groupProbeCmd("deploy"), bssh.Result{Stdout: "www-data staff\n"})
	err := assertGroupMembership(context.Background(), f, "deploy", true)
	if err == nil || !strings.Contains(err.Error(), "usermod -aG") {
		t.Fatalf("err = %v, want a refusal carrying the usermod remedy", err)
	}
}

func TestGroupMembershipPassesWhenAccountMissingAndNotRequired(t *testing.T) {
	// --only appdirs on a host without the account yet: the mutation fails on
	// its own with a clear error, so this guard must not invent a second one.
	// The guard re-probes the account itself before passing (fail-closed).
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On(groupProbeCmd("deploy"), bssh.Result{ExitCode: 1, Stderr: "id: 'deploy': no such user"})
	f.On("id deploy", bssh.Result{ExitCode: 1})
	if err := assertGroupMembership(context.Background(), f, "deploy", false); err != nil {
		t.Fatalf("a missing account must not trip this guard; got %v", err)
	}
}

func TestGroupMembershipHardErrorsWhenProbeFailsButAccountExists(t *testing.T) {
	// `id -nG` also fails on transient NSS or I/O trouble, not only on a
	// missing account. Passing on such a failure would skip the guard silently
	// (fail-open) and the operator would hit the raw EPERM it exists to
	// prevent — so when the account itself still resolves, the failed group
	// probe must be a hard error.
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On(groupProbeCmd("deploy"), bssh.Result{ExitCode: 1, Stderr: "id: cannot find name for group ID 1000"})
	f.On("id deploy", bssh.Result{ExitCode: 0})
	err := assertGroupMembership(context.Background(), f, "deploy", false)
	if err == nil || !strings.Contains(err.Error(), "probing its groups failed") {
		t.Fatalf("err = %v, want a hard error naming the failed group probe", err)
	}
}

func TestGroupMembershipHardErrorsWhenAccountRequired(t *testing.T) {
	// Called after ensureUser, a failing probe is a real failure, not a
	// transient state: the account was just created.
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On(groupProbeCmd("deploy"), bssh.Result{ExitCode: 1, Stderr: "id: 'deploy': no such user"})
	if err := assertGroupMembership(context.Background(), f, "deploy", true); err == nil {
		t.Fatal("a missing account must be a hard error once it is required to exist")
	}
}

func TestOwnSSHDirAcceptsAbsentAndOwned(t *testing.T) {
	for _, out := range []bssh.Result{
		{ExitCode: 92}, // the probe's own "absent" signal
		{Stdout: "deploy directory\n"},
	} {
		f := bssh.NewFakeRunner()
		f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
		f.On(sshDirOwnerCmd("deploy"), out)
		if err := assertOwnSSHDir(context.Background(), f, "deploy"); err != nil {
			t.Fatalf("absent or account-owned ~/.ssh must pass; got %v", err)
		}
	}
}

func TestOwnSSHDirHardErrorsWhenStatFailsOnExistingEntry(t *testing.T) {
	// Exit 91 is the probe's own "stat failed on an existing entry" signal
	// (mirroring assertSafeAncestry); any other unexpected exit is equally a
	// hard error. Reading either as "absent" would skip the guard silently.
	for _, out := range []bssh.Result{
		{ExitCode: 91, Stderr: "stat: cannot read file system information"},
		{ExitCode: 1, Stderr: "sh: some transient failure"},
	} {
		f := bssh.NewFakeRunner()
		f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
		f.On(sshDirOwnerCmd("deploy"), out)
		err := assertOwnSSHDir(context.Background(), f, "deploy")
		if err == nil || !strings.Contains(err.Error(), "probing the owner and type") {
			t.Fatalf("exit %d: err = %v, want a hard error, not an \"absent\" pass", out.ExitCode, err)
		}
	}
}

func TestOwnSSHDirRefusesForeignOwner(t *testing.T) {
	// Previously root re-owned a hand-created root-owned ~/.ssh. The account
	// cannot, so refuse with the exact chown to run.
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On(sshDirOwnerCmd("deploy"), bssh.Result{Stdout: "root directory\n"})
	err := assertOwnSSHDir(context.Background(), f, "deploy")
	if err == nil || !strings.Contains(err.Error(), "chown -R deploy:deploy") {
		t.Fatalf("err = %v, want a refusal carrying the chown remedy", err)
	}
}

func TestOwnSSHDirRefusesSymlinkWithoutSuggestingChown(t *testing.T) {
	// A SYMLINK at ~/.ssh owned by the account passes an owner-only check: the
	// probe deliberately does not follow it, so `stat` reports the link's own
	// owner, which IS the account. The account-run `install -d` then follows it
	// and fails with a raw EPERM if the target is root-owned.
	//
	// The type check must therefore come first, and its remedy must NOT be a
	// chown: `chown` here would act on the link's TARGET, so telling an operator
	// to chown `~/.ssh` when it points at, say, /etc/ssh would hand that
	// directory to the tenant — the escalation delivered inside a help message.
	for _, ftype := range []string{"symbolic link", "regular file"} {
		f := bssh.NewFakeRunner()
		f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
		f.On(sshDirOwnerCmd("deploy"), bssh.Result{Stdout: "deploy " + ftype + "\n"})
		err := assertOwnSSHDir(context.Background(), f, "deploy")
		if err == nil || !strings.Contains(err.Error(), ftype) {
			t.Fatalf("%s: err = %v, want a refusal naming the type", ftype, err)
		}
		if !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("%s: refusal must say it is not a directory; got %v", ftype, err)
		}
		// The message may WARN about chown; it must never hand over a runnable
		// one, because `chown -R` on a symlink acts on its target.
		if strings.Contains(err.Error(), "chown -R") {
			t.Errorf("%s: refusal must not carry a runnable chown — it would act on the link target; got %v", ftype, err)
		}
		if !strings.Contains(err.Error(), "do not chown") {
			t.Errorf("%s: refusal should warn against chowning it; got %v", ftype, err)
		}
	}
}

// stubFullApply stubs a complete Apply pass for the single-site test server
// (berth + deploy created fresh), so break-glass tests can focus on the
// password commands appended at the end of Apply.
func stubFullApply(t *testing.T, _ *config.Server) *bssh.FakeRunner {
	t.Helper()
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	stubReloadScriptAbsent(f)
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
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	// The Check-side guards probe every managed account before the drift loop;
	// on this fresh host neither exists, which the mustExist=false regime passes.
	for _, u := range []string{"berth", "deploy"} {
		f.On(groupProbeCmd(u), bssh.Result{ExitCode: 1, Stderr: "id: no such user"})
		f.On(sshDirOwnerCmd(u), bssh.Result{ExitCode: 92}) // ~/.ssh absent
		f.On("id "+u, bssh.Result{ExitCode: 1})            // both accounts missing
	}
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied when an account is missing")
	}
}

func TestAccountsCheckSatisfiedWhenAllPresent(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want) // user pinned "deploy"
	stubReloadScriptOK(t, f, s)
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
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
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

func TestAccountsCheckUnsatisfiedWhenSudoersMetadataDrifted(t *testing.T) {
	// Content-only probing used to bless a correct-content sudoers file with
	// drifted owner/mode forever: sudo REFUSES a drop-in that is not
	// root-owned 0440 wide, so the grant was broken and no run would heal it
	// (Apply only fires on an unsatisfied Check). Both account classes carry
	// the contract: berth's own /etc/sudoers.d/berth and the per-site
	// berth-<user> grant.
	cases := []struct {
		name string
		user string // the account whose stat probe drifts
		meta string
	}{
		{"berth account world-readable", "berth", "root:root 644"},
		{"site user grant not root-owned", "deploy", "deploy:root 440"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chdirTemp(t)
			s := testServerWithKey(t)
			want := authorizedKeys(testOperatorKey)
			deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
			if err != nil {
				t.Fatal(err)
			}
			f := bssh.NewFakeRunner()
			f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
			stubSiteTreeFresh(f, "/var/www/app")
			stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
			stubAccountExists(f, "deploy", deploySudoers, want)
			f.On(sudoersStatCmd(tc.user), bssh.Result{Stdout: tc.meta + "\n"}) // override the healthy stub
			cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
			if err != nil {
				t.Fatal(err)
			}
			if cr.Satisfied {
				t.Fatalf("expected unsatisfied on sudoers metadata drift; got %+v", cr)
			}
			if !strings.Contains(cr.Reason, accountSudoersPath(tc.user)) || !strings.Contains(cr.Reason, tc.meta) {
				t.Errorf("Reason = %q, want it to name the path and the drifted metadata", cr.Reason)
			}
			if !strings.Contains(strings.Join(cr.Changes, "\n"), "fix owner/mode") {
				t.Errorf("Changes = %q, want a fix owner/mode entry", cr.Changes)
			}
		})
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

func TestSiteSudoersNoProgramGrantsForQueueNoneSite(t *testing.T) {
	s := &config.Server{PHP: config.PHP{Version: "8.4"}, Queue: true,
		Sites: []config.Site{{Domain: "a.example.com", DeployPath: "/var/www/a", User: "auser",
			Queue: &config.QueueConfig{Driver: "none"}}}}
	body, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	// queue: none opts the site out of the server-wide worker, so no
	// supervisorctl grant may appear — there is no program to control.
	if strings.Contains(string(body), "supervisorctl") {
		t.Errorf("queue: none site sudoers must carry no supervisorctl grants:\n%s", body)
	}
	// The version-stable FPM reload grant is unrelated to the queue and stays.
	if !strings.Contains(string(body), "/usr/local/sbin/berth-reload-fpm") {
		t.Errorf("queue: none site sudoers must keep the FPM reload grant:\n%s", body)
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
	chdirTemp(t)
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	stubReloadScriptAbsent(f)

	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	joined := strings.Join(callCmds(f), "\n")
	for _, want := range []string{"useradd -m -s /bin/bash berth", "useradd -m -s /bin/bash deploy", "getent passwd deploy", "install -d -o deploy -g deploy -m 00700 " + shQuote("/home/deploy")} {
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
	// The authorized_keys write now runs as the account (writeFileAsUser), so
	// the mode is pinned by the stubbed command string and content is asserted
	// mechanism-agnostically via writtenContent.
	want := authorizedKeys(testOperatorKey)
	for _, u := range []string{"berth", "deploy"} {
		if got := writtenContent(f, authorizedKeysPath(u)); !bytes.Equal(got, want) {
			t.Errorf("%s authorized_keys content = %q, want %q", u, got, want)
		}
	}
}

func TestAccountsApplyMultiSiteIsolatesUsers(t *testing.T) {
	chdirTemp(t)
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
	f.On(phpPoolConflictProbeCmd("8.5"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/one")
	stubSiteTreeFresh(f, "/var/www/two")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, u1)
	stubAccountCreate(f, u2)
	stubReloadScriptAbsent(f)

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
		if writtenContent(f, authorizedKeysPath(u)) == nil {
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
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	stubReloadScriptAbsent(f)
	f.On("cat "+shQuote(sudoersBerthPath), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(sudoersPath("deploy")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(authorizedKeysPath("berth")), bssh.Result{ExitCode: 1})
	// deploy already has a hand-installed authorized_keys (no berth marker).
	f.On("cat "+shQuote(authorizedKeysPath("deploy")), bssh.Result{ExitCode: 0, Stdout: "ssh-rsa AAAAOPERATORMANUALKEY manual@ops\n"})

	err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	if writtenContent(f, authorizedKeysPath("deploy")) != nil {
		t.Error("a foreign authorized_keys must not be overwritten without --force")
	}
}

func TestAccountsApplyOverwritesForeignAuthorizedKeysWithForce(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	stubReloadScriptAbsent(f)
	f.On("cat "+shQuote(sudoersBerthPath), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(sudoersPath("deploy")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(authorizedKeysPath("berth")), bssh.Result{ExitCode: 1})
	f.On("cat "+shQuote(authorizedKeysPath("deploy")), bssh.Result{ExitCode: 0, Stdout: "ssh-rsa AAAAOPERATORMANUALKEY manual@ops\n"})

	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{Force: true}, s, f); err != nil {
		t.Fatalf("Apply() with --force error = %v", err)
	}
	if writtenContent(f, authorizedKeysPath("deploy")) == nil {
		t.Error("--force must overwrite the foreign authorized_keys")
	}
}

func TestAccountsApplyGeneratesDeployKeyWhenRepository(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	stubReloadScriptAbsent(f)
	f.On("test -e '/home/deploy/.ssh/id_ed25519'", bssh.Result{ExitCode: 1}) // key absent
	f.On("sudo -u deploy ssh-keygen -t ed25519 -N '' -f '/home/deploy/.ssh/id_ed25519' -C 'deploy@github.com'", bssh.Result{})
	f.On("test -e '/home/deploy/.ssh/id_ed25519.pub'", bssh.Result{}) // keygen just wrote it
	kh := "/home/deploy/.ssh/known_hosts"
	scan := "sudo -u deploy sh -c " + shQuote("ssh-keygen -F "+shQuote("github.com")+" -f "+shQuote(kh)+" >/dev/null 2>&1 || ssh-keyscan "+shQuote("github.com")+" >> "+shQuote(kh))
	f.On(scan, bssh.Result{})

	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	joined := strings.Join(callCmds(f), "\n")
	if !strings.Contains(joined, "ssh-keygen -t ed25519") {
		t.Errorf("expected ssh-keygen for deploy; calls:\n%s", joined)
	}
	if !calledCmd(f, scan) {
		t.Errorf("expected the quoted ssh-keyscan of the git host; calls:\n%s", joined)
	}
}

func TestAccountsApplySkipsDeployKeyWithoutRepository(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t) // no repository
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	stubReloadScriptAbsent(f)

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
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On("id app", bssh.Result{ExitCode: 1})
	f.On("useradd -m -s /bin/bash app", bssh.Result{})
	f.On("getent passwd app", bssh.Result{Stdout: "app:x:1002:1002::/home/app:/bin/bash\n"})
	f.On("install -d -o app -g app -m 00700 "+shQuote("/home/app"), bssh.Result{})
	if err := ensureUser(context.Background(), f, "app"); err != nil {
		t.Fatalf("ensureUser() error = %v", err)
	}
}

// A pre-existing account whose home is not /home/<user> (e.g. Debian's stock
// "sync" with home /bin) must be refused with an actionable error rather than a
// blind chmod of a path that does not exist.
func TestEnsureUserRejectsForeignHome(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
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
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubReloadScriptOK(t, f, s)
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
	chdirTemp(t)
	s := testServerWithKey(t)
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubReloadScriptOK(t, f, s)
	f.On("test -e '/home/deploy/.ssh/id_ed25519'", bssh.Result{ExitCode: 0})
	f.On("test -e '/home/deploy/.ssh/id_ed25519.pub'", bssh.Result{ExitCode: 0})
	f.On("ssh-keygen -F "+shQuote("github.com")+" -f "+shQuote("/home/deploy/.ssh/known_hosts")+" >/dev/null 2>&1", bssh.Result{})
	stubConsoleLocked(f)
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied with the deploy key present; got %+v", cr)
	}
}

func TestAccountsCheckUnsatisfiedWhenPubMissing(t *testing.T) {
	// The private key alone is not enough: berth site key prints the .pub and
	// sends the operator to `berth provision`, which must then actually heal.
	s := testServerWithKey(t)
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubReloadScriptOK(t, f, s)
	f.On("test -e "+shQuote("/home/deploy/.ssh/id_ed25519"), bssh.Result{})
	f.On("test -e "+shQuote("/home/deploy/.ssh/id_ed25519.pub"), bssh.Result{ExitCode: 1})
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while the deploy key's .pub is missing")
	}
	if !strings.Contains(cr.Reason, ".pub") {
		t.Errorf("Reason = %q", cr.Reason)
	}
}

func TestAccountsCheckUnsatisfiedWhenKnownHostsMissing(t *testing.T) {
	// Without the git host's known_hosts entry the first deploy fails host-key
	// verification; the old "Apply re-scans anyway" shortcut was false exactly
	// when Check reported Satisfied.
	s := testServerWithKey(t)
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubReloadScriptOK(t, f, s)
	f.On("test -e "+shQuote("/home/deploy/.ssh/id_ed25519"), bssh.Result{})
	f.On("test -e "+shQuote("/home/deploy/.ssh/id_ed25519.pub"), bssh.Result{})
	f.On("ssh-keygen -F "+shQuote("github.com")+" -f "+shQuote("/home/deploy/.ssh/known_hosts")+" >/dev/null 2>&1", bssh.Result{ExitCode: 1})
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("expected unsatisfied while the git host's known_hosts entry is missing")
	}
	if !strings.Contains(cr.Reason, "known_hosts") {
		t.Errorf("Reason = %q", cr.Reason)
	}
}

func TestAccountsCheckProbesKnownHostsPortToken(t *testing.T) {
	// A non-22 ssh:// endpoint is stored under "[host]:port"; the probe must
	// query that token — a bare-host probe would stay unsatisfied forever after
	// a successful port-aware scan (an unstubbed bare-host command would fail
	// the FakeRunner here).
	chdirTemp(t)
	s := testServerWithKey(t)
	s.Sites[0].Repository = "ssh://git@git.example.com:2222/owner/repo.git"
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubReloadScriptOK(t, f, s)
	f.On("test -e "+shQuote("/home/deploy/.ssh/id_ed25519"), bssh.Result{})
	f.On("test -e "+shQuote("/home/deploy/.ssh/id_ed25519.pub"), bssh.Result{})
	f.On("ssh-keygen -F "+shQuote("[git.example.com]:2222")+" -f "+shQuote("/home/deploy/.ssh/known_hosts")+" >/dev/null 2>&1", bssh.Result{})
	stubConsoleLocked(f)
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if !cr.Satisfied {
		t.Errorf("expected satisfied with the [host]:port token present; got %+v", cr)
	}
}

func TestAccountsApplyDerivesMissingPub(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	s.Sites[0].Repository = "git@github.com:owner/repo.git"
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	stubReloadScriptAbsent(f)
	keyPath := "/home/deploy/.ssh/id_ed25519"
	f.On("test -e "+shQuote(keyPath), bssh.Result{})                   // private key present -> no keygen -t
	f.On("test -e "+shQuote(keyPath+".pub"), bssh.Result{ExitCode: 1}) // .pub missing
	derive := "sudo -u deploy sh -c " + shQuote("ssh-keygen -y -f "+shQuote(keyPath)+" > "+shQuote(keyPath+".pub"))
	f.On(derive, bssh.Result{})
	kh := "/home/deploy/.ssh/known_hosts"
	scan := "sudo -u deploy sh -c " + shQuote("ssh-keygen -F "+shQuote("github.com")+" -f "+shQuote(kh)+" >/dev/null 2>&1 || ssh-keyscan "+shQuote("github.com")+" >> "+shQuote(kh))
	f.On(scan, bssh.Result{})
	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, derive) {
		t.Errorf("expected the .pub to be derived via ssh-keygen -y; calls:\n%s", strings.Join(callCmds(f), "\n"))
	}
	// The pair is registered at the git host — it must NEVER be regenerated.
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "ssh-keygen -t") {
			t.Errorf("the registered key pair must never be regenerated: %q", c.Cmd)
		}
	}
}

func TestAccountsApplyScansGitHostPortAware(t *testing.T) {
	// known_hosts stores non-22 endpoints under "[host]:port" and ssh-keyscan
	// needs -p — a port-blind scan on 22 could never converge.
	chdirTemp(t)
	s := testServerWithKey(t)
	s.Sites[0].Repository = "ssh://git@git.example.com:2222/owner/repo.git"
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	stubReloadScriptAbsent(f)
	f.On("test -e "+shQuote("/home/deploy/.ssh/id_ed25519"), bssh.Result{})
	f.On("test -e "+shQuote("/home/deploy/.ssh/id_ed25519.pub"), bssh.Result{})
	kh := "/home/deploy/.ssh/known_hosts"
	scan := "sudo -u deploy sh -c " + shQuote("ssh-keygen -F "+shQuote("[git.example.com]:2222")+" -f "+shQuote(kh)+" >/dev/null 2>&1 || ssh-keyscan -p 2222 "+shQuote("git.example.com")+" >> "+shQuote(kh))
	f.On(scan, bssh.Result{})
	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !calledCmd(f, scan) {
		t.Errorf("expected the port-aware scan; calls:\n%s", strings.Join(callCmds(f), "\n"))
	}
}

// stubConsoleLocked stubs the break-glass probe as "locked" (useradd's default
// state), the satisfied posture for the default break_glass: false.
func stubConsoleLocked(f *bssh.FakeRunner) {
	f.On("passwd -S berth", bssh.Result{ExitCode: 0, Stdout: "berth L 07/24/2026 0 99999 7 -1\n"})
}

// stubReloadScriptAbsent stubs the reload wrapper's write-guard read as absent
// (a fresh host), the state every Apply fixture starts from.
func stubReloadScriptAbsent(f *bssh.FakeRunner) {
	f.On("cat "+shQuote(reloadFPMScriptPath), bssh.Result{ExitCode: 1})
}

// stubReloadScriptOK stubs the reload wrapper's Check probes green: managed
// content up to date AND root:root 755 metadata.
func stubReloadScriptOK(t *testing.T, f *bssh.FakeRunner, s *config.Server) {
	t.Helper()
	body, err := renderReloadFPMScript(s)
	if err != nil {
		t.Fatal(err)
	}
	f.On("cat "+shQuote(reloadFPMScriptPath), bssh.Result{Stdout: string(body)})
	f.On("stat -c '%U:%G %a' "+shQuote(reloadFPMScriptPath), bssh.Result{Stdout: "root:root 755\n"})
}

// The deploy user's FPM reload goes through a stable path: the sudoers grant
// must not name the PHP version, and Apply must write the wrapper script
// BEFORE the sudoers file that grants it (a grant on a nonexistent path is a
// window where the deployer's reload fails).
func TestAccountsApplyWritesReloadScriptBeforeSudoers(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	f := stubFullApply(t, s)
	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	reloadIdx, sudoersIdx := -1, -1
	for i, w := range f.Writes() {
		switch w.Path {
		case reloadFPMScriptPath:
			reloadIdx = i
			if w.Owner != "root" || w.Group != "root" || w.Mode != 0o755 || !w.Sudo {
				t.Errorf("reload wrapper spec = owner %q group %q mode %#o sudo %v, want root:root 0755 Sudo", w.Owner, w.Group, w.Mode, w.Sudo)
			}
			for _, want := range []string{"# managed by berth", "exec /usr/bin/systemctl reload php8.4-fpm"} {
				if !strings.Contains(string(w.Content), want) {
					t.Errorf("reload wrapper content missing %q:\n%s", want, w.Content)
				}
			}
		case sudoersPath("deploy"):
			sudoersIdx = i
			if !strings.Contains(string(w.Content), "/bin/sh /usr/local/sbin/berth-reload-fpm") {
				t.Errorf("deploy sudoers must grant the version-stable wrapper:\n%s", w.Content)
			}
			if strings.Contains(string(w.Content), "reload php") {
				t.Errorf("the PHP version must not appear in the deployer's sudoers contract:\n%s", w.Content)
			}
		}
	}
	if reloadIdx < 0 || sudoersIdx < 0 {
		t.Fatalf("missing writes: reload wrapper idx %d, deploy sudoers idx %d", reloadIdx, sudoersIdx)
	}
	if reloadIdx > sudoersIdx {
		t.Errorf("the wrapper must be written BEFORE the sudoers that grants it; wrapper=%d sudoers=%d", reloadIdx, sudoersIdx)
	}
}

func TestAccountsCheckFlagsMissingReloadScript(t *testing.T) {
	// Every probe green EXCEPT the reload wrapper's managed-file probe: a grant
	// on a nonexistent path would break every deploy's reload, so Check must be
	// unsatisfied with a change entry naming the wrapper.
	chdirTemp(t)
	s := testServerWithKey(t)
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubConsoleLocked(f)
	f.On("cat "+shQuote(reloadFPMScriptPath), bssh.Result{ExitCode: 1}) // wrapper missing
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a missing reload wrapper must be unsatisfied (the sudoers grant names it)")
	}
	if !strings.Contains(strings.Join(cr.Changes, "\n"), reloadFPMScriptPath) {
		t.Errorf("Changes = %v, want an entry naming %s", cr.Changes, reloadFPMScriptPath)
	}
}

func TestAccountsCheckFlagsReloadScriptMetadataDrift(t *testing.T) {
	// Correct bytes, wrong metadata (mode 775: group-writable). sudo runs the
	// wrapper as root, so the metadata IS the security boundary — content-only
	// probing would report Satisfied while whoever can write the file holds
	// root code execution.
	chdirTemp(t)
	s := testServerWithKey(t)
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	body, err := renderReloadFPMScript(s)
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubConsoleLocked(f)
	f.On("cat "+shQuote(reloadFPMScriptPath), bssh.Result{Stdout: string(body)})
	f.On("stat -c '%U:%G %a' "+shQuote(reloadFPMScriptPath), bssh.Result{Stdout: "root:root 775\n"})
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a group-writable reload wrapper must be unsatisfied even with correct bytes")
	}
	if !strings.Contains(strings.Join(cr.Changes, "\n"), reloadFPMScriptPath) {
		t.Errorf("Changes = %v, want an owner/mode entry naming %s", cr.Changes, reloadFPMScriptPath)
	}
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
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubReloadScriptOK(t, f, s)
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
	seedCache(t, s, map[string]string{"console:berth": "OwnedPW123"})
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubReloadScriptOK(t, f, s)
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
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubReloadScriptOK(t, f, s)
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
			chdirTemp(t)
			s := testServerWithKey(t)
			s.System.BreakGlass = tc.knob
			deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
			if err != nil {
				t.Fatal(err)
			}
			f := bssh.NewFakeRunner()
			f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
			stubSiteTreeFresh(f, "/var/www/app")
			stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
			stubAccountExists(f, "deploy", deploySudoers, want)
			stubReloadScriptOK(t, f, s)
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
	seedCache(t, s, map[string]string{"console:berth": "CachedPW123"})
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

func TestAccountsApplyBreakGlassRefusesTamperedConsolePassword(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	s.System.BreakGlass = true
	seedCache(t, s, map[string]string{"console:berth": "good\nroot:evil"})
	f := stubFullApply(t, s)
	stubConsoleLocked(f) // berth console not usable -> the set-password branch runs
	// chpasswd deliberately NOT stubbed: the guard must refuse before running it.
	err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "charset") {
		t.Fatalf("Apply() = %v, want a refusal to use the tampered cached console password", err)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "chpasswd" {
			t.Error("chpasswd must not run with a cache value outside the allowed charset")
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

func TestAccountsCheckBreakGlassOffStaleMarkerUnsatisfied(t *testing.T) {
	// A crash between `passwd -l` and the cache save leaves the ownership
	// marker (and a root-equivalent plaintext) in ~/.berth while the account
	// is already locked; Check must flag it so Apply retries the cleanup.
	chdirTemp(t)
	s := testServerWithKey(t)
	seedCache(t, s, map[string]string{"console:berth": "StalePW123"})
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	stubReloadScriptOK(t, f, s)
	stubConsoleLocked(f)
	cr, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err != nil {
		t.Fatal(err)
	}
	if cr.Satisfied {
		t.Error("a lingering berth ownership marker with break_glass off must be unsatisfied")
	}
}

func TestAccountsApplyBreakGlassOffCleansStaleMarkerWithoutRelocking(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	seedCache(t, s, map[string]string{"console:berth": "StalePW123", "other": "keep"})
	f := stubFullApply(t, s)
	stubConsoleLocked(f) // already locked: the crash happened after passwd -l
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if calledCmd(f, "passwd -l berth") {
		t.Error("an already-locked account must not be re-locked (cache-only cleanup)")
	}
	cache, err := secret.LoadCache(s.Host)
	if err != nil {
		t.Fatal(err)
	}
	if cache["console:berth"] != "" {
		t.Error("the stale marker (and its plaintext) must be dropped")
	}
	if cache["other"] != "keep" {
		t.Error("dropping the marker must not clobber other cached secrets")
	}
}

// chpasswdSpy wraps a FakeRunner: at the exact moment chpasswd runs it loads
// the LOCAL cache from disk and records whether the password on stdin was
// already persisted (the crash-safety ordering ensureConsolePassword promises).
type chpasswdSpy struct {
	*bssh.FakeRunner
	host      string
	ran       bool
	sawCached bool
}

func (s *chpasswdSpy) Run(ctx context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	if cmd == "chpasswd" {
		s.ran = true
		pw := strings.TrimSuffix(strings.TrimPrefix(string(stdin), "berth:"), "\n")
		if cache, err := secret.LoadCache(s.host); err == nil {
			s.sawCached = pw != "" && cache[consoleCacheKey] == pw
		}
	}
	return s.FakeRunner.Run(ctx, cmd, stdin)
}

func TestAccountsApplyBreakGlassCachesPasswordBeforeChpasswd(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	s.System.BreakGlass = true
	f := stubFullApply(t, s)
	stubConsoleLocked(f)
	f.On("chpasswd", bssh.Result{})
	spy := &chpasswdSpy{FakeRunner: f, host: s.Host}
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, spy); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !spy.ran {
		t.Fatal("chpasswd never ran")
	}
	if !spy.sawCached {
		t.Error("the freshly generated console password must be in the local cache BEFORE chpasswd runs")
	}
}

// twoSiteApplyFixture builds a two-site server (users derived — multi-site
// isolates per site) with the account-creation stubs for berth and both site
// users, mirroring stubFullApply's composition. A single-site fixture could not
// catch "validate only the first site user's sudoers".
func twoSiteApplyFixture(t *testing.T) (*config.Server, *bssh.FakeRunner, string, string) {
	t.Helper()
	s := &config.Server{
		SSH: config.SSH{Key: writeOperatorKey(t)},
		PHP: config.PHP{Version: "8.4"},
		Sites: []config.Site{
			{Domain: "one.example.com", DeployPath: "/var/www/one"},
			{Domain: "two.example.com", DeployPath: "/var/www/two"},
		},
	}
	u1, u2 := s.SiteUser(s.Sites[0]), s.SiteUser(s.Sites[1])
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/one")
	stubSiteTreeFresh(f, "/var/www/two")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, u1)
	stubAccountCreate(f, u2)
	stubReloadScriptAbsent(f)
	return s, f, u1, u2
}

func TestAccountsApplyValidatesEverySudoersAfterWrite(t *testing.T) {
	// visudo -cf is the only guard between a template regression and a broken
	// sudoers drop-in (which sudo ignores — or which breaks sudo entirely), so
	// EVERY written drop-in must be validated after its write: berth's and both
	// site users', not just the first. Asserted on the orderedRunner's single
	// event stream (tls_test.go) — FakeRunner.Calls() records only Run, so a
	// Calls()-based index check could not prove the write happened first.
	chdirTemp(t)
	s, f, u1, u2 := twoSiteApplyFixture(t)
	stubConsoleLocked(f)
	spy := &orderedRunner{FakeRunner: f}

	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, spy); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	idx := func(want string) int {
		for i, e := range spy.events {
			if e == want {
				return i
			}
		}
		return -1
	}
	for _, u := range []string{"berth", u1, u2} {
		p := accountSudoersPath(u)
		write := idx("write:" + p)
		validate := idx("run:visudo -cf " + shQuote(p))
		if write < 0 || validate < 0 {
			t.Errorf("sudoers for %s: missing write (idx %d) or visudo validation (idx %d)\nevents: %v", u, write, validate, spy.events)
			continue
		}
		if validate < write {
			t.Errorf("sudoers for %s must be validated AFTER its write; write=%d validate=%d\nevents: %v", u, write, validate, spy.events)
		}
	}
}

func TestAccountsApplyFailsLoudWhenVisudoRejects(t *testing.T) {
	// A visudo rejection must abort Apply loudly. The rejected file stays
	// written (write first, validate after — the error, not a rollback, is the
	// signal), and nothing past the sudoers phase may run.
	s, f, u1, u2 := twoSiteApplyFixture(t)
	// Override the first site user's visudo stub (On is last-wins): the
	// freshly written drop-in fails validation.
	f.On("visudo -cf "+shQuote(sudoersPath(u1)), bssh.Result{ExitCode: 1})

	err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if want := sudoersPath(u1) + " failed visudo -cf validation"; err == nil || err.Error() != want {
		t.Fatalf("Apply() = %v, want exactly %q", err, want)
	}
	var wroteRejected bool
	for _, w := range f.Writes() {
		if w.Path == sudoersPath(u1) {
			wroteRejected = true
		}
		if w.Path == sudoersPath(u2) {
			t.Error("Apply must abort at the rejection; the second site's sudoers must not be written")
		}
	}
	if !wroteRejected {
		t.Error("the rejected sudoers must have been written before validation (write-then-validate semantics)")
	}
	// Abort proof on an UNCONDITIONAL later-stage command: the console-posture
	// probe always follows the account/sudoers phase in a full Apply, so its
	// absence pins that Apply stopped at the rejection.
	if calledCmd(f, "passwd -S berth") {
		t.Error("Apply must abort at the visudo rejection; passwd -S berth must not run")
	}
}

func TestAccountsCheckRefusesForeignOwnedTree(t *testing.T) {
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On(noSymlinkCmd("/var/www/app/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(ownerProbeCmd("/var/www/app"), bssh.Result{Stdout: "b_old_12345678 1003 directory\n"})
	_, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "sites[].user") {
		t.Fatalf("Check() err = %v, want an owner-mismatch refusal", err)
	}
}

func TestAccountsCheckRefusesForeignSSHDir(t *testing.T) {
	// A fully provisioned host reports Satisfied and never enters Apply, so the
	// guard has to live in Check or the operator never learns about the state.
	s := testServerWithKey(t)
	want := authorizedKeys(testOperatorKey)
	deploySudoers, err := renderSiteSudoers(s, s.Sites[0])
	if err != nil {
		t.Fatal(err)
	}
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubSafeAncestry(f, "/", "/home")
	stubAccountExists(f, "berth", []byte(sudoersBerthBody), want)
	stubAccountExists(f, "deploy", deploySudoers, want)
	// …but deploy's ~/.ssh belongs to root (hand-created by an operator).
	f.On(sshDirOwnerCmd("deploy"), bssh.Result{Stdout: "root directory\n"})
	_, err = Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "chown -R deploy:deploy") {
		t.Fatalf("Check() err = %v, want the foreign-~/.ssh refusal with its remedy", err)
	}
}

func TestAccountsApplyRefusesBeforeCreatingAccounts(t *testing.T) {
	// The whole point of guarding in accounts: refuse BEFORE any useradd, so
	// a mismatch never mints an orphan account, deploy key or sudoers entry.
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On(noSymlinkCmd("/var/www/app/shared/tmp"), bssh.Result{ExitCode: 0})
	f.On(ownerProbeCmd("/var/www/app"), bssh.Result{Stdout: "b_old_12345678 1003 directory\n"})
	err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "sites[].user") {
		t.Fatalf("Apply() = %v, want an owner-mismatch refusal", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "useradd") {
			t.Errorf("no useradd may run after an owner mismatch; ran %q", c.Cmd)
		}
	}
}

func TestAccountsRefusesSymlinkedDeployTree(t *testing.T) {
	// --only accounts never reaches appdirs' symlink guard, and the owner
	// probe must not read inodes through tenant-planted symlinks: accounts
	// asserts the deploy tree symlink-free before probing owners
	// (Codex plan-review finding #3).
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	f.On(noSymlinkCmd("/var/www/app/shared/tmp"), bssh.Result{ExitCode: 1})
	_, err := Accounts(secret.NewRedactor()).Check(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Check() err = %v, want a symlink refusal", err)
	}
}

func TestAccountsRefusesTenantOwnedHomeAncestryEvenWithForce(t *testing.T) {
	// Wiring, not gate logic (that is covered via appdirs): accounts must call
	// assertSafeAncestry on the /home chain in BOTH Check and Apply — ensureUser
	// creates /home/<user> as root, so a non-root-owned /home would let its
	// owner redirect that creation. An unused FakeRunner stub never fails a
	// suite, so only a refusal assertion catches a dropped call.
	s := testServerWithKey(t)
	for _, rc := range []provision.RunCtx{{}, {Force: true}} {
		f := bssh.NewFakeRunner()
		f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
		f.On(noSymlinkCmd("/var/www/app/shared/tmp"), bssh.Result{ExitCode: 0})
		stubSiteTreeAbsent(f, "/var/www/app")
		f.On(safeAncestryCmd("/", "/home"),
			bssh.Result{Stdout: "/ 0 755 directory\n/home 1001 755 directory\n"})
		_, err := Accounts(secret.NewRedactor()).Check(context.Background(), rc, s, f)
		if err == nil || !strings.Contains(err.Error(), "/home is owned by uid 1001") {
			t.Fatalf("Force=%v: Check() err = %v, want the /home ancestry refusal", rc.Force, err)
		}
		err = Accounts(secret.NewRedactor()).Apply(context.Background(), rc, s, f)
		if err == nil || !strings.Contains(err.Error(), "/home is owned by uid 1001") {
			t.Fatalf("Force=%v: Apply() err = %v, want the /home ancestry refusal", rc.Force, err)
		}
		for _, c := range f.Calls() {
			if strings.HasPrefix(c.Cmd, "useradd") || strings.Contains(c.Cmd, "install -d") {
				t.Errorf("Force=%v: nothing may be created on an unsafe /home ancestry; ran %q", rc.Force, c.Cmd)
			}
		}
	}
}

func TestAccountsApplyOnlyTenantMutatesItsOwnHome(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubSafeAncestry(f, "/", "/home")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	stubReloadScriptAbsent(f)
	stubConsoleLocked(f)
	if err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, u := range []string{"berth", "deploy"} {
		assertOnlyTenantMutates(t, f, u, "/home/"+u+"/.ssh", authorizedKeysPath(u))
	}
	joined := strings.Join(callCmds(f), "\n")
	for _, want := range []string{
		"sudo -u deploy install -d -g deploy -m 00700 '/home/deploy/.ssh'",
		// /home/<user> itself is root's job: its parent /home is root-controlled.
		"install -d -o deploy -g deploy -m 00700 '/home/deploy'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in calls:\n%s", want, joined)
		}
	}
}

func TestAccountsApplyRefusesNonMemberAfterEnsureUser(t *testing.T) {
	// Same idea for accounts' step-1b loop: dropping it must go red.
	chdirTemp(t)
	s := testServerWithKey(t)
	f := bssh.NewFakeRunner()
	f.On(phpPoolConflictProbeCmd("8.4"), bssh.Result{})
	stubSiteTreeFresh(f, "/var/www/app")
	stubSafeAncestry(f, "/", "/home")
	stubAccountCreate(f, "berth")
	stubAccountCreate(f, "deploy")
	stubReloadScriptAbsent(f)
	// deploy exists after ensureUser but belongs to no group of its own.
	f.On(groupProbeCmd("deploy"), bssh.Result{Stdout: "www-data staff\n"})
	err := Accounts(secret.NewRedactor()).Apply(context.Background(), provision.RunCtx{}, s, f)
	if err == nil || !strings.Contains(err.Error(), "usermod -aG") {
		t.Fatalf("err = %v, want the membership refusal from the post-ensureUser loop", err)
	}
}

func TestAccountsApplyBreakGlassOffLocksOwnedPassword(t *testing.T) {
	chdirTemp(t)
	s := testServerWithKey(t)
	seedCache(t, s, map[string]string{"console:berth": "OwnedPW123", "other": "keep"})
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

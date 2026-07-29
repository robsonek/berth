package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/config"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

const aptFindCmd = "find /etc/apt/sources.list.d -maxdepth 1 -name 'berth-*.list' -print0"

// noLists is the clean-host discovery result: find exits 0 with empty output
// when nothing matches (unlike ls, whose nonzero exit would be ambiguous with
// real errors).
var noLists = bssh.Result{ExitCode: 0}

func aptTestServer(a config.Apt) *config.Server {
	return &config.Server{Apt: a}
}

func signalRepoCfg() config.AptRepo {
	return config.AptRepo{
		Name: "signal-cli", URI: "https://packaging.gitlab.io/signal-cli",
		Suite: "signalcli", KeyURL: "https://packaging.gitlab.io/signal-cli/gpg.key",
		Fingerprint: "02BD5FB7BA4650D50ED69002797DFE3F4F80269B",
	}
}

func TestAptCheckSatisfiedOnCleanHostWithEmptyBlock(t *testing.T) {
	f := bssh.NewFakeRunner().On(aptFindCmd, noLists)
	res, err := Apt().Check(context.Background(), provision.RunCtx{}, aptTestServer(config.Apt{}), f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("want satisfied, got %+v", res)
	}
	if len(f.Calls()) != 1 {
		t.Fatalf("clean host must cost exactly one probe, got %v", f.Calls())
	}
}

func TestAptCheckFlagsUndeclaredManagedListForSweep(t *testing.T) {
	leftover := "/etc/apt/sources.list.d/berth-old.list"
	managed := string(mustRepoContent(t, apt.Repo{Name: "berth-old", URI: "https://old.example/repo", Suite: "trixie", Components: []string{"main"}}))
	f := bssh.NewFakeRunner().
		On(aptFindCmd, bssh.Result{ExitCode: 0, Stdout: leftover + "\x00"}).
		On("cat '"+leftover+"'", bssh.Result{ExitCode: 0, Stdout: managed})
	res, err := Apt().Check(context.Background(), provision.RunCtx{}, aptTestServer(config.Apt{}), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied {
		t.Fatal("undeclared berth-managed list must be unsatisfied (sweep pending)")
	}
	if len(res.Changes) != 1 || !strings.Contains(res.Changes[0], "berth-old") {
		t.Fatalf("changes must announce the sweep: %v", res.Changes)
	}
}

func TestAptCheckIgnoresForeignFileInNamespace(t *testing.T) {
	foreign := "/etc/apt/sources.list.d/berth-foo.list"
	f := bssh.NewFakeRunner().
		On(aptFindCmd, bssh.Result{ExitCode: 0, Stdout: foreign + "\x00"}).
		On("cat '"+foreign+"'", bssh.Result{ExitCode: 0, Stdout: "deb https://operator.example/ trixie main\n"})
	res, err := Apt().Check(context.Background(), provision.RunCtx{}, aptTestServer(config.Apt{}), f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("foreign file must never make the step unsatisfied: %+v", res)
	}
}

func TestAptCheckNamespaceImpostorsStayForeign(t *testing.T) {
	// Neither a non-canonical basename (berth-.list) nor an INI-marker file
	// may ever become a sweep candidate — both would otherwise pull a paired
	// .gpg deletion for a pair berth never wrote.
	empty := "/etc/apt/sources.list.d/berth-.list"
	ini := "/etc/apt/sources.list.d/berth-imp.list"
	f := bssh.NewFakeRunner().
		On(aptFindCmd, bssh.Result{ExitCode: 0, Stdout: empty + "\x00" + ini + "\x00"}).
		On("cat '"+ini+"'", bssh.Result{ExitCode: 0, Stdout: "; managed by berth\ndeb https://x.example/ a main\n"})
	res, err := Apt().Check(context.Background(), provision.RunCtx{}, aptTestServer(config.Apt{}), f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("impostors must stay foreign (satisfied, no sweep): %+v", res)
	}
	for _, c := range f.Calls() {
		if c.Cmd == "cat '"+empty+"'" {
			t.Fatal("non-canonical basename must classify as foreign without being read")
		}
	}
}

func TestAptCheckDiscoveryFailureIsAnError(t *testing.T) {
	f := bssh.NewFakeRunner().On(aptFindCmd, bssh.Result{ExitCode: 1, Stderr: "find: Permission denied"})
	if _, err := Apt().Check(context.Background(), provision.RunCtx{}, aptTestServer(config.Apt{}), f); err == nil {
		t.Fatal("a failing discovery probe must surface as an error, not as an empty namespace")
	}
}

func TestAptCheckDeclaredRepoAndPackageMissing(t *testing.T) {
	cfg := config.Apt{Repos: []config.AptRepo{signalRepoCfg()}, Packages: []string{"htop"}}
	f := bssh.NewFakeRunner().
		On(aptFindCmd, noLists).
		On("cat '/etc/apt/sources.list.d/berth-signal-cli.list'", bssh.Result{ExitCode: 1}).
		On("dpkg -s htop", bssh.Result{ExitCode: 1})
	res, err := Apt().Check(context.Background(), provision.RunCtx{}, aptTestServer(cfg), f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied || len(res.Changes) != 2 {
		t.Fatalf("want two planned changes (repo + package), got %+v", res)
	}
}

func TestAptCheckForeignAtDeclaredPathAbortsWithoutForce(t *testing.T) {
	cfg := config.Apt{Repos: []config.AptRepo{signalRepoCfg()}}
	f := bssh.NewFakeRunner().
		On(aptFindCmd, bssh.Result{ExitCode: 0, Stdout: "/etc/apt/sources.list.d/berth-signal-cli.list\x00"}).
		On("cat '/etc/apt/sources.list.d/berth-signal-cli.list'", bssh.Result{ExitCode: 0, Stdout: "deb https://operator.example/ trixie main\n"})
	_, err := Apt().Check(context.Background(), provision.RunCtx{}, aptTestServer(cfg), f)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want abort-unless---force, got %v", err)
	}
}

// TestAptCheckLowercaseFingerprintConverges pins the strings.ToUpper in
// userRepo: gpg's --with-colons output prints fingerprints uppercase and
// KeyringHoldsExactly compares case-sensitively, while the config validator
// accepts lowercase 40-hex — without the fold a lowercase pin would read
// "restore keyring" forever on a fully converged host.
func TestAptCheckLowercaseFingerprintConverges(t *testing.T) {
	cfg := signalRepoCfg()
	upper := cfg.Fingerprint
	cfg.Fingerprint = strings.ToLower(upper)
	repo := userRepo(cfg)
	if repo.Fingerprint != upper {
		t.Fatalf("userRepo must uppercase the config fingerprint; got %q", repo.Fingerprint)
	}
	f := bssh.NewFakeRunner().
		On(aptFindCmd, noLists).
		On("cat '"+repo.SourceListPath()+"'", bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, repo))}).
		On("gpg --show-keys --with-colons "+repo.KeyringPath(), bssh.Result{ExitCode: 0, Stdout: gpgColonsFor(upper)})
	res, err := Apt().Check(context.Background(), provision.RunCtx{}, aptTestServer(config.Apt{Repos: []config.AptRepo{cfg}}), f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Fatalf("lowercase config fingerprint must converge against the uppercase keyring: %+v", res)
	}
}

func TestAptApplySweepsUndeclaredThenUpdatesOnce(t *testing.T) {
	leftover := "/etc/apt/sources.list.d/berth-old.list"
	managed := string(mustRepoContent(t, apt.Repo{Name: "berth-old", URI: "https://old.example/repo", Suite: "trixie", Components: []string{"main"}}))
	f := bssh.NewFakeRunner().
		On(aptFindCmd, bssh.Result{ExitCode: 0, Stdout: leftover + "\x00"}).
		On("cat '"+leftover+"'", bssh.Result{ExitCode: 0, Stdout: managed}).
		On("rm -f '"+leftover+"' '/usr/share/keyrings/berth-old.gpg'", bssh.Result{ExitCode: 0}).
		On("apt-get update", bssh.Result{ExitCode: 0})
	if err := Apt().Apply(context.Background(), provision.RunCtx{}, aptTestServer(config.Apt{}), f); err != nil {
		t.Fatal(err)
	}
	var updates int
	for _, c := range f.Calls() {
		if c.Cmd == "apt-get update" {
			updates++
		}
	}
	if updates != 1 {
		t.Fatalf("sweep must refresh indexes exactly once, got %d", updates)
	}
}

func TestAptApplyNeverRemovesForeignFileAndWarns(t *testing.T) {
	foreign := "/etc/apt/sources.list.d/berth-foo.list"
	f := bssh.NewFakeRunner().
		On(aptFindCmd, bssh.Result{ExitCode: 0, Stdout: foreign + "\x00"}).
		On("cat '"+foreign+"'", bssh.Result{ExitCode: 0, Stdout: "deb https://operator.example/ trixie main\n"})
	var warns []string
	rc := provision.RunCtx{Force: true, Warn: func(msg string) { warns = append(warns, msg) }}
	if err := Apt().Apply(context.Background(), rc, aptTestServer(config.Apt{}), f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "rm ") {
			t.Fatalf("foreign file removed despite --force: %v", f.Calls())
		}
	}
	if len(warns) != 1 || !strings.Contains(warns[0], foreign) {
		t.Fatalf("want one foreign-file warning naming the path, got %v", warns)
	}
}

// TestAptApplyRegistersDeclaredRepo pins that a declared-but-absent repo
// actually reaches apt.EnsureRepo under its berth-<name> on-host identity.
// The chain internals (key staging, pin verification, index checks) are
// covered by internal/apt tests; here the stub sequence is shared with the
// nginx step's test (stubEnsureRepoChain) and the assertion is the final
// .list write landing at the namespaced path.
func TestAptApplyRegistersDeclaredRepo(t *testing.T) {
	cfg := signalRepoCfg()
	repo := userRepo(cfg)
	f := bssh.NewFakeRunner().
		On(aptFindCmd, noLists).
		On("cat '"+repo.SourceListPath()+"'", bssh.Result{ExitCode: 1})
	stubEnsureRepoChain(f, repo)
	if err := Apt().Apply(context.Background(), provision.RunCtx{}, aptTestServer(config.Apt{Repos: []config.AptRepo{cfg}}), f); err != nil {
		t.Fatal(err)
	}
	var wrote bool
	for _, w := range f.Writes() {
		if w.Path == repo.SourceListPath() {
			wrote = true
		}
	}
	if !wrote {
		t.Fatalf("declared repo must reach EnsureRepo and write %s; writes: %+v", repo.SourceListPath(), f.Writes())
	}
}

func TestAptApplyInstallsOnlyMissingPackages(t *testing.T) {
	cfg := config.Apt{Packages: []string{"htop", "signal-cli-native"}}
	f := bssh.NewFakeRunner().
		On(aptFindCmd, noLists).
		On("dpkg -s htop", bssh.Result{ExitCode: 0, Stdout: "Status: install ok installed\n"}).
		On("dpkg -s signal-cli-native", bssh.Result{ExitCode: 1}).
		On("DEBIAN_FRONTEND=noninteractive apt-get install -y signal-cli-native", bssh.Result{ExitCode: 0})
	if err := Apt().Apply(context.Background(), provision.RunCtx{}, aptTestServer(cfg), f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "install -y") && strings.Contains(c.Cmd, "htop") {
			t.Fatalf("already-installed package must not be re-passed to apt: %v", c.Cmd)
		}
	}
}

func TestAptStepIdentity(t *testing.T) {
	s := Apt()
	if s.Name() != "apt" {
		t.Fatalf("Name() = %q, want apt", s.Name())
	}
	req := s.Requires()
	if len(req) != 1 || req[0] != "base" {
		t.Fatalf("Requires() = %v, want [base]", req)
	}
}

package apt

import (
	"context"
	"strings"
	"testing"

	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestEnsurePackagesFromDebianStock(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx", bssh.Result{})
	m := New(f)
	if err := m.EnsurePackages(context.Background(), nil, "nginx"); err != nil {
		t.Fatalf("EnsurePackages() error = %v", err)
	}
}

func TestSourceContentCarriesMarker(t *testing.T) {
	b, err := NginxOrg().SourceContent()
	if err != nil {
		t.Fatal(err)
	}
	// LegacySourceContents()[0] is by definition the CURRENT marker-less
	// bytes, so managed content = marker line + that.
	want := "# managed by berth\n" + NginxOrg().LegacySourceContents()[0]
	if string(b) != want {
		t.Fatalf("SourceContent:\n got %q\nwant %q", b, want)
	}
}

func TestKeyringHoldsExactly(t *testing.T) {
	repo := NginxOrg()
	gpgCmd := "gpg --show-keys --with-colons " + repo.KeyringPath()
	colons := func(fps ...string) string {
		var b strings.Builder
		for _, fp := range fps {
			b.WriteString("pub:u:4096:1:0000000000000000:1::::::scESC::::::23::0:\n")
			b.WriteString("fpr:::::::::" + fp + ":\n")
		}
		return b.String()
	}
	cases := []struct {
		name string
		stub bssh.Result
		want bool
	}{
		{"absent keyring", bssh.Result{ExitCode: 2}, false},
		{"exact pinned key", bssh.Result{ExitCode: 0, Stdout: colons(repo.Fingerprint)}, true},
		{"wrong key", bssh.Result{ExitCode: 0, Stdout: colons(strings.Repeat("A", 40))}, false},
		{"pinned plus smuggled key", bssh.Result{ExitCode: 0, Stdout: colons(repo.Fingerprint, strings.Repeat("B", 40))}, false},
		{"empty keyring", bssh.Result{ExitCode: 0, Stdout: ""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := bssh.NewFakeRunner().On(gpgCmd, tc.stub)
			got, err := New(f).KeyringHoldsExactly(context.Background(), repo)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRemoveRepoSweepsListKeyringAndUpdates(t *testing.T) {
	repo := NginxOrg()
	f := bssh.NewFakeRunner().
		On("rm -f "+repo.SourceListPath()+" "+repo.KeyringPath(), bssh.Result{ExitCode: 0}).
		On("apt-get update", bssh.Result{ExitCode: 0})
	if err := New(f).RemoveRepo(context.Background(), repo); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()
	if len(calls) != 2 || !strings.HasPrefix(calls[0].Cmd, "rm -f ") || calls[1].Cmd != "apt-get update" {
		t.Fatalf("unexpected call sequence: %+v", calls)
	}
}

func TestEnsureRepoVerifiesFingerprint(t *testing.T) {
	f := bssh.NewFakeRunner()
	// The key download succeeds; the fingerprint check is what must fail: gpg
	// show-keys returns a primary key that does NOT match the pinned one.
	stubKeyTrust(f, Sury(), colonsPrimary("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"))
	m := New(f)
	err := m.EnsureRepo(context.Background(), Sury())
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected fingerprint mismatch error, got %v", err)
	}
}

// keyTrustCmds returns the exact remote commands of EnsureRepo's key-trust
// sequence for a repo, in execution order. Temp files live under root-owned
// /run/berth, never world-writable /tmp; the pinned key is extracted and
// verified on a STAGING keyring and only then installed at the trusted path.
func keyTrustCmds(repo Repo) (workdir, dl, dearmor, export, show, install, cleanup string) {
	tmpKey := "/run/berth/key-" + repo.Name
	tmpRing := "/run/berth/keyring-" + repo.Name + ".gpg"
	tmpOut := "/run/berth/pinned-" + repo.Name + ".gpg"
	workdir = "install -d -m 700 /run/berth"
	dl = "curl -fsSL -o " + tmpKey + " -- '" + repo.KeyURL + "'"
	dearmor = "gpg --yes -o " + tmpRing + " --dearmor " + tmpKey
	export = "gpg --no-default-keyring --keyring " + tmpRing + " --yes -o " + tmpOut + " --export " + repo.Fingerprint
	show = "gpg --show-keys --with-colons " + tmpOut
	install = "install -m 0644 " + tmpOut + " " + repo.KeyringPath()
	cleanup = "rm -f " + tmpKey + " " + tmpRing + " " + tmpOut
	return
}

// colonsPrimary is `gpg --show-keys --with-colons` output for one primary key
// with the given fingerprint plus a signing subkey whose fpr must be IGNORED
// by the primary-fingerprint parser.
func colonsPrimary(fpr string) string {
	return "pub:-:4096:1:0000000000000000:1600000000::-:::scSC::::::23::0:\n" +
		"fpr:::::::::" + fpr + ":\n" +
		"uid:-::::1600000000::0123456789ABCDEF::Repo Signing Key <key@example.org>::::::::::0:\n" +
		"sub:-:4096:1:1111111111111111:1600000000::::::s::::::23:\n" +
		"fpr:::::::::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:\n"
}

// stubKeyTrust stubs the whole key-trust sequence; show-keys returns colons.
func stubKeyTrust(f *bssh.FakeRunner, repo Repo, colons string) {
	workdir, dl, dearmor, export, show, install, cleanup := keyTrustCmds(repo)
	f.On(workdir, bssh.Result{})
	f.On(dl, bssh.Result{})
	f.On(dearmor, bssh.Result{})
	f.On(export, bssh.Result{})
	f.On(show, bssh.Result{Stdout: colons})
	f.On(install, bssh.Result{})
	f.On(cleanup, bssh.Result{})
}

// mustSourceContent renders the repo's managed source bytes or fails the test.
func mustSourceContent(t *testing.T, r Repo) []byte {
	t.Helper()
	b, err := r.SourceContent()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPrimaryFingerprints(t *testing.T) {
	pin := "15058500A0235D97F5D10063B188E2B695BD4743"
	got := primaryFingerprints(colonsPrimary(pin))
	if len(got) != 1 || got[0] != pin {
		t.Fatalf("primaryFingerprints = %v, want exactly [%s] (subkey fpr must be ignored)", got, pin)
	}
	two := colonsPrimary(pin) + colonsPrimary("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
	if got := primaryFingerprints(two); len(got) != 2 {
		t.Fatalf("two primary keys must yield two fingerprints; got %v", got)
	}
	if got := primaryFingerprints("fpr:::::::::ORPHAN:\n"); len(got) != 0 {
		t.Fatalf("an fpr record with no preceding pub must be ignored; got %v", got)
	}
}

func TestEnsureRepoExtractsOnlyPinnedKey(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubKeyTrust(f, Sury(), colonsPrimary(Sury().Fingerprint))
	f.On("apt-get update", bssh.Result{})
	f.On("apt-get update -o Dir::Etc::sourcelist=sources.list.d/sury-php.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any", bssh.Result{ExitCode: 0})

	if err := New(f).EnsureRepo(context.Background(), Sury()); err != nil {
		t.Fatalf("EnsureRepo() error = %v", err)
	}
	_, _, _, export, _, _, cleanup := keyTrustCmds(Sury())
	var sawExport, sawCleanup bool
	for _, c := range f.Calls() {
		if c.Cmd == export {
			sawExport = true
		}
		if c.Cmd == cleanup {
			sawCleanup = true
		}
	}
	if !sawExport {
		t.Error("EnsureRepo must extract ONLY the pinned key into the trusted keyring (gpg --export <pin>)")
	}
	if !sawCleanup {
		t.Error("EnsureRepo must clean up its temp key files")
	}
}

func TestEnsureRepoFailsWhenBundleLacksPinnedKey(t *testing.T) {
	f := bssh.NewFakeRunner()
	workdir, dl, dearmor, export, show, _, _ := keyTrustCmds(Sury())
	f.On(workdir, bssh.Result{})
	f.On(dl, bssh.Result{})
	f.On(dearmor, bssh.Result{})
	f.On(export, bssh.Result{}) // gpg exports nothing for an absent fingerprint
	f.On(show, bssh.Result{ExitCode: 2, Stderr: "gpg: can't open the keyring"})

	err := New(f).EnsureRepo(context.Background(), Sury())
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v, want a pinned-key-not-found error", err)
	}
	for _, w := range f.Writes() {
		if strings.Contains(w.Path, "sources.list.d") {
			t.Error("no apt source may be written when the pinned key is absent (fail closed)")
		}
	}
}

func TestEnsureRepoRejectsUnpinnedPrimaryKey(t *testing.T) {
	// Defence-in-depth: even after extract-by-fingerprint, the verification must
	// refuse a keyring holding any primary key other than the pin.
	f := bssh.NewFakeRunner()
	evil := "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
	stubKeyTrust(f, Sury(), colonsPrimary(Sury().Fingerprint)+colonsPrimary(evil))

	err := New(f).EnsureRepo(context.Background(), Sury())
	if err == nil || !strings.Contains(err.Error(), "unpinned") {
		t.Fatalf("err = %v, want an unpinned-key refusal", err)
	}
}

func TestEnsureRepoSurfacesDownloadFailure(t *testing.T) {
	// A failed key download must be reported as a download error, not surface
	// later as a misleading fingerprint mismatch.
	f := bssh.NewFakeRunner()
	workdir, dl, _, _, _, _, _ := keyTrustCmds(Sury())
	f.On(workdir, bssh.Result{})
	f.On(dl, bssh.Result{ExitCode: 22, Stderr: "curl: (22) The requested URL returned error: 404"})

	err := New(f).EnsureRepo(context.Background(), Sury())
	if err == nil || !strings.Contains(err.Error(), "download key") {
		t.Fatalf("err = %v, want a pointed download error", err)
	}
	if strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("a download failure must not masquerade as a fingerprint problem: %v", err)
	}
}

func TestSuryRepoDefinition(t *testing.T) {
	r := Sury()
	if r.Fingerprint == "" || !strings.Contains(r.URI, "sury") {
		t.Errorf("Sury() looks wrong: %+v", r)
	}
}

func TestUpstreamRepoDefinitions(t *testing.T) {
	// Each upstream repo must carry a full 40-hex pinned fingerprint, a key URL,
	// and a recognizable URI/component so EnsureRepo can register it.
	for _, c := range []struct {
		repo              Repo
		uriContains, comp string
	}{
		{Sury(), "sury", "main"},
		{NginxOrg(), "nginx.org", "nginx"},
		{MariaDBOrg(), "dlm.mariadb.com", "main"},
	} {
		if len(c.repo.Fingerprint) != 40 {
			t.Errorf("%s: fingerprint %q is not a full 40-hex value", c.repo.Name, c.repo.Fingerprint)
		}
		if c.repo.KeyURL == "" {
			t.Errorf("%s: missing KeyURL", c.repo.Name)
		}
		if !strings.Contains(c.repo.URI, c.uriContains) {
			t.Errorf("%s: URI %q missing %q", c.repo.Name, c.repo.URI, c.uriContains)
		}
		if len(c.repo.Components) == 0 || c.repo.Components[0] != c.comp {
			t.Errorf("%s: components %v, want first %q", c.repo.Name, c.repo.Components, c.comp)
		}
	}
}

func TestIsAptLockBusy(t *testing.T) {
	for _, s := range []string{
		"E: Could not get lock /var/lib/apt/lists/lock. It is held by process 15055 (apt-get)",
		"E: Unable to lock directory /var/lib/apt/lists/",
		"E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 42",
	} {
		if !isAptLockBusy(s) {
			t.Errorf("isAptLockBusy(%q) = false, want true", s)
		}
	}
	if isAptLockBusy("E: Failed to fetch ... 404 Not Found") {
		t.Error("a non-lock error must not be treated as lock contention")
	}
}

func TestEnsureRepoRetriesOnAptLock(t *testing.T) {
	prev := aptLockSleep
	aptLockSleep = func() {}
	defer func() { aptLockSleep = prev }()

	f := bssh.NewFakeRunner()
	stubKeyTrust(f, Sury(), colonsPrimary(Sury().Fingerprint))
	// First update hits a concurrent unattended-upgrades holding the lists lock;
	// the retry, once the holder releases, succeeds.
	f.OnSeq("apt-get update",
		bssh.Result{ExitCode: 100, Stderr: "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 999 (apt-get)"},
		bssh.Result{ExitCode: 0})
	// After the full update succeeds, the index-verification guard runs; stub it OK.
	f.On("apt-get update -o Dir::Etc::sourcelist=sources.list.d/sury-php.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any", bssh.Result{ExitCode: 0})

	if err := New(f).EnsureRepo(context.Background(), Sury()); err != nil {
		t.Fatalf("EnsureRepo should wait out apt-lock contention; got %v", err)
	}
	var updates int
	for _, c := range f.Calls() {
		if c.Cmd == "apt-get update" {
			updates++
		}
	}
	if updates < 2 {
		t.Errorf("expected apt-get update to be retried past the lock; got %d call(s)", updates)
	}
}

func TestEnsureRepoUsesKeyURLNotURISuffix(t *testing.T) {
	// nginx.org's key lives at a path unrelated to URI+apt.gpg; EnsureRepo must
	// fetch from repo.KeyURL. Stub the exact KeyURL-based download command.
	f := bssh.NewFakeRunner()
	stubKeyTrust(f, NginxOrg(), colonsPrimary("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"))
	// Wrong fingerprint -> aborts, but only AFTER the KeyURL-based download was
	// the command actually issued (proving KeyURL is used, not URI+apt.gpg).
	if err := New(f).EnsureRepo(context.Background(), NginxOrg()); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected fingerprint mismatch, got %v", err)
	}
	var sawDL bool
	_, dl, _, _, _, _, _ := keyTrustCmds(NginxOrg())
	for _, c := range f.Calls() {
		if c.Cmd == dl {
			sawDL = true
		}
	}
	if !sawDL {
		t.Fatal("EnsureRepo must download from repo.KeyURL")
	}
}

func TestEnsureRepoFailsWhenUpstreamNeverIndexes(t *testing.T) {
	prevLock, prevIdx := aptLockSleep, repoIndexSleep
	aptLockSleep, repoIndexSleep = func() {}, func() {}
	defer func() { aptLockSleep, repoIndexSleep = prevLock, prevIdx }()

	f := bssh.NewFakeRunner()
	stubKeyTrust(f, Sury(), colonsPrimary(Sury().Fingerprint))
	f.On("apt-get update", bssh.Result{ExitCode: 0}) // full update tolerates the ignored source
	// The single-source verify keeps failing (dead upstream mirror).
	verify := "apt-get update -o Dir::Etc::sourcelist=sources.list.d/sury-php.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any"
	f.On(verify, bssh.Result{ExitCode: 100, Stderr: "Err:1 ... Could not connect"})

	err := New(f).EnsureRepo(context.Background(), Sury())
	if err == nil || !strings.Contains(err.Error(), "sury-php") || !strings.Contains(err.Error(), "failed to index") {
		t.Fatalf("expected a loud index-failure error, got %v", err)
	}
	var verifies int
	for _, c := range f.Calls() {
		if c.Cmd == verify {
			verifies++
		}
	}
	if verifies != repoIndexRetries {
		t.Errorf("expected the verify to be retried %d times, got %d", repoIndexRetries, verifies)
	}
}

func TestEnsureRepoRollsBackSourceOnIndexFailure(t *testing.T) {
	prevLock, prevIdx := aptLockSleep, repoIndexSleep
	aptLockSleep, repoIndexSleep = func() {}, func() {}
	defer func() { aptLockSleep, repoIndexSleep = prevLock, prevIdx }()

	f := bssh.NewFakeRunner()
	stubKeyTrust(f, Sury(), colonsPrimary(Sury().Fingerprint))
	f.On("apt-get update", bssh.Result{ExitCode: 0})
	verify := "apt-get update -o Dir::Etc::sourcelist=sources.list.d/sury-php.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any"
	f.On(verify, bssh.Result{ExitCode: 100, Stderr: "Err:1 ... Could not connect"})
	rollback := "rm -f " + Sury().SourceListPath() + " " + Sury().KeyringPath()
	f.On(rollback, bssh.Result{ExitCode: 0})

	err := New(f).EnsureRepo(context.Background(), Sury())
	if err == nil || !strings.Contains(err.Error(), "failed to index") {
		t.Fatalf("expected the loud index-failure error, got %v", err)
	}
	// An unindexable repo must not linger as a trusted source across runs:
	// after exhausting the retries the just-written list AND keyring go away.
	var sawRollback bool
	for _, c := range f.Calls() {
		if c.Cmd == rollback {
			sawRollback = true
		}
	}
	if !sawRollback {
		t.Fatal("expected the rollback rm -f of the source list and keyring after index verification failed")
	}
}

func TestEnsureRepoWritesManagedSource(t *testing.T) {
	// The .list bytes must be the marker-prefixed managed content (the same
	// bytes step Checks compare against), single-sourced in SourceContent.
	f := bssh.NewFakeRunner()
	stubKeyTrust(f, Sury(), colonsPrimary(Sury().Fingerprint))
	f.On("apt-get update", bssh.Result{ExitCode: 0})
	f.On("apt-get update -o Dir::Etc::sourcelist=sources.list.d/sury-php.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any", bssh.Result{ExitCode: 0})

	if err := New(f).EnsureRepo(context.Background(), Sury()); err != nil {
		t.Fatalf("EnsureRepo() error = %v", err)
	}
	var got string
	for _, w := range f.Writes() {
		if w.Path == Sury().SourceListPath() {
			got = string(w.Content)
		}
	}
	if want := string(mustSourceContent(t, Sury())); got != want {
		t.Fatalf("written source list:\n got %q\nwant %q", got, want)
	}
}

func TestEnsureRepoRetriesIndexThenSucceeds(t *testing.T) {
	prevLock, prevIdx := aptLockSleep, repoIndexSleep
	aptLockSleep, repoIndexSleep = func() {}, func() {}
	defer func() { aptLockSleep, repoIndexSleep = prevLock, prevIdx }()

	f := bssh.NewFakeRunner()
	stubKeyTrust(f, Sury(), colonsPrimary(Sury().Fingerprint))
	f.On("apt-get update", bssh.Result{ExitCode: 0})
	verify := "apt-get update -o Dir::Etc::sourcelist=sources.list.d/sury-php.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any"
	f.OnSeq(verify, bssh.Result{ExitCode: 100, Stderr: "transient"}, bssh.Result{ExitCode: 0})

	if err := New(f).EnsureRepo(context.Background(), Sury()); err != nil {
		t.Fatalf("EnsureRepo should succeed once the index retry lands; got %v", err)
	}
}

func TestEnsureRepoVerifiesIndexOnSuccess(t *testing.T) {
	f := bssh.NewFakeRunner()
	stubKeyTrust(f, Sury(), colonsPrimary(Sury().Fingerprint))
	f.On("apt-get update", bssh.Result{ExitCode: 0})
	verify := "apt-get update -o Dir::Etc::sourcelist=sources.list.d/sury-php.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any"
	f.On(verify, bssh.Result{ExitCode: 0})

	if err := New(f).EnsureRepo(context.Background(), Sury()); err != nil {
		t.Fatalf("EnsureRepo should pass when the source indexes; got %v", err)
	}
	// The full `apt-get update` must run BEFORE the single-source verify.
	idxFull, idxVerify := -1, -1
	for i, c := range f.Calls() {
		switch c.Cmd {
		case "apt-get update":
			idxFull = i
		case verify:
			idxVerify = i
		}
	}
	if idxFull < 0 || idxVerify < 0 {
		t.Fatalf("expected both the full update and the verify; calls=%v", f.Calls())
	}
	if idxFull > idxVerify {
		t.Error("the full apt-get update must run before the single-source verify")
	}
}

func TestEnsureRepoGuardWaitsOutAptLock(t *testing.T) {
	prevLock, prevIdx := aptLockSleep, repoIndexSleep
	aptLockSleep, repoIndexSleep = func() {}, func() {}
	defer func() { aptLockSleep, repoIndexSleep = prevLock, prevIdx }()

	f := bssh.NewFakeRunner()
	stubKeyTrust(f, Sury(), colonsPrimary(Sury().Fingerprint))
	f.On("apt-get update", bssh.Result{ExitCode: 0})
	// The verify first hits apt-lock contention (must be waited out, NOT counted as
	// an index failure), then succeeds.
	verify := "apt-get update -o Dir::Etc::sourcelist=sources.list.d/sury-php.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 -o APT::Update::Error-Mode=any"
	f.OnSeq(verify,
		bssh.Result{ExitCode: 100, Stderr: "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 999 (apt-get)"},
		bssh.Result{ExitCode: 0})

	if err := New(f).EnsureRepo(context.Background(), Sury()); err != nil {
		t.Fatalf("EnsureRepo must wait out apt-lock contention in the guard; got %v", err)
	}
}

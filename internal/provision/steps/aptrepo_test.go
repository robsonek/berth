package steps

import (
	"context"
	"strings"
	"testing"

	"github.com/robsonek/berth/internal/apt"
	"github.com/robsonek/berth/internal/provision"
	bssh "github.com/robsonek/berth/internal/ssh"
)

func mustRepoContent(t *testing.T, r apt.Repo) []byte {
	t.Helper()
	b, err := r.SourceContent()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// gpgColonsFor builds a minimal `gpg --show-keys --with-colons` output whose
// primary-key fingerprint is fp.
func gpgColonsFor(fp string) string {
	return "pub:u:4096:1:0000000000000000:1::::::scESC::::::23::0:\nfpr:::::::::" + fp + ":\n"
}

func TestOwnRepoUpToDate(t *testing.T) {
	repo := apt.NginxOrg()
	managed := string(mustRepoContent(t, repo))
	catCmd := "cat '" + repo.SourceListPath() + "'"
	keyCmd := "gpg --no-options --no-keyring --trust-model always --show-keys --with-colons " + repo.KeyringPath()
	cases := []struct {
		name    string
		stub    func(f *bssh.FakeRunner)
		force   bool
		want    bool
		wantErr bool
	}{
		{"absent -> unsatisfied", func(f *bssh.FakeRunner) {
			f.On(catCmd, bssh.Result{ExitCode: 1})
		}, false, false, false},
		{"legacy bytes adopt without force", func(f *bssh.FakeRunner) {
			f.On(catCmd, bssh.Result{ExitCode: 0, Stdout: repo.LegacySourceContents()[0]})
		}, false, false, false},
		{"foreign aborts without force", func(f *bssh.FakeRunner) {
			f.On(catCmd, bssh.Result{ExitCode: 0, Stdout: "deb https://evil.example/ trixie main\n"})
		}, false, false, true},
		{"foreign passes as unsatisfied with force", func(f *bssh.FakeRunner) {
			f.On(catCmd, bssh.Result{ExitCode: 0, Stdout: "deb https://evil.example/ trixie main\n"})
		}, true, false, false},
		{"managed uptodate but keyring missing -> unsatisfied", func(f *bssh.FakeRunner) {
			f.On(catCmd, bssh.Result{ExitCode: 0, Stdout: managed})
			f.On(keyCmd, bssh.Result{ExitCode: 2})
		}, false, false, false},
		{"managed uptodate but keyring holds wrong key -> unsatisfied", func(f *bssh.FakeRunner) {
			f.On(catCmd, bssh.Result{ExitCode: 0, Stdout: managed})
			f.On(keyCmd, bssh.Result{ExitCode: 0, Stdout: gpgColonsFor(strings.Repeat("A", 40))})
		}, false, false, false},
		{"managed uptodate with exact keyring -> satisfied", func(f *bssh.FakeRunner) {
			f.On(catCmd, bssh.Result{ExitCode: 0, Stdout: managed})
			f.On(keyCmd, bssh.Result{ExitCode: 0, Stdout: gpgColonsFor(repo.Fingerprint)})
		}, false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			tc.stub(f)
			got, err := ownRepoUpToDate(context.Background(), f, repo, tc.force)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOwnRepoLingers(t *testing.T) {
	repo := apt.NginxOrg()
	catCmd := "cat '" + repo.SourceListPath() + "'"
	managed := string(mustRepoContent(t, repo))
	cases := []struct {
		name, stdout string
		exit         int
		want         bool
	}{
		{"absent", "", 1, false},
		{"berth-managed lingers", managed, 0, true},
		{"legacy bytes linger", repo.LegacySourceContents()[0], 0, true},
		{"foreign left alone", "deb https://operator.example/ trixie main\n", 0, false},
		// The INI marker is never written into a .list: a file claiming it is
		// FOREIGN on this deletion path (aptListStrictlyManaged, not the
		// generic hasManagedMarker).
		{"INI-marker impostor left alone", "; managed by berth\ndeb https://operator.example/ trixie main\n", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := bssh.NewFakeRunner().On(catCmd, bssh.Result{ExitCode: tc.exit, Stdout: tc.stdout})
			got, err := ownRepoLingers(context.Background(), f, repo)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOwnRepoLingersRecognizesHistoricalVariant(t *testing.T) {
	repo := apt.MariaDBOrg()
	legacy := repo.LegacySourceContents()
	if len(legacy) < 3 {
		t.Fatalf("mariadb must carry its historical URIs, got %d entries", len(legacy))
	}
	f := bssh.NewFakeRunner().On("cat '"+repo.SourceListPath()+"'", bssh.Result{ExitCode: 0, Stdout: legacy[2]})
	got, err := ownRepoLingers(context.Background(), f, repo)
	if err != nil || !got {
		t.Fatalf("a deb.mariadb.org/11.8 list must classify as berth's: got %v err %v", got, err)
	}
}

func TestEnsureOwnRepoRefusesForeignWithoutForce(t *testing.T) {
	repo := apt.NginxOrg()
	f := bssh.NewFakeRunner().
		On("cat '"+repo.SourceListPath()+"'", bssh.Result{ExitCode: 0, Stdout: "deb https://operator.example/ trixie main\n"})
	err := ensureOwnRepo(context.Background(), provision.RunCtx{}, f, repo)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want abort-unless---force from the WRITE path, got %v", err)
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, "curl") {
			t.Fatalf("EnsureRepo must not run for a foreign list: %v", f.Calls())
		}
	}
}

func TestEnsureOwnRepoSkipsWhenConverged(t *testing.T) {
	repo := apt.NginxOrg()
	f := bssh.NewFakeRunner().
		On("cat '"+repo.SourceListPath()+"'", bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, repo))}).
		On("gpg --no-options --no-keyring --trust-model always --show-keys --with-colons "+repo.KeyringPath(), bssh.Result{ExitCode: 0, Stdout: gpgColonsFor(repo.Fingerprint)})
	if err := ensureOwnRepo(context.Background(), provision.RunCtx{}, f, repo); err != nil {
		t.Fatal(err)
	}
	if len(f.Calls()) != 2 {
		t.Fatalf("converged repo must cost exactly the two probes, got %v", f.Calls())
	}
}

func TestRemoveOwnRepoSweepsAndWarns(t *testing.T) {
	repo := apt.NginxOrg()
	f := bssh.NewFakeRunner().
		On("cat '"+repo.SourceListPath()+"'", bssh.Result{ExitCode: 0, Stdout: string(mustRepoContent(t, repo))}).
		On("rm -f "+repo.SourceListPath()+" "+repo.KeyringPath(), bssh.Result{ExitCode: 0}).
		On("apt-get update", bssh.Result{ExitCode: 0})
	var warns []string
	rc := provision.RunCtx{Warn: func(msg string) { warns = append(warns, msg) }}
	if err := removeOwnRepo(context.Background(), rc, f, repo); err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "upstream versions") {
		t.Fatalf("want one upstream-versions warning, got %v", warns)
	}
}

func TestRemoveOwnRepoLeavesForeign(t *testing.T) {
	repo := apt.NginxOrg()
	f := bssh.NewFakeRunner().
		On("cat '"+repo.SourceListPath()+"'", bssh.Result{ExitCode: 0, Stdout: "deb https://operator.example/ trixie main\n"})
	var warns []string
	rc := provision.RunCtx{Warn: func(msg string) { warns = append(warns, msg) }}
	if err := removeOwnRepo(context.Background(), rc, f, repo); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "rm ") {
			t.Fatalf("foreign file was removed: %v", f.Calls())
		}
	}
	if len(warns) != 0 {
		t.Fatalf("no warning expected for the foreign-file no-op, got %v", warns)
	}
}

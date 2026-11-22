package steps

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

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

// gpgColonsExpiring is gpgColonsFor with an expiry on the primary key.
func gpgColonsExpiring(fp string, expires time.Time) string {
	return "pub:-:4096:1:0000000000000000:1552900000:" + strconv.FormatInt(expires.Unix(), 10) + "::-:::scESC::::::23::0:\nfpr:::::::::" + fp + ":\n"
}

// stubNow pins the clock the key-refresh policy reads.
func stubNow(t *testing.T, now time.Time) {
	t.Helper()
	prev := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = prev })
}

// The host keeps the copy of the signing key fetched at the first provision.
// Upstreams extend a key's validity under the same fingerprint, so a copy
// nearing its expiry is re-fetched — but at most once per interval, so a
// host whose upstream has not published the extension yet stays converged
// between attempts.
func TestOwnRepoUpToDateRefreshesAnExpiringKey(t *testing.T) {
	repo := apt.Sury()
	now := time.Unix(1_800_000_000, 0)
	stubNow(t, now)
	day := 24 * time.Hour
	managed := string(mustRepoContent(t, repo))
	catCmd := "cat '" + repo.SourceListPath() + "'"
	keyCmd := "gpg --no-options --no-keyring --trust-model always --show-keys --with-colons " + repo.KeyringPath()
	mtimeCmd := "stat -c %Y " + shQuote(repo.KeyringPath())
	mtime := func(age time.Duration) bssh.Result {
		return bssh.Result{Stdout: strconv.FormatInt(now.Add(-age).Unix(), 10) + "\n"}
	}
	cases := []struct {
		name      string
		expires   time.Duration // from now
		mtime     *bssh.Result  // nil = the probe must not run
		want      bool
		wantProbe bool
	}{
		{"far from expiry: converged, mtime never read", 400 * day, nil, true, false},
		{"just outside the window", keyRefreshWindow + day, nil, true, false},
		{"inside the window, copy older than the interval: refresh", 100 * day, ptr(mtime(30 * day)), false, true},
		{"inside the window, copy fetched recently: converged", 100 * day, ptr(mtime(2 * day)), true, true},
		{"already expired, copy old: refresh", -3 * day, ptr(mtime(60 * day)), false, true},
		{"already expired, copy fetched recently: converged until the next attempt", -3 * day, ptr(mtime(time.Hour)), true, true},
		{"mtime unreadable: refresh", 100 * day, ptr(bssh.Result{ExitCode: 1}), false, true},
		{"mtime garbage: refresh", 100 * day, ptr(bssh.Result{Stdout: "?\n"}), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := bssh.NewFakeRunner()
			f.On(catCmd, bssh.Result{Stdout: managed})
			f.On(keyCmd, bssh.Result{Stdout: gpgColonsExpiring(repo.Fingerprint, now.Add(tc.expires))})
			if tc.mtime != nil {
				f.On(mtimeCmd, *tc.mtime)
			}
			got, err := ownRepoUpToDate(context.Background(), f, repo, false)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("ownRepoUpToDate() = %v, want %v", got, tc.want)
			}
			probed := false
			for _, c := range f.Calls() {
				probed = probed || c.Cmd == mtimeCmd
			}
			if probed != tc.wantProbe {
				t.Errorf("keyring mtime probed = %v, want %v", probed, tc.wantProbe)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// lenientApt answers every unstubbed command with success and accepts every
// write: EnsureRepo's own command strings are pinned in the apt package.
type lenientApt struct {
	*bssh.FakeRunner
	order []string
}

func (l *lenientApt) Run(ctx context.Context, cmd string, stdin []byte) (bssh.Result, error) {
	l.order = append(l.order, cmd)
	res, err := l.FakeRunner.Run(ctx, cmd, stdin)
	if err != nil && strings.Contains(err.Error(), "unstubbed command") {
		return bssh.Result{}, nil
	}
	return res, err
}

// A refresh that still leaves the key inside the window means the upstream
// has not published an extension yet: Apply re-fetches, says so, and the
// operator learns the date while there is time to act.
func TestEnsureOwnRepoRefetchesAndWarnsWhenTheKeyIsStillExpiring(t *testing.T) {
	repo := apt.Sury()
	now := time.Unix(1_800_000_000, 0)
	stubNow(t, now)
	expires := now.Add(40 * 24 * time.Hour)
	f := bssh.NewFakeRunner()
	f.On("cat '"+repo.SourceListPath()+"'", bssh.Result{Stdout: string(mustRepoContent(t, repo))})
	f.On("gpg --no-options --no-keyring --trust-model always --show-keys --with-colons "+repo.KeyringPath(), bssh.Result{Stdout: gpgColonsExpiring(repo.Fingerprint, expires)})
	f.On("stat -c %Y "+shQuote(repo.KeyringPath()), bssh.Result{Stdout: strconv.FormatInt(now.Add(-30*24*time.Hour).Unix(), 10) + "\n"})
	f.On("gpg --show-keys --with-colons /run/berth/pinned-"+repo.Name+".gpg", bssh.Result{Stdout: gpgColonsExpiring(repo.Fingerprint, expires)})
	l := &lenientApt{FakeRunner: f}
	var warnings []string
	rc := provision.RunCtx{Warn: func(msg string) { warnings = append(warnings, msg) }}
	if err := ensureOwnRepo(context.Background(), rc, l, repo); err != nil {
		t.Fatal(err)
	}
	fetched := false
	for _, cmd := range l.order {
		fetched = fetched || strings.HasPrefix(cmd, "curl ")
	}
	if !fetched {
		t.Fatalf("an expiring key must be re-fetched; ran:\n%s", strings.Join(l.order, "\n"))
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], repo.Name) || !strings.Contains(warnings[0], expires.UTC().Format("2006-01-02")) {
		t.Errorf("want one warning naming the repo and the expiry date; got %q", warnings)
	}
}

// The same refresh with an upstream that DID extend the key: no warning.
func TestEnsureOwnRepoRefetchIsQuietWhenTheKeyWasExtended(t *testing.T) {
	repo := apt.Sury()
	now := time.Unix(1_800_000_000, 0)
	stubNow(t, now)
	keyCmd := "gpg --no-options --no-keyring --trust-model always --show-keys --with-colons " + repo.KeyringPath()
	f := bssh.NewFakeRunner()
	f.On("cat '"+repo.SourceListPath()+"'", bssh.Result{Stdout: string(mustRepoContent(t, repo))})
	f.OnSeq(keyCmd,
		bssh.Result{Stdout: gpgColonsExpiring(repo.Fingerprint, now.Add(40*24*time.Hour))},
		bssh.Result{Stdout: gpgColonsExpiring(repo.Fingerprint, now.Add(800*24*time.Hour))},
	)
	f.On("stat -c %Y "+shQuote(repo.KeyringPath()), bssh.Result{Stdout: strconv.FormatInt(now.Add(-30*24*time.Hour).Unix(), 10) + "\n"})
	f.On("gpg --show-keys --with-colons /run/berth/pinned-"+repo.Name+".gpg", bssh.Result{Stdout: gpgColonsExpiring(repo.Fingerprint, now.Add(800*24*time.Hour))})
	l := &lenientApt{FakeRunner: f}
	var warnings []string
	rc := provision.RunCtx{Warn: func(msg string) { warnings = append(warnings, msg) }}
	if err := ensureOwnRepo(context.Background(), rc, l, repo); err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("an extended key must not warn; got %q", warnings)
	}
}

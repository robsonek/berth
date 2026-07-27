package steps

import (
	"context"
	"fmt"
	"os"
	gopath "path"
	"strings"
	"testing"

	bssh "github.com/robsonek/berth/internal/ssh"
)

func TestHasManagedMarkerRequiresExactLine(t *testing.T) {
	for _, tc := range []struct {
		content string
		want    bool
	}{
		{managedMarker + "\nbody\n", true},
		{managedMarkerINI + "\nbody\n", true},
		{managedMarker, true}, // marker-only file, no trailing newline
		{managedMarkerINI, true},
		{managedMarker + "-backup v2\nbody\n", false}, // foreign tool mimicking the prefix
		{managedMarker + " (v2)\nbody\n", false},
		{"body\n" + managedMarker + "\n", false}, // marker not on the first line
		{"", false},
	} {
		if got := hasManagedMarker(tc.content); got != tc.want {
			t.Errorf("hasManagedMarker(%q) = %v, want %v", tc.content, got, tc.want)
		}
	}
}

func TestPkgInstalledRequiresInstalledStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  bssh.Result
		want bool
	}{
		{"installed", bssh.Result{ExitCode: 0, Stdout: "Package: curl\nStatus: install ok installed\nPriority: optional\n"}, true},
		// A held package IS installed — fighting an operator's hold would
		// loop Check/Apply forever (Codex plan-review finding #7).
		{"held but installed", bssh.Result{ExitCode: 0, Stdout: "Package: curl\nStatus: hold ok installed\n"}, true},
		// dpkg -s exits 0 for a package that was removed but not purged
		// (state "rc") — the status line is the only reliable signal.
		{"removed not purged", bssh.Result{ExitCode: 0, Stdout: "Package: curl\nStatus: deinstall ok config-files\n"}, false},
		// The phrase inside a continuation line (leading space) must not
		// spoof the verdict — only a real Status: line counts.
		{"phrase in description", bssh.Result{ExitCode: 0, Stdout: "Package: curl\nStatus: deinstall ok config-files\nDescription: tool\n prints Status: install ok installed somewhere\n"}, false},
		{"absent", bssh.Result{ExitCode: 1, Stderr: "dpkg-query: package 'curl' is not installed"}, false},
	} {
		f := bssh.NewFakeRunner()
		f.On("dpkg -s curl", tc.res)
		got, err := pkgInstalled(context.Background(), f, "curl")
		if err != nil {
			t.Fatalf("%s: pkgInstalled() error = %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: pkgInstalled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// writeAsUserCmd mirrors writeFileAsUser's command so FakeRunner stubs match.
// Keep in lockstep with writeFileAsUser.
func writeAsUserCmd(user, p string, mode os.FileMode) string {
	dir := gopath.Dir(p)
	inner := fmt.Sprintf(`umask 077; t=$(mktemp %s) && trap 'rm -f "$t"' EXIT INT TERM && cat > "$t" && chmod %o "$t" && mv -fT -- "$t" %s`,
		shQuote(dir+"/.berth.XXXXXX"), mode.Perm(), shQuote(p))
	return "sudo -u " + user + " sh -c " + shQuote(inner)
}

// writtenContent returns the bytes berth wrote to path, whichever mechanism it
// used: the root WriteFile path or the tenant-run stdin writer. Tests assert on
// CONTENT and should not care which one a given file uses.
func writtenContent(f *bssh.FakeRunner, path string) []byte {
	for _, w := range f.Writes() {
		if w.Path == path {
			return w.Content
		}
	}
	for _, c := range f.Calls() {
		if strings.Contains(c.Cmd, shQuote(path)) && strings.Contains(c.Cmd, "mv -f") {
			return c.Stdin
		}
	}
	return nil
}

// mutatingVerbs are the command words that CHANGE the filesystem. A root-run
// occurrence of any of them against tenant territory is the bug this package
// closed, so the guard matches the verb anywhere in the command (catching
// `/usr/bin/install -d`, `sudo install -d`, `chown`, a bare `mkdir`, …) rather
// than a single literal prefix. Redirect- and copy-based file writers are
// covered too: "cat >", "cp ", "tee ", "touch " and "truncate " catch a write
// that plants or replaces a file without any directory verb. "mv ", "rm " and
// "cat >" also match writeFileAsUser's own tenant command (`… mv -fT -- …`,
// `trap 'rm -f …'`, `cat > "$t"`) — harmless there, the sudo -u prefix clears
// it, and load-bearing: a regression moving that write into a root
// `sh -c '… cat > …'` fires the command half, not only the WriteFile half.
// Do not trim them as dead weight.
var mutatingVerbs = []string{
	"install ", "mkdir ", "chown ", "chmod ", "rm ", "ln ", "mv ",
	"cat >", "cp ", "tee ", "touch ", "truncate ",
}

// assertOnlyTenantMutates fails when any recorded command mutates one of the
// given paths — or anything beneath them — without running as user, or when
// any privileged WriteFile targets one. Read-only probes (stat, test, cat, id)
// are ignored — they cannot hand anything over. Paths must be absolute and are
// matched shell-quoted, the form every step emits.
func assertOnlyTenantMutates(t *testing.T, f *bssh.FakeRunner, user string, paths ...string) {
	t.Helper()
	for _, v := range tenantMutationViolations(f, user, paths...) {
		t.Error(v)
	}
}

// tenantMutationViolations is assertOnlyTenantMutates' engine, split out so
// the guard itself can be tested (a helper that only t.Errorfs cannot be
// exercised without failing the calling test). Both halves cover the whole
// SUBTREE of each guarded path: the most likely future regression is a NEW
// file under shared/ or ~/.ssh written as root, and an exact-path match would
// stay silent for exactly that case.
func tenantMutationViolations(f *bssh.FakeRunner, user string, paths ...string) []string {
	var out []string
	prefix := "sudo -u " + user + " "
	for _, c := range f.Calls() {
		for _, p := range paths {
			// shQuote(p) is 'p' (guarded paths carry no quotes), so a quoted
			// child appears as 'p/…: match the exact path or the subtree prefix.
			q := shQuote(p)
			if !strings.Contains(c.Cmd, q) && !strings.Contains(c.Cmd, strings.TrimSuffix(q, "'")+"/") {
				continue
			}
			mutating := false
			for _, verb := range mutatingVerbs {
				if strings.Contains(c.Cmd, verb) {
					mutating = true
					break
				}
			}
			if mutating && !strings.HasPrefix(c.Cmd, prefix) {
				out = append(out, fmt.Sprintf("mutation of tenant-owned %s must run as %s; got %q", p, user, c.Cmd))
			}
		}
	}
	for _, w := range f.Writes() {
		for _, p := range paths {
			if w.Path == p || strings.HasPrefix(w.Path, p+"/") {
				out = append(out, fmt.Sprintf("%s must not be written through the privileged WriteFile path; got %+v", p, w))
			}
		}
	}
	return out
}

func TestAssertOnlyTenantMutatesCoversSubtree(t *testing.T) {
	// The most likely future edit is a NEW file under a guarded directory
	// written as root; exact-path matching would stay silent for exactly that
	// case, so both halves must fire on children too.
	guarded := "/var/www/myapp/shared"
	f := bssh.NewFakeRunner()
	if err := f.WriteFile(context.Background(), bssh.FileSpec{Path: guarded + "/newfile", Content: []byte("x"), Mode: 0o600, Sudo: true}); err != nil {
		t.Fatal(err)
	}
	got := tenantMutationViolations(f, "deploy", guarded)
	if len(got) != 1 || !strings.Contains(got[0], guarded+"/newfile") {
		t.Fatalf("a privileged WriteFile to a child of a guarded directory must fire; got %v", got)
	}

	rootCmd := "install -d -o deploy -g deploy -m 00700 " + shQuote(guarded+"/cache")
	f2 := bssh.NewFakeRunner()
	f2.On(rootCmd, bssh.Result{})
	if _, err := f2.Run(context.Background(), rootCmd, nil); err != nil {
		t.Fatal(err)
	}
	got = tenantMutationViolations(f2, "deploy", guarded)
	if len(got) != 1 || !strings.Contains(got[0], "must run as deploy") {
		t.Fatalf("a root-run mutation of a child path must fire; got %v", got)
	}

	// The tenant-run form of the same child mutation must stay clean — the
	// subtree widening must not turn legitimate tenant work into noise.
	tenantCmd := "sudo -u deploy install -d -g deploy -m 00700 " + shQuote(guarded+"/cache")
	f3 := bssh.NewFakeRunner()
	f3.On(tenantCmd, bssh.Result{})
	if _, err := f3.Run(context.Background(), tenantCmd, nil); err != nil {
		t.Fatal(err)
	}
	if got := tenantMutationViolations(f3, "deploy", guarded); len(got) != 0 {
		t.Fatalf("a tenant-run child mutation must not fire; got %v", got)
	}
}

func TestTenantMutationGuardCatchesRedirectAndCopyWriters(t *testing.T) {
	// berth's own tenant writer is a cat-redirect chain (writeFileAsUser), so
	// the most plausible future regression is that same chain running as root
	// without the sudo -u prefix — and it contains none of the classic
	// directory verbs. The guard must fire on redirect- and copy-based
	// writers too, not only on install/mkdir/chown.
	guarded := "/var/www/myapp/shared"
	for _, cmd := range []string{
		// A bare root redirect into a guarded path.
		`sh -c "cat > ` + shQuote(guarded+"/.env") + `"`,
		// A non-install mutator copying a file into place as root.
		"cp /tmp/staged.env " + shQuote(guarded+"/.env"),
	} {
		f := bssh.NewFakeRunner()
		f.On(cmd, bssh.Result{})
		if _, err := f.Run(context.Background(), cmd, nil); err != nil {
			t.Fatal(err)
		}
		if got := tenantMutationViolations(f, "deploy", guarded); len(got) != 1 {
			t.Fatalf("a root-run %q must fire exactly once; got %v", cmd, got)
		}
	}
}

func TestWriteFileAsUserRunsEntirelyAsTheAccount(t *testing.T) {
	// The content sentinel must not collide with the path ("authorized_keys"
	// contains "key"), or the leak assertion below would always fire.
	const secret = "s3cr3t-material\n"
	f := bssh.NewFakeRunner()
	f.On(writeAsUserCmd("deploy", "/home/deploy/.ssh/authorized_keys", 0o600), bssh.Result{})
	if err := writeFileAsUser(context.Background(), f, "deploy", "/home/deploy/.ssh/authorized_keys", 0o600, []byte(secret)); err != nil {
		t.Fatalf("writeFileAsUser() error = %v", err)
	}
	calls := f.Calls()
	if len(calls) != 1 {
		t.Fatalf("want exactly one call, got %d: %v", len(calls), callCmds(f))
	}
	if !strings.HasPrefix(calls[0].Cmd, "sudo -u deploy ") {
		t.Errorf("the whole sequence must run as the account; got %q", calls[0].Cmd)
	}
	if string(calls[0].Stdin) != secret {
		t.Errorf("content must ride on stdin; stdin=%q cmd=%q", calls[0].Stdin, calls[0].Cmd)
	}
	if strings.Contains(calls[0].Cmd, "s3cr3t") {
		t.Error("content must never appear in the command string")
	}
	if len(f.Writes()) != 0 {
		t.Error("writeFileAsUser must not fall back to the root WriteFile path")
	}
}

func TestWriteFileAsUserStagesInsideTheTargetDirectory(t *testing.T) {
	// The temp file must be a sibling of the target so the closing rename is
	// atomic (same filesystem), and it must be created by the account.
	f := bssh.NewFakeRunner()
	f.On(writeAsUserCmd("deploy", "/var/www/app/shared/.env", 0o600), bssh.Result{})
	if err := writeFileAsUser(context.Background(), f, "deploy", "/var/www/app/shared/.env", 0o600, []byte("K=V\n")); err != nil {
		t.Fatal(err)
	}
	got := f.Calls()[0].Cmd
	for _, want := range []string{
		"mktemp", "/var/www/app/shared/.berth.XXXXXX",
		// -T is the security-relevant part: without it a destination that
		// resolves to a directory would move the file INSIDE that directory.
		"mv -fT --",
		// The trap keeps a failed write from leaving a credential behind. Assert
		// a QUOTE-FREE fragment: the inner script is shQuote'd as a whole, so
		// every single quote inside it becomes '\'' and the literal
		// `trap 'rm -f "$t"'` never appears in the final command string.
		"EXIT INT TERM",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("command missing %q: %s", want, got)
		}
	}
}

func TestWriteFileAsUserRefusesZeroMode(t *testing.T) {
	// A zero mode would chmod 0 and lock the owner out of its own file. The
	// root primitive silently defaults to 0644; this helper must not guess —
	// a wrong mode on a credential file is exactly what should be loud.
	f := bssh.NewFakeRunner()
	err := writeFileAsUser(context.Background(), f, "deploy", "/var/www/app/shared/.env", 0, []byte("K=V\n"))
	if err == nil || !strings.Contains(err.Error(), "mode 0") {
		t.Fatalf("err = %v, want a refusal naming the zero mode", err)
	}
	if len(f.Calls()) != 0 {
		t.Errorf("nothing may run when the mode is refused; got %v", callCmds(f))
	}
}

func TestWriteFileAsUserSurfacesFailure(t *testing.T) {
	f := bssh.NewFakeRunner()
	f.On(writeAsUserCmd("deploy", "/var/www/app/shared/.env", 0o600),
		bssh.Result{ExitCode: 1, Stderr: "mv: cannot move: Permission denied"})
	err := writeFileAsUser(context.Background(), f, "deploy", "/var/www/app/shared/.env", 0o600, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("err = %v, want the stderr surfaced", err)
	}
}

func TestWriteManagedFileAsUserKeepsTheDriftGuard(t *testing.T) {
	// A pre-existing file without berth's marker must still abort unless force:
	// the write mechanism changed, the drift policy did not.
	path := "/home/deploy/.ssh/authorized_keys"
	spec := bssh.FileSpec{Path: path, Content: []byte(managedMarker + "\nkey\n"), Mode: 0o600}
	f := bssh.NewFakeRunner()
	f.On("cat "+shQuote(path), bssh.Result{Stdout: "ssh-rsa AAAAMANUAL manual@ops\n"})
	err := writeManagedFileAsUser(context.Background(), f, false, "deploy", spec)
	if err == nil || !strings.Contains(err.Error(), "not managed by berth") {
		t.Fatalf("err = %v, want the unmanaged-file refusal", err)
	}
	for _, c := range f.Calls() {
		if strings.HasPrefix(c.Cmd, "sudo -u") {
			t.Errorf("no write may run once the guard refuses; ran %q", c.Cmd)
		}
	}
	f2 := bssh.NewFakeRunner()
	f2.On("cat "+shQuote(path), bssh.Result{Stdout: "ssh-rsa AAAAMANUAL manual@ops\n"})
	f2.On(writeAsUserCmd("deploy", path, 0o600), bssh.Result{})
	if err := writeManagedFileAsUser(context.Background(), f2, true, "deploy", spec); err != nil {
		t.Fatalf("with force the write must proceed; got %v", err)
	}
}

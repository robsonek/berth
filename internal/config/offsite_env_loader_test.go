package config

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// runShell executes script with the platform sh, in dir (so any command a
// hostile env line managed to run leaves its droppings where the test looks),
// and returns stdout plus the exit code. The loader tests are behavioral —
// they need a real POSIX shell — so they skip on Windows (CI matrix); the
// pure string assertions still run everywhere.
func runShell(t *testing.T, dir, script string) (string, int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX sh")
	}
	cmd := exec.Command("sh")
	cmd.Stdin = strings.NewReader(script)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		}
		t.Fatalf("sh -c: %v", err)
	}
	return string(out), 0
}

// offsiteEnvVars extracts the offsiteEnvKeys lines from an `env` dump. Values
// cannot contain newlines (secret.ValidateSecretValue and Offsite.validate
// both reject them), so line-based parsing is sound.
func offsiteEnvVars(dump string) []string {
	var got []string
	for _, line := range strings.Split(dump, "\n") {
		for _, k := range offsiteEnvKeys {
			if strings.HasPrefix(line, k+"=") {
				got = append(got, line)
			}
		}
	}
	sort.Strings(got)
	return got
}

// assertLoaderMatchesSourcing writes content to a temp env file and asserts
// the loader (1) accepts it, (2) exports exactly the environment that
// `set -a; . file; set +a` exported, and (3) executed nothing (the temp dir
// gains no droppings). That is the contract that makes replacing evaluation
// with parsing safe for already-provisioned hosts.
func assertLoaderMatchesSourcing(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "offsite.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	sourced, rc := runShell(t, dir, "set -a; . "+path+"; set +a; exec env")
	if rc != 0 {
		t.Fatalf("sourcing a legal file failed: rc=%d", rc)
	}
	loaded, rc := runShell(t, dir, offsiteEnvLoaderFor(path)+"; "+OffsiteEnvLoadName+" && exec env")
	if rc != 0 {
		t.Fatalf("loader rejected a legal file: rc=%d", rc)
	}
	want, got := offsiteEnvVars(sourced), offsiteEnvVars(loaded)
	if strings.Join(want, "\n") != strings.Join(got, "\n") {
		t.Errorf("exported environment differs from sourcing:\nsourced: %q\nloaded:  %q", want, got)
	}
	if len(got) == 0 {
		t.Fatal("loader exported nothing — the comparison would be vacuous")
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("something executed a command from the env file: %v %v", entries, err)
	}
}

// The load-bearing case: berth's own RENDERED files, real bytes from the
// template goldens — which begin with the managed marker comment
// (templates.Render prepends it to every rendered file). A hand-made fixture
// missed exactly that and let a loader that rejected berth's own file
// through review; this test is the reason that cannot happen again.
func TestOffsiteEnvLoaderLoadsBerthRenderedFiles(t *testing.T) {
	for _, golden := range []string{"offsite_env.golden", "offsite_env_sftp.golden"} {
		t.Run(golden, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("..", "templates", "testdata", golden))
			if err != nil {
				t.Fatal(err)
			}
			// Vacuity guard: the point of this test is the real rendered
			// shape, marker line included.
			if !strings.HasPrefix(string(content), "# managed by berth\n") {
				t.Fatalf("golden %s no longer starts with the managed marker — this test must exercise the real rendered shape", golden)
			}
			assertLoaderMatchesSourcing(t, string(content))
		})
	}
}

// Inert lines — comments (leading whitespace allowed) and empty or
// whitespace-only lines — are SKIPPED, not rejected: under a parser they
// cannot execute anything, and berth's own rendered file BEGINS with the
// marker comment. An operator's hand-added annotation must not break the
// nightly backup.
func TestOffsiteEnvLoaderSkipsInertLines(t *testing.T) {
	assertLoaderMatchesSourcing(t, "# managed by berth\n"+
		"\n"+
		"   \n"+
		"\t\n"+
		"   # indented comment\n"+
		"RESTIC_REPOSITORY='r'\n"+
		"# trailing comment\n"+
		"RESTIC_PASSWORD='x'\n")
}

// Synthetic value-edge fixtures, shaped like the real file (marker line
// first — see TestOffsiteEnvLoaderLoadsBerthRenderedFiles for why the shape
// matters).
func TestOffsiteEnvLoaderMatchesSourcingForLegalFiles(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"s3", "RESTIC_REPOSITORY='s3:https://s3.example.com/bkt/berth/box-1'\n" +
			"RESTIC_PASSWORD='fake-password-123'\n" +
			"AWS_ACCESS_KEY_ID='AKIAEXAMPLE'\n" +
			"AWS_SECRET_ACCESS_KEY='fake-secret'\n"},
		{"sftp", "RESTIC_REPOSITORY='sftp:backup@sftp.example.com:/srv/restic/box-1'\n" +
			"RESTIC_PASSWORD='fake-password-123'\n"},
		// ValidateSecretValue allows every printable character except the
		// single quote — including the ones that would be live if anything
		// ever evaluated the value: $(), backticks, backslashes, quotes,
		// globs, spaces, '='.
		{"metacharacters", "RESTIC_REPOSITORY='s3:https://s3.example.com/b/p'\n" +
			"RESTIC_PASSWORD='p w$(touch HACK)`touch HACK`\\\"=|*?;&<>~!'\n"},
		{"one-char-value", "RESTIC_REPOSITORY='r'\nRESTIC_PASSWORD='x'\n"},
		{"non-ascii-value", "RESTIC_REPOSITORY='s3:https://s3.example.com/b/p'\n" +
			"RESTIC_PASSWORD='pæßword-日本語'\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertLoaderMatchesSourcing(t, "# managed by berth\n"+tc.content)
		})
	}
}

// Anything berth would not write fails CLOSED: non-zero status, nothing
// executed, and nothing outside the allowlist exported. This is the finding
// being fixed — `. file` gave these lines root's shell.
func TestOffsiteEnvLoaderRejectsHostileFiles(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"command-after-value", "RESTIC_PASSWORD='a'; touch HACK\n"},
		{"unquoted-substitution", "RESTIC_REPOSITORY=$(touch HACK)\n"},
		{"unknown-key", "LD_PRELOAD='/tmp/evil.so'\n"},
		{"embedded-quote", "RESTIC_PASSWORD='a'b'\n"},
		{"unterminated-quote", "RESTIC_PASSWORD='\n"},
		// A KEY line is matched RAW: comments may be indented (inert either
		// way), but an assignment with leading whitespace is not something
		// berth writes and stays rejected.
		{"leading-whitespace", " RESTIC_PASSWORD='a'\n"},
		{"trailing-whitespace", "RESTIC_PASSWORD='a' \n"},
		{"crlf-ending", "RESTIC_PASSWORD='a'\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "offsite.env")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			out, _ := runShell(t, dir, offsiteEnvLoaderFor(path)+"; if "+OffsiteEnvLoadName+" 2>/dev/null; then echo LOADED; else echo REJECTED; fi; printf '%s' \"${LD_PRELOAD-unset}\"")
			if !strings.Contains(out, "REJECTED") {
				t.Errorf("loader accepted a hostile file: %q", out)
			}
			if !strings.Contains(out, "unset") {
				t.Error("a non-allowlisted key leaked into the environment")
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
				t.Fatalf("the hostile line was EXECUTED: %v %v", entries, err)
			}
		})
	}
}

// The failure message must name the key at most — never a value: the values
// are the restic password and the S3 credentials.
func TestOffsiteEnvLoaderErrorNeverEchoesValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "offsite.env")
	if err := os.WriteFile(path, []byte("RESTIC_PASSWORD='sec'ret'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, rc := runShell(t, dir, offsiteEnvLoaderFor(path)+"; "+OffsiteEnvLoadName+" 2>&1")
	if rc == 0 {
		t.Fatal("embedded quote must be rejected")
	}
	for _, leak := range []string{"sec", "ret"} {
		if strings.Contains(out, leak) {
			t.Errorf("loader error leaked a value fragment %q: %q", leak, out)
		}
	}
}

// The definition itself lands in on-host root-executed files; freeze the
// properties the fix depends on so a refactor cannot quietly reintroduce
// evaluation.
func TestOffsiteEnvLoaderShape(t *testing.T) {
	def := OffsiteEnvLoader()
	if strings.Contains(def, "\n") {
		t.Error("the definition must stay one line — it is embedded in command strings")
	}
	for _, evil := range []string{". " + OffsiteEnvPath, "eval", "set -a"} {
		if strings.Contains(def, evil) {
			t.Errorf("loader must parse, never evaluate: found %q", evil)
		}
	}
	for _, k := range offsiteEnvKeys {
		if !strings.Contains(def, k+`=\'*\'`) {
			t.Errorf("allowlist pattern for %s missing", k)
		}
	}
	if !strings.HasPrefix(def, OffsiteEnvLoadName+"() {") {
		t.Errorf("definition must define %s: %q", OffsiteEnvLoadName, def)
	}
}

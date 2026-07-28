package integration

// Real-/bin/sh tests pinning envOverwriteScript's hardened semantics: a
// FakeRunner stub can only echo back what we assume, and the original
// NR==FNR form passed every stubbed test while truncating the .env on empty
// stdin. Deliberately untagged so `go test ./...` always runs them.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const overwriteSeedEnv = "APP_ENV=production\n" +
	"APP_KEY=base64:oldkey\n" +
	"DB_CONNECTION=mysql\n" +
	"DB_PASSWORD=oldpw123\n" +
	"DB_HOST=localhost\n"

// runOverwrite executes envOverwriteScript(envPath) under the local /bin/sh
// with the given stdin, pinning TMPDIR to tmpDir so the script's mktemp lands
// where the test can look for secret-bearing survivors. Returns the exit code.
func runOverwrite(t *testing.T, tmpDir, envPath, stdin string) int {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", envOverwriteScript(envPath))
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), "TMPDIR="+tmpDir)
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0
}

// assertNoSurvivors fails when the script left anything (i.e. its mktemp
// file, which carries the transformed .env) behind in the pinned TMPDIR.
func assertNoSurvivors(t *testing.T, tmpDir string) {
	t.Helper()
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("secret-bearing temp file survived: %s", e.Name())
	}
}

func TestEnvOverwriteScriptSwapsExactlyTwoValues(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte(overwriteSeedEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	if exit := runOverwrite(t, tmpDir, envPath, "newpw456\nbase64:newkey\n"); exit != 0 {
		t.Fatalf("exit = %d, want 0", exit)
	}
	got, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.NewReplacer(
		"APP_KEY=base64:oldkey", "APP_KEY=base64:newkey",
		"DB_PASSWORD=oldpw123", "DB_PASSWORD=newpw456",
	).Replace(overwriteSeedEnv)
	if string(got) != want {
		t.Errorf(".env after overwrite:\n%s\nwant:\n%s", got, want)
	}
	assertNoSurvivors(t, tmpDir)
}

// A stdin record count other than exactly 2 must fail BEFORE `cat > env`: the
// original .env stays byte-identical and the temp file is removed. Zero
// records is the case the original NR==FNR form got fatally wrong — it
// swallowed the whole .env as "values" and truncated it to nothing.
func TestEnvOverwriteScriptRefusesWrongStdinCounts(t *testing.T) {
	cases := []struct {
		name, stdin string
	}{
		{"zero-records", ""},
		{"one-record", "newpw456\n"},
		{"three-records", "newpw456\nbase64:newkey\nstray\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			envPath := filepath.Join(t.TempDir(), ".env")
			if err := os.WriteFile(envPath, []byte(overwriteSeedEnv), 0o600); err != nil {
				t.Fatal(err)
			}
			if exit := runOverwrite(t, tmpDir, envPath, c.stdin); exit != 9 {
				t.Errorf("exit = %d, want 9", exit)
			}
			got, err := os.ReadFile(envPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != overwriteSeedEnv {
				t.Errorf(".env changed on a refused overwrite:\n%s", got)
			}
			assertNoSurvivors(t, tmpDir)
		})
	}
}

// The rewrite goes through the existing inode (`cat > env`), so a pre-set
// restrictive mode survives — the property that keeps the site user's 0600
// ownership intact when the drill runs the script as root.
func TestEnvOverwriteScriptPreservesMode(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte(overwriteSeedEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	if exit := runOverwrite(t, tmpDir, envPath, "newpw456\nbase64:newkey\n"); exit != 0 {
		t.Fatalf("exit = %d, want 0", exit)
	}
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

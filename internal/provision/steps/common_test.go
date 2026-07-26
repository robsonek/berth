package steps

import (
	"context"
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

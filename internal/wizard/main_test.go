package wizard

import (
	"testing"

	"github.com/robsonek/berth/internal/version"
)

// TestMain runs the package as a release build. Under `go test` the version is
// "dev", so ToServer leaves requires_berth empty and every round-trip test
// (a.Write → config.Load) would fail on the missing key; tests that need
// another version swap it with versiontest.Set.
func TestMain(m *testing.M) {
	version.Version = "v0.37.0"
	m.Run()
}

// Package versiontest swaps the build version for one test.
package versiontest

import (
	"testing"

	"github.com/robsonek/berth/internal/version"
)

// Set makes version.Version report v until the test ends. Not for parallel tests.
func Set(t testing.TB, v string) {
	t.Helper()
	old := version.Version
	version.Version = v
	t.Cleanup(func() { version.Version = old })
}

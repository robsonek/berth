// Package version exposes build metadata injected via -ldflags and parses
// and orders berth versions: a release ("v0.37.0", or GoReleaser's "0.37.0")
// and a `git describe --tags --always --dirty` build ("v0.36.0-3-ge363573-dirty").
package version

var (
	// Version is the semantic version, set at build time.
	Version = "dev"
	// Commit is the git commit hash, set at build time.
	Commit = "none"
	// Date is the build date, set at build time.
	Date = "unknown"
)

// String returns a human-readable version line.
func String() string {
	return "berth " + Version + " (" + Commit + ", " + Date + ")"
}

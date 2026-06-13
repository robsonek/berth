// Package version exposes build metadata injected via -ldflags.
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

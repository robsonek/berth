//go:build integration

package steps

// This file bridges the integration suite into the production probe script
// builders, which are package-private by design: the drill must exercise the
// EXACT bytes provisioning runs, not a mirror that can drift. It exists only
// under the integration build tag, so the shipping binary never carries these
// exports.

// EnvValueMatchScript exposes envValueMatchScript: the expected KEY=value line
// rides stdin (never argv, never stdout) and only the exit code answers —
// 0 match, 1 present-but-different, 3 no such key, 2 I/O error.
func EnvValueMatchScript(path, key string) string { return envValueMatchScript(path, key) }

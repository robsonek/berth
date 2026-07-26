//go:build windows

package secret

import "os"

// Windows has no flock; berth on Windows is a rare SSH client and concurrent
// same-host runs are not protected there (a documented best-effort no-op — no
// worse than the pre-lock behaviour on every platform).
func lockFile(_ *os.File) error   { return nil }
func unlockFile(_ *os.File) error { return nil }

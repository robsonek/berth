//go:build !windows

package secret

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on f (released automatically when
// the descriptor closes or the process exits — no stale locks).
func lockFile(f *os.File) error   { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }
func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

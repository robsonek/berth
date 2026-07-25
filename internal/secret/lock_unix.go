//go:build !windows

package secret

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on f (released automatically when
// the descriptor closes or the process exits — no stale locks). flock(2) is
// never auto-restarted after a signal (SA_RESTART has no effect on it) and
// Go's async preemption delivers SIGURG regularly, so EINTR is retried.
func lockFile(f *os.File) error {
	for {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != syscall.EINTR {
			return err
		}
	}
}

func unlockFile(f *os.File) error {
	for {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != syscall.EINTR {
			return err
		}
	}
}

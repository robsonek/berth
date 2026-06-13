// Package ssh abstracts remote command execution and file writes.
package ssh

import (
	"context"
	"io/fs"
)

// Result is the outcome of a remote command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// FileSpec describes an atomic remote file write.
type FileSpec struct {
	Path    string
	Content []byte
	Owner   string
	Group   string
	Mode    fs.FileMode
	Sudo    bool
}

// Runner executes commands and writes files on a target host.
// Implementations must pass secrets via stdin, never via the command string.
type Runner interface {
	Run(ctx context.Context, cmd string, stdin []byte) (Result, error)
	WriteFile(ctx context.Context, f FileSpec) error
}

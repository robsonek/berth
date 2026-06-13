// Package ui renders provisioning progress events.
package ui

import (
	"os"

	"github.com/robsonek/berth/internal/provision"
	"golang.org/x/term"
)

// Renderer consumes the engine's event stream and reports progress.
// Render returns the terminal error (the Err of any EventFailed), or nil.
type Renderer interface {
	Render(events <-chan provision.Event) error
}

// IsTTY reports whether f is an interactive terminal.
func IsTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
